<?php
/**
 * Deception Technology (Honeypots) Module
 * Provides three layers of deception:
 *   1. Honeytrap URLs  — fake sensitive paths that no legitimate user would visit.
 *   2. Login Honeypot  — invisible form field that only bots fill in.
 *   3. User Enumeration Trap — catches author-id scanning on non-existent users.
 *
 * Every trigger logs the event, blocks the offending IP, and terminates
 * the request (unless the visitor is a logged-in administrator).
 *
 * @package NexifyMy_Security
 */

// ── Prevent direct access ──────────────────────────────────────────────
if ( ! defined( 'ABSPATH' ) ) {
	exit( 'Direct access denied.' );
}

/**
 * Class NexifyMy_Security_Deception
 *
 * Singleton-style module — instantiate once via NexifyMy_Security_Deception::init().
 */
class NexifyMy_Security_Deception {

	/**
	 * ================================================================
	 * Constants
	 * =================================================================
	 */

	/**
	 * Nonce action used to validate the hidden honeypot field on the
	 * login form (defence-in-depth; the real check is "was it filled?").
	 */
	const HONEYPOT_NONCE_ACTION = 'nexifymy_login_honeypot';

	/**
	 * Name attribute for the hidden login-form input.
	 * Chosen to look attractive to bots scanning for common field names.
	 */
	const HONEYPOT_FIELD_NAME = 'user_confirm_code';

	/**
	 * HTTP status code returned when a trap is triggered.
	 */
	const BLOCK_STATUS_CODE = 403;

	/**
	 * ================================================================
	 * Properties
	 * =================================================================
	 */

	/**
	 * Cached module settings (populated once by get_settings()).
	 *
	 * @var array|null
	 */
	private static $settings_cache = null;

	/**
	 * Flag to prevent the module from initialising more than once.
	 *
	 * @var bool
	 */
	private static $initialised = false;

	/**
	 * ================================================================
	 * Initialisation
	 * =================================================================
	 */

	/**
	 * Bootstrap the module.
	 *
	 * Called by the main NexifyMy_Security loader after all modules have
	 * been included.  Registers every WordPress hook the module needs.
	 *
	 * @return void
	 */
	public static function init() {

		// Guard: only run once.
		if ( self::$initialised ) {
			return;
		}
		self::$initialised = true;

		// ── Check the kill-switch in settings ──────────────────────
		$settings = self::get_settings();

		if ( empty( $settings['deception_enabled'] ) ) {
			return; // Module disabled — bail silently.
		}

		// Create fake honeypot files if enabled.
		if ( ! empty( $settings['deception_create_fake_files'] ) ) {
			self::create_fake_honeypot_files();
		}

		/*
		 * 1.  Honeytrap URL detection
		 *     Runs on `template_redirect` (priority 1 — before any theme
		 *     template is loaded) so we can intercept as early as possible
		 *     without breaking the REST API or admin-ajax.
		 */
		add_action( 'template_redirect', array( __CLASS__, 'check_honeytrap_urls' ), 1 );
		add_action( 'init', array( __CLASS__, 'monitor_file_access_patterns' ), 0 );

		/*
		 * 2.  Login-page honeypot
		 *     • Inject hidden field into every login form.
		 *     • Validate the field on authentication.
		 */
		add_action( 'login_form', array( __CLASS__, 'render_login_honeypot_field' ) );
		add_action( 'register_form', array( __CLASS__, 'render_login_honeypot_field' ) ); // Cover registration too.
		add_filter( 'wp_authenticate_user', array( __CLASS__, 'validate_login_honeypot' ), 1, 2 );

		/*
		 * 3.  User-enumeration trap
		 *     Fires early on `init` (priority 1) so the redirect that
		 *     WordPress normally performs for `?author=N` never happens.
		 */
		if ( ! empty( $settings['deception_enum_trap'] ) ) {
			add_action( 'init', array( __CLASS__, 'check_user_enumeration' ), 1 );
		}

		/*
		 * 4.  Admin notice — warn administrators who stumble on a
		 *     honeytrap URL while logged in (they are exempt from
		 *     blocking but should know the URL exists).
		 */
		add_action( 'admin_notices', array( __CLASS__, 'maybe_show_admin_notice' ) );
	}

	/**
	 * ================================================================
	 * 1. HONEYTRAP URL DETECTION
	 * =================================================================
	 */

	/**
	 * Compare the current request URI against every configured honeytrap
	 * path.  If a match is found the visitor is either warned (admin) or
	 * blocked (everyone else).
	 *
	 * Hooked to: `template_redirect` @ priority 1.
	 *
	 * @return void
	 */
	public static function check_honeytrap_urls() {

		$settings = self::get_settings();
		$paths    = self::get_honeytrap_paths( $settings );

		if ( empty( $paths ) ) {
			return;
		}

		// Normalise the current URI: strip query string, lowercase, trim slashes.
		$request_uri = self::normalise_path(
			isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : ''
		);

		foreach ( $paths as $trap_path ) {

			$trap_normalised = self::normalise_path( $trap_path );

			if ( '' === $trap_normalised ) {
				continue; // Skip blanks.
			}

			// Support both exact match and prefix match (trailing-slash agnostic).
			if ( $request_uri === $trap_normalised || 0 === strpos( $request_uri, $trap_normalised . '/' ) ) {

				// ── Logged-in admin?  Show notice instead of blocking. ─
				if ( self::is_current_user_admin() ) {
					// Store a transient so the admin notice can fire on
					// the next admin-page load (template_redirect runs
					// before admin_notices in a front-end context).
					set_transient(
						'nexifymy_deception_admin_warning_' . get_current_user_id(),
						sprintf(
							'You just visited a SentinelWP honeytrap URL: <code>%s</code>. '
							. 'Non-admin visitors hitting this path will be <strong>blocked immediately</strong>.',
							esc_html( $trap_path )
						),
						60 // 60 seconds — ephemeral
					);
					return; // Do NOT block the admin.
				}

				// ── Log ────────────────────────────────────────────────
				$ip   = self::get_client_ip();
				$data = array(
					'matched_path' => $trap_path,
					'request_uri'  => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
					'user_agent'   => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
					'referer'      => isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '',
					'method'       => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '',
					'ip'           => $ip,
					'timestamp'    => current_time( 'mysql' ),
				);

				self::log(
					'honeytrap_triggered',
					sprintf( 'Honeytrap triggered on "%s" by %s', $trap_path, $ip ),
					'critical',
					$data
				);

				// ── Block ──────────────────────────────────────────────
				self::block_ip( $ip, sprintf( 'Honeytrap triggered: %s', $trap_path ) );

				// ── Terminate ──────────────────────────────────────────
				self::send_forbidden_and_die( 'Access denied.' );
			}
		}
	}

	/**
	 * Return the list of honeytrap paths.
	 *
	 * Merges the hard-coded defaults with any paths the admin has added
	 * through the settings screen.
	 *
	 * @param  array $settings Plugin settings array.
	 * @return array           Flat array of path strings.
	 */
	private static function get_honeytrap_paths( array $settings ) {

		// ── Sensible defaults: files & directories attackers commonly probe. ─
		$defaults = array(
			'/backup.sql',
			'/database.sql',
			'/db.sql',
			'/dump.sql',
			'/wp-config.php.bak',
			'/wp-config.php.old',
			'/wp-config.php.save',
			'/wp-config.php.swp',
			'/wp-config.php.txt',
			'/wp-config.bak',
			'/wp-config.old',
			'/.env',
			'/.git/config',
			'/.git/HEAD',
			'/.svn/entries',
			'/admin-test/',
			'/admin-old/',
			'/old-site/',
			'/test/',
			'/phpinfo.php',
			'/info.php',
			'/adminer.php',
			'/phpmyadmin/',
			'/server-status',
			'/server-info',
			'/wp-admin/install.php',
			'/wp-content/debug.log',
			'/debug.log',
			'/error_log',
			'/errors.log',
			'/xmlrpc.php.bak',
			'/.htaccess.bak',
			'/.htpasswd',
			'/wp-login.php.bak',
			'/configuration.php.bak',
			'/config.php.bak',
		);

		// ── Merge with user-supplied paths ─────────────────────────
		$custom = array();

		if ( ! empty( $settings['deception_honeytrap_paths'] ) ) {
			if ( is_array( $settings['deception_honeytrap_paths'] ) ) {
				$custom = $settings['deception_honeytrap_paths'];
			} elseif ( is_string( $settings['deception_honeytrap_paths'] ) ) {
				// Support newline- or comma-separated strings from a <textarea>.
				$custom = preg_split( '/[\r\n,]+/', $settings['deception_honeytrap_paths'] );
			}
		}

		// If admin chose to override defaults entirely.
		if ( ! empty( $settings['deception_honeytrap_override_defaults'] ) ) {
			$paths = $custom;
		} else {
			$paths = array_merge( $defaults, $custom );
		}

		// Clean up: trim whitespace, remove empties, deduplicate.
		$paths = array_unique( array_filter( array_map( 'trim', $paths ) ) );

		/**
		 * Filter the final list of honeytrap paths.
		 *
		 * @param array $paths    Paths to act as honeytraps.
		 * @param array $settings Current module settings.
		 */
		return apply_filters( 'nexifymy_security_honeytrap_paths', $paths, $settings );
	}

	/**
	 * ================================================================
	 * 2. LOGIN PAGE HONEYPOT
	 * =================================================================
	 */

	/**
	 * Inject a hidden "honeypot" input field into the WordPress login
	 * (and registration) form.
	 *
	 * The field is styled with multiple layers of invisibility so it is
	 * never seen by real users but is irresistible to bots that blindly
	 * fill in every <input>.
	 *
	 * Hooked to: `login_form`, `register_form`.
	 *
	 * @return void
	 */
	public static function render_login_honeypot_field() {

		/**
		 * We use an outer <div> with:
		 *   - CSS: display:none (primary)
		 *   - aria-hidden="true" (screen readers)
		 *   - tabindex="-1"     (keyboard navigation)
		 *   - autocomplete="off" (password managers)
		 *
		 * The <label> text is deliberately inviting to bots
		 * ("Confirm you are human") but invisible to real users.
		 */
		$field_name = esc_attr( self::HONEYPOT_FIELD_NAME );

		// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<!-- SentinelWP Login Honeypot — do not remove -->' . "\n";
		echo '<div hidden' . "\n";
		echo '     aria-hidden="true"' . "\n";
		echo '     role="presentation">' . "\n";
		echo '    <label for="' . $field_name . '">Confirm you are human</label>' . "\n";
		echo '    <input type="text"' . "\n";
		echo '           name="' . $field_name . '"' . "\n";
		echo '           id="' . $field_name . '"' . "\n";
		echo '           value=""' . "\n";
		echo '           tabindex="-1"' . "\n";
		echo '           autocomplete="off" />' . "\n";
		echo '</div>' . "\n";
		echo '<!-- /SentinelWP Login Honeypot -->' . "\n";
		// phpcs:enable
	}

	/**
	 * Validate the hidden honeypot field when a user attempts to log in.
	 *
	 * If the field contains ANY value the request was almost certainly
	 * submitted by an automated bot.  We log, block, and refuse the
	 * authentication attempt.
	 *
	 * Hooked to: `wp_authenticate_user` (filter), priority 1.
	 *
	 * @param  WP_User|WP_Error $user     The user object (or error) so far.
	 * @param  string           $password  The plaintext password (unused).
	 * @return WP_User|WP_Error           Pass-through or WP_Error on trap.
	 */
	public static function validate_login_honeypot( $user, $password = '' ) {

		// If a previous filter already rejected the user, honour that.
		if ( is_wp_error( $user ) ) {
			return $user;
		}

		// Read the honeypot field from the POST payload.
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- no nonce for login by default
		$honeypot_value = isset( $_POST[ self::HONEYPOT_FIELD_NAME ] )
			? sanitize_text_field( wp_unslash( $_POST[ self::HONEYPOT_FIELD_NAME ] ) )
			: '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		// A legitimate visitor's browser will never populate this field.
		if ( '' !== $honeypot_value ) {

			$ip = self::get_client_ip();

			// phpcs:disable WordPress.Security.NonceVerification.Missing -- no nonce for login by default
			$data = array(
				'honeypot_value' => $honeypot_value,
				'username'       => isset( $_POST['log'] ) ? sanitize_user( wp_unslash( $_POST['log'] ) ) : '',
				'user_agent'     => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
				'ip'             => $ip,
				'timestamp'      => current_time( 'mysql' ),
			);
			// phpcs:enable WordPress.Security.NonceVerification.Missing

			self::log(
				'login_honeypot_triggered',
				sprintf( 'Login honeypot triggered by %s (field value: "%s")', $ip, $honeypot_value ),
				'critical',
				$data
			);

			self::block_ip( $ip, 'Login honeypot triggered (bot detected)' );

			// Return a generic error — never reveal the real reason.
			return new WP_Error(
				'nexifymy_honeypot',
				__( '<strong>Error</strong>: Something went wrong. Please try again later.', 'nexifymy-security' )
			);
		}

		return $user;
	}

	/**
	 * ================================================================
	 * 3. USER ENUMERATION TRAP
	 * =================================================================
	 */

	/**
	 * Detect author-ID enumeration scans.
	 *
	 * Attackers routinely request `/?author=1`, `/?author=2`, … to
	 * discover valid usernames.  If the requested author ID does not
	 * correspond to an existing user we treat it as reconnaissance and
	 * (optionally) block the IP.
	 *
	 * Hooked to: `init` @ priority 1.
	 *
	 * @return void
	 */
	public static function check_user_enumeration() {

		// Only act on front-end GET requests with an `author` query var.
		if ( is_admin() || wp_doing_ajax() || wp_doing_cron() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $_GET['author'] ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$author_id = absint( $_GET['author'] );

		if ( 0 === $author_id ) {
			return; // Not a numeric scan — ignore.
		}

		$user = get_user_by( 'ID', $author_id );

		// If the user exists this might be a legitimate archive request.
		if ( $user ) {
			$settings = self::get_settings();

			// Optional: block ALL author enumeration, even for existing users.
			if ( ! empty( $settings['deception_block_all_enum'] ) ) {

				if ( self::is_current_user_admin() ) {
					return; // Never block admins.
				}

				$ip = self::get_client_ip();

				self::log(
					'user_enum_existing',
					sprintf( 'Author enumeration detected for existing user ID %d by %s', $author_id, $ip ),
					'warning',
					array(
						'author_id'  => $author_id,
						'ip'         => $ip,
						'user_agent' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
						'timestamp'  => current_time( 'mysql' ),
					)
				);

				// Redirect to home instead of blocking (softer response).
				wp_safe_redirect( home_url( '/' ), 301 );
				exit;
			}

			return; // Default: allow valid author archives.
		}

		// ── The author ID does NOT exist — this is almost certainly a scan. ─

		if ( self::is_current_user_admin() ) {
			return; // Admins get a pass.
		}

		$ip = self::get_client_ip();

		$data = array(
			'author_id'  => $author_id,
			'ip'         => $ip,
			'user_agent' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
			'referer'    => isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '',
			'timestamp'  => current_time( 'mysql' ),
		);

		self::log(
			'user_enum_recon',
			sprintf( 'Reconnaissance: author enumeration for non-existent ID %d by %s', $author_id, $ip ),
			'high',
			$data
		);

		$settings = self::get_settings();

		if ( ! empty( $settings['deception_enum_block'] ) ) {
			self::block_ip( $ip, sprintf( 'User enumeration scan (author=%d)', $author_id ) );
			self::send_forbidden_and_die( 'Access denied.' );
		} else {
			// Soft response: silently redirect to the homepage.
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
	}

	/**
	 * ================================================================
	 * 4. FAKE FILE HONEYPOTS
	 * =================================================================
	 */

	/**
	 * Create fake honeypot files in the WordPress root directory.
	 *
	 * These files are designed to look like legitimate sensitive files
	 * that attackers commonly search for, but contain tracking beacons
	 * that alert us when accessed.
	 *
	 * @return void
	 */
	private static function create_fake_honeypot_files() {

		// Ensure we have write access to ABSPATH.
		if ( ! is_writable( ABSPATH ) ) {
			return;
		}

		$token = self::get_or_create_beacon_token();

		$files = array(
			'.env'                 => self::generate_fake_env_content( $token ),
			'wp-config-backup.php' => self::generate_fake_config_backup( $token ),
			'database-backup.sql'  => self::generate_fake_database_backup( $token ),
			'phpinfo.php'          => self::generate_tracking_phpinfo( $token ),
		);

		foreach ( $files as $filename => $content ) {

			$filepath = ABSPATH . $filename;

			// Only create if it doesn't already exist (don't overwrite real files).
			if ( file_exists( $filepath ) ) {
				continue;
			}

			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			file_put_contents( $filepath, $content );

			// Set restrictive permissions.
			chmod( $filepath, 0644 );
		}
	}

	/**
	 * Generate fake .env file content with tracking beacon.
	 *
	 * @param  string $token Unique tracking token.
	 * @return string        Fake .env file content.
	 */
	private static function generate_fake_env_content( $token ) {

		$content  = '# Environment Configuration' . "\n";
		$content .= '# DO NOT COMMIT THIS FILE' . "\n\n";
		$content .= 'APP_ENV=production' . "\n";
		$content .= 'APP_DEBUG=false' . "\n";
		$content .= 'APP_URL=' . home_url() . "\n\n";
		$content .= 'DB_HOST=localhost' . "\n";
		$content .= 'DB_DATABASE=wordpress_db' . "\n";
		$content .= 'DB_USERNAME=wp_user' . "\n";
		$content .= 'DB_PASSWORD=fake_password_' . $token . "\n\n";
		$content .= 'AWS_ACCESS_KEY_ID=AKIA' . strtoupper( substr( md5( $token ), 0, 16 ) ) . "\n";
		$content .= 'AWS_SECRET_ACCESS_KEY=' . base64_encode( $token . '_secret' ) . "\n\n";
		$content .= '# TRACKING_TOKEN=' . $token . "\n";

		return $content;
	}

	/**
	 * Generate fake wp-config backup with tracking beacon.
	 *
	 * @param  string $token Unique tracking token.
	 * @return string        Fake PHP config content.
	 */
	private static function generate_fake_config_backup( $token ) {

		$content  = '<?php' . "\n";
		$content .= '/**' . "\n";
		$content .= ' * WordPress Configuration Backup' . "\n";
		$content .= ' * Generated: ' . current_time( 'mysql' ) . "\n";
		$content .= ' */' . "\n\n";
		$content .= 'define( \'DB_NAME\', \'wordpress_backup_db\' );' . "\n";
		$content .= 'define( \'DB_USER\', \'backup_user\' );' . "\n";
		$content .= 'define( \'DB_PASSWORD\', \'backup_pass_' . $token . '\' );' . "\n";
		$content .= 'define( \'DB_HOST\', \'localhost\' );' . "\n\n";
		$content .= 'define( \'AUTH_KEY\', \'' . wp_generate_password( 64, true, true ) . '\' );' . "\n";
		$content .= 'define( \'SECURE_AUTH_KEY\', \'' . wp_generate_password( 64, true, true ) . '\' );' . "\n";
		$content .= 'define( \'LOGGED_IN_KEY\', \'' . wp_generate_password( 64, true, true ) . '\' );' . "\n";
		$content .= 'define( \'NONCE_KEY\', \'' . wp_generate_password( 64, true, true ) . '\' );' . "\n\n";
		$content .= '// Tracking token: ' . $token . "\n";
		$content .= 'define( \'NEXIFYMY_BEACON\', \'' . $token . '\' );' . "\n\n";
		$content .= 'if ( defined( \'NEXIFYMY_BEACON\' ) ) {' . "\n";
		$content .= '    @file_get_contents( \'' . home_url( '/?nexifymy_beacon=' . $token ) . '\' );' . "\n";
		$content .= '}' . "\n";

		return $content;
	}

	/**
	 * Generate fake database backup with tracking beacon.
	 *
	 * @param  string $token Unique tracking token.
	 * @return string        Fake SQL dump content.
	 */
	private static function generate_fake_database_backup( $token ) {

		$content   = '-- WordPress Database Backup' . "\n";
		$content  .= '-- Generated: ' . current_time( 'mysql' ) . "\n";
		$content  .= '-- Host: localhost' . "\n";
		$content  .= '-- Database: wordpress_backup' . "\n";
		$content  .= '-- Tracking Token: ' . $token . "\n\n";
		$content  .= 'SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";' . "\n";
		$content  .= 'SET time_zone = "+00:00";' . "\n\n";
		$content  .= 'CREATE TABLE IF NOT EXISTS `wp_users_backup` (' . "\n";
		$content  .= '  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,' . "\n";
		$content  .= '  `user_login` varchar(60) NOT NULL DEFAULT \'\',' . "\n";
		$content  .= '  `user_pass` varchar(255) NOT NULL DEFAULT \'\',' . "\n";
		$content  .= '  `user_email` varchar(100) NOT NULL DEFAULT \'\',' . "\n";
		$content  .= '  PRIMARY KEY (`ID`)' . "\n";
		$content  .= ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;' . "\n\n";
		$site_host = isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : 'honeypot.local';
		$content  .= 'INSERT INTO `wp_users_backup` VALUES (1, \'admin\', \'$P$B' . substr( md5( $token ), 0, 29 ) . '\', \'admin@' . $site_host . '\');' . "\n";

		return $content;
	}

	/**
	 * Generate tracking phpinfo script.
	 *
	 * @param  string $token Unique tracking token.
	 * @return string        PHP tracking code.
	 */
	private static function generate_tracking_phpinfo( $token ) {

		$content  = '<?php' . "\n";
		$content .= '// PHP Information - Development Only' . "\n";
		$content .= '// Tracking Token: ' . $token . "\n\n";
		$content .= '$beacon_url = \'' . home_url( '/?nexifymy_beacon=' . $token ) . '\';' . "\n";
		$content .= '@file_get_contents( $beacon_url );' . "\n\n";
		$content .= 'phpinfo();' . "\n";

		return $content;
	}

	/**
	 * Monitor file access patterns for honeypot files.
	 *
	 * Detects when someone tries to access our fake honeypot files
	 * by checking REQUEST_URI for suspicious patterns.
	 *
	 * Hooked to: `init` @ priority 0.
	 *
	 * @return void
	 */
	public static function monitor_file_access_patterns() {

		// Skip admin, AJAX, and cron requests.
		if ( is_admin() || wp_doing_ajax() || wp_doing_cron() ) {
			return;
		}

		// Check if this is a beacon callback.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['nexifymy_beacon'] ) ) {

			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$provided_token = sanitize_text_field( wp_unslash( $_GET['nexifymy_beacon'] ) );
			$expected_token = self::get_or_create_beacon_token();

			if ( $provided_token === $expected_token ) {

				$ip = self::get_client_ip();

				// Exempt admins from tracking.
				if ( self::is_current_user_admin() ) {
					self::serve_fake_404();
					return;
				}

				$data = array(
					'beacon_token' => $provided_token,
					'request_uri'  => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
					'user_agent'   => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
					'referer'      => isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '',
					'ip'           => $ip,
					'timestamp'    => current_time( 'mysql' ),
				);

				self::log(
					'fake_file_accessed',
					sprintf( 'Fake honeypot file accessed by %s (beacon triggered)', $ip ),
					'critical',
					$data
				);

				self::increment_offense_count( $ip, 'fake_file' );
				self::serve_fake_404();
			}

			return;
		}

		// Check REQUEST_URI for direct access to fake files.
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$request_uri = strtolower( $request_uri );

		$suspicious_files = array(
			'/.env',
			'/wp-config-backup.php',
			'/database-backup.sql',
			'/phpinfo.php',
		);

		foreach ( $suspicious_files as $fake_file ) {

			if ( false !== strpos( $request_uri, $fake_file ) ) {

				$ip = self::get_client_ip();

				// Exempt admins.
				if ( self::is_current_user_admin() ) {
					return;
				}

				$data = array(
					'fake_file'   => $fake_file,
					'request_uri' => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
					'user_agent'  => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
					'referer'     => isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '',
					'method'      => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '',
					'ip'          => $ip,
					'timestamp'   => current_time( 'mysql' ),
				);

				self::log(
					'fake_file_direct_access',
					sprintf( 'Direct access attempt to fake file %s by %s', $fake_file, $ip ),
					'critical',
					$data
				);

				// Increment offense count and potentially block.
				self::increment_offense_count( $ip, 'fake_file' );

				// Serve a realistic 404 instead of blocking immediately.
				self::serve_fake_404();
			}
		}
	}

	/**
	 * Increment the offense count for an IP address.
	 *
	 * Tracks repeat offenders. After 3 offenses within 1 hour,
	 * automatically block the IP.
	 *
	 * @param  string $ip   IP address.
	 * @param  string $type Offense type (for logging).
	 * @return void
	 */
	private static function increment_offense_count( $ip, $type ) {

		$transient_key = 'nexifymy_honeypot_offense_' . md5( $ip );
		$count         = (int) get_transient( $transient_key );

		++$count;

		// Store for 1 hour.
		set_transient( $transient_key, $count, HOUR_IN_SECONDS );

		// Block after 3 offenses.
		if ( $count >= 3 ) {

			self::log(
				'honeypot_repeat_offender',
				sprintf( 'IP %s blocked after %d honeypot offenses (%s)', $ip, $count, $type ),
				'critical',
				array(
					'ip'            => $ip,
					'offense_count' => $count,
					'offense_type'  => $type,
					'timestamp'     => current_time( 'mysql' ),
				)
			);

			self::block_ip( $ip, sprintf( 'Honeypot repeat offender (%d offenses, type: %s)', $count, $type ) );
		}
	}

	/**
	 * Serve a realistic 404 page and terminate.
	 *
	 * Instead of immediately blocking (403), we serve a fake 404 to
	 * avoid tipping off the attacker that they've triggered a honeypot.
	 *
	 * @return void This method never returns.
	 */
	private static function serve_fake_404() {

		if ( ! headers_sent() ) {
			status_header( 404 );
			header( 'Content-Type: text/html; charset=UTF-8' );
			nocache_headers();
		}

		$site_name = get_bloginfo( 'name' );

		$html  = '<!DOCTYPE html>' . "\n";
		$html .= '<html lang="en">' . "\n";
		$html .= '<head>' . "\n";
		$html .= '<meta charset="UTF-8">' . "\n";
		$html .= '<meta name="viewport" content="width=device-width, initial-scale=1.0">' . "\n";
		$html .= '<title>404 Not Found</title>' . "\n";
		$html .= '<style>body{font-family:Arial,sans-serif;text-align:center;padding:50px;background:#f4f4f4;}h1{font-size:50px;margin:0;}p{font-size:18px;color:#666;}</style>' . "\n";
		$html .= '</head>' . "\n";
		$html .= '<body>' . "\n";
		$html .= '<h1>404</h1>' . "\n";
		$html .= '<p>The requested file was not found on this server.</p>' . "\n";
		$html .= '<p><a href="' . esc_url( home_url( '/' ) ) . '">Return to ' . esc_html( $site_name ) . '</a></p>' . "\n";
		$html .= '</body>' . "\n";
		$html .= '</html>' . "\n";

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo $html;
		exit;
	}

	/**
	 * Get or create the beacon tracking token.
	 *
	 * This token is embedded in all fake honeypot files and used to
	 * verify legitimate beacon callbacks.
	 *
	 * @return string Unique tracking token.
	 */
	private static function get_or_create_beacon_token() {

		$token = get_option( 'nexifymy_honeypot_beacon_token' );

		if ( ! $token ) {
			$token = wp_generate_password( 32, false );
			update_option( 'nexifymy_honeypot_beacon_token', $token, false );
		}

		return $token;
	}

	/**
	 * ================================================================
	 * 5. ADMIN NOTICE
	 * =================================================================
	 */

	/**
	 * Display an admin-area warning if the current administrator has
	 * recently visited a honeytrap URL.
	 *
	 * The notice uses a short-lived transient so it only shows once and
	 * does not clutter the dashboard.
	 *
	 * Hooked to: `admin_notices`.
	 *
	 * @return void
	 */
	public static function maybe_show_admin_notice() {

		if ( ! self::is_current_user_admin() ) {
			return;
		}

		$transient_key = 'nexifymy_deception_admin_warning_' . get_current_user_id();
		$message       = get_transient( $transient_key );

		if ( ! $message ) {
			return;
		}

		// Show the notice and delete the transient immediately.
		delete_transient( $transient_key );

		printf(
			'<div class="notice notice-warning is-dismissible"><p><strong>⚠️ SentinelWP Deception Module:</strong> %s</p></div>',
			wp_kses(
				$message,
				array(
					'code'   => array(),
					'strong' => array(),
					'em'     => array(),
				)
			)
		);
	}

	/**
	 * ================================================================
	 * Settings Helper
	 * =================================================================
	 */

	/**
	 * Retrieve and cache the plugin settings relevant to this module.
	 *
	 * All SentinelWP settings live in a single serialised option row.
	 * This method fetches the row once per request, merges it with sane
	 * defaults, and returns the result.
	 *
	 * Expected settings keys consumed by this module:
	 *
	 *   deception_enabled                bool   Master switch.
	 *   deception_honeytrap_paths        mixed  Array or newline-separated string of extra paths.
	 *   deception_honeytrap_override_defaults bool  If true, ONLY use the custom paths.
	 *   deception_enum_trap              bool   Enable the user-enumeration trap.
	 *   deception_enum_block             bool   Hard-block on enum (vs. soft redirect).
	 *   deception_block_all_enum         bool   Block enumeration even for existing users.
	 *
	 * @return array
	 */
	public static function get_settings() {

		if ( null !== self::$settings_cache ) {
			return self::$settings_cache;
		}

		$defaults = array(
			'deception_enabled'                     => true,
			'deception_honeytrap_paths'             => array(),
			'deception_honeytrap_override_defaults' => false,
			'deception_enum_trap'                   => true,
			'deception_enum_block'                  => false, // Soft redirect by default.
			'deception_block_all_enum'              => false,
			'deception_create_fake_files'           => true,
		);

		$stored = get_option( 'nexifymy_security_settings', array() );

		if ( ! is_array( $stored ) ) {
			$stored = array();
		}

		$module_settings = ( isset( $stored['modules'] ) && is_array( $stored['modules'] ) ) ? $stored['modules'] : array();
		foreach ( array_keys( $defaults ) as $key ) {
			if ( array_key_exists( $key, $module_settings ) ) {
				$stored[ $key ] = $module_settings[ $key ];
			}
		}

		self::$settings_cache = wp_parse_args( $stored, $defaults );

		return self::$settings_cache;
	}

	/**
	 * Bust the internal settings cache.
	 *
	 * Useful in unit tests or after programmatic settings changes.
	 *
	 * @return void
	 */
	public static function flush_settings_cache() {
		self::$settings_cache = null;
	}

	/**
	 * ================================================================
	 * Wrapper / Utility Methods
	 * =================================================================
	 */

	/**
	 * Write an event to the SentinelWP log.
	 *
	 * Falls back to `error_log()` if the dedicated logger class is not
	 * available (e.g., during isolated testing).
	 *
	 * @param  string $type    Short machine-readable event type.
	 * @param  string $message Human-readable description.
	 * @param  string $level   Severity: info | warning | high | critical.
	 * @param  array  $data    Arbitrary context data.
	 * @return void
	 */
	private static function log( $type, $message, $level = 'warning', $data = array() ) {

		if ( class_exists( 'NexifyMy_Security_Logger' ) && method_exists( 'NexifyMy_Security_Logger', 'log' ) ) {
			NexifyMy_Security_Logger::log( $type, $message, $level, $data );
			return;
		}

		// Fallback: PHP error log.
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		error_log(
			sprintf(
				'[SentinelWP Deception] [%s] [%s] %s | %s',
				strtoupper( $level ),
				$type,
				$message,
				wp_json_encode( $data )
			)
		);
	}

	/**
	 * Block an IP address via the SentinelWP firewall.
	 *
	 * Gracefully degrades if the firewall class is absent.
	 *
	 * @param  string $ip     IPv4 or IPv6 address.
	 * @param  string $reason Explanation stored alongside the block rule.
	 * @return void
	 */
	private static function block_ip( $ip, $reason = '' ) {

		if ( class_exists( 'NexifyMy_Security_Firewall' ) && method_exists( 'NexifyMy_Security_Firewall', 'block_ip' ) ) {
			NexifyMy_Security_Firewall::block_ip( $ip, $reason );
			return;
		}

		// Fallback: log the intent so it can be reviewed.
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		error_log(
			sprintf(
				'[SentinelWP Deception] BLOCK_IP (firewall unavailable): %s — %s',
				$ip,
				$reason
			)
		);
	}

	/**
	 * Return the client's IP address.
	 *
	 * Respects common reverse-proxy headers but prefers REMOTE_ADDR
	 * when no proxy header is present.
	 *
	 * @return string
	 */
	private static function get_client_ip() {
		$remote_addr     = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$trusted_proxies = get_option( 'nexifymy_security_trusted_proxies', array() );

		if ( $remote_addr && in_array( $remote_addr, (array) $trusted_proxies, true ) ) {
			$headers = array(
				'HTTP_CF_CONNECTING_IP', // Cloudflare.
				'HTTP_X_FORWARDED_FOR',  // Generic proxy / load balancer.
				'HTTP_X_REAL_IP',        // Nginx proxy_pass.
				'HTTP_CLIENT_IP',
			);

			foreach ( $headers as $header ) {
				if ( empty( $_SERVER[ $header ] ) ) {
					continue;
				}

				// X-Forwarded-For may be a comma-separated list; take the first.
				$raw = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
				$ip  = trim( strtok( $raw, ',' ) );

				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}

		if ( $remote_addr && filter_var( $remote_addr, FILTER_VALIDATE_IP ) ) {
			return $remote_addr;
		}

		return '0.0.0.0';
	}

	/**
	 * Normalise a URL path for reliable comparison.
	 *
	 * Strips the query string, lowercases the path, and trims leading/
	 * trailing slashes.
	 *
	 * @param  string $path Raw path or URI.
	 * @return string       Normalised path.
	 */
	private static function normalise_path( $path ) {

		// Remove query string and fragment.
		$path = strtok( $path, '?#' );

		// Decode percent-encoded characters so `/wp%2Dconfig.php.bak` matches.
		$path = rawurldecode( $path );

		// Collapse duplicate slashes.
		$path = preg_replace( '#/+#', '/', $path );

		// Lowercase for case-insensitive matching.
		$path = strtolower( $path );

		// Trim surrounding slashes for uniform comparison.
		$path = trim( $path, '/' );

		return $path;
	}

	/**
	 * Send a 403 Forbidden response and terminate.
	 *
	 * @param  string $message Optional body text.
	 * @return void            This method never returns.
	 */
	private static function send_forbidden_and_die( $message = 'Forbidden' ) {

		// If headers haven't been sent yet, set the status code.
		if ( ! headers_sent() ) {
			status_header( self::BLOCK_STATUS_CODE );
			header( 'Content-Type: text/plain; charset=UTF-8' );
			nocache_headers();
		}

		// Use wp_die() for a cleaner output when available.
		if ( function_exists( 'wp_die' ) ) {
			wp_die(
				esc_html( $message ),
				esc_html__( '403 Forbidden', 'nexifymy-security' ),
				array( 'response' => (int) self::BLOCK_STATUS_CODE )
			);
		}

		// Hard fallback.
		exit( esc_html( $message ) );
	}

	/**
	 * Determine whether the current visitor is a logged-in administrator.
	 *
	 * @return bool
	 */
	private static function is_current_user_admin() {

		// is_user_logged_in() may not be available during very early hooks.
		if ( ! function_exists( 'is_user_logged_in' ) || ! function_exists( 'current_user_can' ) ) {
			return false;
		}

		return is_user_logged_in() && current_user_can( 'manage_options' );
	}

	/**
	 * ================================================================
	 * Reset (for unit tests)
	 * =================================================================
	 */

	/**
	 * Reset internal state so the module can be re-initialised in tests.
	 *
	 * @internal Only for PHPUnit / integration tests.
	 * @return void
	 */
	public static function _reset() {
		self::$initialised    = false;
		self::$settings_cache = null;
	}
}
