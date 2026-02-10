<?php
/**
 * Plugin Self-Protection Module.
 * Protects the plugin files from tampering and unauthorized modifications.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Self_Protection {

	/**
	 * Option key for file hashes.
	 */
	const HASH_OPTION = 'nexifymy_plugin_hashes';

	/**
	 * Option key for protection status.
	 */
	const STATUS_OPTION = 'nexifymy_protection_status';

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'              => true,
		'monitor_plugin_files' => true,
		'check_interval'       => 'hourly',
		'auto_restore'         => false,
		'email_alerts'         => true,
		'block_file_editor'    => true,
	);

	/**
	 * Critical plugin files to protect.
	 */
	private $protected_files = array(
		'nexifymy-security.php',
		'includes/class-nexifymy-security-admin.php',
		'includes/class-nexifymy-security-settings.php',
		'modules/firewall.php',
		'modules/scanner.php',
		'modules/rate-limiter.php',
	);

	/**
	 * Initialize the module.
	 */
	public function init() {
		$all_settings = get_option( 'nexifymy_security_settings', array() );
		if ( isset( $all_settings['modules']['self_protection_enabled'] ) && ! $all_settings['modules']['self_protection_enabled'] ) {
			return;
		}

		$settings = $this->get_settings();

		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Block file editor for plugin files.
		if ( ! empty( $settings['block_file_editor'] ) ) {
			add_filter( 'plugin_action_links', array( $this, 'remove_edit_link' ), 10, 4 );
			add_action( 'admin_init', array( $this, 'block_editor_access' ) );
		}

		// Schedule integrity checks.
		add_action( 'nexifymy_integrity_check', array( $this, 'run_integrity_check' ) );
		if ( ! wp_next_scheduled( 'nexifymy_integrity_check' ) ) {
			$interval = $settings['check_interval'] === 'daily' ? 'daily' : 'hourly';
			wp_schedule_event( time(), $interval, 'nexifymy_integrity_check' );
		}

		// Verify on admin load.
		add_action( 'admin_init', array( $this, 'verify_on_load' ) );

		// Protect against direct file access.
		add_action( 'init', array( $this, 'prevent_direct_access' ), 0 );

		// Anti-tampering headers.
		add_action( 'send_headers', array( $this, 'add_protection_headers' ) );

		// Monitor plugin deactivation.
		add_action( 'deactivated_plugin', array( $this, 'monitor_deactivation' ) );

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_run_integrity_check', array( $this, 'ajax_run_check' ) );
		add_action( 'wp_ajax_nexifymy_generate_hashes', array( $this, 'ajax_generate_hashes' ) );
		add_action( 'wp_ajax_nexifymy_get_protection_status', array( $this, 'ajax_get_status' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['self_protection'] ) ) {
				return wp_parse_args( $all_settings['self_protection'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Generate file hash.
	 *
	 * @param string $file_path Absolute file path.
	 * @return string|false SHA256 hash or false.
	 */
	private function generate_file_hash( $file_path ) {
		if ( ! file_exists( $file_path ) || ! is_readable( $file_path ) ) {
			return false;
		}
		return hash_file( 'sha256', $file_path );
	}

	/**
	 * Generate hashes for all protected files.
	 *
	 * @return array File => hash pairs.
	 */
	public function generate_all_hashes() {
		$hashes = array();

		foreach ( $this->get_all_plugin_files() as $file ) {
			$full_path = NEXIFYMY_SECURITY_PATH . $file;
			$hash = $this->generate_file_hash( $full_path );
			if ( $hash ) {
				$hashes[ $file ] = $hash;
			}
		}

		return $hashes;
	}

	/**
	 * Get all plugin PHP files.
	 *
	 * @return array List of relative file paths.
	 */
	private function get_all_plugin_files() {
		$files = array();
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( NEXIFYMY_SECURITY_PATH, RecursiveDirectoryIterator::SKIP_DOTS )
		);

		foreach ( $iterator as $file ) {
			if ( $file->isFile() && $file->getExtension() === 'php' ) {
				$relative_path = str_replace( NEXIFYMY_SECURITY_PATH, '', $file->getPathname() );
				$relative_path = ltrim( str_replace( '\\', '/', $relative_path ), '/' );
				$files[] = $relative_path;
			}
		}

		return $files;
	}

	/**
	 * Store hashes in database.
	 *
	 * @param array $hashes File hashes.
	 */
	public function store_hashes( $hashes ) {
		$data = array(
			'hashes'    => $hashes,
			'generated' => current_time( 'mysql' ),
			'version'   => NEXIFYMY_SECURITY_VERSION,
		);
		update_option( self::HASH_OPTION, $data, false );
	}

	/**
	 * Get stored hashes.
	 *
	 * @return array|false Stored data or false.
	 */
	public function get_stored_hashes() {
		return get_option( self::HASH_OPTION, false );
	}

	/**
	 * Run integrity check.
	 *
	 * @return array Check results.
	 */
	public function run_integrity_check() {
		$stored = $this->get_stored_hashes();

		if ( ! $stored || empty( $stored['hashes'] ) ) {
			// First run - generate baseline.
			$hashes = $this->generate_all_hashes();
			$this->store_hashes( $hashes );
			return array(
				'status'  => 'baseline_created',
				'message' => 'Baseline hashes created.',
				'files'   => count( $hashes ),
			);
		}

		$current_hashes = $this->generate_all_hashes();
		$stored_hashes = $stored['hashes'];

		$modified = array();
		$added = array();
		$deleted = array();

		// Check for modified and deleted files.
		foreach ( $stored_hashes as $file => $hash ) {
			if ( ! isset( $current_hashes[ $file ] ) ) {
				$deleted[] = $file;
			} elseif ( $current_hashes[ $file ] !== $hash ) {
				$modified[] = $file;
			}
		}

		// Check for new files.
		foreach ( $current_hashes as $file => $hash ) {
			if ( ! isset( $stored_hashes[ $file ] ) ) {
				$added[] = $file;
			}
		}

		$tampered = ! empty( $modified ) || ! empty( $deleted );

		// Log and alert if tampered.
		if ( $tampered ) {
			$this->handle_tampering( $modified, $added, $deleted );
		}

		// Update status.
		$status = array(
			'last_check' => current_time( 'mysql' ),
			'status'     => $tampered ? 'tampered' : 'ok',
			'modified'   => $modified,
			'added'      => $added,
			'deleted'    => $deleted,
		);
		update_option( self::STATUS_OPTION, $status, false );

		return $status;
	}

	/**
	 * Handle detected tampering.
	 *
	 * @param array $modified Modified files.
	 * @param array $added Added files.
	 * @param array $deleted Deleted files.
	 */
	private function handle_tampering( $modified, $added, $deleted ) {
		$settings = $this->get_settings();

		// Log the event.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'plugin_tampering',
				sprintf( 'Plugin tampering detected: %d modified, %d added, %d deleted', count( $modified ), count( $added ), count( $deleted ) ),
				'critical',
				array(
					'modified' => $modified,
					'added'    => $added,
					'deleted'  => $deleted,
				)
			);
		}

		// Send email alert.
		if ( ! empty( $settings['email_alerts'] ) ) {
			$this->send_tampering_alert( $modified, $added, $deleted );
		}
	}

	/**
	 * Send tampering alert email.
	 *
	 * @param array $modified Modified files.
	 * @param array $added Added files.
	 * @param array $deleted Deleted files.
	 */
	private function send_tampering_alert( $modified, $added, $deleted ) {
		$to = get_option( 'admin_email' );
		$subject = sprintf( '[%s] CRITICAL: Security Plugin Tampering Detected', get_bloginfo( 'name' ) );

		$message = "CRITICAL SECURITY ALERT\n\n";
		$message .= "NexifyMy Security has detected unauthorized modifications to its own files.\n\n";

		if ( ! empty( $modified ) ) {
			$message .= "MODIFIED FILES:\n";
			foreach ( $modified as $file ) {
				$message .= "  - {$file}\n";
			}
			$message .= "\n";
		}

		if ( ! empty( $added ) ) {
			$message .= "NEW SUSPICIOUS FILES:\n";
			foreach ( $added as $file ) {
				$message .= "  - {$file}\n";
			}
			$message .= "\n";
		}

		if ( ! empty( $deleted ) ) {
			$message .= "DELETED FILES:\n";
			foreach ( $deleted as $file ) {
				$message .= "  - {$file}\n";
			}
			$message .= "\n";
		}

		$message .= "RECOMMENDED ACTIONS:\n";
		$message .= "1. Log in to your WordPress admin immediately\n";
		$message .= "2. Check if you made these changes yourself\n";
		$message .= "3. If not, reinstall the plugin from a trusted source\n";
		$message .= "4. Run a full malware scan\n";
		$message .= "5. Change all admin passwords\n\n";
		$message .= "Site: " . home_url() . "\n";
		$message .= "Time: " . current_time( 'mysql' ) . "\n";

		wp_mail( $to, $subject, $message );
	}

	/**
	 * Verify plugin integrity on admin load.
	 */
	public function verify_on_load() {
		// Only check once per hour in admin.
		$last_check = get_transient( 'nexifymy_last_admin_check' );
		if ( $last_check ) {
			return;
		}

		set_transient( 'nexifymy_last_admin_check', true, HOUR_IN_SECONDS );

		// Quick check of critical files only.
		$stored = $this->get_stored_hashes();
		if ( ! $stored || empty( $stored['hashes'] ) ) {
			return;
		}

		foreach ( $this->protected_files as $file ) {
			$full_path = NEXIFYMY_SECURITY_PATH . $file;
			$current_hash = $this->generate_file_hash( $full_path );

			if ( isset( $stored['hashes'][ $file ] ) && $current_hash !== $stored['hashes'][ $file ] ) {
				// Critical file modified!
				add_action( 'admin_notices', array( $this, 'show_tampering_notice' ) );
				break;
			}
		}
	}

	/**
	 * Show tampering admin notice.
	 */
	public function show_tampering_notice() {
		echo '<div class="notice notice-error">';
		echo '<p><strong>' . esc_html__( 'SECURITY ALERT:', 'nexifymy-security' ) . '</strong> ';
		echo esc_html__( 'NexifyMy Security has detected unauthorized modifications to its files. Please verify your installation.', 'nexifymy-security' );
		echo '</p></div>';
	}

	/**
	 * Remove edit link for this plugin.
	 *
	 * @param array  $actions Plugin action links.
	 * @param string $plugin_file Plugin file.
	 * @param array  $plugin_data Plugin data.
	 * @param string $context Context.
	 * @return array
	 */
	public function remove_edit_link( $actions, $plugin_file, $plugin_data, $context ) {
		if ( strpos( $plugin_file, 'nexifymy-security' ) !== false ) {
			unset( $actions['edit'] );
		}
		return $actions;
	}

	/**
	 * Block editor access for plugin files.
	 */
	public function block_editor_access() {
		global $pagenow;

		if ( 'plugin-editor.php' !== $pagenow ) {
			return;
		}

		$file = isset( $_REQUEST['file'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['file'] ) ) : '';
		$plugin = isset( $_REQUEST['plugin'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['plugin'] ) ) : '';

		if ( strpos( $file, 'nexifymy-security' ) !== false || strpos( $plugin, 'nexifymy-security' ) !== false ) {
			wp_die(
				__( 'Editing NexifyMy Security plugin files is disabled for security reasons.', 'nexifymy-security' ),
				__( 'Access Denied', 'nexifymy-security' ),
				array( 'response' => 403, 'back_link' => true )
			);
		}
	}

	/**
	 * Prevent direct file access attempts.
	 */
	public function prevent_direct_access() {
		// All plugin files already have ABSPATH check.
		// This adds an extra layer by monitoring suspicious access patterns.
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		// Check for direct access attempts to plugin files.
		if ( strpos( $request_uri, 'nexifymy-security' ) !== false && strpos( $request_uri, '.php' ) !== false ) {
			// Allow normal WordPress requests.
			if ( defined( 'DOING_AJAX' ) || defined( 'DOING_CRON' ) || is_admin() ) {
				return;
			}

			// Log suspicious access.
			if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
				NexifyMy_Security_Logger::log(
					'direct_access_attempt',
					'Direct access attempt to plugin file blocked',
					'warning',
					array( 'uri' => $request_uri, 'ip' => $this->get_client_ip() )
				);
			}
		}
	}

	/**
	 * Add protection headers.
	 */
	public function add_protection_headers() {
		if ( headers_sent() ) {
			return;
		}

		// Content Security Policy for admin pages.
		if ( is_admin() ) {
			// X-Content-Type-Options.
			header( 'X-Content-Type-Options: nosniff' );
		}
	}

	/**
	 * Monitor plugin deactivation.
	 *
	 * @param string $plugin Plugin basename.
	 */
	public function monitor_deactivation( $plugin ) {
		if ( strpos( $plugin, 'nexifymy-security' ) === false ) {
			return;
		}

		// Log deactivation.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			$user = wp_get_current_user();
			NexifyMy_Security_Logger::log(
				'plugin_deactivated',
				sprintf( 'NexifyMy Security was deactivated by user: %s', $user->user_login ),
				'warning',
				array( 'user_id' => $user->ID, 'user_login' => $user->user_login )
			);
		}

		// Send alert email.
		$settings = $this->get_settings();
		if ( ! empty( $settings['email_alerts'] ) ) {
			$user = wp_get_current_user();
			$to = get_option( 'admin_email' );
			$subject = sprintf( '[%s] Security Plugin Deactivated', get_bloginfo( 'name' ) );
			$message = sprintf(
				"NexifyMy Security was deactivated.\n\nUser: %s\nTime: %s\nIP: %s",
				$user->user_login,
				current_time( 'mysql' ),
				$this->get_client_ip()
			);
			wp_mail( $to, $subject, $message );
		}
	}

	/**
	 * Get client IP.
	 *
	 * @return string
	 */
	private function get_client_ip() {
		$remote_addr     = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$trusted_proxies = get_option( 'nexifymy_security_trusted_proxies', array() );

		if ( $remote_addr && in_array( $remote_addr, (array) $trusted_proxies, true ) ) {
			$headers = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP' );
			foreach ( $headers as $header ) {
				if ( empty( $_SERVER[ $header ] ) ) {
					continue;
				}

				$raw = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
				$ip  = strpos( $raw, ',' ) !== false ? trim( explode( ',', $raw )[0] ) : $raw;
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

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	/**
	 * Run integrity check via AJAX.
	 */
	public function ajax_run_check() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$result = $this->run_integrity_check();
		wp_send_json_success( $result );
	}

	/**
	 * Generate new baseline hashes via AJAX.
	 */
	public function ajax_generate_hashes() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$hashes = $this->generate_all_hashes();
		$this->store_hashes( $hashes );

		wp_send_json_success( array(
			'message' => 'Baseline hashes regenerated.',
			'files'   => count( $hashes ),
			'time'    => current_time( 'mysql' ),
		) );
	}

	/**
	 * Get protection status via AJAX.
	 */
	public function ajax_get_status() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$status = get_option( self::STATUS_OPTION, array() );
		$stored = $this->get_stored_hashes();

		wp_send_json_success( array(
			'status'         => $status,
			'baseline_date'  => isset( $stored['generated'] ) ? $stored['generated'] : null,
			'baseline_files' => isset( $stored['hashes'] ) ? count( $stored['hashes'] ) : 0,
			'version'        => isset( $stored['version'] ) ? $stored['version'] : null,
		) );
	}
}
