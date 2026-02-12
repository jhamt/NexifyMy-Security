<?php
/**
 * Consent Management Module.
 *
 * Tracks, enforces, and exports consent records for GDPR/CCPA workflows.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Consent_Management {

	/**
	 * Consent table suffix.
	 */
	const TABLE = 'nexifymy_consent_records';

	/**
	 * AJAX nonce action for consent writes.
	 */
	const AJAX_NONCE_ACTION = 'nexifymy_consent_record';

	/**
	 * IP rate-limit window in seconds.
	 */
	const RATE_LIMIT_WINDOW = 60;

	/**
	 * Max write requests per IP/window.
	 */
	const RATE_LIMIT_MAX_REQUESTS = 20;

	/**
	 * Default settings.
	 *
	 * @var array
	 */
	private static $defaults = array(
		'enabled'              => true,
		'banner_enabled'       => true,
		'preference_page_slug' => 'privacy-preferences',
	);

	/**
	 * Initialize module.
	 *
	 * @return void
	 */
	public function init() {
		$this->maybe_create_table();

		add_action( 'init', array( $this, 'handle_privacy_preferences_form' ) );
		add_action( 'wp_footer', array( $this, 'render_cookie_banner' ), 20 );
		add_shortcode( 'nexifymy_privacy_preferences', array( $this, 'render_privacy_preferences_shortcode' ) );

		add_action( 'user_register', array( $this, 'record_default_consent' ) );
		add_action( 'wp_login', array( $this, 'record_login_context' ), 10, 2 );

		add_filter( 'script_loader_tag', array( $this, 'enforce_script_consent' ), 10, 3 );

		add_action( 'wp_ajax_nexifymy_record_consent', array( $this, 'ajax_record_consent' ) );
		add_action( 'wp_ajax_nopriv_nexifymy_record_consent', array( $this, 'ajax_record_consent' ) );
		add_action( 'wp_ajax_nexifymy_export_consent_records', array( $this, 'ajax_export_consent_records' ) );

		add_action( 'show_user_profile', array( $this, 'render_user_consent_profile' ) );
		add_action( 'edit_user_profile', array( $this, 'render_user_consent_profile' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['consent'] ) ) {
				return wp_parse_args( $all_settings['consent'], self::$defaults );
			}
		}

		return self::$defaults;
	}

	/**
	 * Get allowed consent types.
	 *
	 * @return array
	 */
	private function get_allowed_consent_types() {
		$allowed = array( 'essential', 'functional', 'analytics', 'marketing', 'third_party' );

		if ( function_exists( 'apply_filters' ) ) {
			$allowed = apply_filters( 'nexifymy_allowed_consent_types', $allowed );
		}

		return array_values( array_unique( array_map( 'sanitize_key', (array) $allowed ) ) );
	}

	/**
	 * Validate a consent type.
	 *
	 * @param string $consent_type Consent type.
	 * @return bool
	 */
	private function is_valid_consent_type( $consent_type ) {
		return in_array( sanitize_key( (string) $consent_type ), $this->get_allowed_consent_types(), true );
	}

	/**
	 * Create consent table.
	 *
	 * @return void
	 */
	public function maybe_create_table() {
		global $wpdb;

		if ( empty( $wpdb ) || ! function_exists( 'dbDelta' ) ) {
			$upgrade_file = ABSPATH . 'wp-admin/includes/upgrade.php';
			if ( file_exists( $upgrade_file ) ) {
				require_once $upgrade_file;
			}
		}

		if ( empty( $wpdb ) || ! function_exists( 'dbDelta' ) ) {
			return;
		}

		$table_name      = $wpdb->prefix . self::TABLE;
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			consent_type varchar(32) NOT NULL,
			purpose varchar(255) NOT NULL,
			given_at datetime NOT NULL,
			expires_at datetime NULL,
			withdrawn_at datetime NULL,
			ip_address varchar(45) DEFAULT '',
			user_agent text NULL,
			consent_method varchar(50) NOT NULL DEFAULT 'checkbox',
			PRIMARY KEY (id),
			KEY user_id (user_id),
			KEY consent_type (consent_type),
			KEY given_at (given_at),
			KEY withdrawn_at (withdrawn_at)
		) {$charset_collate};";

		dbDelta( $sql );
	}

	/**
	 * Record consent grant.
	 *
	 * @param int         $user_id User ID.
	 * @param string      $consent_type Consent type.
	 * @param string      $purpose Purpose.
	 * @param string      $method Capture method.
	 * @param string|null $expires_at Expiration datetime.
	 * @return bool
	 */
	public function record_consent( $user_id, $consent_type, $purpose, $method, $expires_at = null ) {
		global $wpdb;

		$user_id      = absint( $user_id );
		$consent_type = sanitize_key( $consent_type );
		$purpose      = sanitize_text_field( $purpose );
		$method       = sanitize_key( $method );

		if ( empty( $consent_type ) || ! $this->is_valid_consent_type( $consent_type ) ) {
			return false;
		}

		$table_name = $wpdb->prefix . self::TABLE;
		$wpdb->insert(
			$table_name,
			array(
				'user_id'        => $user_id,
				'consent_type'   => $consent_type,
				'purpose'        => $purpose,
				'given_at'       => current_time( 'mysql' ),
				'expires_at'     => ! empty( $expires_at ) ? sanitize_text_field( $expires_at ) : null,
				'withdrawn_at'   => null,
				'ip_address'     => $this->get_client_ip(),
				'user_agent'     => substr( (string) $this->get_user_agent(), 0, 255 ),
				'consent_method' => $method,
			)
		);

		$cookie_name            = 'nexifymy_consent_' . $consent_type;
		$_COOKIE[ $cookie_name ] = '1';
		if ( ! headers_sent() ) {
			$cookie_path = defined( 'COOKIEPATH' ) && COOKIEPATH ? COOKIEPATH : '/';
			setcookie( $cookie_name, '1', time() + YEAR_IN_SECONDS, $cookie_path );
		}

		return true;
	}

	/**
	 * Check whether consent exists.
	 *
	 * @param int    $user_id User ID.
	 * @param string $consent_type Consent type.
	 * @return bool
	 */
	public function has_consent( $user_id, $consent_type ) {
		global $wpdb;

		$consent_type = sanitize_key( $consent_type );
		if ( 'essential' === $consent_type ) {
			return true;
		}
		if ( ! $this->is_valid_consent_type( $consent_type ) ) {
			return false;
		}

		$user_id = absint( $user_id );
		if ( $user_id > 0 ) {
			$table_name = $wpdb->prefix . self::TABLE;
			$query      = "SELECT id FROM {$table_name}
				WHERE user_id = {$user_id}
					AND consent_type = '" . esc_sql( $consent_type ) . "'
					AND withdrawn_at IS NULL
					AND (expires_at IS NULL OR expires_at > NOW())
				ORDER BY given_at DESC
				LIMIT 1";
			return ! empty( $wpdb->get_var( $query ) );
		}

		$cookie_name = 'nexifymy_consent_' . $consent_type;
		return isset( $_COOKIE[ $cookie_name ] ) && '1' === $_COOKIE[ $cookie_name ];
	}

	/**
	 * Withdraw consent.
	 *
	 * @param int    $user_id User ID.
	 * @param string $consent_type Consent type.
	 * @return bool
	 */
	public function withdraw_consent( $user_id, $consent_type ) {
		global $wpdb;

		$user_id      = absint( $user_id );
		$consent_type = sanitize_key( $consent_type );
		if ( ! $this->is_valid_consent_type( $consent_type ) ) {
			return false;
		}

		$table_name = $wpdb->prefix . self::TABLE;
		$wpdb->query(
			"UPDATE {$table_name}
			SET withdrawn_at = NOW()
			WHERE user_id = {$user_id}
				AND consent_type = '" . esc_sql( $consent_type ) . "'
				AND withdrawn_at IS NULL"
		);

		$cookie_name            = 'nexifymy_consent_' . $consent_type;
		$_COOKIE[ $cookie_name ] = '0';
		if ( ! headers_sent() ) {
			$cookie_path = defined( 'COOKIEPATH' ) && COOKIEPATH ? COOKIEPATH : '/';
			setcookie( $cookie_name, '0', time() - HOUR_IN_SECONDS, $cookie_path );
		}

		return true;
	}

	/**
	 * Return user consent timeline.
	 *
	 * @param int $user_id User ID.
	 * @return array
	 */
	public function get_user_consent_status( $user_id ) {
		global $wpdb;

		$user_id    = absint( $user_id );
		$table_name = $wpdb->prefix . self::TABLE;
		$query      = "SELECT consent_type, purpose, given_at, expires_at, withdrawn_at, consent_method
			FROM {$table_name}
			WHERE user_id = {$user_id}
			ORDER BY given_at DESC";

		return $wpdb->get_results( $query, ARRAY_A );
	}

	/**
	 * Export consent records for audit workflows.
	 *
	 * @param string $format csv|json.
	 * @param int    $user_id Optional user ID.
	 * @return string
	 */
	public function export_consent_records( $format = 'csv', $user_id = 0 ) {
		global $wpdb;

		$user_id    = absint( $user_id );
		$table_name = $wpdb->prefix . self::TABLE;
		$where_sql  = $user_id > 0 ? " WHERE user_id = {$user_id}" : '';
		$rows       = $wpdb->get_results( "SELECT * FROM {$table_name}{$where_sql} ORDER BY given_at DESC", ARRAY_A );

		if ( 'json' === $format ) {
			return wp_json_encode( $rows );
		}

		$stream = fopen( 'php://temp', 'r+' );
		fputcsv( $stream, array( 'id', 'user_id', 'consent_type', 'purpose', 'given_at', 'expires_at', 'withdrawn_at', 'ip_address', 'user_agent', 'consent_method' ) );
		foreach ( $rows as $row ) {
			fputcsv( $stream, $row );
		}
		rewind( $stream );
		$csv = stream_get_contents( $stream );
		fclose( $stream );

		return (string) $csv;
	}

	/**
	 * Conditionally block third-party scripts without consent.
	 *
	 * @param string $tag Script tag.
	 * @param string $handle Handle.
	 * @param string $src Src URL.
	 * @return string
	 */
	public function enforce_script_consent( $tag, $handle, $src ) {
		$required = $this->detect_required_consent_type( $src );
		if ( empty( $required ) ) {
			return $tag;
		}

		$user_id = get_current_user_id();
		if ( ! $this->has_consent( $user_id, $required ) ) {
			return '';
		}

		return $tag;
	}

	/**
	 * Detect required consent type based on script URL.
	 *
	 * @param string $src Script source.
	 * @return string
	 */
	private function detect_required_consent_type( $src ) {
		$src = strtolower( (string) $src );

		$analytics_hosts = array( 'google-analytics.com', 'googletagmanager.com', 'plausible.io' );
		$marketing_hosts = array( 'doubleclick.net', 'facebook.net', 'mailchimp.com', 'hubspot.com' );

		foreach ( $analytics_hosts as $host ) {
			if ( false !== strpos( $src, $host ) ) {
				return 'analytics';
			}
		}
		foreach ( $marketing_hosts as $host ) {
			if ( false !== strpos( $src, $host ) ) {
				return 'marketing';
			}
		}

		$site_host = wp_parse_url( home_url(), PHP_URL_HOST );
		$src_host  = wp_parse_url( $src, PHP_URL_HOST );
		if ( ! empty( $src_host ) && ! empty( $site_host ) && $src_host !== $site_host ) {
			return 'third_party';
		}

		return '';
	}

	/**
	 * Render consent banner.
	 *
	 * @return void
	 */
	public function render_cookie_banner() {
		$settings = $this->get_settings();
		if ( is_admin() || empty( $settings['banner_enabled'] ) ) {
			return;
		}

		$has_analytics = $this->has_consent( get_current_user_id(), 'analytics' );
		$has_marketing = $this->has_consent( get_current_user_id(), 'marketing' );
		if ( $has_analytics && $has_marketing ) {
			return;
		}
		$ajax_nonce = function_exists( 'wp_create_nonce' ) ? wp_create_nonce( self::AJAX_NONCE_ACTION ) : '';
		?>
		<div id="nexifymy-consent-banner" style="position:fixed;left:20px;right:20px;bottom:20px;z-index:99999;background:#111827;color:#f9fafb;padding:14px 16px;border-radius:8px;box-shadow:0 10px 24px rgba(0,0,0,.28)">
			<div style="display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap">
				<div>
					<strong>Privacy Preferences</strong>
					<p style="margin:4px 0 0">We use analytics and optional marketing scripts only with your consent.</p>
				</div>
				<div style="display:flex;gap:8px;align-items:center">
					<button type="button" id="nexifymy-consent-essential" style="border:1px solid #6b7280;background:transparent;color:#f9fafb;padding:8px 10px;border-radius:6px;cursor:pointer">Essential Only</button>
					<button type="button" id="nexifymy-consent-all" style="border:0;background:#10b981;color:#06281f;padding:8px 10px;border-radius:6px;cursor:pointer;font-weight:700">Accept All</button>
					<a href="<?php echo esc_url( home_url( '/' . trim( $settings['preference_page_slug'], '/' ) . '/' ) ); ?>" style="color:#93c5fd">Manage</a>
				</div>
			</div>
		</div>
		<script>
			(function() {
				var banner = document.getElementById('nexifymy-consent-banner');
				if (!banner) return;
				var nonce = <?php echo wp_json_encode( $ajax_nonce ); ?>;
				function postConsent(consentType, method) {
					var xhr = new XMLHttpRequest();
					xhr.open('POST', '<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>', true);
					xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
					xhr.send(
						'action=nexifymy_record_consent' +
						'&nonce=' + encodeURIComponent(nonce || '') +
						'&consent_type=' + encodeURIComponent(consentType) +
						'&purpose=' + encodeURIComponent('Cookie consent') +
						'&consent_method=' + encodeURIComponent(method)
					);
				}
			document.getElementById('nexifymy-consent-essential').addEventListener('click', function() {
				postConsent('functional', 'cookie_banner');
				banner.remove();
			});
			document.getElementById('nexifymy-consent-all').addEventListener('click', function() {
				['functional', 'analytics', 'marketing', 'third_party'].forEach(function(type) {
					postConsent(type, 'cookie_banner');
				});
				banner.remove();
			});
		})();
		</script>
		<?php
	}

	/**
	 * Render preference center shortcode.
	 *
	 * @return string
	 */
	public function render_privacy_preferences_shortcode() {
		$user_id = get_current_user_id();
		$types   = array(
			'functional'  => 'Functional',
			'analytics'   => 'Analytics',
			'marketing'   => 'Marketing',
			'third_party' => 'Third-party Sharing',
		);

		ob_start();
		?>
		<form method="post" class="nexifymy-privacy-preferences-form">
			<h3><?php esc_html_e( 'Privacy Preferences', 'nexifymy-security' ); ?></h3>
			<p><?php esc_html_e( 'Select which optional processing categories you allow.', 'nexifymy-security' ); ?></p>
			<?php wp_nonce_field( 'nexifymy_privacy_preferences', 'nexifymy_privacy_nonce' ); ?>
			<input type="hidden" name="nexifymy_privacy_preferences_submit" value="1">
			<?php foreach ( $types as $type => $label ) : ?>
				<p>
					<label>
						<input type="checkbox" name="consents[]" value="<?php echo esc_attr( $type ); ?>" <?php checked( $this->has_consent( $user_id, $type ) ); ?>>
						<?php echo esc_html( $label ); ?>
					</label>
				</p>
			<?php endforeach; ?>
			<p><button type="submit"><?php esc_html_e( 'Save Preferences', 'nexifymy-security' ); ?></button></p>
		</form>
		<?php

		return (string) ob_get_clean();
	}

	/**
	 * Persist preference center form submission.
	 *
	 * @return void
	 */
	public function handle_privacy_preferences_form() {
		if ( empty( $_POST['nexifymy_privacy_preferences_submit'] ) ) {
			return;
		}

		if ( ! isset( $_POST['nexifymy_privacy_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['nexifymy_privacy_nonce'] ) ), 'nexifymy_privacy_preferences' ) ) {
			return;
		}

		$user_id   = get_current_user_id();
		$selected  = isset( $_POST['consents'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['consents'] ) ) : array();
		$available = array( 'functional', 'analytics', 'marketing', 'third_party' );

		foreach ( $available as $type ) {
			if ( in_array( $type, $selected, true ) ) {
				$this->record_consent( $user_id, $type, 'Privacy preference center', 'granular_selection' );
			} else {
				$this->withdraw_consent( $user_id, $type );
			}
		}
	}

	/**
	 * Record default essential consent at registration.
	 *
	 * @param int $user_id User ID.
	 * @return void
	 */
	public function record_default_consent( $user_id ) {
		$this->record_consent( $user_id, 'essential', 'Required for site operation', 'registration' );
	}

	/**
	 * Record minimal login context consent evidence.
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user User object.
	 * @return void
	 */
	public function record_login_context( $user_login, $user ) {
		$user_id = is_object( $user ) && isset( $user->ID ) ? (int) $user->ID : 0;
		if ( $user_id > 0 && ! $this->has_consent( $user_id, 'essential' ) ) {
			$this->record_consent( $user_id, 'essential', 'Required for site authentication', 'login' );
		}
	}

	/**
	 * AJAX handler to record consent.
	 *
	 * @return void
	 */
	public function ajax_record_consent() {
		check_ajax_referer( self::AJAX_NONCE_ACTION, 'nonce' );

		$user_id      = get_current_user_id();
		$consent_type = isset( $_POST['consent_type'] ) ? sanitize_key( wp_unslash( $_POST['consent_type'] ) ) : '';
		$purpose      = isset( $_POST['purpose'] ) ? sanitize_text_field( wp_unslash( $_POST['purpose'] ) ) : 'Consent granted';
		$method       = isset( $_POST['consent_method'] ) ? sanitize_key( wp_unslash( $_POST['consent_method'] ) ) : 'cookie_banner';
		$purpose      = substr( (string) $purpose, 0, 255 );

		if ( empty( $consent_type ) ) {
			wp_send_json_error( 'Missing consent type' );
		}
		if ( ! $this->is_valid_consent_type( $consent_type ) ) {
			wp_send_json_error( 'Invalid consent type' );
		}

		$ip = $this->get_client_ip();
		if ( ! $this->consume_rate_limit_bucket( $ip ) ) {
			wp_send_json_error( 'Too many consent requests. Please retry shortly.', 429 );
		}

		$this->record_consent( $user_id, $consent_type, $purpose, $method );
		wp_send_json_success( array( 'consent_type' => $consent_type ) );
	}

	/**
	 * AJAX export consent records.
	 *
	 * @return void
	 */
	public function ajax_export_consent_records() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$format  = isset( $_POST['format'] ) ? sanitize_key( wp_unslash( $_POST['format'] ) ) : 'csv';
		$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
		if ( ! in_array( $format, array( 'csv', 'json' ), true ) ) {
			$format = 'csv';
		}

		$content = $this->export_consent_records( $format, $user_id );
		wp_send_json_success(
			array(
				'format'  => $format,
				'content' => $content,
			)
		);
	}

	/**
	 * Render consent status on user profile.
	 *
	 * @param WP_User $user User object.
	 * @return void
	 */
	public function render_user_consent_profile( $user ) {
		if ( ! is_object( $user ) || empty( $user->ID ) ) {
			return;
		}

		$records = $this->get_user_consent_status( (int) $user->ID );
		?>
		<h2><?php esc_html_e( 'Consent Management', 'nexifymy-security' ); ?></h2>
		<table class="widefat striped">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Type', 'nexifymy-security' ); ?></th>
					<th><?php esc_html_e( 'Purpose', 'nexifymy-security' ); ?></th>
					<th><?php esc_html_e( 'Given', 'nexifymy-security' ); ?></th>
					<th><?php esc_html_e( 'Withdrawn', 'nexifymy-security' ); ?></th>
					<th><?php esc_html_e( 'Method', 'nexifymy-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php if ( empty( $records ) ) : ?>
				<tr><td colspan="5"><?php esc_html_e( 'No consent records found.', 'nexifymy-security' ); ?></td></tr>
			<?php else : ?>
				<?php foreach ( $records as $record ) : ?>
					<tr>
						<td><?php echo esc_html( $record['consent_type'] ); ?></td>
						<td><?php echo esc_html( $record['purpose'] ); ?></td>
						<td><?php echo esc_html( $record['given_at'] ); ?></td>
						<td><?php echo esc_html( $record['withdrawn_at'] ?: '-' ); ?></td>
						<td><?php echo esc_html( $record['consent_method'] ); ?></td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Resolve request IP.
	 *
	 * @return string
	 */
	private function get_client_ip() {
		$candidates = array(
			$_SERVER['HTTP_CF_CONNECTING_IP'] ?? '',
			$_SERVER['HTTP_X_FORWARDED_FOR'] ?? '',
			$_SERVER['REMOTE_ADDR'] ?? '',
		);

		foreach ( $candidates as $value ) {
			$value = trim( explode( ',', (string) $value )[0] );
			if ( filter_var( $value, FILTER_VALIDATE_IP ) ) {
				return $value;
			}
		}

		return '';
	}

	/**
	 * Per-IP write throttling for public consent endpoint.
	 *
	 * @param string $ip_address Client IP.
	 * @return bool
	 */
	private function consume_rate_limit_bucket( $ip_address ) {
		$ip_address = (string) $ip_address;
		if ( '' === $ip_address || ! function_exists( 'get_transient' ) || ! function_exists( 'set_transient' ) ) {
			return true;
		}

		$key    = 'nexifymy_consent_rl_' . md5( $ip_address );
		$bucket = get_transient( $key );
		$count  = is_array( $bucket ) ? absint( $bucket['count'] ?? 0 ) : 0;
		$count++;

		if ( $count > self::RATE_LIMIT_MAX_REQUESTS ) {
			return false;
		}

		set_transient(
			$key,
			array(
				'count' => $count,
			),
			self::RATE_LIMIT_WINDOW
		);

		return true;
	}

	/**
	 * Resolve request User-Agent.
	 *
	 * @return string
	 */
	private function get_user_agent() {
		return sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ?? '' );
	}
}
