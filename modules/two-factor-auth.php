<?php
/**
 * Two-Factor Authentication Module.
 * Adds TOTP-based 2FA to WordPress login.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Two_Factor {

	/**
	 * Meta key for user's 2FA secret.
	 */
	const SECRET_META_KEY = '_nexifymy_2fa_secret';

	/**
	 * Meta key for 2FA enabled status.
	 */
	const ENABLED_META_KEY = '_nexifymy_2fa_enabled';

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'          => true,
		'force_admin'      => false,  // Force 2FA for admins.
		'force_all'        => false,  // Force 2FA for all users.
		'email_backup'     => true,   // Allow email code as backup.
		'remember_days'    => 30,     // Days to remember device.
	);

	/**
	 * Initialize the module.
	 */
	public function init() {
		$all_settings = get_option( 'nexifymy_security_settings', array() );
		if ( isset( $all_settings['modules']['two_factor_enabled'] ) && ! $all_settings['modules']['two_factor_enabled'] ) {
			return;
		}

		$settings = $this->get_settings();

		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Hook into authentication.
		add_action( 'wp_login', array( $this, 'check_2fa_requirement' ), 10, 2 );
		add_filter( 'authenticate', array( $this, 'validate_2fa_code' ), 99, 3 );

		// Add 2FA verification form.
		add_action( 'login_form_2fa_verify', array( $this, 'render_2fa_form' ) );

		// User profile settings.
		add_action( 'show_user_profile', array( $this, 'render_user_settings' ) );
		add_action( 'edit_user_profile', array( $this, 'render_user_settings' ) );
		add_action( 'personal_options_update', array( $this, 'save_user_settings' ) );
		add_action( 'edit_user_profile_update', array( $this, 'save_user_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_profile_assets' ) );

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_generate_2fa_secret', array( $this, 'ajax_generate_secret' ) );
		add_action( 'wp_ajax_nexifymy_verify_2fa_setup', array( $this, 'ajax_verify_setup' ) );
		add_action( 'wp_ajax_nexifymy_disable_2fa', array( $this, 'ajax_disable_2fa' ) );
		add_action( 'wp_ajax_nexifymy_send_email_code', array( $this, 'ajax_send_email_code' ) );
		add_action( 'wp_ajax_nopriv_nexifymy_send_email_code', array( $this, 'ajax_send_email_code' ) );
		add_action( 'wp_ajax_nexifymy_get_2fa_settings', array( $this, 'ajax_get_settings' ) );
		add_action( 'wp_ajax_nexifymy_save_2fa_settings', array( $this, 'ajax_save_settings' ) );
	}

	/**
	 * Enqueue minimal profile-page styles for 2FA status badges.
	 *
	 * @param string $hook Current admin page hook.
	 * @return void
	 */
	public function enqueue_profile_assets( $hook ) {
		if ( ! in_array( $hook, array( 'profile.php', 'user-edit.php' ), true ) ) {
			return;
		}

		wp_enqueue_style(
			'nexifymy-two-factor-profile',
			NEXIFYMY_SECURITY_URL . 'assets/css/two-factor-auth.css',
			array(),
			NEXIFYMY_SECURITY_VERSION
		);
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['two_factor'] ) ) {
				return wp_parse_args( $all_settings['two_factor'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Generate a new secret key.
	 *
	 * @return string Base32 encoded secret.
	 */
	public function generate_secret() {
		$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$secret = '';
		for ( $i = 0; $i < 16; $i++ ) {
			$secret .= $chars[ wp_rand( 0, 31 ) ];
		}
		return $secret;
	}

	/**
	 * Generate TOTP code.
	 *
	 * @param string $secret Base32 secret.
	 * @param int    $time_slice Time slice (default: current).
	 * @return string 6-digit code.
	 */
	public function get_totp_code( $secret, $time_slice = null ) {
		if ( null === $time_slice ) {
			$time_slice = floor( time() / 30 );
		}

		// Decode base32 secret.
		$secret_key = $this->base32_decode( $secret );

		// Pack time into binary.
		$time = pack( 'N*', 0 ) . pack( 'N*', $time_slice );

		// Generate HMAC.
		$hash = hash_hmac( 'sha1', $time, $secret_key, true );

		// Get offset.
		$offset = ord( substr( $hash, -1 ) ) & 0x0F;

		// Get 4 bytes at offset.
		$binary = unpack( 'N', substr( $hash, $offset, 4 ) )[1] & 0x7FFFFFFF;

		// Get 6 digits.
		$otp = $binary % 1000000;

		return str_pad( $otp, 6, '0', STR_PAD_LEFT );
	}

	/**
	 * Verify TOTP code.
	 *
	 * @param string $secret User's secret.
	 * @param string $code Submitted code.
	 * @param int    $window Time window for verification.
	 * @return bool
	 */
	public function verify_totp( $secret, $code, $window = 1 ) {
		$time_slice = floor( time() / 30 );

		for ( $i = -$window; $i <= $window; $i++ ) {
			if ( $this->get_totp_code( $secret, $time_slice + $i ) === $code ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Base32 decode.
	 *
	 * @param string $input Base32 string.
	 * @return string Binary data.
	 */
	private function base32_decode( $input ) {
		$map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$input = strtoupper( $input );
		$input = str_replace( '=', '', $input );

		$buffer = 0;
		$bits_left = 0;
		$output = '';

		for ( $i = 0; $i < strlen( $input ); $i++ ) {
			$char = $input[ $i ];
			$value = strpos( $map, $char );

			if ( false === $value ) {
				continue;
			}

			$buffer = ( $buffer << 5 ) | $value;
			$bits_left += 5;

			if ( $bits_left >= 8 ) {
				$bits_left -= 8;
				$output .= chr( ( $buffer >> $bits_left ) & 0xFF );
			}
		}

		return $output;
	}

	/**
	 * Check if user has 2FA enabled.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public function is_2fa_enabled( $user_id ) {
		return (bool) get_user_meta( $user_id, self::ENABLED_META_KEY, true );
	}

	/**
	 * Get user's 2FA secret.
	 *
	 * @param int $user_id User ID.
	 * @return string|false
	 */
	public function get_user_secret( $user_id ) {
		return get_user_meta( $user_id, self::SECRET_META_KEY, true );
	}

	/**
	 * Generate QR code URL for Google Authenticator.
	 *
	 * @param string $secret Secret key.
	 * @param string $email User email.
	 * @return string QR code URL.
	 */
	public function get_qr_url( $secret, $email ) {
		$issuer = rawurlencode( get_bloginfo( 'name' ) );
		$email = rawurlencode( $email );
		$otpauth = "otpauth://totp/{$issuer}:{$email}?secret={$secret}&issuer={$issuer}";
		return 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=' . rawurlencode( $otpauth );
	}

	/**
	 * Check if user requires 2FA on login.
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user User object.
	 */
	public function check_2fa_requirement( $user_login, $user ) {
		if ( ! $this->is_2fa_enabled( $user->ID ) ) {
			return;
		}

		// Check if device is remembered.
		if ( $this->is_device_remembered( $user->ID ) ) {
			return;
		}

		// Log out and redirect to 2FA form.
		wp_clear_auth_cookie();

		$token = wp_generate_password( 32, false );
		set_transient( 'nexifymy_2fa_' . $token, $user->ID, 5 * MINUTE_IN_SECONDS );

		wp_safe_redirect( add_query_arg( array(
			'action' => '2fa_verify',
			'token'  => $token,
		), wp_login_url() ) );
		exit;
	}

	/**
	 * Validate 2FA code during verification.
	 *
	 * @param WP_User|WP_Error|null $user User or error.
	 * @param string                $username Username.
	 * @param string                $password Password.
	 * @return WP_User|WP_Error
	 */
	public function validate_2fa_code( $user, $username, $password ) {
		// Only process during 2FA verification.
		if ( ! isset( $_POST['nexifymy_2fa_token'] ) ) {
			return $user;
		}

		$token = sanitize_text_field( wp_unslash( $_POST['nexifymy_2fa_token'] ) );
		$code = isset( $_POST['nexifymy_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['nexifymy_2fa_code'] ) ) : '';

		$user_id = get_transient( 'nexifymy_2fa_' . $token );

		if ( ! $user_id ) {
			return new WP_Error( '2fa_expired', __( 'Verification session expired. Please log in again.', 'nexifymy-security' ) );
		}

		$secret = $this->get_user_secret( $user_id );

		if ( ! $this->verify_totp( $secret, $code ) ) {
			return new WP_Error( '2fa_invalid', __( 'Invalid verification code.', 'nexifymy-security' ) );
		}

		// Clear token.
		delete_transient( 'nexifymy_2fa_' . $token );

		// Remember device if requested.
		if ( ! empty( $_POST['nexifymy_remember_device'] ) ) {
			$this->remember_device( $user_id );
		}

		// Return user object.
		return get_user_by( 'ID', $user_id );
	}

	/**
	 * Check if device is remembered.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	private function is_device_remembered( $user_id ) {
		$cookie_name = 'nexifymy_2fa_remember_' . $user_id;
		if ( ! isset( $_COOKIE[ $cookie_name ] ) ) {
			return false;
		}

		$token = sanitize_text_field( wp_unslash( $_COOKIE[ $cookie_name ] ) );
		$stored = get_user_meta( $user_id, '_nexifymy_2fa_remember', true );

		return $token === $stored;
	}

	/**
	 * Remember device.
	 *
	 * @param int $user_id User ID.
	 */
	private function remember_device( $user_id ) {
		$settings = $this->get_settings();
		$days = absint( $settings['remember_days'] ) ?: 30;

		$token = wp_generate_password( 32, false );
		update_user_meta( $user_id, '_nexifymy_2fa_remember', $token );

		setcookie(
			'nexifymy_2fa_remember_' . $user_id,
			$token,
			time() + ( $days * DAY_IN_SECONDS ),
			COOKIEPATH,
			COOKIE_DOMAIN,
			is_ssl(),
			true
		);
	}

	/**
	 * Render 2FA verification form.
	 */
	public function render_2fa_form() {
		$token = isset( $_GET['token'] ) ? sanitize_text_field( wp_unslash( $_GET['token'] ) ) : '';

		if ( ! get_transient( 'nexifymy_2fa_' . $token ) ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		login_header( __( 'Two-Factor Authentication', 'nexifymy-security' ) );
		?>
		<form name="2fa_form" id="2fa_form" action="<?php echo esc_url( wp_login_url() ); ?>" method="post">
			<input type="hidden" name="nexifymy_2fa_token" value="<?php echo esc_attr( $token ); ?>" />

			<p>
				<label for="nexifymy_2fa_code"><?php _e( 'Authentication Code', 'nexifymy-security' ); ?></label>
				<input type="text" name="nexifymy_2fa_code" id="nexifymy_2fa_code" class="input" size="20" autocomplete="off" autofocus />
			</p>

			<p>
				<label>
					<input type="checkbox" name="nexifymy_remember_device" value="1" />
					<?php _e( 'Remember this device', 'nexifymy-security' ); ?>
				</label>
			</p>

			<p class="submit">
				<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'nexifymy-security' ); ?>" />
			</p>
		</form>
		<?php
		login_footer();
		exit;
	}

	/**
	 * Render user profile 2FA settings.
	 *
	 * @param WP_User $user User object.
	 */
	public function render_user_settings( $user ) {
		$is_enabled = $this->is_2fa_enabled( $user->ID );
		?>
		<h2><?php _e( 'Two-Factor Authentication', 'nexifymy-security' ); ?></h2>
		<table class="form-table">
			<tr>
				<th><?php _e( 'Status', 'nexifymy-security' ); ?></th>
				<td>
					<?php if ( $is_enabled ) : ?>
						<span class="nms-2fa-status nms-2fa-status-enabled"><?php _e( 'Enabled', 'nexifymy-security' ); ?></span>
						<button type="button" class="button" id="disable-2fa"><?php _e( 'Disable 2FA', 'nexifymy-security' ); ?></button>
					<?php else : ?>
						<span class="nms-2fa-status nms-2fa-status-disabled"><?php _e( 'Not Enabled', 'nexifymy-security' ); ?></span>
						<button type="button" class="button button-primary" id="setup-2fa"><?php _e( 'Enable 2FA', 'nexifymy-security' ); ?></button>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<div id="2fa-setup-modal" hidden></div>
		<?php
	}

	/**
	 * Save user 2FA settings.
	 *
	 * @param int $user_id User ID.
	 */
	public function save_user_settings( $user_id ) {
		// Handled via AJAX.
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	/**
	 * Generate new 2FA secret via AJAX.
	 */
	public function ajax_generate_secret() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! is_user_logged_in() ) {
			wp_send_json_error( 'Not logged in' );
		}

		$user = wp_get_current_user();
		$secret = $this->generate_secret();

		// Store temporarily.
		set_transient( 'nexifymy_2fa_setup_' . $user->ID, $secret, 10 * MINUTE_IN_SECONDS );

		wp_send_json_success( array(
			'secret' => $secret,
			'qr_url' => $this->get_qr_url( $secret, $user->user_email ),
		) );
	}

	/**
	 * Verify 2FA setup via AJAX.
	 */
	public function ajax_verify_setup() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! is_user_logged_in() ) {
			wp_send_json_error( 'Not logged in' );
		}

		$user = wp_get_current_user();
		$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
		$secret = get_transient( 'nexifymy_2fa_setup_' . $user->ID );

		if ( ! $secret ) {
			wp_send_json_error( 'Setup session expired.' );
		}

		if ( ! $this->verify_totp( $secret, $code ) ) {
			wp_send_json_error( 'Invalid code. Please try again.' );
		}

		// Save secret and enable 2FA.
		update_user_meta( $user->ID, self::SECRET_META_KEY, $secret );
		update_user_meta( $user->ID, self::ENABLED_META_KEY, true );
		delete_transient( 'nexifymy_2fa_setup_' . $user->ID );

		wp_send_json_success( array( 'message' => '2FA enabled successfully.' ) );
	}

	/**
	 * Disable 2FA via AJAX.
	 */
	public function ajax_disable_2fa() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! is_user_logged_in() ) {
			wp_send_json_error( 'Not logged in' );
		}

		$user = wp_get_current_user();

		delete_user_meta( $user->ID, self::SECRET_META_KEY );
		delete_user_meta( $user->ID, self::ENABLED_META_KEY );
		delete_user_meta( $user->ID, '_nexifymy_2fa_remember' );

		wp_send_json_success( array( 'message' => '2FA disabled.' ) );
	}

	/**
	 * Send email backup code.
	 * Rate limited to one email per 60 seconds per token.
	 */
	public function ajax_send_email_code() {
		$token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';

		if ( empty( $token ) ) {
			wp_send_json_error( 'Missing token.' );
		}

		// Rate limit check - only allow one email per 60 seconds per token.
		$rate_key = 'nexifymy_2fa_email_rate_' . md5( $token );
		if ( get_transient( $rate_key ) ) {
			wp_send_json_error( 'Please wait before requesting another code.' );
		}

		$user_id = get_transient( 'nexifymy_2fa_' . $token );

		if ( ! $user_id ) {
			wp_send_json_error( 'Invalid session.' );
		}

		$user = get_user_by( 'ID', $user_id );
		$code = wp_rand( 100000, 999999 );

		set_transient( 'nexifymy_2fa_email_' . $user_id, $code, 10 * MINUTE_IN_SECONDS );
		set_transient( $rate_key, true, 60 ); // Rate limit for 60 seconds.

		$subject = sprintf( '[%s] Your login verification code', get_bloginfo( 'name' ) );
		$message = sprintf( __( 'Your verification code is: %s', 'nexifymy-security' ), $code );

		wp_mail( $user->user_email, $subject, $message );

		wp_send_json_success( array( 'message' => 'Code sent to your email.' ) );
	}

	/**
	 * Get settings via AJAX.
	 */
	public function ajax_get_settings() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		wp_send_json_success( array( 'settings' => $this->get_settings() ) );
	}

	/**
	 * Save settings via AJAX.
	 */
	public function ajax_save_settings() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$settings = array(
			'enabled'       => ! empty( $_POST['enabled'] ),
			'force_admin'   => ! empty( $_POST['force_admin'] ),
			'force_all'     => ! empty( $_POST['force_all'] ),
			'email_backup'  => ! empty( $_POST['email_backup'] ),
			'remember_days' => isset( $_POST['remember_days'] ) ? absint( $_POST['remember_days'] ) : 30,
		);

		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			$all_settings['two_factor'] = $settings;
			update_option( 'nexifymy_security_settings', $all_settings );
		}

		wp_send_json_success( array( 'message' => 'Settings saved.' ) );
	}
}
