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
		'enabled'       => true,
		'force_admin'   => false,  // Force 2FA for admins.
		'force_all'     => false,  // Force 2FA for all users.
		'email_backup'  => true,   // Allow email code as backup.
		'remember_days' => 30,     // Days to remember device.
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
		$chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
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

		$map       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$input     = strtoupper( $input );
		$input     = str_replace( '=', '', $input );
		$buffer    = 0;
		$bits_left = 0;
		$output    = '';

		for ( $i = 0; $i < strlen( $input ); $i++ ) {
			$char  = $input[ $i ];
			$value = strpos( $map, $char );

			if ( false === $value ) {
				continue;
			}

			$buffer     = ( $buffer << 5 ) | $value;
			$bits_left += 5;

			if ( $bits_left >= 8 ) {
				$bits_left -= 8;
				$output    .= chr( ( $buffer >> $bits_left ) & 0xFF );
			}
		}

		return $output;
	}

	/**
	 * Validate 2FA session token format.
	 *
	 * @param string $token Session token.
	 * @return bool
	 */
	private function is_valid_session_token( $token ) {

		return is_string( $token ) && 1 === preg_match( '/^[A-Za-z0-9]{20,64}$/', $token );
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
		$issuer  = rawurlencode( get_bloginfo( 'name' ) );
		$email   = rawurlencode( $email );
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

		wp_safe_redirect(
			add_query_arg(
				array(
					'action' => '2fa_verify',
					'token'  => $token,
				),
				wp_login_url()
			)
		);
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
       // phpcs:disable WordPress.Security.NonceVerification.Missing
		// Login flow is pre-auth and uses the 2FA session token.
		if ( ! isset( $_POST['nexifymy_2fa_token'] ) ) {
			return $user;
		}

		$token = sanitize_text_field( wp_unslash( $_POST['nexifymy_2fa_token'] ) );
		$code  = isset( $_POST['nexifymy_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['nexifymy_2fa_code'] ) ) : '';
		$nonce = isset( $_POST['nexifymy_2fa_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['nexifymy_2fa_nonce'] ) ) : '';

		if ( ! $this->is_valid_session_token( $token ) ) {
			return new WP_Error( '2fa_invalid_session', __( 'Invalid verification session. Please log in again.', 'nexifymy-security' ) );
		}

		if ( ! wp_verify_nonce( $nonce, 'nexifymy_2fa_verify_' . $token ) ) {
			return new WP_Error( '2fa_invalid_request', __( 'Invalid verification request. Please try again.', 'nexifymy-security' ) );
		}

		$code = preg_replace( '/\D+/', '', $code );
		if ( strlen( $code ) !== 6 ) {
			return new WP_Error( '2fa_invalid', __( 'Invalid verification code.', 'nexifymy-security' ) );
		}

		$user_id = get_transient( 'nexifymy_2fa_' . $token );

		if ( ! $user_id ) {
			return new WP_Error( '2fa_expired', __( 'Verification session expired. Please log in again.', 'nexifymy-security' ) );
		}

		$secret = $this->get_user_secret( $user_id );
		if ( ! is_string( $secret ) || '' === trim( $secret ) ) {
			return new WP_Error( '2fa_not_configured', __( 'Two-factor authentication is not configured for this account.', 'nexifymy-security' ) );
		}

		if ( ! $this->verify_totp( $secret, $code ) ) {
			return new WP_Error( '2fa_invalid', __( 'Invalid verification code.', 'nexifymy-security' ) );
		}
		// Clear token.
		delete_transient( 'nexifymy_2fa_' . $token );

		// Remember device if requested.
		if ( ! empty( $_POST['nexifymy_remember_device'] ) ) {
			$this->remember_device( $user_id );
		}
      // phpcs:enable WordPress.Security.NonceVerification.Missing

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

		$token  = sanitize_text_field( wp_unslash( $_COOKIE[ $cookie_name ] ) );
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
		$days     = absint( $settings['remember_days'] ) ?: 30;

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

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only session token from login URL.
		$token = isset( $_GET['token'] ) ? sanitize_text_field( wp_unslash( $_GET['token'] ) ) : '';

		if ( ! $this->is_valid_session_token( $token ) || ! get_transient( 'nexifymy_2fa_' . $token ) ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}
		login_header( __( 'Two-Factor Authentication', 'nexifymy-security' ) );
		?>
		<form name="2fa_form" id="2fa_form" action="<?php echo esc_url( wp_login_url() ); ?>" method="post">
			<input type="hidden" name="nexifymy_2fa_token" value="<?php echo esc_attr( $token ); ?>" />
			<?php wp_nonce_field( 'nexifymy_2fa_verify_' . $token, 'nexifymy_2fa_nonce' ); ?>

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
    // phpcs:disable WordPress.Security.NonceVerification.Missing
	// Renders profile UI only; does not process submitted data.
	public function render_user_settings( $user ) {

		$is_enabled = $this->is_2fa_enabled( $user->ID );
		$ajax_url   = admin_url( 'admin-ajax.php' );
		$nonce      = wp_create_nonce( 'nexifymy_security_nonce' );
		?>
		<h2><?php _e( 'Two-Factor Authentication', 'nexifymy-security' ); ?></h2>
		<table class="form-table">
			<tr>
				<th><?php _e( 'Status', 'nexifymy-security' ); ?></th>
				<td>
					<?php if ( $is_enabled ) : ?>
						<span style="color: green; font-weight: bold;">✓ <?php _e( 'Enabled', 'nexifymy-security' ); ?></span>
						<button type="button" class="button" id="disable-2fa"><?php _e( 'Disable 2FA', 'nexifymy-security' ); ?></button>
					<?php else : ?>
						<span style="color: orange;">✗ <?php _e( 'Not Enabled', 'nexifymy-security' ); ?></span>
						<button type="button" class="button button-primary" id="setup-2fa"><?php _e( 'Enable 2FA', 'nexifymy-security' ); ?></button>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<div id="2fa-setup-modal" style="display: none;"></div>
		<script type="text/javascript">
		(function() {
			const setupBtn = document.getElementById('setup-2fa');
			const disableBtn = document.getElementById('disable-2fa');
			const modal = document.getElementById('2fa-setup-modal');
			const ajaxUrl = <?php echo wp_json_encode( $ajax_url ); ?>;
			const nonce = <?php echo wp_json_encode( $nonce ); ?>;
			const userId = <?php echo (int) $user->ID; ?>;
			const successColor = '#008a20';
			const errorColor = '#b32d2e';

			function extractMessage(response, fallback) {
				if (!response || typeof response !== 'object') {
					return fallback;
				}
				if (typeof response.data === 'string' && response.data.trim() !== '') {
					return response.data;
				}
				if (response.data && typeof response.data.message === 'string' && response.data.message.trim() !== '') {
					return response.data.message;
				}
				return fallback;
			}

			function postAction(action, payload) {
				const body = new URLSearchParams({
					action: action,
					nonce: nonce,
					user_id: String(userId)
				});
				if (payload && typeof payload === 'object') {
					Object.keys(payload).forEach(function(key) {
						body.append(key, payload[key]);
					});
				}

				return fetch(ajaxUrl, {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
					credentials: 'same-origin',
					body: body.toString()
				}).then(function(res) {
					return res.json();
				});
			}

			function closeModal() {
				if (!modal) {
					return;
				}
				modal.style.display = 'none';
				modal.innerHTML = '';
			}

			function showMessage(element, message, isError) {
				if (!element) {
					return;
				}
				element.textContent = message;
				element.style.color = isError ? errorColor : successColor;
			}

			function showSetupModal(payload) {
				if (!modal) {
					return;
				}

				modal.style.display = 'block';
				modal.style.padding = '16px';
				modal.style.background = '#fff';
				modal.style.border = '1px solid #ccd0d4';
				modal.style.maxWidth = '420px';
				modal.style.marginTop = '12px';
				modal.innerHTML =
					'<h3 style="margin-top:0;">' + <?php echo wp_json_encode( __( 'Set up Two-Factor Authentication', 'nexifymy-security' ) ); ?> + '</h3>' +
					'<p>' + <?php echo wp_json_encode( __( 'Scan this QR code in your authenticator app, then enter the 6-digit code to finish setup.', 'nexifymy-security' ) ); ?> + '</p>' +
					'<p><img src=\"' + payload.qr_url + '\" alt=\"QR Code\" style=\"max-width:200px;height:auto;\" /></p>' +
					'<p><strong>' + <?php echo wp_json_encode( __( 'Manual key:', 'nexifymy-security' ) ); ?> + '</strong> <code>' + payload.secret + '</code></p>' +
					'<p><input type=\"text\" id=\"nexifymy-2fa-verify-code\" class=\"regular-text\" maxlength=\"6\" placeholder=\"123456\" /></p>' +
					'<p>' +
					'<button type=\"button\" class=\"button button-primary\" id=\"nexifymy-2fa-verify-btn\">' + <?php echo wp_json_encode( __( 'Verify & Enable', 'nexifymy-security' ) ); ?> + '</button> ' +
					'<button type=\"button\" class=\"button\" id=\"nexifymy-2fa-cancel-btn\">' + <?php echo wp_json_encode( __( 'Cancel', 'nexifymy-security' ) ); ?> + '</button>' +
					'</p>' +
					'<p id=\"nexifymy-2fa-modal-message\"></p>';

				const verifyBtn = document.getElementById('nexifymy-2fa-verify-btn');
				const cancelBtn = document.getElementById('nexifymy-2fa-cancel-btn');
				const codeInput = document.getElementById('nexifymy-2fa-verify-code');
				const messageEl = document.getElementById('nexifymy-2fa-modal-message');

				if (cancelBtn) {
					cancelBtn.addEventListener('click', closeModal);
				}

				if (verifyBtn && codeInput) {
					verifyBtn.addEventListener('click', function() {
						const code = (codeInput.value || '').replace(/\D+/g, '').trim();
						if (code.length !== 6) {
							showMessage(messageEl, <?php echo wp_json_encode( __( 'Please enter a valid 6-digit code.', 'nexifymy-security' ) ); ?>, true);
							return;
						}

						verifyBtn.disabled = true;
						postAction('nexifymy_verify_2fa_setup', { code: code })
							.then(function(response) {
								if (!response || !response.success) {
									throw new Error(extractMessage(response, <?php echo wp_json_encode( __( 'Failed to verify 2FA code.', 'nexifymy-security' ) ); ?>));
								}
								showMessage(messageEl, extractMessage(response, <?php echo wp_json_encode( __( 'Two-factor authentication enabled.', 'nexifymy-security' ) ); ?>), false);
								window.setTimeout(function() {
									window.location.reload();
								}, 600);
							})
							.catch(function(err) {
								showMessage(messageEl, err && err.message ? err.message : <?php echo wp_json_encode( __( 'Unable to verify setup right now.', 'nexifymy-security' ) ); ?>, true);
								verifyBtn.disabled = false;
							});
					});
				}
			}

			if (setupBtn) {
				setupBtn.addEventListener('click', function() {
					setupBtn.disabled = true;
					postAction('nexifymy_generate_2fa_secret')
						.then(function(response) {
							if (!response || !response.success || !response.data || !response.data.qr_url || !response.data.secret) {
								throw new Error(extractMessage(response, <?php echo wp_json_encode( __( 'Unable to start 2FA setup.', 'nexifymy-security' ) ); ?>));
							}
							showSetupModal(response.data);
						})
						.catch(function(err) {
							window.alert(err && err.message ? err.message : <?php echo wp_json_encode( __( 'Unable to start 2FA setup.', 'nexifymy-security' ) ); ?>);
						})
						.finally(function() {
							setupBtn.disabled = false;
						});
				});
			}

			if (disableBtn) {
				disableBtn.addEventListener('click', function() {
					if (!window.confirm(<?php echo wp_json_encode( __( 'Are you sure you want to disable two-factor authentication?', 'nexifymy-security' ) ); ?>)) {
						return;
					}

					disableBtn.disabled = true;
					postAction('nexifymy_disable_2fa')
						.then(function(response) {
							if (!response || !response.success) {
								throw new Error(extractMessage(response, <?php echo wp_json_encode( __( 'Failed to disable 2FA.', 'nexifymy-security' ) ); ?>));
							}
							window.alert(extractMessage(response, <?php echo wp_json_encode( __( 'Two-factor authentication disabled.', 'nexifymy-security' ) ); ?>));
							window.location.reload();
						})
						.catch(function(err) {
							window.alert(err && err.message ? err.message : <?php echo wp_json_encode( __( 'Unable to disable 2FA right now.', 'nexifymy-security' ) ); ?>);
							disableBtn.disabled = false;
						});
				});
			}
		})();
		</script>
		<?php
	}
  // phpcs:enable WordPress.Security.NonceVerification.Missing

	/**
	 * Save user 2FA settings.
	 *
	 * @param int $user_id User ID.
	 */
    // phpcs:disable WordPress.Security.NonceVerification.Missing
	// No-op compatibility hook; 2FA profile changes are saved via AJAX.
	public function save_user_settings( $user_id ) {

		unset( $user_id );
	}
  // phpcs:enable WordPress.Security.NonceVerification.Missing

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	/**
	 * Generate new 2FA secret via AJAX.
	 */
    // phpcs:disable WordPress.Security.NonceVerification.Missing
	// Nonce is verified via check_ajax_referer() at method start.
	public function ajax_generate_secret() {

		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! is_user_logged_in() ) {
			wp_send_json_error( 'Not logged in' );
		}

		$current_user = wp_get_current_user();
		$user_id      = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : (int) $current_user->ID;
		if ( $user_id <= 0 ) {
			wp_send_json_error( 'Invalid user.' );
		}

		if ( (int) $current_user->ID !== $user_id && ! current_user_can( 'edit_user', $user_id ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$user = get_user_by( 'ID', $user_id );
		if ( ! $user || empty( $user->user_email ) ) {
			wp_send_json_error( 'Invalid user.' );
		}

		$secret = $this->generate_secret();

		// Store temporarily.
		set_transient( 'nexifymy_2fa_setup_' . $user_id, $secret, 10 * MINUTE_IN_SECONDS );

		wp_send_json_success(
			array(
				'secret' => $secret,
				'qr_url' => $this->get_qr_url( $secret, $user->user_email ),
			)
		);
	}
  // phpcs:enable WordPress.Security.NonceVerification.Missing

	/**
	 * Verify 2FA setup via AJAX.
	 */
	public function ajax_verify_setup() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! is_user_logged_in() ) {
			wp_send_json_error( 'Not logged in' );
		}

		$current_user = wp_get_current_user();
		$user_id      = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : (int) $current_user->ID;
		$code         = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
		if ( $user_id <= 0 ) {
			wp_send_json_error( 'Invalid user.' );
		}

		if ( (int) $current_user->ID !== $user_id && ! current_user_can( 'edit_user', $user_id ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$secret = get_transient( 'nexifymy_2fa_setup_' . $user_id );

		if ( ! $secret ) {
			wp_send_json_error( 'Setup session expired.' );
		}

		if ( ! $this->verify_totp( $secret, $code ) ) {
			wp_send_json_error( 'Invalid code. Please try again.' );
		}

		// Save secret and enable 2FA.
		update_user_meta( $user_id, self::SECRET_META_KEY, $secret );
		update_user_meta( $user_id, self::ENABLED_META_KEY, true );
		delete_transient( 'nexifymy_2fa_setup_' . $user_id );

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

		$current_user = wp_get_current_user();
		$user_id      = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : (int) $current_user->ID;
		if ( $user_id <= 0 ) {
			wp_send_json_error( 'Invalid user.' );
		}

		if ( (int) $current_user->ID !== $user_id && ! current_user_can( 'edit_user', $user_id ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		delete_user_meta( $user_id, self::SECRET_META_KEY );
		delete_user_meta( $user_id, self::ENABLED_META_KEY );
		delete_user_meta( $user_id, '_nexifymy_2fa_remember' );

		wp_send_json_success( array( 'message' => '2FA disabled.' ) );
	}

	/**
	 * Send email backup code.
	 * Rate limited to one email per 60 seconds per token.
	 */
	public function ajax_send_email_code() {

       // phpcs:disable WordPress.Security.NonceVerification.Missing
		// Public login endpoint validated via session token.
		$token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';

		if ( ! $this->is_valid_session_token( $token ) ) {
			wp_send_json_error( 'Missing token.' );
		}

		$settings = $this->get_settings();
		if ( empty( $settings['email_backup'] ) ) {
			wp_send_json_error( 'Email backup codes are disabled.' );
		}

		// Rate limit check - only allow one email per 60 seconds per token.
		$rate_key = 'nexifymy_2fa_email_rate_' . md5( $token );
		if ( get_transient( $rate_key ) ) {
			wp_send_json_error( 'Please wait before requesting another code.' );
		}

		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : 'unknown';
		$ip_rate_key = 'nexifymy_2fa_email_ip_rate_' . md5( $remote_addr );
		if ( get_transient( $ip_rate_key ) ) {
			wp_send_json_error( 'Please wait before requesting another code.' );
		}

		$user_id = absint( get_transient( 'nexifymy_2fa_' . $token ) );

		if ( $user_id <= 0 ) {
			wp_send_json_error( 'Invalid session.' );
		}

		$user = get_user_by( 'ID', $user_id );
		if ( ! $user || empty( $user->user_email ) ) {
			wp_send_json_error( 'Invalid session.' );
		}

		$code = wp_rand( 100000, 999999 );

		set_transient( 'nexifymy_2fa_email_' . $user_id, $code, 10 * MINUTE_IN_SECONDS );
		set_transient( $rate_key, true, 60 );
		// Rate limit for 60 seconds.
		set_transient( $ip_rate_key, true, 20 );
		// Additional short IP rate limit.

		$subject = sprintf( '[%s] Your login verification code', get_bloginfo( 'name' ) );
		$message = sprintf( __( 'Your verification code is: %s', 'nexifymy-security' ), $code );

		if ( ! wp_mail( $user->user_email, $subject, $message ) ) {
			wp_send_json_error( 'Unable to send verification code at this time.' );
		}
      // phpcs:enable WordPress.Security.NonceVerification.Missing

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
			$all_settings               = NexifyMy_Security_Settings::get_all();
			$all_settings['two_factor'] = $settings;
			update_option( 'nexifymy_security_settings', $all_settings );
		}

		wp_send_json_success( array( 'message' => 'Settings saved.' ) );
	}
}
