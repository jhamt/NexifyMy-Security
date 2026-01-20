<?php
/**
 * Passkey/WebAuthn Authentication Module.
 * Modern passwordless authentication using public-key cryptography.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Passkey {

	/**
	 * Meta key for stored credentials.
	 */
	const CREDENTIALS_META_KEY = 'nexifymy_passkey_credentials';

	/**
	 * Transient prefix for challenges.
	 */
	const CHALLENGE_PREFIX = 'nexifymy_passkey_challenge_';

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'              => true,
		'allow_passwordless'   => true,
		'require_for_admins'   => false,
		'auto_prompt_register' => true,
		'credential_timeout'   => 60000,  // 60 seconds.
		'authenticator_type'   => 'platform', // platform, cross-platform, any.
		'user_verification'    => 'preferred', // required, preferred, discouraged.
	);

	/**
	 * Relying Party info.
	 */
	private $rp_id;
	private $rp_name;
	private $rp_origin;

	/**
	 * Initialize the module.
	 */
	public function init() {
		$settings = $this->get_settings();

		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Set Relying Party info.
		$this->rp_id = wp_parse_url( home_url(), PHP_URL_HOST );
		$this->rp_name = get_bloginfo( 'name' );
		$this->rp_origin = home_url();

		// Enqueue scripts.
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login_scripts' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_scripts' ) );

		// Add passkey UI to login form.
		add_action( 'login_form', array( $this, 'render_login_passkey_button' ) );
		add_action( 'show_user_profile', array( $this, 'render_profile_passkey_section' ) );
		add_action( 'edit_user_profile', array( $this, 'render_profile_passkey_section' ) );

		// AJAX handlers for registration.
		add_action( 'wp_ajax_nexifymy_passkey_register_options', array( $this, 'ajax_register_options' ) );
		add_action( 'wp_ajax_nexifymy_passkey_register_verify', array( $this, 'ajax_register_verify' ) );
		add_action( 'wp_ajax_nexifymy_passkey_delete', array( $this, 'ajax_delete_credential' ) );
		add_action( 'wp_ajax_nexifymy_passkey_get_credentials', array( $this, 'ajax_get_credentials' ) );

		// AJAX handlers for authentication (no-priv for login).
		add_action( 'wp_ajax_nopriv_nexifymy_passkey_auth_options', array( $this, 'ajax_auth_options' ) );
		add_action( 'wp_ajax_nopriv_nexifymy_passkey_auth_verify', array( $this, 'ajax_auth_verify' ) );
		add_action( 'wp_ajax_nexifymy_passkey_auth_options', array( $this, 'ajax_auth_options' ) );
		add_action( 'wp_ajax_nexifymy_passkey_auth_verify', array( $this, 'ajax_auth_verify' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['passkey'] ) ) {
				return wp_parse_args( $all_settings['passkey'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Enqueue login page scripts.
	 */
	public function enqueue_login_scripts() {
		wp_enqueue_script(
			'nexifymy-passkey-login',
			NEXIFYMY_SECURITY_URL . 'assets/js/passkey.js',
			array( 'jquery' ),
			NEXIFYMY_SECURITY_VERSION,
			true
		);

		wp_localize_script( 'nexifymy-passkey-login', 'nexifymyPasskey', array(
			'ajaxUrl'      => admin_url( 'admin-ajax.php' ),
			'nonce'        => wp_create_nonce( 'nexifymy_passkey_nonce' ),
			'rpId'         => $this->rp_id,
			'rpName'       => $this->rp_name,
			'isSupported'  => true,
			'strings'      => array(
				'authenticating' => __( 'Authenticating...', 'nexifymy-security' ),
				'error'          => __( 'Authentication failed. Please try again.', 'nexifymy-security' ),
				'notSupported'   => __( 'Passkeys are not supported in this browser.', 'nexifymy-security' ),
			),
		) );

		wp_enqueue_style(
			'nexifymy-passkey-login',
			NEXIFYMY_SECURITY_URL . 'assets/css/passkey.css',
			array(),
			NEXIFYMY_SECURITY_VERSION
		);
	}

	/**
	 * Enqueue admin scripts.
	 */
	public function enqueue_admin_scripts( $hook ) {
		if ( $hook !== 'profile.php' && $hook !== 'user-edit.php' ) {
			return;
		}

		wp_enqueue_script(
			'nexifymy-passkey-admin',
			NEXIFYMY_SECURITY_URL . 'assets/js/passkey.js',
			array( 'jquery' ),
			NEXIFYMY_SECURITY_VERSION,
			true
		);

		wp_localize_script( 'nexifymy-passkey-admin', 'nexifymyPasskey', array(
			'ajaxUrl'      => admin_url( 'admin-ajax.php' ),
			'nonce'        => wp_create_nonce( 'nexifymy_passkey_nonce' ),
			'rpId'         => $this->rp_id,
			'rpName'       => $this->rp_name,
			'isSupported'  => true,
			'strings'      => array(
				'registering'    => __( 'Registering passkey...', 'nexifymy-security' ),
				'registered'     => __( 'Passkey registered successfully!', 'nexifymy-security' ),
				'error'          => __( 'Failed to register passkey.', 'nexifymy-security' ),
				'confirmDelete'  => __( 'Are you sure you want to delete this passkey?', 'nexifymy-security' ),
			),
		) );
	}

	/**
	 * Render passkey login button.
	 */
	public function render_login_passkey_button() {
		?>
		<div id="nexifymy-passkey-login" style="margin-bottom: 16px; text-align: center;">
			<button type="button" id="passkey-login-btn" class="button button-secondary" style="width: 100%; padding: 10px;">
				<span class="dashicons dashicons-admin-network" style="margin-right: 8px;"></span>
				<?php _e( 'Sign in with Passkey', 'nexifymy-security' ); ?>
			</button>
			<p class="passkey-divider" style="margin: 16px 0; color: #666;">
				<span style="background: #fff; padding: 0 10px;"><?php _e( 'or', 'nexifymy-security' ); ?></span>
			</p>
		</div>
		<script>
		if (!window.PublicKeyCredential) {
			document.getElementById('nexifymy-passkey-login').style.display = 'none';
		}
		</script>
		<?php
	}

	/**
	 * Render passkey management section on profile.
	 *
	 * @param WP_User $user User object.
	 */
	public function render_profile_passkey_section( $user ) {
		$credentials = $this->get_user_credentials( $user->ID );
		?>
		<h2><?php _e( 'Passkey Authentication', 'nexifymy-security' ); ?></h2>
		<table class="form-table" id="passkey-section">
			<tr>
				<th><?php _e( 'Registered Passkeys', 'nexifymy-security' ); ?></th>
				<td>
					<div id="passkey-list">
						<?php if ( empty( $credentials ) ) : ?>
							<p class="description"><?php _e( 'No passkeys registered yet.', 'nexifymy-security' ); ?></p>
						<?php else : ?>
							<ul style="margin: 0;">
								<?php foreach ( $credentials as $id => $cred ) : ?>
									<li style="margin-bottom: 8px; padding: 10px; background: #f9f9f9; border-radius: 4px;" data-credential-id="<?php echo esc_attr( $id ); ?>">
										<strong><?php echo esc_html( $cred['name'] ); ?></strong>
										<br>
										<small>
											<?php printf( __( 'Created: %s', 'nexifymy-security' ), esc_html( $cred['created'] ) ); ?>
											<?php if ( ! empty( $cred['last_used'] ) ) : ?>
												| <?php printf( __( 'Last used: %s', 'nexifymy-security' ), esc_html( $cred['last_used'] ) ); ?>
											<?php endif; ?>
										</small>
										<button type="button" class="button button-small passkey-delete" style="float: right;" data-id="<?php echo esc_attr( $id ); ?>">
											<?php _e( 'Delete', 'nexifymy-security' ); ?>
										</button>
									</li>
								<?php endforeach; ?>
							</ul>
						<?php endif; ?>
					</div>
				</td>
			</tr>
			<tr>
				<th><?php _e( 'Add New Passkey', 'nexifymy-security' ); ?></th>
				<td>
					<input type="text" id="passkey-name" placeholder="<?php esc_attr_e( 'Passkey name (e.g., MacBook Touch ID)', 'nexifymy-security' ); ?>" style="width: 300px;">
					<button type="button" id="passkey-register-btn" class="button button-primary">
						<?php _e( 'Register Passkey', 'nexifymy-security' ); ?>
					</button>
					<p class="description"><?php _e( 'Use Touch ID, Face ID, Windows Hello, or a hardware security key.', 'nexifymy-security' ); ?></p>
					<div id="passkey-status" style="margin-top: 10px;"></div>
				</td>
			</tr>
		</table>
		<input type="hidden" id="passkey-user-id" value="<?php echo esc_attr( $user->ID ); ?>">
		<?php
	}

	/*
	 * =========================================================================
	 * REGISTRATION FLOW
	 * =========================================================================
	 */

	/**
	 * Generate registration options (AJAX).
	 */
	public function ajax_register_options() {
		check_ajax_referer( 'nexifymy_passkey_nonce', 'nonce' );

		if ( ! is_user_logged_in() ) {
			wp_send_json_error( 'Not logged in.' );
		}

		$user = wp_get_current_user();
		$settings = $this->get_settings();

		// Generate challenge.
		$challenge = $this->generate_challenge();
		$this->store_challenge( $user->ID, $challenge, 'registration' );

		// Get existing credential IDs to exclude.
		$exclude_credentials = array();
		$existing = $this->get_user_credentials( $user->ID );
		foreach ( $existing as $id => $cred ) {
			$exclude_credentials[] = array(
				'type' => 'public-key',
				'id'   => $id,
			);
		}

		$options = array(
			'challenge' => $this->base64url_encode( $challenge ),
			'rp' => array(
				'name' => $this->rp_name,
				'id'   => $this->rp_id,
			),
			'user' => array(
				'id'          => $this->base64url_encode( hash( 'sha256', $user->ID . $user->user_login, true ) ),
				'name'        => $user->user_login,
				'displayName' => $user->display_name,
			),
			'pubKeyCredParams' => array(
				array( 'type' => 'public-key', 'alg' => -7 ),   // ES256.
				array( 'type' => 'public-key', 'alg' => -257 ), // RS256.
			),
			'timeout' => $settings['credential_timeout'],
			'attestation' => 'none',
			'authenticatorSelection' => array(
				'authenticatorAttachment' => $settings['authenticator_type'] === 'any' ? null : $settings['authenticator_type'],
				'residentKey'             => 'preferred',
				'userVerification'        => $settings['user_verification'],
			),
			'excludeCredentials' => $exclude_credentials,
		);

		// Remove null values.
		if ( $options['authenticatorSelection']['authenticatorAttachment'] === null ) {
			unset( $options['authenticatorSelection']['authenticatorAttachment'] );
		}

		wp_send_json_success( $options );
	}

	/**
	 * Verify registration response (AJAX).
	 */
	public function ajax_register_verify() {
		check_ajax_referer( 'nexifymy_passkey_nonce', 'nonce' );

		if ( ! is_user_logged_in() ) {
			wp_send_json_error( 'Not logged in.' );
		}

		$user = wp_get_current_user();
		$credential_name = isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : 'Passkey';
		$response = isset( $_POST['response'] ) ? json_decode( wp_unslash( $_POST['response'] ), true ) : null;

		if ( ! $response ) {
			wp_send_json_error( 'Invalid response.' );
		}

		// Verify challenge.
		$stored_challenge = $this->get_stored_challenge( $user->ID, 'registration' );
		if ( ! $stored_challenge ) {
			wp_send_json_error( 'Challenge expired.' );
		}

		// Decode attestation object.
		$attestation_object = $this->base64url_decode( $response['attestationObject'] );
		$client_data_json = $this->base64url_decode( $response['clientDataJSON'] );

		// Parse client data.
		$client_data = json_decode( $client_data_json, true );

		// Verify origin.
		if ( $client_data['origin'] !== $this->rp_origin ) {
			wp_send_json_error( 'Origin mismatch.' );
		}

		// Verify challenge.
		$received_challenge = $this->base64url_decode( $client_data['challenge'] );
		if ( ! hash_equals( $stored_challenge, $received_challenge ) ) {
			wp_send_json_error( 'Challenge mismatch.' );
		}

		// Parse attestation object (CBOR).
		$attestation = $this->parse_attestation_object( $attestation_object );

		if ( ! $attestation || empty( $attestation['authData'] ) ) {
			wp_send_json_error( 'Failed to parse attestation.' );
		}

		// Parse authenticator data.
		$auth_data = $this->parse_authenticator_data( $attestation['authData'] );

		if ( ! $auth_data || empty( $auth_data['credentialId'] ) ) {
			wp_send_json_error( 'Failed to parse authenticator data.' );
		}

		// Store credential.
		$credential_id = $this->base64url_encode( $auth_data['credentialId'] );
		$public_key = $auth_data['credentialPublicKey'];

		$credentials = $this->get_user_credentials( $user->ID );
		$credentials[ $credential_id ] = array(
			'name'       => $credential_name,
			'public_key' => $this->base64url_encode( $public_key ),
			'counter'    => $auth_data['signCount'],
			'created'    => current_time( 'mysql' ),
			'last_used'  => null,
		);

		$this->save_user_credentials( $user->ID, $credentials );
		$this->clear_challenge( $user->ID, 'registration' );

		// Log registration.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'passkey_registered',
				sprintf( 'User %s registered a new passkey: %s', $user->user_login, $credential_name ),
				'info'
			);
		}

		wp_send_json_success( array(
			'message'      => 'Passkey registered successfully.',
			'credentialId' => $credential_id,
		) );
	}

	/*
	 * =========================================================================
	 * AUTHENTICATION FLOW
	 * =========================================================================
	 */

	/**
	 * Generate authentication options (AJAX).
	 */
	public function ajax_auth_options() {
		check_ajax_referer( 'nexifymy_passkey_nonce', 'nonce' );

		$username = isset( $_POST['username'] ) ? sanitize_user( wp_unslash( $_POST['username'] ) ) : '';

		// Generate challenge.
		$challenge = $this->generate_challenge();
		$session_id = wp_generate_password( 32, false );

		// Store challenge with session ID.
		set_transient( self::CHALLENGE_PREFIX . $session_id, array(
			'challenge' => $challenge,
			'username'  => $username,
			'type'      => 'authentication',
		), 300 );

		$settings = $this->get_settings();

		// Get allowed credentials if username provided.
		$allow_credentials = array();
		if ( $username ) {
			$user = get_user_by( 'login', $username );
			if ( ! $user ) {
				$user = get_user_by( 'email', $username );
			}

			if ( $user ) {
				$credentials = $this->get_user_credentials( $user->ID );
				foreach ( $credentials as $id => $cred ) {
					$allow_credentials[] = array(
						'type' => 'public-key',
						'id'   => $id,
					);
				}
			}
		}

		$options = array(
			'challenge'        => $this->base64url_encode( $challenge ),
			'rpId'             => $this->rp_id,
			'timeout'          => $settings['credential_timeout'],
			'userVerification' => $settings['user_verification'],
			'sessionId'        => $session_id,
		);

		if ( ! empty( $allow_credentials ) ) {
			$options['allowCredentials'] = $allow_credentials;
		}

		wp_send_json_success( $options );
	}

	/**
	 * Verify authentication response (AJAX).
	 */
	public function ajax_auth_verify() {
		check_ajax_referer( 'nexifymy_passkey_nonce', 'nonce' );

		$session_id = isset( $_POST['sessionId'] ) ? sanitize_text_field( wp_unslash( $_POST['sessionId'] ) ) : '';
		$response = isset( $_POST['response'] ) ? json_decode( wp_unslash( $_POST['response'] ), true ) : null;

		if ( ! $response || ! $session_id ) {
			wp_send_json_error( 'Invalid response.' );
		}

		// Get stored challenge.
		$stored = get_transient( self::CHALLENGE_PREFIX . $session_id );
		if ( ! $stored ) {
			wp_send_json_error( 'Session expired.' );
		}

		delete_transient( self::CHALLENGE_PREFIX . $session_id );

		// Decode response.
		$credential_id = $response['id'];
		$authenticator_data = $this->base64url_decode( $response['authenticatorData'] );
		$client_data_json = $this->base64url_decode( $response['clientDataJSON'] );
		$signature = $this->base64url_decode( $response['signature'] );

		// Parse client data.
		$client_data = json_decode( $client_data_json, true );

		// Verify origin.
		if ( $client_data['origin'] !== $this->rp_origin ) {
			wp_send_json_error( 'Origin mismatch.' );
		}

		// Verify challenge.
		$received_challenge = $this->base64url_decode( $client_data['challenge'] );
		if ( ! hash_equals( $stored['challenge'], $received_challenge ) ) {
			wp_send_json_error( 'Challenge mismatch.' );
		}

		// Find user by credential ID.
		$user = $this->find_user_by_credential( $credential_id );
		if ( ! $user ) {
			wp_send_json_error( 'Credential not found.' );
		}

		$credentials = $this->get_user_credentials( $user->ID );
		$credential = $credentials[ $credential_id ] ?? null;

		if ( ! $credential ) {
			wp_send_json_error( 'Credential not found.' );
		}

		// Verify signature.
		$public_key = $this->base64url_decode( $credential['public_key'] );
		$client_data_hash = hash( 'sha256', $client_data_json, true );
		$signed_data = $authenticator_data . $client_data_hash;

		$verified = $this->verify_signature( $signed_data, $signature, $public_key );

		if ( ! $verified ) {
			wp_send_json_error( 'Signature verification failed.' );
		}

		// Update counter (replay protection).
		$auth_data = $this->parse_authenticator_data( $authenticator_data );
		if ( $auth_data['signCount'] > 0 && $auth_data['signCount'] <= $credential['counter'] ) {
			// Possible cloned authenticator.
			wp_send_json_error( 'Counter mismatch - possible cloned authenticator.' );
		}

		$credentials[ $credential_id ]['counter'] = $auth_data['signCount'];
		$credentials[ $credential_id ]['last_used'] = current_time( 'mysql' );
		$this->save_user_credentials( $user->ID, $credentials );

		// Log the user in.
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, true );
		do_action( 'wp_login', $user->user_login, $user );

		// Log authentication.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'passkey_login',
				sprintf( 'User %s logged in with passkey', $user->user_login ),
				'info'
			);
		}

		wp_send_json_success( array(
			'message'     => 'Authentication successful.',
			'redirectUrl' => admin_url(),
		) );
	}

	/*
	 * =========================================================================
	 * CREDENTIAL MANAGEMENT
	 * =========================================================================
	 */

	/**
	 * Delete a credential (AJAX).
	 */
	public function ajax_delete_credential() {
		check_ajax_referer( 'nexifymy_passkey_nonce', 'nonce' );

		if ( ! is_user_logged_in() ) {
			wp_send_json_error( 'Not logged in.' );
		}

		$credential_id = isset( $_POST['credentialId'] ) ? sanitize_text_field( wp_unslash( $_POST['credentialId'] ) ) : '';

		if ( ! $credential_id ) {
			wp_send_json_error( 'Invalid credential ID.' );
		}

		$user = wp_get_current_user();
		$credentials = $this->get_user_credentials( $user->ID );

		if ( ! isset( $credentials[ $credential_id ] ) ) {
			wp_send_json_error( 'Credential not found.' );
		}

		unset( $credentials[ $credential_id ] );
		$this->save_user_credentials( $user->ID, $credentials );

		wp_send_json_success( array( 'message' => 'Passkey deleted.' ) );
	}

	/**
	 * Get user credentials (AJAX).
	 */
	public function ajax_get_credentials() {
		check_ajax_referer( 'nexifymy_passkey_nonce', 'nonce' );

		if ( ! is_user_logged_in() ) {
			wp_send_json_error( 'Not logged in.' );
		}

		$user = wp_get_current_user();
		$credentials = $this->get_user_credentials( $user->ID );

		// Remove sensitive data.
		$safe_credentials = array();
		foreach ( $credentials as $id => $cred ) {
			$safe_credentials[ $id ] = array(
				'name'      => $cred['name'],
				'created'   => $cred['created'],
				'last_used' => $cred['last_used'],
			);
		}

		wp_send_json_success( $safe_credentials );
	}

	/*
	 * =========================================================================
	 * HELPER METHODS
	 * =========================================================================
	 */

	private function get_user_credentials( $user_id ) {
		return get_user_meta( $user_id, self::CREDENTIALS_META_KEY, true ) ?: array();
	}

	private function save_user_credentials( $user_id, $credentials ) {
		update_user_meta( $user_id, self::CREDENTIALS_META_KEY, $credentials );
	}

	private function find_user_by_credential( $credential_id ) {
		global $wpdb;

		$users = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s",
				self::CREDENTIALS_META_KEY
			)
		);

		foreach ( $users as $user_id ) {
			$credentials = $this->get_user_credentials( $user_id );
			if ( isset( $credentials[ $credential_id ] ) ) {
				return get_user_by( 'id', $user_id );
			}
		}

		return null;
	}

	private function generate_challenge() {
		return random_bytes( 32 );
	}

	private function store_challenge( $user_id, $challenge, $type ) {
		set_transient( self::CHALLENGE_PREFIX . $user_id . '_' . $type, $challenge, 300 );
	}

	private function get_stored_challenge( $user_id, $type ) {
		return get_transient( self::CHALLENGE_PREFIX . $user_id . '_' . $type );
	}

	private function clear_challenge( $user_id, $type ) {
		delete_transient( self::CHALLENGE_PREFIX . $user_id . '_' . $type );
	}

	private function base64url_encode( $data ) {
		return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
	}

	private function base64url_decode( $data ) {
		return base64_decode( strtr( $data, '-_', '+/' ) . str_repeat( '=', 3 - ( 3 + strlen( $data ) ) % 4 ) );
	}

	private function parse_attestation_object( $data ) {
		// Simple CBOR parsing for attestation object.
		// Format: { fmt, attStmt, authData }.
		$result = array();

		// Skip CBOR map header.
		$pos = 1;
		$len = strlen( $data );

		while ( $pos < $len ) {
			// Read key (text string).
			$key_info = ord( $data[ $pos ] );
			$pos++;

			if ( ( $key_info & 0xe0 ) === 0x60 ) {
				$key_len = $key_info & 0x1f;
				$key = substr( $data, $pos, $key_len );
				$pos += $key_len;

				// Read value based on key.
				if ( $key === 'authData' ) {
					$val_info = ord( $data[ $pos ] );
					$pos++;

					if ( ( $val_info & 0xe0 ) === 0x40 ) {
						// Byte string.
						if ( ( $val_info & 0x1f ) === 24 ) {
							$val_len = ord( $data[ $pos ] );
							$pos++;
						} elseif ( ( $val_info & 0x1f ) === 25 ) {
							$val_len = unpack( 'n', substr( $data, $pos, 2 ) )[1];
							$pos += 2;
						} else {
							$val_len = $val_info & 0x1f;
						}

						$result['authData'] = substr( $data, $pos, $val_len );
						$pos += $val_len;
					}
				} else {
					// Skip other values.
					break;
				}
			} else {
				break;
			}
		}

		return $result;
	}

	private function parse_authenticator_data( $data ) {
		$result = array();
		$pos = 0;

		// RP ID hash (32 bytes).
		$result['rpIdHash'] = substr( $data, $pos, 32 );
		$pos += 32;

		// Flags (1 byte).
		$flags = ord( $data[ $pos ] );
		$pos++;
		$result['flags'] = $flags;
		$result['userPresent'] = ( $flags & 0x01 ) !== 0;
		$result['userVerified'] = ( $flags & 0x04 ) !== 0;
		$result['attestedCredentialData'] = ( $flags & 0x40 ) !== 0;

		// Sign count (4 bytes, big-endian).
		$result['signCount'] = unpack( 'N', substr( $data, $pos, 4 ) )[1];
		$pos += 4;

		// Attested credential data (if present).
		if ( $result['attestedCredentialData'] && strlen( $data ) > $pos ) {
			// AAGUID (16 bytes).
			$result['aaguid'] = substr( $data, $pos, 16 );
			$pos += 16;

			// Credential ID length (2 bytes, big-endian).
			$cred_id_len = unpack( 'n', substr( $data, $pos, 2 ) )[1];
			$pos += 2;

			// Credential ID.
			$result['credentialId'] = substr( $data, $pos, $cred_id_len );
			$pos += $cred_id_len;

			// Credential public key (COSE format, rest of data).
			$result['credentialPublicKey'] = substr( $data, $pos );
		}

		return $result;
	}

	private function verify_signature( $data, $signature, $public_key_cose ) {
		// Parse COSE public key and verify.
		// This is a simplified verification - production should use proper COSE parsing.
		$key_data = $this->parse_cose_key( $public_key_cose );

		if ( ! $key_data ) {
			return false;
		}

		// Create PEM public key.
		$pem = $this->cose_to_pem( $key_data );

		if ( ! $pem ) {
			return false;
		}

		// Verify signature.
		$pub_key = openssl_pkey_get_public( $pem );
		if ( ! $pub_key ) {
			return false;
		}

		$algo = $key_data['alg'] === -7 ? OPENSSL_ALGO_SHA256 : OPENSSL_ALGO_SHA256;

		// For ES256, signature needs to be converted from DER to raw format.
		if ( $key_data['alg'] === -7 ) {
			$signature = $this->der_to_raw( $signature );
		}

		$result = openssl_verify( $data, $signature, $pub_key, $algo );

		return $result === 1;
	}

	private function parse_cose_key( $data ) {
		// Simple CBOR map parser for COSE key.
		$result = array();
		$pos = 1; // Skip map header.
		$len = strlen( $data );

		while ( $pos < $len - 1 ) {
			// Read key (usually negative integer for COSE).
			$key_byte = ord( $data[ $pos ] );
			$pos++;

			$key = null;
			if ( ( $key_byte & 0xe0 ) === 0x20 ) {
				$key = -1 - ( $key_byte & 0x1f );
			} elseif ( ( $key_byte & 0xe0 ) === 0x00 ) {
				$key = $key_byte & 0x1f;
			} else {
				break;
			}

			// Read value.
			$val_byte = ord( $data[ $pos ] );
			$pos++;

			if ( ( $val_byte & 0xe0 ) === 0x20 ) {
				// Negative integer.
				$result[ $key ] = -1 - ( $val_byte & 0x1f );
			} elseif ( ( $val_byte & 0xe0 ) === 0x00 ) {
				// Positive integer.
				$result[ $key ] = $val_byte & 0x1f;
			} elseif ( ( $val_byte & 0xe0 ) === 0x40 ) {
				// Byte string.
				$val_len = $val_byte & 0x1f;
				$result[ $key ] = substr( $data, $pos, $val_len );
				$pos += $val_len;
			}
		}

		// Map COSE keys to named fields.
		return array(
			'kty' => $result[1] ?? null,  // Key type.
			'alg' => $result[3] ?? null,  // Algorithm.
			'crv' => $result[-1] ?? null, // Curve.
			'x'   => $result[-2] ?? null, // X coordinate.
			'y'   => $result[-3] ?? null, // Y coordinate.
			'n'   => $result[-1] ?? null, // RSA modulus.
			'e'   => $result[-2] ?? null, // RSA exponent.
		);
	}

	private function cose_to_pem( $key_data ) {
		if ( $key_data['kty'] === 2 ) {
			// EC2 key (ECDSA).
			$x = $key_data['x'];
			$y = $key_data['y'];

			if ( ! $x || ! $y ) {
				return null;
			}

			// Build uncompressed EC point.
			$ec_point = "\x04" . $x . $y;

			// Build DER structure.
			$der = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00" . $ec_point;

			return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $der ), 64 ) . "-----END PUBLIC KEY-----";
		}

		return null;
	}

	private function der_to_raw( $der_signature ) {
		// Convert DER-encoded ECDSA signature to raw format.
		if ( strlen( $der_signature ) < 8 ) {
			return $der_signature;
		}

		$pos = 2; // Skip sequence header.

		// Read R.
		if ( ord( $der_signature[ $pos ] ) !== 0x02 ) {
			return $der_signature;
		}
		$pos++;
		$r_len = ord( $der_signature[ $pos ] );
		$pos++;
		$r = substr( $der_signature, $pos, $r_len );
		$pos += $r_len;

		// Read S.
		if ( ord( $der_signature[ $pos ] ) !== 0x02 ) {
			return $der_signature;
		}
		$pos++;
		$s_len = ord( $der_signature[ $pos ] );
		$pos++;
		$s = substr( $der_signature, $pos, $s_len );

		// Pad/trim to 32 bytes each.
		$r = str_pad( ltrim( $r, "\x00" ), 32, "\x00", STR_PAD_LEFT );
		$s = str_pad( ltrim( $s, "\x00" ), 32, "\x00", STR_PAD_LEFT );

		return $r . $s;
	}
}
