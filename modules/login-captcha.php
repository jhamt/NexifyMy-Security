<?php
/**
 * Login Captcha Module.
 * Adds math-based captcha to login, registration, and password reset forms.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Login_Captcha {

	/**
	 * Session key for captcha answer.
	 */
	const SESSION_KEY = 'nexifymy_captcha_answer';

	/**
	 * Transient prefix for captcha answer (fallback when sessions fail).
	 */
	const TRANSIENT_PREFIX = 'nexifymy_captcha_';

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'              => true,
		'provider'             => 'nexifymy',  // nexifymy, recaptcha, recaptcha_v3, turnstile
		'nexifymy_type'        => 'math',      // math, text_match, image, audio
		'enable_login'         => true,
		'enable_registration'  => true,
		'enable_reset'         => true,
		'enable_comment'       => false,
		'difficulty'           => 'easy',      // easy, medium, hard
		'site_key'             => '',          // For reCAPTCHA/Turnstile
		'secret_key'           => '',          // For reCAPTCHA/Turnstile
		'failed_threshold'     => 3,           // Show captcha after X failed attempts
	);

	/**
	 * Initialize the module.
	 */
	public function init() {
		// Check if module is enabled globally.
		$all_settings = get_option( 'nexifymy_security_settings', array() );
		if ( isset( $all_settings['modules']['captcha_enabled'] ) && ! $all_settings['modules']['captcha_enabled'] ) {
			return;
		}

		$settings = $this->get_settings();

		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Start session as early as possible - before any output.
		$this->start_session();
		add_action( 'init', array( $this, 'start_session' ), -1 );
		add_action( 'login_init', array( $this, 'start_session' ), -1 );

		// Login form.
		if ( ! empty( $settings['enable_login'] ) ) {
			add_action( 'login_form', array( $this, 'render_captcha' ) );
			add_filter( 'authenticate', array( $this, 'validate_login_captcha' ), 30, 3 );
		}

		// Registration form.
		if ( ! empty( $settings['enable_registration'] ) ) {
			add_action( 'register_form', array( $this, 'render_captcha' ) );
			add_filter( 'registration_errors', array( $this, 'validate_registration_captcha' ), 10, 3 );
		}

		// Password reset form.
		if ( ! empty( $settings['enable_reset'] ) ) {
			add_action( 'lostpassword_form', array( $this, 'render_captcha' ) );
			add_action( 'lostpassword_post', array( $this, 'validate_reset_captcha' ) );
		}

		// Comment form.
		if ( ! empty( $settings['enable_comment'] ) ) {
			add_action( 'comment_form_after_fields', array( $this, 'render_captcha' ) );
			add_action( 'comment_form_logged_in_after', array( $this, 'render_captcha' ) );
			add_filter( 'preprocess_comment', array( $this, 'validate_comment_captcha' ) );
		}

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_refresh_captcha', array( $this, 'ajax_refresh_captcha' ) );
		add_action( 'wp_ajax_nopriv_nexifymy_refresh_captcha', array( $this, 'ajax_refresh_captcha' ) );
		add_action( 'wp_ajax_nexifymy_get_captcha_settings', array( $this, 'ajax_get_settings' ) );
		add_action( 'wp_ajax_nexifymy_save_captcha_settings', array( $this, 'ajax_save_settings' ) );

		// Enqueue assets.
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_assets' ) );
	}

	/**
	 * Start PHP session.
	 */
	public function start_session() {
		if ( defined( 'DOING_CRON' ) || defined( 'WP_CLI' ) || defined( 'REST_REQUEST' ) ) {
			return;
		}

		if ( ! session_id() && ! headers_sent() ) {
			// Prevent session issues with some hosts
			if ( ! defined( 'PHP_SESSION_NONE' ) || session_status() === PHP_SESSION_NONE ) {
				@session_start();
			}
		}
	}

	/**
	 * Get unique client identifier for transient fallback.
	 *
	 * @return string
	 */
	private function get_client_id() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( $_SERVER['REMOTE_ADDR'] ) : 'unknown';
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ) : '';
		return md5( $ip . $ua );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['captcha'] ) ) {
				return wp_parse_args( $all_settings['captcha'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Generate a new captcha question.
	 *
	 * @return array Question and answer.
	 */
	private function generate_captcha() {
		$settings = $this->get_settings();
		$difficulty = $settings['difficulty'];

		switch ( $difficulty ) {
			case 'hard':
				$num1 = wp_rand( 10, 50 );
				$num2 = wp_rand( 10, 50 );
				$operations = array( '+', '-', '*', '/' );
				break;
			case 'medium':
				$num1 = wp_rand( 5, 20 );
				$num2 = wp_rand( 1, 10 );
				$operations = array( '+', '-' );
				break;
			case 'easy':
			default:
				$num1 = wp_rand( 1, 10 );
				$num2 = wp_rand( 1, 10 );
				$operations = array( '+' );
				break;
		}

		$operation = $operations[ array_rand( $operations ) ];

		// Ensure no negative results for subtraction.
		if ( '-' === $operation && $num2 > $num1 ) {
			$temp = $num1;
			$num1 = $num2;
			$num2 = $temp;
		}

		// Ensure clean division for division operation.
		if ( '/' === $operation ) {
			$num1 = $num2 * wp_rand( 2, 10 ); // Make num1 divisible by num2.
		}

		switch ( $operation ) {
			case '+':
				$answer = $num1 + $num2;
				$symbol = '+';
				break;
			case '-':
				$answer = $num1 - $num2;
				$symbol = '-';
				break;
			case '*':
				$answer = $num1 * $num2;
				$symbol = '*';
				break;
			case '/':
				$answer = $num1 / $num2;
				$symbol = '/';
				break;
			default:
				$answer = $num1 + $num2;
				$symbol = '+';
		}

		// Store answer in session (primary).
		if ( isset( $_SESSION ) ) {
			$_SESSION[ self::SESSION_KEY ] = $answer;
		}

		// Store answer in transient (fallback) - 5 minute expiry.
		$client_id = $this->get_client_id();
		set_transient( self::TRANSIENT_PREFIX . $client_id, $answer, 5 * MINUTE_IN_SECONDS );

		return array(
			'question' => sprintf( '%d %s %d = ?', $num1, $symbol, $num2 ),
			'answer'   => $answer,
		);
	}

	/**
	 * Render the captcha field.
	 */
	public function render_captcha() {
		$settings = $this->get_settings();
		$provider = $settings['provider'] ?? 'nexifymy';

		switch ( $provider ) {
			case 'recaptcha':
				$this->render_recaptcha_v2();
				break;
			case 'recaptcha_v3':
				$this->render_recaptcha_v3();
				break;
			case 'turnstile':
				$this->render_turnstile();
				break;
			case 'nexifymy':
			default:
				$this->render_nexifymy_captcha();
				break;
		}
	}

	/**
	 * Render NexifyMy custom captcha.
	 */
	private function render_nexifymy_captcha() {
		$settings = $this->get_settings();
		$type = $settings['nexifymy_type'] ?? 'math';

		switch ( $type ) {
			case 'text_match':
				$this->render_text_match_captcha();
				break;
			case 'image':
				$this->render_image_captcha();
				break;
			case 'audio':
				$this->render_audio_captcha();
				break;
			case 'math':
			default:
				$this->render_math_captcha();
				break;
		}
	}

	/**
	 * Render math captcha.
	 */
	private function render_math_captcha() {
		$captcha = $this->generate_captcha();
		?>
		<p class="nexifymy-captcha-field">
			<label for="nexifymy_captcha"><?php echo esc_html( $captcha['question'] ); ?></label>
			<input type="number" name="nexifymy_captcha" id="nexifymy_captcha" class="input" required aria-required="true" />
		</p>
		<?php
	}

	/**
	 * Render text matching captcha.
	 */
	private function render_text_match_captcha() {
		$words = array( 'apple', 'banana', 'orange', 'grape', 'watermelon', 'security', 'protect', 'password' );
		$word = $words[ array_rand( $words ) ];

		// Store answer
		if ( isset( $_SESSION ) ) {
			$_SESSION[ self::SESSION_KEY ] = $word;
		}
		$client_id = $this->get_client_id();
		set_transient( self::TRANSIENT_PREFIX . $client_id, $word, 5 * MINUTE_IN_SECONDS );
		?>
		<p class="nexifymy-captcha-field">
			<label for="nexifymy_captcha"><?php _e( 'Type the word:', 'nexifymy-security' ); ?> <strong><?php echo esc_html( $word ); ?></strong></label>
			<input type="text" name="nexifymy_captcha" id="nexifymy_captcha" class="input" required aria-required="true" autocomplete="off" />
		</p>
		<?php
	}

	/**
	 * Render image selection captcha.
	 */
	private function render_image_captcha() {
		$answer = wp_rand( 1, 4 );

		// Store answer
		if ( isset( $_SESSION ) ) {
			$_SESSION[ self::SESSION_KEY ] = $answer;
		}
		$client_id = $this->get_client_id();
		set_transient( self::TRANSIENT_PREFIX . $client_id, $answer, 5 * MINUTE_IN_SECONDS );
		?>
		<p class="nexifymy-captcha-field">
			<label><?php _e( 'Select the image with a checkmark:', 'nexifymy-security' ); ?></label>
			<div class="nexifymy-captcha-grid">
				<?php for ( $i = 1; $i <= 4; $i++ ) : ?>
					<label class="nexifymy-captcha-choice">
						<input type="radio" name="nexifymy_captcha" value="<?php echo $i; ?>" required class="nexifymy-captcha-choice-input">
						<div class="nexifymy-captcha-choice-icon">
							<?php echo $i === $answer ? '&#10003;' : '&#10007;'; ?>
						</div>
					</label>
				<?php endfor; ?>
			</div>
		</p>
		<?php
	}

	/**
	 * Render audio/speaking captcha.
	 */
	private function render_audio_captcha() {
		$number = wp_rand( 1000, 9999 );

		// Store answer
		if ( isset( $_SESSION ) ) {
			$_SESSION[ self::SESSION_KEY ] = $number;
		}
		$client_id = $this->get_client_id();
		set_transient( self::TRANSIENT_PREFIX . $client_id, $number, 5 * MINUTE_IN_SECONDS );
		?>
		<p class="nexifymy-captcha-field">
			<label for="nexifymy_captcha"><?php _e( 'Enter the code:', 'nexifymy-security' ); ?> <strong><?php echo esc_html( $number ); ?></strong></label>
			<small class="nexifymy-captcha-hint"><?php _e( '(Speak this code to verify)', 'nexifymy-security' ); ?></small>
			<input type="number" name="nexifymy_captcha" id="nexifymy_captcha" class="input" required aria-required="true" />
		</p>
		<?php
	}

	/**
	 * Render Google reCAPTCHA v2.
	 */
	private function render_recaptcha_v2() {
		$settings = $this->get_settings();
		$site_key = $settings['site_key'] ?? '';

		if ( empty( $site_key ) ) {
			echo '<p class="nexifymy-captcha-error">reCAPTCHA site key not configured.</p>';
			return;
		}

		wp_enqueue_script( 'google-recaptcha', 'https://www.google.com/recaptcha/api.js', array(), null, true );
		?>
		<div class="g-recaptcha nexifymy-recaptcha" data-sitekey="<?php echo esc_attr( $site_key ); ?>"></div>
		<?php
	}

	/**
	 * Render Google reCAPTCHA v3.
	 */
	private function render_recaptcha_v3() {
		$settings = $this->get_settings();
		$site_key = $settings['site_key'] ?? '';

		if ( empty( $site_key ) ) {
			echo '<p class="nexifymy-captcha-error">reCAPTCHA site key not configured.</p>';
			return;
		}

		wp_enqueue_script( 'google-recaptcha-v3', 'https://www.google.com/recaptcha/api.js?render=' . $site_key, array(), null, true );
		?>
		<input
			type="hidden"
			name="recaptcha_token"
			id="recaptcha_token"
			class="nexifymy-recaptcha-v3-token"
			data-site-key="<?php echo esc_attr( $site_key ); ?>"
			data-action="login">
		<?php
	}

	/**
	 * Render Cloudflare Turnstile.
	 */
	private function render_turnstile() {
		$settings = $this->get_settings();
		$site_key = $settings['site_key'] ?? '';

		if ( empty( $site_key ) ) {
			echo '<p class="nexifymy-captcha-error">Turnstile site key not configured.</p>';
			return;
		}

		wp_enqueue_script( 'cloudflare-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js', array(), null, true );
		?>
		<div class="cf-turnstile nexifymy-turnstile" data-sitekey="<?php echo esc_attr( $site_key ); ?>"></div>
		<?php
	}

	/**
	 * Validate captcha answer.
	 *
	 * @param int|string $submitted Submitted answer.
	 * @return bool
	 */
	private function validate_captcha( $submitted ) {
		$settings = $this->get_settings();
		$type = $settings['nexifymy_type'] ?? 'math';
		$expected = null;

		// Try session first (primary).
		if ( isset( $_SESSION[ self::SESSION_KEY ] ) ) {
			$expected = $_SESSION[ self::SESSION_KEY ];
			unset( $_SESSION[ self::SESSION_KEY ] );
		}

		// Try transient (fallback) if session failed.
		if ( null === $expected ) {
			$client_id = $this->get_client_id();
			$transient_answer = get_transient( self::TRANSIENT_PREFIX . $client_id );
			if ( false !== $transient_answer ) {
				$expected = $transient_answer;
				delete_transient( self::TRANSIENT_PREFIX . $client_id );
			}
		}

		// No stored answer found.
		if ( null === $expected ) {
			return false;
		}

		// For text matching, do case-insensitive comparison
		if ( $type === 'text_match' ) {
			return strtolower( trim( $submitted ) ) === strtolower( trim( $expected ) );
		}

		// For numeric types (math, image, audio), convert to int
		return (int) $submitted === (int) $expected;
	}

	/**
	 * Validate login captcha.
	 *
	 * @param WP_User|WP_Error|null $user User object or error.
	 * @param string                $username Username.
	 * @param string                $password Password.
	 * @return WP_User|WP_Error
	 */
	public function validate_login_captcha( $user, $username, $password ) {
		// Skip if already an error or empty credentials.
		if ( empty( $username ) || empty( $password ) ) {
			return $user;
		}

		$submitted = isset( $_POST['nexifymy_captcha'] ) ? sanitize_text_field( wp_unslash( $_POST['nexifymy_captcha'] ) ) : '';

		if ( empty( $submitted ) ) {
			return new WP_Error( 'captcha_empty', __( 'Please solve the math captcha.', 'nexifymy-security' ) );
		}

		if ( ! $this->validate_captcha( $submitted ) ) {
			// Log failed attempt.
			if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
				NexifyMy_Security_Logger::log(
					'captcha_failed',
					sprintf( 'Login captcha failed for user: %s', $username ),
					'warning',
					array( 'username' => $username )
				);
			}

			return new WP_Error( 'captcha_failed', __( 'Incorrect captcha answer. Please try again.', 'nexifymy-security' ) );
		}

		return $user;
	}

	/**
	 * Validate registration captcha.
	 *
	 * @param WP_Error $errors Error object.
	 * @param string   $sanitized_user_login Username.
	 * @param string   $user_email Email.
	 * @return WP_Error
	 */
	public function validate_registration_captcha( $errors, $sanitized_user_login, $user_email ) {
		$submitted = isset( $_POST['nexifymy_captcha'] ) ? sanitize_text_field( wp_unslash( $_POST['nexifymy_captcha'] ) ) : '';

		if ( empty( $submitted ) ) {
			$errors->add( 'captcha_empty', __( 'Please solve the math captcha.', 'nexifymy-security' ) );
			return $errors;
		}

		if ( ! $this->validate_captcha( $submitted ) ) {
			$errors->add( 'captcha_failed', __( 'Incorrect captcha answer. Please try again.', 'nexifymy-security' ) );
		}

		return $errors;
	}

	/**
	 * Validate password reset captcha.
	 *
	 * @param WP_Error $errors Error object.
	 */
	public function validate_reset_captcha( $errors ) {
		$submitted = isset( $_POST['nexifymy_captcha'] ) ? sanitize_text_field( wp_unslash( $_POST['nexifymy_captcha'] ) ) : '';

		if ( empty( $submitted ) ) {
			$errors->add( 'captcha_empty', __( 'Please solve the math captcha.', 'nexifymy-security' ) );
			return;
		}

		if ( ! $this->validate_captcha( $submitted ) ) {
			$errors->add( 'captcha_failed', __( 'Incorrect captcha answer. Please try again.', 'nexifymy-security' ) );
		}
	}

	/**
	 * Validate comment captcha.
	 *
	 * @param array $commentdata Comment data.
	 * @return array
	 */
	public function validate_comment_captcha( $commentdata ) {
		// Skip for logged-in users with high capability.
		if ( current_user_can( 'moderate_comments' ) ) {
			return $commentdata;
		}

		$submitted = isset( $_POST['nexifymy_captcha'] ) ? sanitize_text_field( wp_unslash( $_POST['nexifymy_captcha'] ) ) : '';

		if ( empty( $submitted ) || ! $this->validate_captcha( $submitted ) ) {
			wp_die(
				__( 'Incorrect captcha answer. Please go back and try again.', 'nexifymy-security' ),
				__( 'Comment Blocked', 'nexifymy-security' ),
				array( 'response' => 403, 'back_link' => true )
			);
		}

		return $commentdata;
	}

	/**
	 * Enqueue login page styles.
	 */
	public function enqueue_assets() {
		wp_enqueue_style(
			'nexifymy-login-captcha',
			NEXIFYMY_SECURITY_URL . 'assets/css/login-captcha.css',
			array(),
			NEXIFYMY_SECURITY_VERSION
		);

		wp_enqueue_script(
			'nexifymy-login-captcha',
			NEXIFYMY_SECURITY_URL . 'assets/js/login-captcha.js',
			array( 'jquery' ),
			NEXIFYMY_SECURITY_VERSION,
			true
		);
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	/**
	 * Refresh captcha via AJAX.
	 */
	public function ajax_refresh_captcha() {
		$captcha = $this->generate_captcha();
		wp_send_json_success( array( 'question' => $captcha['question'] ) );
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
			'enabled'              => ! empty( $_POST['enabled'] ),
			'enable_login'         => ! empty( $_POST['enable_login'] ),
			'enable_registration'  => ! empty( $_POST['enable_registration'] ),
			'enable_reset'         => ! empty( $_POST['enable_reset'] ),
			'enable_comment'       => ! empty( $_POST['enable_comment'] ),
			'difficulty'           => isset( $_POST['difficulty'] ) && in_array( $_POST['difficulty'], array( 'easy', 'medium', 'hard' ), true ) ? $_POST['difficulty'] : 'easy',
			'failed_threshold'     => isset( $_POST['failed_threshold'] ) ? absint( $_POST['failed_threshold'] ) : 3,
		);

		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			$all_settings['captcha'] = $settings;
			update_option( 'nexifymy_security_settings', $all_settings );
		}

		wp_send_json_success( array( 'message' => 'Settings saved.' ) );
	}
}

