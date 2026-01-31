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
		'enable_login'         => true,
		'enable_registration'  => true,
		'enable_reset'         => true,
		'enable_comment'       => false,
		'difficulty'           => 'easy', // easy, medium, hard
		'failed_threshold'     => 3,      // Show captcha after X failed attempts
	);

	/**
	 * Initialize the module.
	 */
	public function init() {
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

		// Enqueue styles.
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_styles' ) );
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
				$operations = array( '+', '-', '*' );
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
				$symbol = '×';
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
		$captcha = $this->generate_captcha();
		?>
		<p class="nexifymy-captcha-field">
			<label for="nexifymy_captcha"><?php echo esc_html( $captcha['question'] ); ?></label>
			<input type="number" name="nexifymy_captcha" id="nexifymy_captcha" class="input" required aria-required="true" />
		</p>
		<style>
			.nexifymy-captcha-field { margin-bottom: 15px; }
			.nexifymy-captcha-field label { display: block; font-weight: 600; margin-bottom: 5px; font-size: 14px; }
			.nexifymy-captcha-field input { width: 100%; padding: 8px; font-size: 16px; }
		</style>
		<?php
	}

	/**
	 * Validate captcha answer.
	 *
	 * @param int|string $submitted Submitted answer.
	 * @return bool
	 */
	private function validate_captcha( $submitted ) {
		$submitted = (int) $submitted;
		$expected = null;

		// Try session first (primary).
		if ( isset( $_SESSION[ self::SESSION_KEY ] ) ) {
			$expected = (int) $_SESSION[ self::SESSION_KEY ];
			unset( $_SESSION[ self::SESSION_KEY ] );
		}

		// Try transient (fallback) if session failed.
		if ( null === $expected ) {
			$client_id = $this->get_client_id();
			$transient_answer = get_transient( self::TRANSIENT_PREFIX . $client_id );
			if ( false !== $transient_answer ) {
				$expected = (int) $transient_answer;
				delete_transient( self::TRANSIENT_PREFIX . $client_id );
			}
		}

		// No stored answer found.
		if ( null === $expected ) {
			return false;
		}

		return $submitted === $expected;
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
	public function enqueue_styles() {
		wp_add_inline_style( 'login', '
			.nexifymy-captcha-field {
				margin-bottom: 20px;
			}
			.nexifymy-captcha-field label {
				color: #333;
				font-size: 14px;
				font-weight: 600;
			}
		' );
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
