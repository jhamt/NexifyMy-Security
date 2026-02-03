<?php
/**
 * Password Security Enforcement Module.
 * Enforces strong password policies for WordPress users.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Password {

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'         => true,
		'min_length'      => 12,
		'require_upper'   => true,
		'require_lower'   => true,
		'require_number'  => true,
		'require_special' => true,
		'block_common'    => true,
		'expiry_days'     => 0, // 0 = disabled
	);

	/**
	 * Common weak passwords list (top 100).
	 */
	private static $common_passwords = array(
		'123456', '123456789', 'qwerty', 'password', '12345678', '111111', '123123',
		'1234567890', '1234567', 'qwerty123', '000000', '1q2w3e', 'aa12345678',
		'abc123', 'password1', '1234', 'qwertyuiop', '123321', 'password123',
		'1q2w3e4r5t', 'iloveyou', '654321', '666666', '987654321', '123', '123456a',
		'qwe123', '1q2w3e4r', '7777777', '1qaz2wsx', '123qwe', 'zxcvbnm', '121212',
		'asdasd', 'a]123456', 'dragon', 'sunshine', 'princess', 'letmein', 'monkey',
		'shadow', 'master', 'qazwsx', 'trustno1', 'superman', 'hello', 'charlie',
		'donald', 'admin', 'welcome', 'login', 'baseball', 'football', 'pass',
		'test', 'guest', '1111', '2222', 'love', 'god', 'secret', 'asdfgh', 'zxcv',
	);

	/**
	 * Initialize the module.
	 */
	public function init() {
		$all_settings = get_option( 'nexifymy_security_settings', array() );
		if ( isset( $all_settings['modules']['password_enabled'] ) && ! $all_settings['modules']['password_enabled'] ) {
			return;
		}

		$settings = $this->get_settings();

		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Hook into password validation.
		add_action( 'user_profile_update_errors', array( $this, 'validate_password_change' ), 10, 3 );
		add_filter( 'registration_errors', array( $this, 'validate_registration_password' ), 10, 3 );

		// Hook into password reset.
		add_action( 'validate_password_reset', array( $this, 'validate_password_reset' ), 10, 2 );
		add_action( 'resetpass_form', array( $this, 'add_password_requirements' ) );

		// Password expiry check.
		if ( ! empty( $settings['expiry_days'] ) ) {
			add_action( 'wp_login', array( $this, 'check_password_expiry' ), 10, 2 );
		}

		// Add password strength indicator script.
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_password_script' ) );
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_password_script' ) );

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_check_password_strength', array( $this, 'ajax_check_strength' ) );
		add_action( 'wp_ajax_nopriv_nexifymy_check_password_strength', array( $this, 'ajax_check_strength' ) );
		add_action( 'wp_ajax_nexifymy_get_password_settings', array( $this, 'ajax_get_settings' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['password'] ) ) {
				return wp_parse_args( $all_settings['password'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Validate password strength.
	 *
	 * @param string $password The password to validate.
	 * @return array Array of error messages (empty if valid).
	 */
	public function validate_password( $password ) {
		$settings = $this->get_settings();
		$errors = array();

		// Minimum length.
		$min_length = absint( $settings['min_length'] ) ?: 12;
		if ( strlen( $password ) < $min_length ) {
			$errors[] = sprintf(
				__( 'Password must be at least %d characters long.', 'nexifymy-security' ),
				$min_length
			);
		}

		// Require uppercase.
		if ( ! empty( $settings['require_upper'] ) && ! preg_match( '/[A-Z]/', $password ) ) {
			$errors[] = __( 'Password must contain at least one uppercase letter.', 'nexifymy-security' );
		}

		// Require lowercase.
		if ( ! empty( $settings['require_lower'] ) && ! preg_match( '/[a-z]/', $password ) ) {
			$errors[] = __( 'Password must contain at least one lowercase letter.', 'nexifymy-security' );
		}

		// Require number.
		if ( ! empty( $settings['require_number'] ) && ! preg_match( '/[0-9]/', $password ) ) {
			$errors[] = __( 'Password must contain at least one number.', 'nexifymy-security' );
		}

		// Require special character.
		if ( ! empty( $settings['require_special'] ) && ! preg_match( '/[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]/', $password ) ) {
			$errors[] = __( 'Password must contain at least one special character.', 'nexifymy-security' );
		}

		// Check against common passwords.
		if ( ! empty( $settings['block_common'] ) && $this->is_common_password( $password ) ) {
			$errors[] = __( 'This password is too common. Please choose a more unique password.', 'nexifymy-security' );
		}

		return $errors;
	}

	/**
	 * Check if password is in common passwords list.
	 *
	 * @param string $password The password to check.
	 * @return bool
	 */
	private function is_common_password( $password ) {
		$lower = strtolower( $password );
		return in_array( $lower, self::$common_passwords, true );
	}

	/**
	 * Validate password on profile update.
	 *
	 * @param WP_Error $errors Error object.
	 * @param bool     $update Whether this is an update.
	 * @param WP_User  $user User object.
	 */
	public function validate_password_change( $errors, $update, $user ) {
		if ( isset( $_POST['pass1'] ) && ! empty( $_POST['pass1'] ) ) {
			$password = wp_unslash( $_POST['pass1'] );
			$validation_errors = $this->validate_password( $password );

			foreach ( $validation_errors as $error ) {
				$errors->add( 'weak_password', $error );
			}

			// Update password timestamp.
			if ( empty( $validation_errors ) && $update && isset( $user->ID ) ) {
				update_user_meta( $user->ID, '_nexifymy_password_changed', time() );
			}
		}
	}

	/**
	 * Validate password on registration.
	 *
	 * @param WP_Error $errors Error object.
	 * @param string   $sanitized_user_login User login.
	 * @param string   $user_email User email.
	 * @return WP_Error
	 */
	public function validate_registration_password( $errors, $sanitized_user_login, $user_email ) {
		if ( isset( $_POST['user_pass'] ) && ! empty( $_POST['user_pass'] ) ) {
			$password = wp_unslash( $_POST['user_pass'] );
			$validation_errors = $this->validate_password( $password );

			foreach ( $validation_errors as $error ) {
				$errors->add( 'weak_password', $error );
			}
		}
		return $errors;
	}

	/**
	 * Validate password on reset.
	 *
	 * @param WP_Error $errors Error object.
	 * @param WP_User  $user User object.
	 */
	public function validate_password_reset( $errors, $user ) {
		if ( isset( $_POST['pass1'] ) && ! empty( $_POST['pass1'] ) ) {
			$password = wp_unslash( $_POST['pass1'] );
			$validation_errors = $this->validate_password( $password );

			foreach ( $validation_errors as $error ) {
				$errors->add( 'weak_password', $error );
			}

			// Update password timestamp.
			if ( empty( $validation_errors ) && isset( $user->ID ) ) {
				update_user_meta( $user->ID, '_nexifymy_password_changed', time() );
			}
		}
	}

	/**
	 * Add password requirements info to reset form.
	 */
	public function add_password_requirements() {
		$settings = $this->get_settings();
		echo '<p class="description" style="margin-bottom: 15px;">';
		echo '<strong>' . esc_html__( 'Password Requirements:', 'nexifymy-security' ) . '</strong><br>';
		echo sprintf( esc_html__( 'Minimum %d characters', 'nexifymy-security' ), absint( $settings['min_length'] ) );

		$requirements = array();
		if ( ! empty( $settings['require_upper'] ) ) {
			$requirements[] = __( 'uppercase letter', 'nexifymy-security' );
		}
		if ( ! empty( $settings['require_lower'] ) ) {
			$requirements[] = __( 'lowercase letter', 'nexifymy-security' );
		}
		if ( ! empty( $settings['require_number'] ) ) {
			$requirements[] = __( 'number', 'nexifymy-security' );
		}
		if ( ! empty( $settings['require_special'] ) ) {
			$requirements[] = __( 'special character', 'nexifymy-security' );
		}

		if ( ! empty( $requirements ) ) {
			echo ', ' . esc_html__( 'including:', 'nexifymy-security' ) . ' ' . esc_html( implode( ', ', $requirements ) );
		}
		echo '</p>';
	}

	/**
	 * Check password expiry on login.
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user User object.
	 */
	public function check_password_expiry( $user_login, $user ) {
		$settings = $this->get_settings();
		$expiry_days = absint( $settings['expiry_days'] );

		if ( empty( $expiry_days ) ) {
			return;
		}

		$last_changed = get_user_meta( $user->ID, '_nexifymy_password_changed', true );

		if ( empty( $last_changed ) ) {
			// First time - set current timestamp.
			update_user_meta( $user->ID, '_nexifymy_password_changed', time() );
			return;
		}

		$expiry_time = $last_changed + ( $expiry_days * DAY_IN_SECONDS );

		if ( time() > $expiry_time ) {
			// Password expired - force reset.
			update_user_meta( $user->ID, '_nexifymy_password_expired', true );

			// Redirect to password change.
			add_action( 'admin_init', function() {
				if ( ! isset( $_GET['action'] ) || 'profile' !== $_GET['action'] ) {
					wp_safe_redirect( admin_url( 'profile.php?nexifymy_expired=1' ) );
					exit;
				}
			} );
		}
	}

	/**
	 * Enqueue password strength script.
	 */
	public function enqueue_password_script() {
		// Only on relevant pages.
		$screen = get_current_screen();
		if ( $screen && in_array( $screen->id, array( 'profile', 'user-edit', 'user-new' ), true ) ) {
			// WordPress password strength meter is already enqueued.
			return;
		}
	}

	/**
	 * Calculate password strength score.
	 *
	 * @param string $password Password to check.
	 * @return array Score and feedback.
	 */
	public function get_strength_score( $password ) {
		$score = 0;
		$feedback = array();
		$settings = $this->get_settings();

		// Length points (up to 25).
		$length = strlen( $password );
		$score += min( 25, $length * 2 );

		if ( $length < $settings['min_length'] ) {
			$feedback[] = sprintf( __( 'Add %d more characters.', 'nexifymy-security' ), $settings['min_length'] - $length );
		}

		// Character variety (up to 25 each).
		if ( preg_match( '/[a-z]/', $password ) ) {
			$score += 15;
		} else {
			$feedback[] = __( 'Add lowercase letters.', 'nexifymy-security' );
		}

		if ( preg_match( '/[A-Z]/', $password ) ) {
			$score += 15;
		} else {
			$feedback[] = __( 'Add uppercase letters.', 'nexifymy-security' );
		}

		if ( preg_match( '/[0-9]/', $password ) ) {
			$score += 15;
		} else {
			$feedback[] = __( 'Add numbers.', 'nexifymy-security' );
		}

		if ( preg_match( '/[^a-zA-Z0-9]/', $password ) ) {
			$score += 20;
		} else {
			$feedback[] = __( 'Add special characters.', 'nexifymy-security' );
		}

		// Penalty for common passwords.
		if ( $this->is_common_password( $password ) ) {
			$score = max( 0, $score - 50 );
			$feedback[] = __( 'This is a common password.', 'nexifymy-security' );
		}

		// Determine strength label.
		if ( $score >= 80 ) {
			$label = 'strong';
		} elseif ( $score >= 60 ) {
			$label = 'good';
		} elseif ( $score >= 40 ) {
			$label = 'fair';
		} else {
			$label = 'weak';
		}

		return array(
			'score'    => min( 100, $score ),
			'label'    => $label,
			'feedback' => $feedback,
		);
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	/**
	 * Check password strength via AJAX.
	 */
	public function ajax_check_strength() {
		// Note: This endpoint intentionally allows nopriv access for password strength checking on login/registration forms.
		// We still verify a nonce if one is provided for logged-in users.
		if ( isset( $_POST['nonce'] ) ) {
			check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		}

		$password = isset( $_POST['password'] ) ? wp_unslash( $_POST['password'] ) : '';

		if ( empty( $password ) ) {
			wp_send_json_error( 'Password required.' );
		}

		$result = $this->get_strength_score( $password );
		$errors = $this->validate_password( $password );

		wp_send_json_success( array(
			'strength' => $result,
			'valid'    => empty( $errors ),
			'errors'   => $errors,
		) );
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
}
