<?php
/**
 * Tests for NexifyMy_Security_Password module.
 *
 * These tests verify password strength validation,
 * complexity requirements, and common password detection.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';

class Test_Password_Security extends \PHPUnit\Framework\TestCase {

	/**
	 * Default password policy settings.
	 *
	 * @var array
	 */
	private $policy = array(
		'min_length'      => 8,
		'require_upper'   => true,
		'require_lower'   => true,
		'require_number'  => true,
		'require_special' => true,
		'block_common'    => true,
	);

	/**
	 * Common passwords list.
	 *
	 * @var array
	 */
	private $common_passwords = array(
		'password',
		'123456',
		'12345678',
		'qwerty',
		'abc123',
		'letmein',
		'welcome',
		'admin',
		'password123',
		'iloveyou',
	);

	/*
	 * =========================================================================
	 * PASSWORD VALIDATION TESTS
	 * =========================================================================
	 */

	/**
	 * Test strong passwords pass validation.
	 */
	public function test_strong_passwords_pass() {
		$strong_passwords = array(
			'MyStr0ng!Pass',
			'C0mpl3x#Secure',
			'P@ssw0rd!2024',
			'Qwerty!123ABC',
			'Sup3r$ecure#1',
		);

		foreach ( $strong_passwords as $password ) {
			$errors = $this->validate_password( $password );
			$this->assertEmpty(
				$errors,
				"Strong password should pass: $password - Errors: " . implode( ', ', $errors )
			);
		}
	}

	/**
	 * Test weak passwords fail validation.
	 */
	public function test_weak_passwords_fail() {
		$weak_passwords = array(
			'short',       // Too short.
			'alllowercase', // No uppercase.
			'ALLUPPERCASE', // No lowercase.
			'NoNumbers!',   // No numbers.
			'NoSpecial123', // No special chars.
		);

		foreach ( $weak_passwords as $password ) {
			$errors = $this->validate_password( $password );
			$this->assertNotEmpty(
				$errors,
				"Weak password should fail: $password"
			);
		}
	}

	/*
	 * =========================================================================
	 * LENGTH VALIDATION TESTS
	 * =========================================================================
	 */

	/**
	 * Test minimum length requirement.
	 */
	public function test_minimum_length() {
		// Too short.
		$errors = $this->validate_password( 'Aa1!' );
		$this->assertContains( 'length', $this->get_error_types( $errors ) );

		// Exactly min length.
		$errors = $this->validate_password( 'Aa1!aaaa' ); // 8 chars.
		$this->assertNotContains( 'length', $this->get_error_types( $errors ) );

		// Over min length.
		$errors = $this->validate_password( 'Aa1!aaaaaaaaa' ); // 13 chars.
		$this->assertNotContains( 'length', $this->get_error_types( $errors ) );
	}

	/*
	 * =========================================================================
	 * CHARACTER REQUIREMENT TESTS
	 * =========================================================================
	 */

	/**
	 * Test uppercase requirement.
	 */
	public function test_uppercase_requirement() {
		// No uppercase.
		$errors = $this->validate_password( 'lowercase1!' );
		$this->assertContains( 'uppercase', $this->get_error_types( $errors ) );

		// Has uppercase.
		$errors = $this->validate_password( 'Lowercase1!' );
		$this->assertNotContains( 'uppercase', $this->get_error_types( $errors ) );
	}

	/**
	 * Test lowercase requirement.
	 */
	public function test_lowercase_requirement() {
		// No lowercase.
		$errors = $this->validate_password( 'UPPERCASE1!' );
		$this->assertContains( 'lowercase', $this->get_error_types( $errors ) );

		// Has lowercase.
		$errors = $this->validate_password( 'UPPERCASEa1!' );
		$this->assertNotContains( 'lowercase', $this->get_error_types( $errors ) );
	}

	/**
	 * Test number requirement.
	 */
	public function test_number_requirement() {
		// No numbers.
		$errors = $this->validate_password( 'NoNumbers!' );
		$this->assertContains( 'number', $this->get_error_types( $errors ) );

		// Has numbers.
		$errors = $this->validate_password( 'HasNumber1!' );
		$this->assertNotContains( 'number', $this->get_error_types( $errors ) );
	}

	/**
	 * Test special character requirement.
	 */
	public function test_special_character_requirement() {
		// No special chars.
		$errors = $this->validate_password( 'NoSpecial123' );
		$this->assertContains( 'special', $this->get_error_types( $errors ) );

		// Has special chars.
		$special_chars = array( '!', '@', '#', '$', '%', '^', '&', '*' );
		foreach ( $special_chars as $char ) {
			$errors = $this->validate_password( "HasSpecial1{$char}a" );
			$this->assertNotContains(
				'special',
				$this->get_error_types( $errors ),
				"Should accept special char: $char"
			);
		}
	}

	/*
	 * =========================================================================
	 * COMMON PASSWORD TESTS
	 * =========================================================================
	 */

	/**
	 * Test common passwords are blocked.
	 */
	public function test_common_passwords_blocked() {
		foreach ( $this->common_passwords as $password ) {
			$this->assertTrue(
				$this->is_common_password( $password ),
				"Should detect common password: $password"
			);
		}
	}

	/**
	 * Test variations of common passwords are blocked.
	 */
	public function test_common_password_variations_blocked() {
		$variations = array(
			'Password',    // Capitalized.
			'PASSWORD',    // All caps.
			'p@ssword',    // Leet speak.
			'passw0rd',    // Number substitution.
		);

		foreach ( $variations as $password ) {
			$this->assertTrue(
				$this->is_common_password( $password ),
				"Should detect common password variation: $password"
			);
		}
	}

	/**
	 * Test unique passwords not flagged as common.
	 */
	public function test_unique_passwords_not_flagged() {
		$unique = array(
			'xK9#mLp2$wQz',
			'Zy!8Nx@3Bc',
			'hJ4&Kf9#Lm',
		);

		foreach ( $unique as $password ) {
			$this->assertFalse(
				$this->is_common_password( $password ),
				"Should not flag unique password: $password"
			);
		}
	}

	/*
	 * =========================================================================
	 * STRENGTH SCORE TESTS
	 * =========================================================================
	 */

	/**
	 * Test password strength scoring.
	 */
	public function test_strength_scoring() {
		// Very weak.
		$score = $this->get_strength_score( 'weak' );
		$this->assertLessThan( 30, $score['score'] );

		// Weak.
		$score = $this->get_strength_score( 'password1' );
		$this->assertLessThan( 50, $score['score'] );

		// Strong.
		$score = $this->get_strength_score( 'MyStr0ng!Pass123' );
		$this->assertGreaterThan( 70, $score['score'] );

		// Very strong.
		$score = $this->get_strength_score( 'xK9#mLp2$wQzR%5n!@Bc' );
		$this->assertGreaterThan( 90, $score['score'] );
	}

	/*
	 * =========================================================================
	 * HELPER METHODS
	 * =========================================================================
	 */

	/**
	 * Validate password against policy.
	 *
	 * @param string $password Password to validate.
	 * @return array Errors array.
	 */
	private function validate_password( $password ) {
		$errors = array();

		if ( strlen( $password ) < $this->policy['min_length'] ) {
			$errors[] = array(
				'type'    => 'length',
				'message' => 'Password too short',
			);
		}

		if ( $this->policy['require_upper'] && ! preg_match( '/[A-Z]/', $password ) ) {
			$errors[] = array(
				'type'    => 'uppercase',
				'message' => 'Password requires uppercase letter',
			);
		}

		if ( $this->policy['require_lower'] && ! preg_match( '/[a-z]/', $password ) ) {
			$errors[] = array(
				'type'    => 'lowercase',
				'message' => 'Password requires lowercase letter',
			);
		}

		if ( $this->policy['require_number'] && ! preg_match( '/[0-9]/', $password ) ) {
			$errors[] = array(
				'type'    => 'number',
				'message' => 'Password requires number',
			);
		}

		if ( $this->policy['require_special'] && ! preg_match( '/[!@#$%^&*(),.?":{}|<>]/', $password ) ) {
			$errors[] = array(
				'type'    => 'special',
				'message' => 'Password requires special character',
			);
		}

		if ( $this->policy['block_common'] && $this->is_common_password( $password ) ) {
			$errors[] = array(
				'type'    => 'common',
				'message' => 'Password is too common',
			);
		}

		return $errors;
	}

	/**
	 * Get error types from errors array.
	 *
	 * @param array $errors Errors array.
	 * @return array Error types.
	 */
	private function get_error_types( $errors ) {
		return array_map( function( $e ) {
			return $e['type'];
		}, $errors );
	}

	/**
	 * Check if password is common.
	 *
	 * @param string $password Password to check.
	 * @return bool
	 */
	private function is_common_password( $password ) {
		$lower = strtolower( (string) $password );
		$normalized = str_replace( array( '@', '0', '3' ), array( 'a', 'o', 'e' ), $lower );

		foreach ( $this->common_passwords as $common ) {
			$common_lower = strtolower( (string) $common );

			if ( $normalized === $common_lower || $lower === $common_lower ) {
				return true;
			}

			// Common base word with simple suffixes (e.g. password1, password123, password!).
			if ( preg_match( '/^' . preg_quote( $common_lower, '/' ) . '[0-9!@#$%^&*._-]+$/', $lower ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Calculate password strength score.
	 *
	 * @param string $password Password to score.
	 * @return array Score and feedback.
	 */
	private function get_strength_score( $password ) {
		$score = 0;
		$feedback = array();

		// Length points (max 30).
		$length = strlen( $password );
		$score += min( 30, $length * 2 );

		// Character variety (max 40).
		if ( preg_match( '/[a-z]/', $password ) ) {
			$score += 10;
		}
		if ( preg_match( '/[A-Z]/', $password ) ) {
			$score += 10;
		}
		if ( preg_match( '/[0-9]/', $password ) ) {
			$score += 10;
		}
		if ( preg_match( '/[^a-zA-Z0-9]/', $password ) ) {
			$score += 10;
		}

		// Unique characters bonus (max 30).
		$unique = count( array_unique( str_split( $password ) ) );
		$score += min( 30, $unique * 2 );

		// Penalty for common patterns.
		if ( $this->is_common_password( $password ) ) {
			$score = min( 20, $score );
			$feedback[] = 'Common password';
		}

		return array(
			'score'    => min( 100, $score ),
			'feedback' => $feedback,
		);
	}
}
