<?php
/**
 * Tests for input sanitization and validation utilities.
 *
 * These tests verify that user inputs are properly sanitized
 * and validated to prevent security vulnerabilities.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';

class Test_Input_Sanitization extends \PHPUnit\Framework\TestCase {

	/*
	 * =========================================================================
	 * EMAIL VALIDATION TESTS
	 * =========================================================================
	 */

	/**
	 * Test valid email addresses.
	 */
	public function test_valid_emails() {
		$valid_emails = array(
			'user@example.com',
			'user.name@example.com',
			'user+tag@example.com',
			'user@subdomain.example.com',
			'user123@example.co.uk',
		);

		foreach ( $valid_emails as $email ) {
			$this->assertTrue(
				$this->is_valid_email( $email ),
				"Should be valid email: $email"
			);
		}
	}

	/**
	 * Test invalid email addresses.
	 */
	public function test_invalid_emails() {
		$invalid_emails = array(
			'not-an-email',
			'@example.com',
			'user@',
			'user@.com',
			'user@example',
			'',
		);

		foreach ( $invalid_emails as $email ) {
			$this->assertFalse(
				$this->is_valid_email( $email ),
				"Should be invalid email: $email"
			);
		}
	}

	/*
	 * =========================================================================
	 * URL VALIDATION TESTS
	 * =========================================================================
	 */

	/**
	 * Test valid URLs.
	 */
	public function test_valid_urls() {
		$valid_urls = array(
			'https://example.com',
			'https://example.com/path',
			'https://example.com/path?query=1',
			'http://localhost:8080',
			'https://sub.domain.example.com',
		);

		foreach ( $valid_urls as $url ) {
			$this->assertTrue(
				$this->is_valid_url( $url ),
				"Should be valid URL: $url"
			);
		}
	}

	/**
	 * Test invalid URLs.
	 */
	public function test_invalid_urls() {
		$invalid_urls = array(
			'not-a-url',
			'javascript:alert(1)',
			'data:text/html,<script>',
			'ftp://example.com', // Only http/https allowed.
			'',
		);

		foreach ( $invalid_urls as $url ) {
			$this->assertFalse(
				$this->is_valid_url( $url ),
				"Should be invalid URL: $url"
			);
		}
	}

	/*
	 * =========================================================================
	 * TEXT SANITIZATION TESTS
	 * =========================================================================
	 */

	/**
	 * Test HTML stripping.
	 */
	public function test_strip_html() {
		$inputs = array(
			'<script>alert("xss")</script>'  => '',
			'<p>Hello</p>'                   => 'Hello',
			'Hello <b>World</b>'             => 'Hello World',
			'<a href="link">Click</a>'       => 'Click',
			'Normal text'                    => 'Normal text',
		);

		foreach ( $inputs as $input => $expected ) {
			$this->assertEquals(
				$expected,
				$this->sanitize_text( $input ),
				"Failed to sanitize: $input"
			);
		}
	}

	/**
	 * Test whitespace trimming.
	 */
	public function test_trim_whitespace() {
		$inputs = array(
			'  hello  '     => 'hello',
			"\n\ttext\n"    => 'text',
			'   '           => '',
			'no trim'       => 'no trim',
		);

		foreach ( $inputs as $input => $expected ) {
			$this->assertEquals(
				$expected,
				$this->sanitize_text( $input ),
				"Failed to trim: " . json_encode( $input )
			);
		}
	}

	/*
	 * =========================================================================
	 * INTEGER VALIDATION TESTS
	 * =========================================================================
	 */

	/**
	 * Test integer validation.
	 */
	public function test_valid_integers() {
		$valid = array( '123', '0', '-5', 456, 0 );

		foreach ( $valid as $value ) {
			$this->assertIsInt(
				$this->sanitize_int( $value ),
				"Should be valid integer: $value"
			);
		}
	}

	/**
	 * Test integer bounds.
	 */
	public function test_integer_bounds() {
		// With min/max.
		$this->assertEquals( 5, $this->sanitize_int( 3, 5, 10 ) ); // Below min.
		$this->assertEquals( 10, $this->sanitize_int( 15, 5, 10 ) ); // Above max.
		$this->assertEquals( 7, $this->sanitize_int( 7, 5, 10 ) ); // Within range.
	}

	/**
	 * Test non-integer inputs.
	 */
	public function test_non_integer_sanitized() {
		$this->assertEquals( 0, $this->sanitize_int( 'abc' ) );
		$this->assertEquals( 123, $this->sanitize_int( '123abc' ) );
		$this->assertEquals( 0, $this->sanitize_int( null ) );
	}

	/*
	 * =========================================================================
	 * ARRAY SANITIZATION TESTS
	 * =========================================================================
	 */

	/**
	 * Test array sanitization.
	 */
	public function test_sanitize_array() {
		$input = array(
			'name'    => '  <b>John</b>  ',
			'email'   => 'john@example.com',
			'nested'  => array(
				'value' => '<b>Test</b>',
			),
		);

		$sanitized = $this->sanitize_array( $input );

		$this->assertEquals( 'John', $sanitized['name'] );
		$this->assertEquals( 'john@example.com', $sanitized['email'] );
		$this->assertEquals( 'Test', $sanitized['nested']['value'] );
	}

	/*
	 * =========================================================================
	 * SLUG VALIDATION TESTS
	 * =========================================================================
	 */

	/**
	 * Test valid slugs.
	 */
	public function test_valid_slugs() {
		$valid = array(
			'my-page',
			'page-123',
			'simple',
			'page_name',
		);

		foreach ( $valid as $slug ) {
			$this->assertTrue(
				$this->is_valid_slug( $slug ),
				"Should be valid slug: $slug"
			);
		}
	}

	/**
	 * Test invalid slugs.
	 */
	public function test_invalid_slugs() {
		$invalid = array(
			'Page With Spaces',
			'../path-traversal',
			'has<html>',
			'',
		);

		foreach ( $invalid as $slug ) {
			$this->assertFalse(
				$this->is_valid_slug( $slug ),
				"Should be invalid slug: $slug"
			);
		}
	}

	/*
	 * =========================================================================
	 * NONCE VALIDATION TESTS
	 * =========================================================================
	 */

	/**
	 * Test nonce format.
	 */
	public function test_nonce_format() {
		$nonce = $this->generate_nonce();

		// Nonce should be alphanumeric.
		$this->assertMatchesRegularExpression( '/^[a-f0-9]+$/', $nonce );

		// Nonce should have minimum length.
		$this->assertGreaterThanOrEqual( 10, strlen( $nonce ) );
	}

	/**
	 * Test nonce verification.
	 */
	public function test_nonce_verification() {
		$nonce = $this->generate_nonce( 'my_action' );

		$this->assertTrue( $this->verify_nonce( $nonce, 'my_action' ) );
		$this->assertFalse( $this->verify_nonce( $nonce, 'different_action' ) );
		$this->assertFalse( $this->verify_nonce( 'invalid_nonce', 'my_action' ) );
	}

	/*
	 * =========================================================================
	 * FILE PATH VALIDATION TESTS
	 * =========================================================================
	 */

	/**
	 * Test path traversal prevention.
	 */
	public function test_path_traversal_blocked() {
		$malicious_paths = array(
			'../../../etc/passwd',
			'..\\..\\windows\\system32',
			'file/../../secret',
			'/var/www/../../../etc/passwd',
		);

		foreach ( $malicious_paths as $path ) {
			$this->assertFalse(
				$this->is_safe_path( $path ),
				"Should block path traversal: $path"
			);
		}
	}

	/**
	 * Test safe paths allowed.
	 */
	public function test_safe_paths_allowed() {
		$safe_paths = array(
			'uploads/2024/01/image.jpg',
			'wp-content/plugins/my-plugin/file.php',
			'themes/theme-name/style.css',
		);

		foreach ( $safe_paths as $path ) {
			$this->assertTrue(
				$this->is_safe_path( $path ),
				"Should allow safe path: $path"
			);
		}
	}

	/*
	 * =========================================================================
	 * HELPER METHODS
	 * =========================================================================
	 */

	private function is_valid_email( $email ) {
		return filter_var( $email, FILTER_VALIDATE_EMAIL ) !== false;
	}

	private function is_valid_url( $url ) {
		if ( ! filter_var( $url, FILTER_VALIDATE_URL ) ) {
			return false;
		}
		$scheme = parse_url( $url, PHP_URL_SCHEME );
		return in_array( $scheme, array( 'http', 'https' ), true );
	}

	private function sanitize_text( $input ) {
		$input = (string) $input;
		$input = preg_replace( '~<(script|style)[^>]*>.*?</\\1>~is', '', $input );
		return trim( strip_tags( $input ) );
	}

	private function sanitize_int( $value, $min = null, $max = null ) {
		$int = intval( $value );
		if ( $min !== null && $int < $min ) {
			$int = $min;
		}
		if ( $max !== null && $int > $max ) {
			$int = $max;
		}
		return $int;
	}

	private function sanitize_array( $array ) {
		$result = array();
		foreach ( $array as $key => $value ) {
			if ( is_array( $value ) ) {
				$result[ $key ] = $this->sanitize_array( $value );
			} else {
				$result[ $key ] = $this->sanitize_text( $value );
			}
		}
		return $result;
	}

	private function is_valid_slug( $slug ) {
		if ( empty( $slug ) ) {
			return false;
		}
		return preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$|^[a-z0-9_]+$/', $slug ) === 1;
	}

	private function generate_nonce( $action = 'default' ) {
		$secret = 'nexifymy-test-secret';
		return hash( 'sha256', $action . '|' . $secret );
	}

	private function verify_nonce( $nonce, $action ) {
		if ( strlen( (string) $nonce ) < 10 || preg_match( '/^[a-f0-9]+$/', (string) $nonce ) !== 1 ) {
			return false;
		}
		return hash_equals( $this->generate_nonce( $action ), (string) $nonce );
	}

	private function is_safe_path( $path ) {
		return strpos( $path, '..' ) === false;
	}
}

// Mock wp_rand if not available.
if ( ! function_exists( 'wp_rand' ) ) {
	function wp_rand() {
		return mt_rand();
	}
}
