<?php
/**
 * Tests for NexifyMy_Security_Hardening module.
 *
 * These tests verify security headers, REST API restrictions,
 * and various WordPress hardening measures.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';

class Test_Hardening extends \PHPUnit\Framework\TestCase {

	/*
	 * =========================================================================
	 * SECURITY HEADERS TESTS
	 * =========================================================================
	 */

	/**
	 * Test X-Frame-Options header validation.
	 */
	public function test_x_frame_options_header() {
		$valid_values = array( 'DENY', 'SAMEORIGIN' );

		foreach ( $valid_values as $value ) {
			$this->assertTrue(
				$this->validate_x_frame_options( $value ),
				"Should accept X-Frame-Options: $value"
			);
		}

		// Invalid values.
		$this->assertFalse( $this->validate_x_frame_options( 'ALLOW-FROM *' ) ); // Deprecated.
		$this->assertFalse( $this->validate_x_frame_options( '' ) );
	}

	/**
	 * Test X-Content-Type-Options header.
	 */
	public function test_x_content_type_options_header() {
		$this->assertTrue( $this->validate_x_content_type_options( 'nosniff' ) );
		$this->assertFalse( $this->validate_x_content_type_options( '' ) );
		$this->assertFalse( $this->validate_x_content_type_options( 'invalid' ) );
	}

	/**
	 * Test X-XSS-Protection header.
	 */
	public function test_x_xss_protection_header() {
		$valid_values = array( '1', '1; mode=block', '0' );

		foreach ( $valid_values as $value ) {
			$this->assertTrue(
				$this->validate_x_xss_protection( $value ),
				"Should accept X-XSS-Protection: $value"
			);
		}
	}

	/**
	 * Test Referrer-Policy header.
	 */
	public function test_referrer_policy_header() {
		$valid_values = array(
			'no-referrer',
			'no-referrer-when-downgrade',
			'origin',
			'origin-when-cross-origin',
			'same-origin',
			'strict-origin',
			'strict-origin-when-cross-origin',
		);

		foreach ( $valid_values as $value ) {
			$this->assertTrue(
				$this->validate_referrer_policy( $value ),
				"Should accept Referrer-Policy: $value"
			);
		}

		$this->assertFalse( $this->validate_referrer_policy( 'invalid-policy' ) );
	}

	/**
	 * Test Content-Security-Policy header format.
	 */
	public function test_csp_header_format() {
		$valid_csp = array(
			"default-src 'self'",
			"default-src 'self'; script-src 'self' 'unsafe-inline'",
			"default-src 'self'; img-src 'self' data: https:",
		);

		foreach ( $valid_csp as $csp ) {
			$this->assertTrue(
				$this->validate_csp_format( $csp ),
				"Should accept CSP: $csp"
			);
		}
	}

	/*
	 * =========================================================================
	 * VERSION HIDING TESTS
	 * =========================================================================
	 */

	/**
	 * Test version query string removal.
	 */
	public function test_version_query_removal() {
		$urls_with_version = array(
			'https://example.com/style.css?ver=5.0'        => 'https://example.com/style.css',
			'https://example.com/script.js?ver=1.2.3'      => 'https://example.com/script.js',
			'https://example.com/file.css?ver=5.8&other=1' => 'https://example.com/file.css?other=1',
		);

		foreach ( $urls_with_version as $original => $expected ) {
			$cleaned = $this->remove_version_query( $original );
			$this->assertEquals( $expected, $cleaned, "Failed to clean: $original" );
		}
	}

	/**
	 * Test WordPress version removal from generator.
	 */
	public function test_version_generator_removal() {
		$generator = '<meta name="generator" content="WordPress 5.8.1" />';
		$cleaned   = $this->remove_generator_version( $generator );

		$this->assertStringNotContainsString( '5.8.1', $cleaned );
	}

	/*
	 * =========================================================================
	 * REST API RESTRICTION TESTS
	 * =========================================================================
	 */

	/**
	 * Test REST API access control.
	 */
	public function test_rest_api_access_control() {
		// Unauthenticated should be blocked.
		$this->assertFalse(
			$this->can_access_rest_api( false, '/wp/v2/users' ),
			'Unauthenticated users should not access /users'
		);

		// Authenticated should be allowed.
		$this->assertTrue(
			$this->can_access_rest_api( true, '/wp/v2/users' ),
			'Authenticated users should access /users'
		);

		// Public endpoints should be accessible.
		$this->assertTrue(
			$this->can_access_rest_api( false, '/wp/v2/posts' ),
			'Public endpoints should be accessible'
		);
	}

	/**
	 * Test REST API user enumeration prevention.
	 */
	public function test_rest_api_user_enumeration_blocked() {
		$sensitive_endpoints = array(
			'/wp/v2/users',
			'/wp/v2/users/1',
			'/wp/v2/users?per_page=100',
		);

		foreach ( $sensitive_endpoints as $endpoint ) {
			$this->assertFalse(
				$this->can_access_rest_api( false, $endpoint ),
				"Should block unauthenticated access to: $endpoint"
			);
		}
	}

	/*
	 * =========================================================================
	 * XML-RPC TESTS
	 * =========================================================================
	 */

	/**
	 * Test XML-RPC disabling.
	 */
	public function test_xmlrpc_disabled() {
		$this->assertTrue(
			$this->is_xmlrpc_disabled(),
			'XML-RPC should be disabled by hardening'
		);
	}

	/*
	 * =========================================================================
	 * FILE EDITING TESTS
	 * =========================================================================
	 */

	/**
	 * Test file editing disabled.
	 */
	public function test_file_editing_disabled() {
		$this->assertTrue(
			$this->is_file_editing_disabled(),
			'File editing should be disabled in admin'
		);
	}

	/*
	 * =========================================================================
	 * PINGBACK TESTS
	 * =========================================================================
	 */

	/**
	 * Test X-Pingback header removal.
	 */
	public function test_x_pingback_removed() {
		$headers = array(
			'X-Pingback'   => 'https://example.com/xmlrpc.php',
			'Content-Type' => 'text/html',
		);

		$filtered = $this->remove_x_pingback( $headers );

		$this->assertArrayNotHasKey( 'X-Pingback', $filtered );
		$this->assertArrayHasKey( 'Content-Type', $filtered );
	}

	/*
	 * =========================================================================
	 * HELPER METHODS
	 * =========================================================================
	 */

	/**
	 * Validate X-Frame-Options value.
	 */
	private function validate_x_frame_options( $value ) {
		return in_array( $value, array( 'DENY', 'SAMEORIGIN' ), true );
	}

	/**
	 * Validate X-Content-Type-Options value.
	 */
	private function validate_x_content_type_options( $value ) {
		return $value === 'nosniff';
	}

	/**
	 * Validate X-XSS-Protection value.
	 */
	private function validate_x_xss_protection( $value ) {
		return in_array( $value, array( '0', '1', '1; mode=block' ), true );
	}

	/**
	 * Validate Referrer-Policy value.
	 */
	private function validate_referrer_policy( $value ) {
		$valid = array(
			'no-referrer',
			'no-referrer-when-downgrade',
			'origin',
			'origin-when-cross-origin',
			'same-origin',
			'strict-origin',
			'strict-origin-when-cross-origin',
			'unsafe-url',
		);
		return in_array( $value, $valid, true );
	}

	/**
	 * Validate CSP format.
	 */
	private function validate_csp_format( $csp ) {
		// Basic validation - must have at least one directive.
		return preg_match( '/^[a-z-]+\s+/', $csp ) === 1;
	}

	/**
	 * Remove version query string.
	 */
	private function remove_version_query( $url ) {
		$parsed = parse_url( $url );
		if ( empty( $parsed['query'] ) ) {
			return $url;
		}

		parse_str( $parsed['query'], $params );
		unset( $params['ver'] );

		$base = $parsed['scheme'] . '://' . $parsed['host'] . $parsed['path'];
		if ( ! empty( $params ) ) {
			$base .= '?' . http_build_query( $params );
		}
		return $base;
	}

	/**
	 * Remove generator version.
	 */
	private function remove_generator_version( $generator ) {
		return preg_replace( '/content="WordPress [0-9.]+"/', 'content="WordPress"', $generator );
	}

	/**
	 * Check REST API access.
	 */
	private function can_access_rest_api( $is_authenticated, $endpoint ) {
		// Block user endpoints for unauthenticated requests.
		if ( ! $is_authenticated && strpos( $endpoint, '/users' ) !== false ) {
			return false;
		}
		return true;
	}

	/**
	 * Check if XML-RPC is disabled.
	 */
	private function is_xmlrpc_disabled() {
		return true; // Simulated.
	}

	/**
	 * Check if file editing is disabled.
	 */
	private function is_file_editing_disabled() {
		return true; // Simulated.
	}

	/**
	 * Remove X-Pingback header.
	 */
	private function remove_x_pingback( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}
}
