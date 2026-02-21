<?php
/**
 * Tests for WAF pattern matching.
 *
 * These tests verify that WAF patterns correctly identify attacks
 * while avoiding false positives on legitimate content.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';

class Test_WAF_Patterns extends \PHPUnit\Framework\TestCase {

	/**
	 * SQL Injection patterns.
	 *
	 * @var array
	 */
	private $sqli_patterns = array(
		'/union\s+(all\s+)?select\s+/i',
		'/\)\s*union\s+select/i',
		'/information_schema\./i',
		'/(?:\x27;|--|#)\s*$/i',
		'/(?:benchmark|sleep)\s*\(\s*\d/i',
		'/\/\*![0-9]+/i',
		'/load_file\s*\(/i',
		'/into\s+(out|dump)file/i',
	);

	/**
	 * XSS patterns.
	 *
	 * @var array
	 */
	private $xss_patterns = array(
		'/<script[^>]*>.*<\/script>/is',
		'/javascript\s*:/i',
		'/on(error|load|click|mouse|submit|focus|blur)\s*=/i',
		'/<iframe[^>]*>/i',
		'/<object[^>]*>/i',
		'/<embed[^>]*>/i',
		'/<svg[^>]*onload/i',
	);

	/**
	 * Helper to check if any pattern matches.
	 *
	 * @param array  $patterns Patterns to check.
	 * @param string $input    Input to test.
	 * @return bool
	 */
	private function matches_any( $patterns, $input ) {
		foreach ( $patterns as $pattern ) {
			if ( preg_match( $pattern, $input ) ) {
				return true;
			}
		}
		return false;
	}

	/*
	 * =========================================================================
	 * SQL INJECTION TESTS
	 * =========================================================================
	 */

	/**
	 * Test SQLi detection for UNION SELECT attacks.
	 */
	public function test_sqli_union_select_detected() {
		$attacks = array(
			"' UNION SELECT * FROM users",
			'1 UNION ALL SELECT password FROM wp_users',
			') UNION SELECT username,password FROM users',
		);

		foreach ( $attacks as $attack ) {
			$this->assertTrue(
				$this->matches_any( $this->sqli_patterns, $attack ),
				"Failed to detect: $attack"
			);
		}
	}

	/**
	 * Test SQLi detection for time-based attacks.
	 */
	public function test_sqli_time_based_detected() {
		$attacks = array(
			"1' AND SLEEP(5)--",
			"1; BENCHMARK(5000000, SHA1('test'))#",
		);

		foreach ( $attacks as $attack ) {
			$this->assertTrue(
				$this->matches_any( $this->sqli_patterns, $attack ),
				"Failed to detect: $attack"
			);
		}
	}

	/**
	 * Test SQLi false positives - these should NOT match.
	 */
	public function test_sqli_false_positives_avoided() {
		$legitimate = array(
			'I want to select a color',
			'Please select from the dropdown',
			'This is a union of ideas',
			'The reunion was great',
			'SELECT query syntax tutorial', // Documentation content.
			'contact@information.com', // Email with "information".
		);

		foreach ( $legitimate as $text ) {
			$this->assertFalse(
				$this->matches_any( $this->sqli_patterns, $text ),
				"False positive on: $text"
			);
		}
	}

	/*
	 * =========================================================================
	 * XSS TESTS
	 * =========================================================================
	 */

	/**
	 * Test XSS detection for script tags.
	 */
	public function test_xss_script_tags_detected() {
		$attacks = array(
			"<script>alert('XSS')</script>",
			'<SCRIPT SRC="evil.js"></SCRIPT>',
			"<script type='text/javascript'>document.cookie</script>",
		);

		foreach ( $attacks as $attack ) {
			$this->assertTrue(
				$this->matches_any( $this->xss_patterns, $attack ),
				"Failed to detect: $attack"
			);
		}
	}

	/**
	 * Test XSS detection for event handlers.
	 */
	public function test_xss_event_handlers_detected() {
		$attacks = array(
			'<img src=x onerror="alert(1)">',
			'<body onload="evil()">',
			'<div onclick="steal()">',
		);

		foreach ( $attacks as $attack ) {
			$this->assertTrue(
				$this->matches_any( $this->xss_patterns, $attack ),
				"Failed to detect: $attack"
			);
		}
	}

	/**
	 * Test XSS detection for javascript: URLs.
	 */
	public function test_xss_javascript_url_detected() {
		$attacks = array(
			'<a href="javascript:alert(1)">click</a>',
			'<a href="JAVASCRIPT:void(0)">link</a>',
		);

		foreach ( $attacks as $attack ) {
			$this->assertTrue(
				$this->matches_any( $this->xss_patterns, $attack ),
				"Failed to detect: $attack"
			);
		}
	}

	/**
	 * Test XSS false positives - these should NOT match.
	 */
	public function test_xss_false_positives_avoided() {
		$legitimate = array(
			'The script of the play was excellent',
			'Loading the page takes 3 seconds',
			'Click here for more information',
			"I'm focused on my work",
			'<p>Normal HTML paragraph</p>',
			'<strong>Bold text</strong>',
		);

		foreach ( $legitimate as $text ) {
			$this->assertFalse(
				$this->matches_any( $this->xss_patterns, $text ),
				"False positive on: $text"
			);
		}
	}
}
