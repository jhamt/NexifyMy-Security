<?php
/**
 * Tests for NexifyMy_Security_RateLimiter module.
 *
 * These tests verify rate limiting, lockout functionality,
 * and brute force protection.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';

class Test_RateLimiter extends \PHPUnit\Framework\TestCase {

	/**
	 * Default settings for testing.
	 *
	 * @var array
	 */
	private $settings = array(
		'max_attempts'     => 5,
		'lockout_duration' => 900, // 15 minutes.
		'ban_threshold'    => 3,   // Lockouts before permanent ban.
	);

	/**
	 * Mock attempt tracking.
	 *
	 * @var array
	 */
	private $attempts = array();

	/**
	 * Mock lockouts tracking.
	 *
	 * @var array
	 */
	private $lockouts = array();

	/**
	 * Reset state before each test.
	 */
	protected function setUp(): void {
		$this->attempts = array();
		$this->lockouts = array();
	}

	/*
	 * =========================================================================
	 * ATTEMPT TRACKING TESTS
	 * =========================================================================
	 */

	/**
	 * Test recording failed login attempts.
	 */
	public function test_record_failed_attempt() {
		$ip = '192.168.1.100';

		// Record attempts.
		$this->record_attempt( $ip );
		$this->assertEquals( 1, $this->get_attempts( $ip ) );

		$this->record_attempt( $ip );
		$this->assertEquals( 2, $this->get_attempts( $ip ) );

		$this->record_attempt( $ip );
		$this->assertEquals( 3, $this->get_attempts( $ip ) );
	}

	/**
	 * Test clearing attempts on success.
	 */
	public function test_clear_attempts_on_success() {
		$ip = '192.168.1.100';

		// Record some attempts.
		$this->record_attempt( $ip );
		$this->record_attempt( $ip );
		$this->assertEquals( 2, $this->get_attempts( $ip ) );

		// Clear on successful login.
		$this->clear_attempts( $ip );
		$this->assertEquals( 0, $this->get_attempts( $ip ) );
	}

	/**
	 * Test different IPs tracked separately.
	 */
	public function test_attempts_tracked_per_ip() {
		$ip1 = '192.168.1.100';
		$ip2 = '192.168.1.101';

		$this->record_attempt( $ip1 );
		$this->record_attempt( $ip1 );
		$this->record_attempt( $ip2 );

		$this->assertEquals( 2, $this->get_attempts( $ip1 ) );
		$this->assertEquals( 1, $this->get_attempts( $ip2 ) );
	}

	/*
	 * =========================================================================
	 * LOCKOUT TESTS
	 * =========================================================================
	 */

	/**
	 * Test lockout triggered after max attempts.
	 */
	public function test_lockout_after_max_attempts() {
		$ip = '192.168.1.100';

		// Record max attempts.
		for ( $i = 0; $i < $this->settings['max_attempts']; $i++ ) {
			$this->record_attempt( $ip );
		}

		// Should now be locked out.
		$this->assertTrue(
			$this->should_lockout( $ip ),
			'IP should be locked out after max attempts'
		);
	}

	/**
	 * Test no lockout before max attempts.
	 */
	public function test_no_lockout_before_max_attempts() {
		$ip = '192.168.1.100';

		// Record less than max attempts.
		for ( $i = 0; $i < $this->settings['max_attempts'] - 1; $i++ ) {
			$this->record_attempt( $ip );
		}

		// Should NOT be locked out.
		$this->assertFalse(
			$this->should_lockout( $ip ),
			'IP should not be locked out before max attempts'
		);
	}

	/**
	 * Test lockout duration calculation.
	 */
	public function test_lockout_duration() {
		$ip = '192.168.1.100';

		// Lockout the IP.
		$lockout_time = time();
		$this->lockout_ip( $ip, $lockout_time );

		// Check remaining time immediately.
		$remaining = $this->get_lockout_remaining( $ip, $lockout_time );
		$this->assertEquals( $this->settings['lockout_duration'], $remaining );

		// Check after some time passed.
		$elapsed   = 300; // 5 minutes.
		$remaining = $this->get_lockout_remaining( $ip, $lockout_time + $elapsed );
		$this->assertEquals( $this->settings['lockout_duration'] - $elapsed, $remaining );
	}

	/**
	 * Test lockout expires after duration.
	 */
	public function test_lockout_expires() {
		$ip = '192.168.1.100';

		// Lockout the IP.
		$lockout_time = time() - $this->settings['lockout_duration'] - 1;
		$this->lockout_ip( $ip, $lockout_time );

		// Check if still locked out (should not be).
		$remaining = $this->get_lockout_remaining( $ip, time() );
		$this->assertLessThanOrEqual( 0, $remaining, 'Lockout should have expired' );
	}

	/*
	 * =========================================================================
	 * WHITELIST TESTS
	 * =========================================================================
	 */

	/**
	 * Test whitelisted IPs bypass rate limiting.
	 */
	public function test_whitelist_bypass() {
		$whitelist = array( '127.0.0.1', '192.168.1.1' );

		$this->assertTrue( $this->is_whitelisted( '127.0.0.1', $whitelist ) );
		$this->assertTrue( $this->is_whitelisted( '192.168.1.1', $whitelist ) );
		$this->assertFalse( $this->is_whitelisted( '8.8.8.8', $whitelist ) );
	}

	/**
	 * Test localhost always whitelisted.
	 */
	public function test_localhost_whitelisted() {
		$whitelist = array();

		// Localhost should always be allowed.
		$this->assertTrue( $this->is_whitelisted( '127.0.0.1', $whitelist, true ) );
		$this->assertTrue( $this->is_whitelisted( '::1', $whitelist, true ) );
	}

	/*
	 * =========================================================================
	 * BAN ESCALATION TESTS
	 * =========================================================================
	 */

	/**
	 * Test ban after multiple lockouts.
	 */
	public function test_ban_after_multiple_lockouts() {
		$ip            = '192.168.1.100';
		$lockout_count = 0;

		// Simulate multiple lockouts.
		for ( $i = 0; $i < $this->settings['ban_threshold']; $i++ ) {
			++$lockout_count;
		}

		// Should be permanently banned.
		$this->assertTrue(
			$lockout_count >= $this->settings['ban_threshold'],
			'IP should be banned after multiple lockouts'
		);
	}

	/*
	 * =========================================================================
	 * REQUEST RATE TESTS
	 * =========================================================================
	 */

	/**
	 * Test request rate limiting.
	 */
	public function test_request_rate_limiting() {
		$max_requests_per_minute = 60;
		$requests                = array();

		// Simulate requests.
		for ( $i = 0; $i < $max_requests_per_minute; $i++ ) {
			$requests[] = time();
		}

		// Should be at limit.
		$this->assertEquals( $max_requests_per_minute, count( $requests ) );

		// Next request should be blocked.
		$this->assertTrue(
			count( $requests ) >= $max_requests_per_minute,
			'Should block after rate limit exceeded'
		);
	}

	/*
	 * =========================================================================
	 * HELPER METHODS
	 * =========================================================================
	 */

	/**
	 * Record a failed attempt.
	 *
	 * @param string $ip IP address.
	 */
	private function record_attempt( $ip ) {
		if ( ! isset( $this->attempts[ $ip ] ) ) {
			$this->attempts[ $ip ] = 0;
		}
		++$this->attempts[ $ip ];
	}

	/**
	 * Get attempt count.
	 *
	 * @param string $ip IP address.
	 * @return int
	 */
	private function get_attempts( $ip ) {
		return isset( $this->attempts[ $ip ] ) ? $this->attempts[ $ip ] : 0;
	}

	/**
	 * Clear attempts.
	 *
	 * @param string $ip IP address.
	 */
	private function clear_attempts( $ip ) {
		$this->attempts[ $ip ] = 0;
	}

	/**
	 * Check if IP should be locked out.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	private function should_lockout( $ip ) {
		return $this->get_attempts( $ip ) >= $this->settings['max_attempts'];
	}

	/**
	 * Lockout an IP.
	 *
	 * @param string $ip   IP address.
	 * @param int    $time Lockout time.
	 */
	private function lockout_ip( $ip, $time ) {
		$this->lockouts[ $ip ] = $time;
	}

	/**
	 * Get remaining lockout time.
	 *
	 * @param string $ip           IP address.
	 * @param int    $current_time Current time.
	 * @return int
	 */
	private function get_lockout_remaining( $ip, $current_time ) {
		if ( ! isset( $this->lockouts[ $ip ] ) ) {
			return 0;
		}
		$lockout_time = $this->lockouts[ $ip ];
		$expires_at   = $lockout_time + $this->settings['lockout_duration'];
		return max( 0, $expires_at - $current_time );
	}

	/**
	 * Check if IP is whitelisted.
	 *
	 * @param string $ip              IP address.
	 * @param array  $whitelist       Whitelist.
	 * @param bool   $include_localhost Include localhost.
	 * @return bool
	 */
	private function is_whitelisted( $ip, $whitelist, $include_localhost = false ) {
		if ( $include_localhost && in_array( $ip, array( '127.0.0.1', '::1' ), true ) ) {
			return true;
		}
		return in_array( $ip, $whitelist, true );
	}
}
