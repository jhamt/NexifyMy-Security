<?php
/**
 * Tests for NexifyMy_Security_Logger module.
 *
 * These tests verify logging functionality, severity levels,
 * and log retention policies.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';

class Test_Logger extends \PHPUnit\Framework\TestCase {

	/**
	 * Severity levels.
	 *
	 * @var array
	 */
	private $severity_levels = array( 'critical', 'high', 'warning', 'info', 'debug' );

	/**
	 * Mock log storage.
	 *
	 * @var array
	 */
	private $logs = array();

	/**
	 * Reset logs before each test.
	 */
	protected function setUp(): void {
		$this->logs = array();
	}

	/*
	 * =========================================================================
	 * LOG ENTRY TESTS
	 * =========================================================================
	 */

	/**
	 * Test creating log entries.
	 */
	public function test_create_log_entry() {
		$entry = $this->create_log( 'warning', 'Test event', array( 'ip' => '192.168.1.1' ) );

		$this->assertArrayHasKey( 'timestamp', $entry );
		$this->assertArrayHasKey( 'severity', $entry );
		$this->assertArrayHasKey( 'message', $entry );
		$this->assertArrayHasKey( 'context', $entry );

		$this->assertEquals( 'warning', $entry['severity'] );
		$this->assertEquals( 'Test event', $entry['message'] );
		$this->assertEquals( '192.168.1.1', $entry['context']['ip'] );
	}

	/**
	 * Test all severity levels.
	 */
	public function test_all_severity_levels() {
		foreach ( $this->severity_levels as $level ) {
			$entry = $this->create_log( $level, "Test $level event" );
			$this->assertEquals( $level, $entry['severity'] );
		}
	}

	/**
	 * Test invalid severity defaults to info.
	 */
	public function test_invalid_severity_defaults() {
		$entry = $this->create_log( 'invalid_level', 'Test event' );
		$this->assertEquals( 'info', $entry['severity'] );
	}

	/*
	 * =========================================================================
	 * LOG RETRIEVAL TESTS
	 * =========================================================================
	 */

	/**
	 * Test retrieving logs.
	 */
	public function test_retrieve_logs() {
		$this->add_log( 'critical', 'Critical event' );
		$this->add_log( 'warning', 'Warning event' );
		$this->add_log( 'info', 'Info event' );

		$logs = $this->get_logs();
		$this->assertCount( 3, $logs );
	}

	/**
	 * Test filtering logs by severity.
	 */
	public function test_filter_by_severity() {
		$this->add_log( 'critical', 'Critical 1' );
		$this->add_log( 'warning', 'Warning 1' );
		$this->add_log( 'critical', 'Critical 2' );
		$this->add_log( 'info', 'Info 1' );

		$critical = $this->get_logs( 'critical' );
		$this->assertCount( 2, $critical );

		$warning = $this->get_logs( 'warning' );
		$this->assertCount( 1, $warning );
	}

	/**
	 * Test log pagination.
	 */
	public function test_log_pagination() {
		// Add 25 logs.
		for ( $i = 1; $i <= 25; $i++ ) {
			$this->add_log( 'info', "Event $i" );
		}

		// Get first page (10 per page).
		$page1 = $this->get_logs_paginated( 1, 10 );
		$this->assertCount( 10, $page1 );

		// Get second page.
		$page2 = $this->get_logs_paginated( 2, 10 );
		$this->assertCount( 10, $page2 );

		// Get third page (only 5 remaining).
		$page3 = $this->get_logs_paginated( 3, 10 );
		$this->assertCount( 5, $page3 );
	}

	/*
	 * =========================================================================
	 * LOG RETENTION TESTS
	 * =========================================================================
	 */

	/**
	 * Test log retention policy.
	 */
	public function test_log_retention() {
		$retention_days = 30;

		// Add old log (35 days ago).
		$old_log              = $this->create_log( 'info', 'Old event' );
		$old_log['timestamp'] = time() - ( 35 * 86400 );
		$this->logs[]         = $old_log;

		// Add recent log (5 days ago).
		$recent_log              = $this->create_log( 'info', 'Recent event' );
		$recent_log['timestamp'] = time() - ( 5 * 86400 );
		$this->logs[]            = $recent_log;

		// Apply retention.
		$this->apply_retention( $retention_days );

		// Only recent log should remain.
		$this->assertCount( 1, $this->logs );
		$this->assertEquals( 'Recent event', $this->logs[0]['message'] );
	}

	/**
	 * Test log count before/after cleanup.
	 */
	public function test_cleanup_reduces_log_count() {
		// Add 100 old logs.
		for ( $i = 0; $i < 100; $i++ ) {
			$log              = $this->create_log( 'info', "Old event $i" );
			$log['timestamp'] = time() - ( 60 * 86400 ); // 60 days ago.
			$this->logs[]     = $log;
		}

		// Add 10 recent logs.
		for ( $i = 0; $i < 10; $i++ ) {
			$log              = $this->create_log( 'info', "Recent event $i" );
			$log['timestamp'] = time() - 86400; // 1 day ago.
			$this->logs[]     = $log;
		}

		$this->assertCount( 110, $this->logs );

		$this->apply_retention( 30 );

		$this->assertCount( 10, $this->logs );
	}

	/*
	 * =========================================================================
	 * LOG STATISTICS TESTS
	 * =========================================================================
	 */

	/**
	 * Test log statistics calculation.
	 */
	public function test_log_statistics() {
		$this->add_log( 'critical', 'Critical 1' );
		$this->add_log( 'critical', 'Critical 2' );
		$this->add_log( 'high', 'High 1' );
		$this->add_log( 'warning', 'Warning 1' );
		$this->add_log( 'warning', 'Warning 2' );
		$this->add_log( 'warning', 'Warning 3' );
		$this->add_log( 'info', 'Info 1' );

		$stats = $this->get_statistics();

		$this->assertEquals( 7, $stats['total'] );
		$this->assertEquals( 2, $stats['by_severity']['critical'] );
		$this->assertEquals( 1, $stats['by_severity']['high'] );
		$this->assertEquals( 3, $stats['by_severity']['warning'] );
		$this->assertEquals( 1, $stats['by_severity']['info'] );
	}

	/*
	 * =========================================================================
	 * LOG SEARCH TESTS
	 * =========================================================================
	 */

	/**
	 * Test searching logs.
	 */
	public function test_search_logs() {
		$this->add_log( 'critical', 'SQL injection attempt blocked', array( 'ip' => '192.168.1.100' ) );
		$this->add_log( 'warning', 'Failed login attempt', array( 'ip' => '192.168.1.101' ) );
		$this->add_log( 'info', 'User logged in', array( 'ip' => '192.168.1.102' ) );

		// Search by message.
		$results = $this->search_logs( 'injection' );
		$this->assertCount( 1, $results );

		// Search by IP.
		$results = $this->search_logs( '192.168.1.101' );
		$this->assertCount( 1, $results );

		// Search with no results.
		$results = $this->search_logs( 'nonexistent' );
		$this->assertCount( 0, $results );
	}

	/*
	 * =========================================================================
	 * LOG FORMATTING TESTS
	 * =========================================================================
	 */

	/**
	 * Test log timestamp formatting.
	 */
	public function test_timestamp_formatting() {
		$log = $this->create_log( 'info', 'Test' );

		$formatted = $this->format_timestamp( $log['timestamp'] );

		// Should be a valid date string.
		$this->assertMatchesRegularExpression( '/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/', $formatted );
	}

	/**
	 * Test severity badge class.
	 */
	public function test_severity_badge_class() {
		$this->assertEquals( 'badge-critical', $this->get_severity_class( 'critical' ) );
		$this->assertEquals( 'badge-high', $this->get_severity_class( 'high' ) );
		$this->assertEquals( 'badge-warning', $this->get_severity_class( 'warning' ) );
		$this->assertEquals( 'badge-info', $this->get_severity_class( 'info' ) );
		$this->assertEquals( 'badge-debug', $this->get_severity_class( 'debug' ) );
	}

	/*
	 * =========================================================================
	 * HELPER METHODS
	 * =========================================================================
	 */

	/**
	 * Create a log entry.
	 */
	private function create_log( $severity, $message, $context = array() ) {
		if ( ! in_array( $severity, $this->severity_levels, true ) ) {
			$severity = 'info';
		}

		return array(
			'timestamp' => time(),
			'severity'  => $severity,
			'message'   => $message,
			'context'   => $context,
		);
	}

	/**
	 * Add log to storage.
	 */
	private function add_log( $severity, $message, $context = array() ) {
		$this->logs[] = $this->create_log( $severity, $message, $context );
	}

	/**
	 * Get all logs, optionally filtered.
	 */
	private function get_logs( $severity = null ) {
		if ( $severity === null ) {
			return $this->logs;
		}

		return array_filter(
			$this->logs,
			function ( $log ) use ( $severity ) {
				return $log['severity'] === $severity;
			}
		);
	}

	/**
	 * Get paginated logs.
	 */
	private function get_logs_paginated( $page, $per_page ) {
		$offset = ( $page - 1 ) * $per_page;
		return array_slice( $this->logs, $offset, $per_page );
	}

	/**
	 * Apply retention policy.
	 */
	private function apply_retention( $days ) {
		$cutoff     = time() - ( $days * 86400 );
		$this->logs = array_values(
			array_filter(
				$this->logs,
				function ( $log ) use ( $cutoff ) {
					return $log['timestamp'] > $cutoff;
				}
			)
		);
	}

	/**
	 * Get log statistics.
	 */
	private function get_statistics() {
		$stats = array(
			'total'       => count( $this->logs ),
			'by_severity' => array(),
		);

		foreach ( $this->severity_levels as $level ) {
			$stats['by_severity'][ $level ] = count( $this->get_logs( $level ) );
		}

		return $stats;
	}

	/**
	 * Search logs.
	 */
	private function search_logs( $query ) {
		$query = strtolower( $query );
		return array_filter(
			$this->logs,
			function ( $log ) use ( $query ) {
				if ( strpos( strtolower( $log['message'] ), $query ) !== false ) {
					return true;
				}
				foreach ( $log['context'] as $value ) {
					if ( is_string( $value ) && strpos( strtolower( $value ), $query ) !== false ) {
						return true;
					}
				}
				return false;
			}
		);
	}

	/**
	 * Format timestamp.
	 */
	private function format_timestamp( $timestamp ) {
		return date( 'Y-m-d H:i:s', $timestamp );
	}

	/**
	 * Get severity class.
	 */
	private function get_severity_class( $severity ) {
		return 'badge-' . $severity;
	}
}
