<?php
/**
 * Tests for NexifyMy_Security_Scanner AJAX registration and guards.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';
require_once dirname( __DIR__ ) . '/modules/scanner.php';

class Test_Scanner_Ajax extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		global $nexifymy_test_options;
		$nexifymy_test_options = array();
		$GLOBALS['nexifymy_test_actions'] = array();
		$GLOBALS['nexifymy_test_filters'] = array();
	}

	public function test_ajax_endpoints_registered_even_when_disabled() {
		update_option(
			'nexifymy_security_settings',
			array(
				'modules' => array(
					'scanner_enabled' => false,
				),
			),
			false
		);

		$scanner = new NexifyMy_Security_Scanner();
		$scanner->init();

		$this->assertArrayHasKey( 'wp_ajax_nexifymy_scan', $GLOBALS['nexifymy_test_actions'] );
		$this->assertArrayHasKey( 'wp_ajax_nexifymy_scan_progress', $GLOBALS['nexifymy_test_actions'] );
		$this->assertArrayHasKey( 'wp_ajax_nexifymy_core_integrity', $GLOBALS['nexifymy_test_actions'] );
	}

	public function test_ajax_scan_returns_json_error_when_disabled() {
		update_option(
			'nexifymy_security_settings',
			array(
				'modules' => array(
					'scanner_enabled' => false,
				),
			),
			false
		);

		$scanner = new NexifyMy_Security_Scanner();

		$this->expectException( \RuntimeException::class );
		$this->expectExceptionMessage( 'Scanner module is disabled' );
		$scanner->ajax_scan();
	}
}

