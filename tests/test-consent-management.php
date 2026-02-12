<?php
/**
 * Tests for consent management module.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';
require_once dirname( __DIR__ ) . '/modules/consent-management.php';

class Test_Consent_Management extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		global $wpdb;

		$GLOBALS['nexifymy_testing_user_id']    = 0;
		$GLOBALS['nexifymy_test_shortcodes']    = array();
		$GLOBALS['nexifymy_test_transients']    = array();
		$GLOBALS['nexifymy_test_options']       = array();
		$_COOKIE                                = array();

		$wpdb->queries         = array();
		$wpdb->get_var_map     = array();
		$wpdb->get_results_map = array();
		$wpdb->insert_calls    = array();
	}

	public function test_record_consent_inserts_audit_row() {
		global $wpdb;

		$module = new NexifyMy_Security_Consent_Management();
		$result = $module->record_consent( 12, 'analytics', 'Analytics tracking', 'checkbox' );

		$this->assertTrue( $result );
		$this->assertNotEmpty( $wpdb->insert_calls );
		$insert = end( $wpdb->insert_calls );
		$this->assertSame( 'analytics', $insert['data']['consent_type'] );
		$this->assertSame( 12, $insert['data']['user_id'] );
		$this->assertSame( 'checkbox', $insert['data']['consent_method'] );
	}

	public function test_has_consent_uses_user_record_when_logged_in() {
		global $wpdb;

		$wpdb->get_var_map = array(
			'WHERE user_id = 7' => 123,
		);

		$module = new NexifyMy_Security_Consent_Management();
		$this->assertTrue( $module->has_consent( 7, 'marketing' ) );
	}

	public function test_has_consent_uses_cookie_for_anonymous_user() {
		$_COOKIE['nexifymy_consent_analytics'] = '1';

		$module = new NexifyMy_Security_Consent_Management();
		$this->assertTrue( $module->has_consent( 0, 'analytics' ) );
	}
}
