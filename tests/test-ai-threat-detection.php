<?php
/**
 * Tests for NexifyMy_Security_AI_Threat_Detection module.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';
require_once dirname( __DIR__ ) . '/modules/ai-threat-detection.php';

class Test_AI_Threat_Detection extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		global $nexifymy_test_options;
		$nexifymy_test_options = array();

		$GLOBALS['nexifymy_testing_doing_ajax'] = false;
		$GLOBALS['nexifymy_testing_doing_cron'] = false;
		$GLOBALS['nexifymy_testing_user_id'] = 0;

		$GLOBALS['nexifymy_test_actions'] = array();
		$GLOBALS['nexifymy_test_filters'] = array();
		$GLOBALS['nexifymy_test_cron'] = array();
		$GLOBALS['nexifymy_test_mail'] = array();

		unset( $GLOBALS['nexifymy_geo_blocking'] );

		// Reset $wpdb behavior for each test.
		$GLOBALS['wpdb']->insert_calls = array();
		$GLOBALS['wpdb']->queries = array();
		$GLOBALS['wpdb']->get_var_map = array();
		$GLOBALS['wpdb']->get_col_map = array();

		$_SERVER = array();
	}

	public function test_init_registers_hooks_and_schedules_learning() {
		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		$this->assertArrayHasKey( 'init', $GLOBALS['nexifymy_test_actions'] );
		$this->assertArrayHasKey( 'nexifymy_learn_patterns', $GLOBALS['nexifymy_test_actions'] );

		$this->assertArrayHasKey( 'wp_ajax_nexifymy_get_ai_threats', $GLOBALS['nexifymy_test_actions'] );
		$this->assertArrayHasKey( 'wp_ajax_nexifymy_get_ai_status', $GLOBALS['nexifymy_test_actions'] );
		$this->assertArrayHasKey( 'wp_ajax_nexifymy_reset_ai_learning', $GLOBALS['nexifymy_test_actions'] );

		$this->assertArrayHasKey( 'nexifymy_learn_patterns', $GLOBALS['nexifymy_test_cron'] );
		$this->assertEquals( 'hourly', $GLOBALS['nexifymy_test_cron']['nexifymy_learn_patterns']['recurrence'] );
	}

	public function test_analyze_request_skips_during_ajax() {
		$GLOBALS['nexifymy_testing_doing_ajax'] = true;

		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		$_SERVER['REMOTE_ADDR'] = '203.0.113.10';
		$_SERVER['REQUEST_URI'] = '/?author=1';
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$_SERVER['HTTP_USER_AGENT'] = 'sqlmap';

		$ai->analyze_request();

		$this->assertEmpty( $GLOBALS['wpdb']->insert_calls );
		$this->assertEmpty( get_option( NexifyMy_Security_AI_Threat_Detection::THREATS_OPTION, array() ) );
	}

	public function test_analyze_request_blocks_high_risk_activity() {
		// Provide patterns that make the current hour "unusual".
		update_option(
			NexifyMy_Security_AI_Threat_Detection::PATTERNS_OPTION,
			array(
				'peak_hours'      => array( 99 ),
				'known_countries' => array( 'CA' ),
			),
			false
		);

		$GLOBALS['nexifymy_geo_blocking'] = new class() {
			public function get_country( $ip ) {
				return 'US';
			}
		};

		// Configure database-derived signals to be suspicious.
		$GLOBALS['wpdb']->get_var_map = array(
			'INTERVAL 1 MINUTE' => 35, // Rapid requests.
			'is_login_attempt = 1' => 5, // Credential stuffing.
		);
		$GLOBALS['wpdb']->get_col_map = array(
			'DISTINCT request_uri' => array(
				'/a', '/b', '/c', '/d', '/e', '/f', '/g', '/h',
			),
		);

		$_SERVER['REMOTE_ADDR'] = '203.0.113.99';
		$_SERVER['REQUEST_URI'] = '/?author=1';
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$_SERVER['HTTP_USER_AGENT'] = 'sqlmap';
		unset( $_SERVER['HTTP_ACCEPT'], $_SERVER['HTTP_ACCEPT_LANGUAGE'], $_SERVER['HTTP_ACCEPT_ENCODING'] );

		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();
		$ai->analyze_request();

		$this->assertNotEmpty( $GLOBALS['wpdb']->insert_calls );

		$threats = get_option( NexifyMy_Security_AI_Threat_Detection::THREATS_OPTION, array() );
		$this->assertNotEmpty( $threats );

		$latest = end( $threats );
		$this->assertEquals( '203.0.113.99', $latest['ip'] );
		$this->assertEquals( 'blocked', $latest['status'] );
		$this->assertGreaterThanOrEqual( 90, $latest['score'] );
	}

	public function test_respects_global_module_toggle() {
		require_once dirname( __DIR__ ) . '/includes/class-nexifymy-security-settings.php';

		update_option(
			NexifyMy_Security_Settings::OPTION_KEY,
			array(
				'modules' => array(
					'ai_detection_enabled' => false,
				),
				'ai_detection' => array(
					'enabled' => true,
				),
			),
			false
		);

		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$settings = $ai->get_settings();
		$this->assertFalse( $settings['enabled'] );
	}
}
