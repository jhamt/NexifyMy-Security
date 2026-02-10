<?php
/**
 * Tests for AI Threat Detection Module.
 *
 * Verifies behavioral analysis, insider threat detection,
 * data exfiltration monitoring, and continuous authentication.
 *
 * @package NexifyMy_Security
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';
require_once dirname( __DIR__ ) . '/modules/ai-threat-detection.php';

/**
 * Test class for NexifyMy_Security_AI_Threat_Detection.
 */
class Test_AI_Threat_Detection extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		global $nexifymy_test_options;
		$nexifymy_test_options = array();

		$GLOBALS['nexifymy_testing_doing_ajax']    = false;
		$GLOBALS['nexifymy_testing_doing_cron']    = false;
		$GLOBALS['nexifymy_testing_user_id']       = 0;
		$GLOBALS['nexifymy_testing_session_token'] = 'test-session-token';

		$GLOBALS['nexifymy_test_actions']    = array();
		$GLOBALS['nexifymy_test_filters']    = array();
		$GLOBALS['nexifymy_test_cron']       = array();
		$GLOBALS['nexifymy_test_mail']       = array();
		$GLOBALS['nexifymy_test_user_meta']  = array();
		$GLOBALS['nexifymy_test_user_meta']  = array();
		$GLOBALS['nexifymy_test_userdata']   = array(
			1 => (object) array(
				'ID'         => 1,
				'user_login' => 'testuser',
				'user_email' => 'test@example.com',
				'roles'      => array( 'administrator' ),
			),
		);
		$GLOBALS['nexifymy_test_logged_out'] = false;
		$GLOBALS['nexifymy_test_redirect']   = null;

		unset( $GLOBALS['nexifymy_geo_blocking'] );
		unset( $GLOBALS['nexifymy_passkey'] );

		// Reset $wpdb behavior for each test.
		$GLOBALS['wpdb']->insert_calls = array();
		$GLOBALS['wpdb']->update_calls = array();
		$GLOBALS['wpdb']->queries      = array();
		$GLOBALS['wpdb']->get_var_map  = array();
		$GLOBALS['wpdb']->get_col_map  = array();
		$GLOBALS['wpdb']->get_row_map  = array();

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

		$_SERVER['REMOTE_ADDR']     = '203.0.113.10';
		$_SERVER['REQUEST_URI']     = '/?author=1';
		$_SERVER['REQUEST_METHOD']  = 'GET';
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
			'INTERVAL 1 MINUTE'    => 35, // Rapid requests.
			'is_login_attempt = 1' => 5, // Credential stuffing.
		);
		$GLOBALS['wpdb']->get_col_map = array(
			'DISTINCT request_uri' => array(
				'/a',
				'/b',
				'/c',
				'/d',
				'/e',
				'/f',
				'/g',
				'/h',
			),
		);

		$_SERVER['REMOTE_ADDR']     = '203.0.113.99';
		$_SERVER['REQUEST_URI']     = '/?author=1';
		$_SERVER['REQUEST_METHOD']  = 'GET';
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
				'modules'      => array(
					'ai_detection_enabled' => false,
				),
				'ai_detection' => array(
					'enabled' => true,
				),
			),
			false
		);

		$ai       = new NexifyMy_Security_AI_Threat_Detection();
		$settings = $ai->get_settings();
		$this->assertFalse( $settings['enabled'] );
	}

	public function test_get_settings_exposes_saved_zero_trust_and_ai_controls() {
		require_once dirname( __DIR__ ) . '/includes/class-nexifymy-security-settings.php';

		update_option(
			NexifyMy_Security_Settings::OPTION_KEY,
			array(
				'modules'      => array(
					'ai_detection_enabled' => true,
				),
				'ai_detection' => array(
					'enabled'                         => true,
					'insider_threat_enabled'          => false,
					'insider_threat_threshold'        => 55,
					'data_exfiltration_enabled'       => false,
					'exfiltration_threshold'          => 51,
					'exfiltration_baseline_days'      => 45,
					'session_risk_threshold'          => 72,
					'zero_trust_reauth_interval'      => 1200,
					'zero_trust_risk_spike_threshold' => 33,
				),
			),
			false
		);

		$ai       = new NexifyMy_Security_AI_Threat_Detection();
		$settings = $ai->get_settings();

		$this->assertEquals( 1200, $settings['zero_trust_reauth_interval'] );
		$this->assertEquals( 33, $settings['zero_trust_risk_spike_threshold'] );
		$this->assertFalse( $settings['insider_threat_enabled'] );
		$this->assertFalse( $settings['data_exfiltration_enabled'] );
		$this->assertEquals( 45, $settings['exfiltration_baseline_days'] );
	}

	public function test_get_settings_uses_defaults_for_new_zero_trust_fields() {
		require_once dirname( __DIR__ ) . '/includes/class-nexifymy-security-settings.php';

		$ai       = new NexifyMy_Security_AI_Threat_Detection();
		$settings = $ai->get_settings();

		$this->assertEquals( 900, $settings['zero_trust_reauth_interval'] );
		$this->assertEquals( 20, $settings['zero_trust_risk_spike_threshold'] );
	}

	/*
	 * =====================================================================
	 * CONTINUOUS AUTHENTICATION TESTS
	 * =====================================================================
	 */

	public function test_init_registers_continuous_auth_filter() {
		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		$this->assertArrayHasKey( 'determine_current_user', $GLOBALS['nexifymy_test_filters'] );

		$filter = $GLOBALS['nexifymy_test_filters']['determine_current_user'][0];
		$this->assertEquals( 99, $filter['priority'] );
	}

	public function test_continuous_auth_skips_guest_users() {
		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		// Guest user (user_id = 0) should pass through unchanged.
		$result = $ai->continuous_auth_check( 0 );
		$this->assertEquals( 0, $result );
	}

	public function test_check_session_validity_skips_within_interval() {
		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		$user_id                    = 42;
		$_SERVER['REMOTE_ADDR']     = '127.0.0.1';
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';

		// Set last check to 5 minutes ago (within 900s default interval).
		update_user_meta( $user_id, '_last_risk_check', time() - 300 );
		update_user_meta( $user_id, '_nexifymy_login_risk_score', 10 );

		$result = $ai->check_session_validity( $user_id, 'test-session-token' );

		$this->assertFalse( $result, 'Should not require re-auth within the interval.' );
	}

	public function test_check_session_validity_recalculates_after_interval() {
		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		$user_id                    = 42;
		$_SERVER['REMOTE_ADDR']     = '127.0.0.1';
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';

		// Set last check to 20 minutes ago (exceeds 900s default interval).
		update_user_meta( $user_id, '_last_risk_check', time() - 1200 );
		update_user_meta( $user_id, '_nexifymy_login_risk_score', 0 );
		// Mark session as verified to isolate spike detection.
		update_user_meta( $user_id, '_nexifymy_reauth_token', 'test-session-token' );

		$result = $ai->check_session_validity( $user_id, 'test-session-token' );

		// Risk should be recalculated; new user profile has 0 risk so no re-auth.
		$this->assertFalse( $result );

		// Verify the timestamp was updated.
		$updated = get_user_meta( $user_id, '_last_risk_check', true );
		$this->assertGreaterThanOrEqual( time() - 5, $updated );
	}

	public function test_risk_spike_triggers_reauth() {
		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		$user_id = 42;

		// Login-time score was low.
		update_user_meta( $user_id, '_nexifymy_login_risk_score', 5 );

		// Set admin email for alert.
		update_option( 'admin_email', 'admin@example.com' );

		// Current score is 30 → spike of 25, exceeds default threshold of 20.
		$result = $ai->detect_risk_spike( $user_id, 30 );

		$this->assertTrue( $result, 'Risk spike of 25 (>20 threshold) should trigger re-auth.' );

		// Verify alert email was sent.
		$this->assertNotEmpty( $GLOBALS['nexifymy_test_mail'] );
		$mail = $GLOBALS['nexifymy_test_mail'][0];
		$this->assertEquals( 'admin@example.com', $mail['to'] );
		$this->assertStringContainsString( 'Risk Spike', $mail['subject'] );
	}

	/*
	 * =====================================================================
	 * INSIDER THREAT DETECTION TESTS
	 * =====================================================================
	 */

	public function test_detect_insider_threat_returns_risk_score() {
		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		$GLOBALS['nexifymy_testing_user_id'] = 1;

		// No baseline, first occurrence → 30% of max weight.
		$GLOBALS['wpdb']->get_var_map = array(
			'COUNT(*) / 30'          => 0,
			'INTERVAL 24 HOUR'       => 0,
			'SUM(risk_contribution)' => 0,
		);

		$risk = $ai->detect_insider_threat( 1, 'bulk_delete', array( 'test' => true ) );

		$this->assertGreaterThanOrEqual( 0, $risk );
		$this->assertLessThanOrEqual( 40, $risk );

		// Verify event was inserted.
		$inserts = array_filter(
			$GLOBALS['wpdb']->insert_calls,
			function ( $call ) {
				return strpos( $call['table'], 'insider_events' ) !== false;
			}
		);
		$this->assertNotEmpty( $inserts );
	}

	public function test_detect_insider_threat_rejects_invalid_action() {
		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		$risk = $ai->detect_insider_threat( 1, 'invalid_action' );
		$this->assertEquals( 0, $risk );
	}

	public function test_track_post_deletion_triggers_on_bulk() {
		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		$GLOBALS['nexifymy_testing_user_id'] = 1;
		$GLOBALS['wpdb']->get_var_map        = array(
			'COUNT(*) / 30'          => 0,
			'INTERVAL 24 HOUR'       => 0,
			'SUM(risk_contribution)' => 0,
		);

		// Simulate 5 rapid deletions (triggers at >=5).
		for ( $i = 1; $i <= 5; $i++ ) {
			$ai->track_post_deletion( $i );
		}

		// Verify an insider event was inserted.
		$inserts = array_filter(
			$GLOBALS['wpdb']->insert_calls,
			function ( $call ) {
				return strpos( $call['table'], 'insider_events' ) !== false;
			}
		);
		$this->assertNotEmpty( $inserts, 'Bulk deletion should trigger insider event recording.' );
	}

	public function test_track_user_creation_detects_admin_role() {
		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		$GLOBALS['nexifymy_testing_user_id'] = 1;

		// Mock new user as administrator.
		$GLOBALS['nexifymy_test_userdata'][99] = (object) array(
			'ID'         => 99,
			'user_login' => 'newadmin',
			'user_email' => 'newadmin@example.com',
			'roles'      => array( 'administrator' ),
		);

		$GLOBALS['wpdb']->get_var_map = array(
			'COUNT(*) / 30'          => 0,
			'INTERVAL 24 HOUR'       => 0,
			'SUM(risk_contribution)' => 0,
		);

		$ai->track_user_creation( 99 );

		$inserts = array_filter(
			$GLOBALS['wpdb']->insert_calls,
			function ( $call ) {
				return strpos( $call['table'], 'insider_events' ) !== false;
			}
		);
		$this->assertNotEmpty( $inserts, 'Creating admin user should trigger insider event.' );

		// Verify the action is create_admin_user.
		$event = end( $inserts );
		$this->assertEquals( 'create_admin_user', $event['data']['action'] );
	}

	public function test_track_option_update_detects_disabled_module() {
		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		$GLOBALS['nexifymy_testing_user_id'] = 1;
		$GLOBALS['wpdb']->get_var_map        = array(
			'COUNT(*) / 30'          => 0,
			'INTERVAL 24 HOUR'       => 0,
			'SUM(risk_contribution)' => 0,
		);

		$old_value = array( 'modules' => array( 'waf_enabled' => true ) );
		$new_value = array( 'modules' => array( 'waf_enabled' => false ) );

		$ai->track_option_update( 'nexifymy_security_settings', $old_value, $new_value );

		$inserts = array_filter(
			$GLOBALS['wpdb']->insert_calls,
			function ( $call ) {
				return strpos( $call['table'], 'insider_events' ) !== false;
			}
		);
		$this->assertNotEmpty( $inserts, 'Disabling a security module should trigger insider event.' );

		$event = end( $inserts );
		$this->assertEquals( 'disable_security', $event['data']['action'] );
	}

	public function test_insider_alert_sent_when_threshold_exceeded() {
		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		$GLOBALS['nexifymy_testing_user_id'] = 1;
		update_option( 'admin_email', 'admin@example.com' );

		// Cumulative risk exceeds threshold of 60.
		// Match on unique parts of each query. Order matters - more specific first.
		$GLOBALS['wpdb']->get_var_map = array(
			'SUM(risk_contribution)' => 65,   // Cumulative risk (most specific).
			'INTERVAL 30 DAY'        => 0,    // Baseline query (30-day).
			'INTERVAL 24 HOUR'       => 2,    // Today count (24-hour).
		);

		$ai->detect_insider_threat( 1, 'bulk_delete', array() );

		$this->assertNotEmpty( $GLOBALS['nexifymy_test_mail'], 'Alert email should be sent when cumulative risk exceeds threshold.' );
		$mail = $GLOBALS['nexifymy_test_mail'][0];
		$this->assertEquals( 'admin@example.com', $mail['to'] );
		$this->assertStringContainsString( 'Insider Threat', $mail['subject'] );
	}

	/*
	 * =====================================================================
	 * DATA EXFILTRATION DETECTION TESTS
	 * =====================================================================
	 */

	public function test_monitor_data_exfiltration_detects_export_uri() {
		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		$GLOBALS['nexifymy_testing_user_id']    = 1;
		$GLOBALS['nexifymy_testing_doing_ajax'] = false;
		$GLOBALS['nexifymy_testing_doing_cron'] = false;

		$_SERVER['REQUEST_URI'] = '/wp-admin/export.php';
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';

		$GLOBALS['wpdb']->get_var_map = array(
			'COUNT(*)'         => 0,
			'exfiltration_log' => 0,
		);

		$ai->monitor_data_exfiltration();

		$inserts = array_filter(
			$GLOBALS['wpdb']->insert_calls,
			function ( $call ) {
				return strpos( $call['table'], 'exfiltration_log' ) !== false;
			}
		);
		$this->assertNotEmpty( $inserts, 'Export URI should trigger exfiltration event.' );
	}

	public function test_track_wp_export_records_event() {
		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		$GLOBALS['nexifymy_testing_user_id'] = 1;
		$GLOBALS['wpdb']->get_var_map        = array(
			'COUNT(*)'         => 0,
			'exfiltration_log' => 0,
		);

		$ai->track_wp_export( array( 'content' => 'all' ) );

		$inserts = array_filter(
			$GLOBALS['wpdb']->insert_calls,
			function ( $call ) {
				return strpos( $call['table'], 'exfiltration_log' ) !== false;
			}
		);
		$this->assertNotEmpty( $inserts, 'WordPress export should record exfiltration event.' );

		$event = end( $inserts );
		$this->assertEquals( 'db_export', $event['data']['export_type'] );
	}

	public function test_exfiltration_risk_calculation() {
		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		$GLOBALS['nexifymy_testing_user_id'] = 1;

		// No baseline, 3 events today → full weight.
		$GLOBALS['wpdb']->get_var_map = array(
			'COUNT(*) / '      => 0,    // Baseline = 0.
			'INTERVAL 24 HOUR' => 3, // Today count = 3.
		);

		$risk = $ai->track_exfiltration_event( 1, 'db_export', 0 );

		$this->assertGreaterThan( 0, $risk, 'Risk should be > 0 with 3 events and no baseline.' );
		$this->assertEquals( 30, $risk, 'With 3+ events and no baseline, risk should equal full weight (30).' );
	}

	public function test_exfiltration_alert_sent_when_threshold_exceeded() {
		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		$GLOBALS['nexifymy_testing_user_id'] = 1;
		update_option( 'admin_email', 'admin@example.com' );

		// Use high risk bonus to push over threshold.
		$GLOBALS['wpdb']->get_var_map = array(
			'COUNT(*) / '      => 0,
			'INTERVAL 24 HOUR' => 3,
		);

		$ai->track_exfiltration_event( 1, 'db_export', 0, 40 );

		$this->assertNotEmpty( $GLOBALS['nexifymy_test_mail'] );
		$mail = $GLOBALS['nexifymy_test_mail'][0];
		$this->assertEquals( 'admin@example.com', $mail['to'] );
		$this->assertStringContainsString( 'Exfiltration', $mail['subject'] );
	}

	public function test_init_registers_insider_threat_hooks() {
		$ai = new NexifyMy_Security_AI_Threat_Detection();
		$ai->init();

		$this->assertArrayHasKey( 'before_delete_post', $GLOBALS['nexifymy_test_actions'] );
		$this->assertArrayHasKey( 'user_register', $GLOBALS['nexifymy_test_actions'] );
		$this->assertArrayHasKey( 'activated_plugin', $GLOBALS['nexifymy_test_actions'] );
		$this->assertArrayHasKey( 'updated_option', $GLOBALS['nexifymy_test_actions'] );
		$this->assertArrayHasKey( 'shutdown', $GLOBALS['nexifymy_test_actions'] );
		$this->assertArrayHasKey( 'export_wp', $GLOBALS['nexifymy_test_actions'] );
	}
}
