<?php
/**
 * Tests for Predictive Threat Hunting module.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';
require_once dirname( __DIR__ ) . '/modules/predictive-threat-hunting.php';

class Test_Predictive_Threat_Hunting extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		global $nexifymy_test_options, $wpdb;

		$nexifymy_test_options = array(
			'active_plugins' => array(),
		);

		$wpdb->queries         = array();
		$wpdb->get_var_map     = array();
		$wpdb->get_col_map     = array();
		$wpdb->get_row_map     = array();
		$wpdb->get_results_map = array();
		$wpdb->insert_calls    = array();
		$wpdb->update_calls    = array();
	}

	public function test_profile_site_detects_healthcare_context() {
		global $nexifymy_test_options;

		$nexifymy_test_options['blogdescription'] = 'Patient portal for medical clinic with HIPAA workflows.';
		$nexifymy_test_options['active_plugins']  = array( 'contact-form-7/wp-contact-form-7.php' );

		$module = new NexifyMy_Security_Predictive_Threat_Hunting();
		$module->create_table();
		$profile = $module->profile_site();

		$this->assertSame( 'healthcare', $profile['industry'] );
		$this->assertSame( 'contact-form-7/wp-contact-form-7.php', $nexifymy_test_options['active_plugins'][0] );
	}

	public function test_predict_next_attack_vector_includes_healthcare_rule() {
		global $nexifymy_test_options, $wpdb;

		$nexifymy_test_options['blogdescription'] = 'Medical patient intake form and HIPAA onboarding.';
		$nexifymy_test_options['active_plugins']  = array( 'contact-form-7/wp-contact-form-7.php' );
		$wpdb->get_var_map                        = array(
			"SHOW TABLES LIKE 'wp_nexifymy_behavior_log'"   => 'wp_nexifymy_behavior_log',
			'AND is_login_attempt = 1'                     => 12,
			'SELECT COUNT(*) FROM wp_nexifymy_threat_predictions' => 0,
		);

		$module = new NexifyMy_Security_Predictive_Threat_Hunting();
		$module->create_table();
		$module->profile_site();
		$predictions = $module->predict_next_attack_vector();

		$joined_vectors = implode(
			' | ',
			array_map(
				function ( $row ) {
					return (string) ( $row['vector'] ?? '' );
				},
				$predictions
			)
		);
		$this->assertStringContainsString( 'Form injection attacks', $joined_vectors );
		$this->assertStringContainsString( 'Credential stuffing attack within 7 days', $joined_vectors );
	}

	public function test_get_hardening_recommendations_maps_vectors() {
		$module = new NexifyMy_Security_Predictive_Threat_Hunting();

		$recommendations = $module->get_hardening_recommendations(
			array(
				array(
					'vector'      => 'SQL injection on checkout',
					'probability' => 70,
					'reasons'     => array(),
				),
				array(
					'vector'      => 'Credential stuffing attack within 7 days',
					'probability' => 65,
					'reasons'     => array(),
				),
			)
		);

		$ids = array_map(
			function ( $row ) {
				return (string) ( $row['id'] ?? '' );
			},
			$recommendations
		);
		$this->assertContains( 'enable_strict_waf', $ids );
		$this->assertContains( 'strengthen_auth', $ids );
	}

	public function test_run_monthly_penetration_test_stores_audit_report() {
		global $nexifymy_test_options;

		$nexifymy_test_options['nexifymy_security_settings'] = array(
			'modules' => array(
				'waf_enabled'             => true,
				'rate_limiter_enabled'    => true,
				'two_factor_enabled'      => true,
				'self_protection_enabled' => true,
				'supply_chain_enabled'    => true,
				'ai_detection_enabled'    => true,
				'activity_log_enabled'    => true,
			),
		);

		$module = new NexifyMy_Security_Predictive_Threat_Hunting();
		$report = $module->run_monthly_penetration_test();

		$this->assertArrayHasKey( 'report_id', $report );
		$this->assertArrayHasKey( 'analysis', $report );
		$this->assertNotEmpty( $module->get_latest_simulation_report() );
	}
}
