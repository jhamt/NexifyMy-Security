<?php
/**
 * Tests for GDPR/CCPA compliance enhancements.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';
require_once dirname( __DIR__ ) . '/modules/compliance-reporting.php';

class Test_Compliance_Reporting extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		global $wpdb, $nexifymy_test_options;

		$nexifymy_test_options               = array();
		$GLOBALS['nexifymy_test_transients'] = array();
		$GLOBALS['nexifymy_test_userdata']   = array(
			42 => (object) array(
				'ID'         => 42,
				'user_email' => 'user42@example.com',
			),
		);

		$wpdb->queries         = array();
		$wpdb->get_var_map     = array();
		$wpdb->get_col_map     = array();
		$wpdb->get_row_map     = array();
		$wpdb->get_results_map = array();
		$wpdb->insert_calls    = array();
	}

	public function test_scan_for_pii_discovers_email_columns() {
		global $wpdb;

		$wpdb->get_col_map     = array(
			'SHOW TABLES' => array( 'wp_users', 'wp_comments' ),
		);
		$wpdb->get_results_map = array(
			'DESCRIBE `wp_users`'    => array(
				array(
					'Field' => 'user_email',
					'Type'  => 'varchar(255)',
				),
				array(
					'Field' => 'display_name',
					'Type'  => 'varchar(255)',
				),
			),
			'DESCRIBE `wp_comments`' => array(
				array(
					'Field' => 'comment_author_email',
					'Type'  => 'varchar(255)',
				),
			),
		);
		$wpdb->get_var_map     = array(
			'FROM `wp_users` WHERE `user_email` IS NOT NULL'            => 4,
			'FROM `wp_users` WHERE `display_name` IS NOT NULL'          => 4,
			'FROM `wp_comments` WHERE `comment_author_email` IS NOT NULL' => 2,
		);

		$module  = new NexifyMy_Security_Compliance();
		$results = $module->scan_for_pii();

		$this->assertArrayHasKey( 'wp_users', $results );
		$this->assertArrayHasKey( 'user_email', $results['wp_users'] );
		$this->assertArrayHasKey( 'email', $results['wp_users']['user_email'] );
		$this->assertSame( 4, $results['wp_users']['user_email']['email'] );
	}

	public function test_generate_data_map_report_includes_article_30_metadata() {
		global $wpdb;

		$wpdb->get_col_map     = array(
			'SHOW TABLES' => array( 'wp_users', 'wp_options' ),
		);
		$wpdb->get_results_map = array(
			'DESCRIBE `wp_users`'   => array(
				array(
					'Field' => 'user_email',
					'Type'  => 'varchar(255)',
				),
			),
			'DESCRIBE `wp_options`' => array(
				array(
					'Field' => 'option_name',
					'Type'  => 'varchar(191)',
				),
			),
			'FROM `wp_options`'     => array(
				array( 'option_name' => 'google_analytics_key' ),
			),
		);
		$wpdb->get_var_map     = array(
			"SHOW TABLES LIKE 'wp_options'" => 'wp_options',
			"SHOW TABLES LIKE 'wp_users'"   => 'wp_users',
			'FROM `wp_users` WHERE `user_email` IS NOT NULL' => 5,
		);

		$GLOBALS['nexifymy_test_transients']['nexifymy_external_scripts'] = array(
			'value'      => array(
				array(
					'host' => 'cdn.example.net',
				),
			),
			'expiration' => 0,
		);

		$module = new NexifyMy_Security_Compliance();
		$report = $module->generate_data_map_report( 'array' );

		$this->assertTrue( ! empty( $report['article_30'] ) );
		$this->assertArrayHasKey( 'records', $report );
		$this->assertNotEmpty( $report['records'] );
		$this->assertSame( 'email', $report['records'][0]['pii_type'] );
	}

	public function test_request_third_party_erasure_defaults_to_queue() {
		$module = new NexifyMy_Security_Compliance();
		$result = $module->request_third_party_erasure( 'user@example.com', 'stripe' );

		$this->assertArrayHasKey( 'status', $result );
		$this->assertNotEmpty( $result['status'] );
	}
}
