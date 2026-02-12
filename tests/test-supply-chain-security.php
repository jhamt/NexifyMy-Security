<?php
/**
 * Tests for Supply Chain patch suggestion and preview workflow.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';
require_once dirname( __DIR__ ) . '/modules/supply-chain-security.php';

class Test_Supply_Chain_Security extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		global $wpdb;
		$wpdb->insert_calls = array();
	}

	public function test_suggest_patches_builds_composer_command() {
		$module = new NexifyMy_Security_Supply_Chain();

		$vulnerabilities = array(
			array(
				'id'            => 'OSV-2026-1000',
				'cve'           => 'CVE-2026-1000',
				'summary'       => 'Test vuln',
				'severity'      => 'HIGH',
				'fixed_version' => '1.2.3',
			),
		);

		$suggestions = $module->suggest_patches( $vulnerabilities, 'vendor/package', '1.1.0', 'composer' );

		$this->assertCount( 1, $suggestions );
		$this->assertSame( 'composer require vendor/package:^1.2.3', $suggestions[0]['command'] );
		$this->assertStringContainsString( 'CVE-2026-1000', $suggestions[0]['display_text'] );
	}

	public function test_suggest_patches_extracts_fixed_from_raw_osv_data() {
		$module = new NexifyMy_Security_Supply_Chain();

		$vulnerabilities = array(
			array(
				'id'      => 'OSV-2026-2000',
				'summary' => 'Raw OSV payload',
				'affected' => array(
					array(
						'ranges' => array(
							array(
								'events' => array(
									array( 'introduced' => '0' ),
									array( 'fixed' => '4.2.0' ),
								),
							),
						),
					),
				),
			),
		);

		$suggestions = $module->suggest_patches( $vulnerabilities, 'lodash', '4.1.0', 'npm' );

		$this->assertCount( 1, $suggestions );
		$this->assertSame( '4.2.0', $suggestions[0]['fixed_version'] );
		$this->assertSame( 'npm install lodash@^4.2.0', $suggestions[0]['command'] );
	}

	public function test_apply_patches_safely_preview_returns_report_and_logs_attempt() {
		global $wpdb;

		$module = new NexifyMy_Security_Supply_Chain();
		$patch  = array(
			'package_name'     => 'vendor/package',
			'ecosystem'        => 'composer',
			'current_version'  => '1.1.0',
			'fixed_version'    => '1.2.3',
			'vulnerability_id' => 'OSV-2026-1000',
			'command'          => 'composer require vendor/package:^1.2.3',
			'wp_compatible'    => true,
			'major_upgrade'    => false,
		);

		$result = $module->apply_patches_safely( array( $patch ), true );

		$this->assertTrue( $result['success'] );
		$this->assertSame( 'preview', $result['mode'] );
		$this->assertArrayHasKey( 'compatibility_report', $result );
		$this->assertNotEmpty( $wpdb->insert_calls );
	}

	public function test_apply_patches_safely_rejects_invalid_command() {
		$module = new NexifyMy_Security_Supply_Chain();

		$result = $module->apply_patches_safely(
			array(
				array(
					'package_name' => 'vendor/package',
					'ecosystem'    => 'composer',
					'command'      => 'rm -rf /',
				),
			),
			true
		);

		$this->assertFalse( $result['success'] );
		$this->assertSame( 'No valid patch commands found.', $result['message'] );
	}
}
