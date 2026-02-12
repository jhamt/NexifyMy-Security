<?php
/**
 * Tests for NexifyMy_Security_Settings class.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';
require_once dirname( __DIR__ ) . '/includes/class-nexifymy-security-settings.php';

class Test_Settings extends \PHPUnit\Framework\TestCase {

	/**
	 * Set up before each test.
	 */
	protected function setUp(): void {
		global $nexifymy_test_options;
		$nexifymy_test_options = array();
	}

	/**
	 * Test get_all returns defaults when no options set.
	 */
	public function test_get_all_returns_defaults() {
		$settings = NexifyMy_Security_Settings::get_all();

		$this->assertIsArray( $settings );
		$this->assertArrayHasKey( 'modules', $settings );
		$this->assertArrayHasKey( 'rate_limiter', $settings );
		$this->assertArrayHasKey( 'logging', $settings );
	}

	/**
	 * Test default values are correct.
	 */
	public function test_default_values() {
		$settings = NexifyMy_Security_Settings::get_all();

		// Check module defaults.
		$this->assertTrue( $settings['modules']['waf_enabled'] );
		$this->assertTrue( $settings['modules']['scanner_enabled'] );
		$this->assertTrue( $settings['modules']['rate_limiter_enabled'] );
		$this->assertTrue( $settings['modules']['temp_permissions_enabled'] );
		$this->assertTrue( $settings['modules']['predictive_hunting_enabled'] );

		// Check rate limiter defaults.
		$this->assertEquals( 5, $settings['rate_limiter']['max_attempts'] );
		$this->assertEquals( 900, $settings['rate_limiter']['lockout_duration'] );

		// Check logging defaults.
		$this->assertEquals( 30, $settings['logging']['retention_days'] );

		// Check AI zero-trust defaults.
		$this->assertEquals( 900, $settings['ai_detection']['zero_trust_reauth_interval'] );
		$this->assertEquals( 20, $settings['ai_detection']['zero_trust_risk_spike_threshold'] );
	}

	/**
	 * Test get method retrieves nested value.
	 */
	public function test_get_nested_value() {
		$max_attempts = NexifyMy_Security_Settings::get( 'rate_limiter', 'max_attempts', 0 );
		$this->assertEquals( 5, $max_attempts );
	}

	/**
	 * Test get method returns default for missing key.
	 */
	public function test_get_returns_default_for_missing() {
		$value = NexifyMy_Security_Settings::get( 'nonexistent', 'key', 'default_value' );
		$this->assertEquals( 'default_value', $value );
	}

	/**
	 * Test set method updates value.
	 */
	public function test_set_updates_value() {
		NexifyMy_Security_Settings::set( 'rate_limiter', 'max_attempts', 20 );
		$max_attempts = NexifyMy_Security_Settings::get( 'rate_limiter', 'max_attempts', 0 );
		$this->assertEquals( 20, $max_attempts );
	}

	/**
	 * Test update merges settings correctly.
	 */
	public function test_update_merges_settings() {
		NexifyMy_Security_Settings::update( array(
			'modules' => array(
				'waf_enabled' => false,
			),
		) );

		$settings = NexifyMy_Security_Settings::get_all();
		$this->assertFalse( $settings['modules']['waf_enabled'] );
		// Other values should remain.
		$this->assertTrue( $settings['modules']['scanner_enabled'] );
	}

	/**
	 * Test reset restores defaults.
	 */
	public function test_reset_restores_defaults() {
		// Change a value.
		NexifyMy_Security_Settings::set( 'rate_limiter', 'max_attempts', 999 );
		
		// Reset.
		NexifyMy_Security_Settings::reset();
		
		// Check it's back to default.
		$max_attempts = NexifyMy_Security_Settings::get( 'rate_limiter', 'max_attempts', 0 );
		$this->assertEquals( 5, $max_attempts );
	}

	/**
	 * Test sanitization for temp-permissions module toggle and AI zero-trust ranges.
	 */
	public function test_sanitize_settings_clamps_new_module_and_ai_fields() {
		$settings = new NexifyMy_Security_Settings();
		$output   = $settings->sanitize_settings(
			array(
				'modules'      => array(
					'temp_permissions_enabled' => '',
					'predictive_hunting_enabled' => 0,
				),
				'ai_detection' => array(
					'zero_trust_reauth_interval'      => 20,
					'zero_trust_risk_spike_threshold' => 500,
				),
			)
		);

		$this->assertFalse( $output['modules']['temp_permissions_enabled'] );
		$this->assertFalse( $output['modules']['predictive_hunting_enabled'] );
		$this->assertEquals( 60, $output['ai_detection']['zero_trust_reauth_interval'] );
		$this->assertEquals( 100, $output['ai_detection']['zero_trust_risk_spike_threshold'] );
	}
}
