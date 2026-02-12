<?php
/**
 * Tests for Deception module helpers and non-exit code paths.
 *
 * @package NexifyMy_Security
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';
require_once dirname( __DIR__ ) . '/modules/deception.php';

class Test_Deception_Files extends \PHPUnit\Framework\TestCase {

	/**
	 * Set up test state.
	 */
	public function setUp(): void {
		parent::setUp();

		NexifyMy_Security_Deception::_reset();
		delete_option( 'nexifymy_honeypot_beacon_token' );
		delete_option( 'nexifymy_deception_beacon_token' );

		$GLOBALS['nexifymy_test_logger_calls']   = array();
		$GLOBALS['nexifymy_test_firewall_blocks'] = array();
		$GLOBALS['nexifymy_test_transients']      = array();
		$GLOBALS['nexifymy_testing_user_id']      = 0;

		update_option(
			'nexifymy_security_settings',
			array(
				'deception_enabled'           => true,
				'deception_create_fake_files' => false,
			)
		);

		$_POST   = array();
		$_GET    = array();
		$_SERVER = array();
	}

	/**
	 * Clean up test state.
	 */
	public function tearDown(): void {
		NexifyMy_Security_Deception::_reset();
		$_POST   = array();
		$_GET    = array();
		$_SERVER = array();
		parent::tearDown();
	}

	/**
	 * Beacon token is created on init.
	 */
	public function test_beacon_token_creation() {
		$method = new \ReflectionMethod( 'NexifyMy_Security_Deception', 'get_or_create_beacon_token' );
		$method->setAccessible( true );
		$token = $method->invoke( null );

		$stored = get_option( 'nexifymy_honeypot_beacon_token' );

		$this->assertNotEmpty( $token, 'Beacon token should be created' );
		$this->assertSame( 32, strlen( $token ), 'Beacon token should be 32 characters' );
		$this->assertSame( $token, $stored, 'Stored token should match generated token' );
	}

	/**
	 * .env generator output contains expected markers.
	 */
	public function test_generate_fake_env_content() {
		$method = new \ReflectionMethod( 'NexifyMy_Security_Deception', 'generate_fake_env_content' );
		$method->setAccessible( true );

		$content = $method->invoke( null, 'unit-test-token' );

		$this->assertStringContainsString( 'DB_HOST=localhost', $content );
		$this->assertStringContainsString( 'AWS_ACCESS_KEY_ID=AKIA', $content );
		$this->assertStringContainsString( 'TRACKING_TOKEN=unit-test-token', $content );
	}

	/**
	 * Config backup generator includes beacon callout.
	 */
	public function test_generate_fake_config_backup() {
		$method = new \ReflectionMethod( 'NexifyMy_Security_Deception', 'generate_fake_config_backup' );
		$method->setAccessible( true );

		$content = $method->invoke( null, 'unit-test-token' );

		$this->assertStringContainsString( "define( 'DB_NAME'", $content );
		$this->assertStringContainsString( "define( 'NEXIFYMY_BEACON'", $content );
		$this->assertStringContainsString( 'nexifymy_beacon=unit-test-token', $content );
	}

	/**
	 * SQL honeypot generator produces expected schema markers.
	 */
	public function test_generate_fake_database_backup() {
		$method = new \ReflectionMethod( 'NexifyMy_Security_Deception', 'generate_fake_database_backup' );
		$method->setAccessible( true );

		$content = $method->invoke( null, 'unit-test-token' );

		$this->assertStringContainsString( '-- WordPress Database Backup', $content );
		$this->assertStringContainsString( 'CREATE TABLE IF NOT EXISTS `wp_users_backup`', $content );
		$this->assertStringContainsString( 'INSERT INTO `wp_users_backup`', $content );
	}

	/**
	 * Tracking phpinfo generator embeds beacon URL.
	 */
	public function test_generate_tracking_phpinfo() {
		$method = new \ReflectionMethod( 'NexifyMy_Security_Deception', 'generate_tracking_phpinfo' );
		$method->setAccessible( true );

		$content = $method->invoke( null, 'unit-test-token' );

		$this->assertStringContainsString( '<?php', $content );
		$this->assertStringContainsString( 'nexifymy_beacon=unit-test-token', $content );
		$this->assertStringContainsString( 'phpinfo();', $content );
	}

	/**
	 * Honeypot login field triggers block + WP_Error when populated.
	 */
	public function test_validate_login_honeypot_triggers_block() {
		$_POST['user_confirm_code'] = 'bot-filled-value';
		$_POST['log']               = 'scannerbot';
		$_SERVER['REMOTE_ADDR']     = '203.0.113.10';
		$_SERVER['HTTP_USER_AGENT'] = 'ScannerBot/1.0';

		$user   = (object) array( 'ID' => 1 );
		$result = NexifyMy_Security_Deception::validate_login_honeypot( $user, 'password' );

		$this->assertInstanceOf( 'WP_Error', $result );
		$this->assertSame( 'nexifymy_honeypot', $result->code );

		$this->assertNotEmpty( $GLOBALS['nexifymy_test_logger_calls'] );
		$this->assertNotEmpty( $GLOBALS['nexifymy_test_firewall_blocks'] );
		$this->assertSame( '203.0.113.10', $GLOBALS['nexifymy_test_firewall_blocks'][0]['ip'] );
	}

	/**
	 * Honeypot login field allows authentication when empty.
	 */
	public function test_validate_login_honeypot_allows_empty_field() {
		$user   = (object) array( 'ID' => 1 );
		$result = NexifyMy_Security_Deception::validate_login_honeypot( $user, 'password' );

		$this->assertSame( $user, $result );
		$this->assertEmpty( $GLOBALS['nexifymy_test_firewall_blocks'] );
	}

	/**
	 * Settings helper maps module-level overrides.
	 */
	public function test_get_settings_reads_module_overrides() {
		update_option(
			'nexifymy_security_settings',
			array(
				'deception_enabled'   => false,
				'modules'             => array(
					'deception_enabled' => true,
				),
				'deception_enum_trap' => false,
			)
		);

		NexifyMy_Security_Deception::flush_settings_cache();
		$settings = NexifyMy_Security_Deception::get_settings();

		$this->assertTrue( $settings['deception_enabled'] );
		$this->assertFalse( $settings['deception_enum_trap'] );
	}
}
