<?php
/**
 * Tests for NexifyMy_Security_Database class.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';
require_once dirname( __DIR__ ) . '/modules/database-security.php';

class Test_Database_Security extends \PHPUnit\Framework\TestCase {

	/**
	 * Database security instance.
	 */
	private $database;

	/**
	 * Set up before each test.
	 */
	protected function setUp(): void {
		global $nexifymy_test_options;
		$nexifymy_test_options = array();
		$this->database = new NexifyMy_Security_Database();
	}

	/**
	 * Test backup path contains correct directory name.
	 */
	public function test_backup_path_contains_directory() {
		$path = $this->database->get_backup_path();
		$this->assertStringContainsString( 'nexifymy-backups', $path );
	}

	/**
	 * Test get_settings returns defaults.
	 */
	public function test_get_settings_returns_defaults() {
		$settings = $this->database->get_settings();

		$this->assertIsArray( $settings );
		$this->assertArrayHasKey( 'backup_enabled', $settings );
		$this->assertArrayHasKey( 'backup_schedule', $settings );
		$this->assertArrayHasKey( 'max_backups', $settings );
		$this->assertTrue( $settings['backup_enabled'] );
		$this->assertEquals( 'weekly', $settings['backup_schedule'] );
		$this->assertEquals( 5, $settings['max_backups'] );
	}

	/**
	 * Test backup log is empty by default.
	 */
	public function test_backups_list_empty_by_default() {
		$backups = $this->database->get_backups();
		$this->assertIsArray( $backups );
		$this->assertEmpty( $backups );
	}
}
