<?php
/**
 * Tests for NexifyMy_Security_Temp_Permissions class.
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';
require_once dirname( __DIR__ ) . '/modules/time-bound-permissions.php';

class Test_Time_Bound_Permissions extends \PHPUnit\Framework\TestCase {

	/**
	 * Module instance.
	 *
	 * @var NexifyMy_Security_Temp_Permissions
	 */
	private $perms;

	/**
	 * Set up before each test.
	 */
	protected function setUp(): void {
		global $nexifymy_test_options, $wpdb;

		$nexifymy_test_options                 = array();
		$GLOBALS['nexifymy_test_wp_update_user'] = array();
		$GLOBALS['nexifymy_test_mail']           = array();
		$GLOBALS['nexifymy_testing_user_id']     = 1;

		$wpdb->insert_calls    = array();
		$wpdb->update_calls    = array();
		$wpdb->queries         = array();
		$wpdb->get_var_map     = array();
		$wpdb->get_results_map = array();
		$wpdb->get_row_map     = array();
		$wpdb->insert_id       = 1;

		$GLOBALS['nexifymy_test_userdata'] = array(
			1  => (object) array(
				'ID'         => 1,
				'user_login' => 'approver',
				'user_email' => 'approver@example.com',
				'roles'      => array( 'administrator' ),
			),
			42 => (object) array(
				'ID'         => 42,
				'user_login' => 'requester',
				'user_email' => 'requester@example.com',
				'roles'      => array( 'subscriber' ),
			),
		);

		$this->perms = new NexifyMy_Security_Temp_Permissions();
	}

	public function test_grant_inserts_virtual_grant_without_role_mutation() {
		global $wpdb;

		$result = $this->perms->grant_temporary_permission( 42, 'administrator', 60, 'Emergency fix', 1 );

		$this->assertNotFalse( $result );
		$this->assertNotEmpty( $wpdb->insert_calls, 'Grant should insert DB row.' );
		$this->assertEmpty(
			$GLOBALS['nexifymy_test_wp_update_user'],
			'Grant must not mutate user role in virtual-capability mode.'
		);

		$insert = end( $wpdb->insert_calls );
		$this->assertEquals( 42, $insert['data']['user_id'] );
		$this->assertEquals( 'subscriber', $insert['data']['original_role'] );
		$this->assertEquals( 'administrator', $insert['data']['elevated_role'] );
		$this->assertEquals( 1, $insert['data']['granted_by'] );
	}

	public function test_duplicate_pending_or_active_request_is_rejected() {
		global $wpdb;

		$first = $this->perms->grant_temporary_permission( 42, 'editor', 60, 'Need content access', 0 );
		$this->assertNotFalse( $first );

		$wpdb->get_var_map['granted_by = 0'] = 55;

		$second = $this->perms->grant_temporary_permission( 42, 'editor', 60, 'Second request', 0 );
		$this->assertFalse( $second, 'Duplicate request for same role should be blocked.' );
	}

	public function test_invalid_elevated_role_is_rejected() {
		$result = $this->perms->grant_temporary_permission( 42, 'subscriber', 60, 'Invalid role test', 1 );
		$this->assertFalse( $result );
	}

	public function test_pending_request_does_not_grant_caps() {
		$allcaps = array( 'read' => true );
		$user    = (object) array( 'ID' => 42 );

		$GLOBALS['wpdb']->get_row_map = array(
			'granted_by = 0' => (object) array(
				'elevated_role' => 'administrator',
			),
		);

		$filtered = $this->perms->filter_user_has_cap( $allcaps, array(), array(), $user );
		$this->assertArrayNotHasKey( 'manage_options', $filtered );
	}

	public function test_active_approved_request_grants_caps() {
		$allcaps = array( 'read' => true );
		$user    = (object) array( 'ID' => 42 );

		$GLOBALS['wpdb']->get_row_map = array(
			'granted_by > 0' => (object) array(
				'elevated_role' => 'administrator',
			),
		);

		$filtered = $this->perms->filter_user_has_cap( $allcaps, array(), array(), $user );
		$this->assertArrayHasKey( 'manage_options', $filtered );
		$this->assertTrue( $filtered['manage_options'] );
	}

	public function test_revoke_expired_marks_revoked_without_restoring_role() {
		global $wpdb;

		$expired = (object) array(
			'id'            => 7,
			'user_id'       => 42,
			'original_role' => 'subscriber',
			'elevated_role' => 'administrator',
			'granted_at'    => '2025-01-01 00:00:00',
			'expires_at'    => '2025-01-01 00:05:00',
			'granted_by'    => 1,
			'reason'        => 'test',
			'revoked'       => 0,
		);

		$wpdb->get_results_map['revoked = 0 AND expires_at <='] = array( $expired );

		$this->perms->revoke_expired_permissions();

		$this->assertNotEmpty( $wpdb->update_calls );
		$update = end( $wpdb->update_calls );
		$this->assertEquals( 1, $update['data']['revoked'] );
		$this->assertEquals( array( 'id' => 7 ), $update['where'] );
		$this->assertEmpty(
			$GLOBALS['nexifymy_test_wp_update_user'],
			'Expired grants must not trigger role restoration in virtual mode.'
		);
	}

	public function test_init_runs_legacy_migration_once() {
		global $wpdb;

		$wpdb->get_results_map['granted_by > 0'] = array(
			(object) array(
				'user_id'       => 42,
				'original_role' => 'subscriber',
				'elevated_role' => 'administrator',
				'expires_at'    => '2999-01-01 00:00:00',
				'granted_by'    => 1,
				'revoked'       => 0,
			),
		);

		$GLOBALS['nexifymy_test_userdata'][42]->roles = array( 'administrator' );

		$this->perms->init();
		$first_run_updates = count( $GLOBALS['nexifymy_test_wp_update_user'] );
		$this->assertSame( 1, $first_run_updates );
		$this->assertArrayHasKey( 'nexifymy_temp_permissions_legacy_migrated', $GLOBALS['nexifymy_test_options'] );

		$this->perms->init();
		$this->assertSame(
			$first_run_updates,
			count( $GLOBALS['nexifymy_test_wp_update_user'] ),
			'Migration should be idempotent after first successful run.'
		);
	}
}
