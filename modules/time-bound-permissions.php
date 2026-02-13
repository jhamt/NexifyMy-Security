<?php
/**
 * Time-Bound Permissions Module.
 *
 * Provides just-in-time (JIT) privilege elevation using virtual capabilities.
 * This module never mutates stored user roles for active grants.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Temp_Permissions {

	/**
	 * Database table name (without prefix).
	 */
	const TABLE_SUFFIX = 'nexifymy_temp_permissions';

	/**
	 * Cron hook name.
	 */
	const CRON_HOOK = 'nexifymy_revoke_expired_permissions';

	/**
	 * WordPress capability required to approve/revoke requests.
	 */
	const APPROVER_CAPABILITY = 'manage_options';

	/**
	 * Option used to flag one-time legacy migration.
	 */
	const MIGRATION_OPTION = 'nexifymy_temp_permissions_legacy_migrated';

	/**
	 * Option key used to track schema version.
	 */
	const SCHEMA_OPTION = 'nexifymy_temp_permissions_schema_version';

	/**
	 * Current schema version.
	 */
	const SCHEMA_VERSION = '1.0.0';

	/**
	 * Minimum duration for a JIT grant (minutes).
	 */
	const MIN_DURATION_MINUTES = 5;

	/**
	 * Default duration for a JIT grant (minutes).
	 */
	const DEFAULT_DURATION_MINUTES = 60;

	/**
	 * Maximum duration for a JIT grant (minutes).
	 */
	const MAX_DURATION_MINUTES = 1440;

	/**
	 * Allowed elevated roles for JIT access.
	 *
	 * @var string[]
	 */
	private static $allowed_elevated_roles = array( 'administrator', 'editor' );

	/**
	 * Get the full table name.
	 *
	 * @return string
	 */
	private function get_table_name() {
		global $wpdb;
		return $wpdb->prefix . self::TABLE_SUFFIX;
	}

	/**
	 * Get current UTC time formatted for database storage.
	 *
	 * @return string
	 */
	private function get_utc_now() {
		return gmdate( 'Y-m-d H:i:s' );
	}

	/**
	 * Clamp a requested duration to configured bounds.
	 *
	 * @param int $duration_minutes Requested duration in minutes.
	 * @return int
	 */
	private function clamp_duration_minutes( $duration_minutes ) {
		$duration = absint( $duration_minutes );
		if ( $duration < self::MIN_DURATION_MINUTES ) {
			$duration = self::DEFAULT_DURATION_MINUTES;
		}

		return min( self::MAX_DURATION_MINUTES, $duration );
	}

	/**
	 * Normalize and validate a role for elevation.
	 *
	 * @param string $role Requested role.
	 * @return string
	 */
	private function sanitize_elevated_role( $role ) {
		$normalized = sanitize_key( (string) $role );
		if ( in_array( $normalized, self::$allowed_elevated_roles, true ) ) {
			return $normalized;
		}

		return '';
	}

	/**
	 * Get primary role for a user.
	 *
	 * @param WP_User $user User object.
	 * @return string
	 */
	private function get_primary_role( $user ) {
		if ( isset( $user->roles ) && is_array( $user->roles ) && ! empty( $user->roles ) ) {
			return (string) reset( $user->roles );
		}

		return 'subscriber';
	}

	/**
	 * Check whether the user already has a pending or active grant for a role.
	 *
	 * @param int    $user_id User ID.
	 * @param string $role Elevated role.
	 * @return bool
	 */
	private function has_pending_or_active_grant( $user_id, $role ) {
		global $wpdb;

		$table = $this->get_table_name();
		$now   = $this->get_utc_now();

		$existing = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM {$table}
				WHERE user_id = %d
					AND elevated_role = %s
					AND revoked = 0
					AND ( granted_by = 0 OR ( granted_by > 0 AND expires_at > %s ) )
				LIMIT 1",
				absint( $user_id ),
				$role,
				$now
			)
		);

		return ! empty( $existing );
	}

	/**
	 * Create the database table.
	 *
	 * @return void
	 */
	public function create_table() {
		global $wpdb;

		$table_name      = $this->get_table_name();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id BIGINT(20) UNSIGNED NOT NULL,
			original_role VARCHAR(50) NOT NULL,
			elevated_role VARCHAR(50) NOT NULL,
			granted_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			granted_by BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
			reason TEXT NOT NULL,
			revoked TINYINT(1) NOT NULL DEFAULT 0,
			PRIMARY KEY (id),
			KEY user_id (user_id),
			KEY expires_at (expires_at),
			KEY revoked (revoked)
		) {$charset_collate};";

		if ( ! function_exists( 'dbDelta' ) ) {
			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		}

		if ( function_exists( 'dbDelta' ) ) {
			dbDelta( $sql );
		} else {
			$wpdb->query( $sql );
		}

		update_option( self::SCHEMA_OPTION, self::SCHEMA_VERSION, false );
	}

	/**
	 * Ensure schema is created only when needed.
	 *
	 * @return void
	 */
	private function maybe_ensure_schema() {
		$installed_version = get_option( self::SCHEMA_OPTION, '' );
		if ( self::SCHEMA_VERSION === (string) $installed_version ) {
			return;
		}

		$this->create_table();
	}

	/**
	 * Initialize the module.
	 *
	 * @return void
	 */
	public function init() {
		// Keep schema and legacy migration idempotent on normal runtime loads.
		$this->maybe_ensure_schema();
		$this->maybe_migrate_legacy_role_assignments();

		// Capability filter dynamically grants elevated capabilities for approved active grants.
		add_filter( 'user_has_cap', array( $this, 'filter_user_has_cap' ), 10, 4 );

		// Cron handler for status revocation and notifications.
		add_action( self::CRON_HOOK, array( $this, 'revoke_expired_permissions' ) );

		// Schedule cron if not already scheduled.
		if ( function_exists( 'wp_next_scheduled' ) && ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'every_five_minutes', self::CRON_HOOK );
		}

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_request_temp_access', array( $this, 'ajax_request_access' ) );
		add_action( 'wp_ajax_nexifymy_approve_temp_access', array( $this, 'ajax_approve_access' ) );
		add_action( 'wp_ajax_nexifymy_revoke_temp_access', array( $this, 'ajax_revoke_access' ) );
		add_action( 'wp_ajax_nexifymy_get_temp_permissions', array( $this, 'ajax_get_temp_permissions' ) );
		add_action( 'wp_ajax_nexifymy_grant_temp_access', array( $this, 'ajax_grant_access' ) );
	}

	/**
	 * Run one-time migration for legacy role-mutated grants.
	 *
	 * @return void
	 */
	private function maybe_migrate_legacy_role_assignments() {
		$migrated = get_option( self::MIGRATION_OPTION, false );
		if ( ! empty( $migrated ) ) {
			return;
		}

		global $wpdb;
		$table = $this->get_table_name();
		$now   = $this->get_utc_now();

		$active_grants = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table}
				WHERE granted_by > 0
					AND revoked = 0
					AND expires_at > %s",
				$now
			)
		);

		$restored_users = 0;
		if ( is_array( $active_grants ) ) {
			foreach ( $active_grants as $grant ) {
				$user = get_userdata( (int) $grant->user_id );
				if ( ! $user ) {
					continue;
				}

				$current_role = $this->get_primary_role( $user );
				$target_role  = sanitize_key( (string) $grant->elevated_role );
				$source_role  = sanitize_key( (string) $grant->original_role );

				if ( empty( $source_role ) || $source_role === $target_role ) {
					continue;
				}

				// Reconcile only users likely still role-mutated from legacy behavior.
				if ( $current_role === $target_role && function_exists( 'wp_update_user' ) ) {
					wp_update_user(
						array(
							'ID'   => (int) $grant->user_id,
							'role' => $source_role,
						)
					);
					++$restored_users;
				}
			}
		}

		update_option(
			self::MIGRATION_OPTION,
			array(
				'migrated_at'    => $this->get_utc_now(),
				'restored_users' => $restored_users,
			),
			false
		);

		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'temp_permissions_migration',
				sprintf( 'Temporary permission legacy migration completed. Restored users: %d', $restored_users ),
				'info'
			);
		}
	}

	/**
	 * Grant temporary elevated permission to a user.
	 *
	 * @param int    $user_id          User ID to elevate.
	 * @param string $role             Target elevated role.
	 * @param int    $duration_minutes Duration in minutes.
	 * @param string $reason           Reason for elevation.
	 * @param int    $granted_by       User ID of approver (0 = pending request).
	 * @return bool|int Insert ID on success, false on failure.
	 */
	public function grant_temporary_permission( $user_id, $role, $duration_minutes, $reason, $granted_by = 0 ) {
		global $wpdb;

		$user = get_userdata( absint( $user_id ) );
		if ( ! $user ) {
			return false;
		}

		$elevated_role = $this->sanitize_elevated_role( $role );
		if ( '' === $elevated_role ) {
			return false;
		}

		$duration      = $this->clamp_duration_minutes( $duration_minutes );
		$original_role = $this->get_primary_role( $user );

		// No-op requests are blocked.
		if ( $original_role === $elevated_role ) {
			return false;
		}

		if ( $this->has_pending_or_active_grant( $user_id, $elevated_role ) ) {
			return false;
		}

		$now        = $this->get_utc_now();
		$expires_at = gmdate( 'Y-m-d H:i:s', time() + ( $duration * 60 ) );
		$table      = $this->get_table_name();

		$result = $wpdb->insert(
			$table,
			array(
				'user_id'       => absint( $user_id ),
				'original_role' => sanitize_text_field( $original_role ),
				'elevated_role' => $elevated_role,
				'granted_at'    => $now,
				'expires_at'    => $expires_at,
				'granted_by'    => absint( $granted_by ),
				'reason'        => sanitize_text_field( $reason ),
				'revoked'       => 0,
			),
			array( '%d', '%s', '%s', '%s', '%s', '%d', '%s', '%d' )
		);

		if ( ! $result ) {
			return false;
		}

		$insert_id = isset( $wpdb->insert_id ) ? (int) $wpdb->insert_id : true;

		if ( absint( $granted_by ) > 0 ) {
			$this->notify_permission_granted( $user_id, $elevated_role, $duration, $reason, $granted_by );
		}

		return $insert_id;
	}

	/**
	 * Revoke all expired temporary permissions (cron callback).
	 *
	 * @return void
	 */
	public function revoke_expired_permissions() {
		global $wpdb;

		$table = $this->get_table_name();
		$now   = $this->get_utc_now();

		$expired_grants = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE revoked = 0 AND expires_at <= %s",
				$now
			)
		);

		if ( empty( $expired_grants ) || ! is_array( $expired_grants ) ) {
			return;
		}

		foreach ( $expired_grants as $grant ) {
			$this->mark_grant_revoked( $grant, 'expired' );
		}
	}

	/**
	 * Check and enforce permissions for a specific user.
	 *
	 * @param int $user_id User ID.
	 * @return bool True if a revocation occurred.
	 */
	public function check_and_enforce_permissions( $user_id ) {
		global $wpdb;

		$table = $this->get_table_name();
		$now   = $this->get_utc_now();

		$expired = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE user_id = %d AND revoked = 0 AND expires_at <= %s",
				absint( $user_id ),
				$now
			)
		);

		if ( empty( $expired ) || ! is_array( $expired ) ) {
			return false;
		}

		foreach ( $expired as $grant ) {
			$this->mark_grant_revoked( $grant, 'expired' );
		}

		return true;
	}

	/**
	 * Mark a single grant as revoked and send notifications when relevant.
	 *
	 * @param object $grant  Grant row from database.
	 * @param string $reason Revocation reason.
	 * @return void
	 */
	private function mark_grant_revoked( $grant, $reason = 'revoked' ) {
		global $wpdb;

		$table = $this->get_table_name();

		$wpdb->update(
			$table,
			array( 'revoked' => 1 ),
			array( 'id' => (int) $grant->id ),
			array( '%d' ),
			array( '%d' )
		);

		// Only approved grants trigger expiry/revocation notifications.
		if ( isset( $grant->granted_by ) && (int) $grant->granted_by > 0 ) {
			$this->notify_permission_expired( $grant, $reason );
		}
	}

	/**
	 * Get active approved grants.
	 *
	 * @return array
	 */
	public function get_active_grants() {
		global $wpdb;

		$table = $this->get_table_name();
		$now   = $this->get_utc_now();

		$results = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table}
				WHERE granted_by > 0
					AND revoked = 0
					AND expires_at > %s
				ORDER BY expires_at ASC",
				$now
			)
		);

		return is_array( $results ) ? $results : array();
	}

	/**
	 * Get all grants for admin table display.
	 *
	 * @param int $limit Max rows.
	 * @return array
	 */
	public function get_all_grants( $limit = 100 ) {
		global $wpdb;

		$table  = $this->get_table_name();
		$limit  = max( 1, absint( $limit ) );
		$result = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} ORDER BY granted_at DESC LIMIT %d",
				$limit
			)
		);

		return is_array( $result ) ? $result : array();
	}

	/**
	 * Get pending requests.
	 *
	 * @return array
	 */
	public function get_pending_requests() {
		global $wpdb;

		$table = $this->get_table_name();
		$now   = $this->get_utc_now();

		$results = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table}
				WHERE granted_by = 0
					AND revoked = 0
					AND expires_at > %s
				ORDER BY granted_at DESC",
				$now
			)
		);

		return is_array( $results ) ? $results : array();
	}

	/**
	 * Filter user capabilities based on active temporary grants.
	 *
	 * @param array   $allcaps All capabilities of the user.
	 * @param array   $caps    Required capabilities.
	 * @param array   $args    Arguments (capability, user_id, ...).
	 * @param WP_User $user    The user object.
	 * @return array Modified capabilities.
	 */
	public function filter_user_has_cap( $allcaps, $caps, $args, $user = null ) {
		$user_id = 0;
		if ( $user && isset( $user->ID ) ) {
			$user_id = (int) $user->ID;
		} elseif ( ! empty( $args[1] ) ) {
			$user_id = (int) $args[1];
		}

		if ( $user_id <= 0 ) {
			return $allcaps;
		}

		global $wpdb;
		$table = $this->get_table_name();
		$now   = $this->get_utc_now();

		$active_grant = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT elevated_role FROM {$table}
				WHERE user_id = %d
					AND granted_by > 0
					AND revoked = 0
					AND expires_at > %s
				ORDER BY expires_at DESC
				LIMIT 1",
				$user_id,
				$now
			)
		);

		if ( empty( $active_grant ) || empty( $active_grant->elevated_role ) ) {
			return $allcaps;
		}

		if ( function_exists( 'get_role' ) ) {
			$effective_role = $this->sanitize_elevated_role( $active_grant->elevated_role );
			if ( '' === $effective_role ) {
				return $allcaps;
			}

			$role_obj = get_role( $effective_role );
			if ( $role_obj && ! empty( $role_obj->capabilities ) ) {
				foreach ( $role_obj->capabilities as $cap => $granted ) {
					if ( $granted ) {
						$allcaps[ $cap ] = true;
					}
				}
			}
		}

		return $allcaps;
	}

	/**
	 * Handle access request from logged-in users.
	 *
	 * @return void
	 */
	public function ajax_request_access() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			wp_send_json_error( __( 'Not logged in', 'nexifymy-security' ) );
		}

		$reason             = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : '';
		$duration           = isset( $_POST['duration'] ) ? absint( $_POST['duration'] ) : self::DEFAULT_DURATION_MINUTES;
		$requested_role_raw = isset( $_POST['requested_role'] ) ? sanitize_key( wp_unslash( $_POST['requested_role'] ) ) : self::$allowed_elevated_roles[0];

		if ( '' === $reason ) {
			wp_send_json_error( __( 'A reason is required', 'nexifymy-security' ) );
		}

		$requested_role = $this->sanitize_elevated_role( $requested_role_raw );
		if ( '' === $requested_role ) {
			wp_send_json_error( __( 'Invalid requested role', 'nexifymy-security' ) );
		}

		$duration       = $this->clamp_duration_minutes( $duration );

		$insert_id = $this->grant_temporary_permission( $user_id, $requested_role, $duration, $reason, 0 );
		if ( ! $insert_id ) {
			wp_send_json_error( __( 'An active or pending request already exists for this role.', 'nexifymy-security' ) );
		}

		$this->notify_access_requested( $user_id, $reason, $duration, $requested_role );

		wp_send_json_success(
			array(
				'message' => __( 'Access request submitted. An administrator will review your request.', 'nexifymy-security' ),
			)
		);
	}

	/**
	 * Approve a pending access request.
	 *
	 * @return void
	 */
	public function ajax_approve_access() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( self::APPROVER_CAPABILITY ) ) {
			wp_send_json_error( __( 'Unauthorized', 'nexifymy-security' ) );
		}

		$request_id = isset( $_POST['request_id'] ) ? absint( $_POST['request_id'] ) : 0;
		if ( $request_id <= 0 ) {
			wp_send_json_error( __( 'Invalid request', 'nexifymy-security' ) );
		}

		$approved_role = isset( $_POST['approved_role'] ) ? sanitize_key( wp_unslash( $_POST['approved_role'] ) ) : '';
		$duration      = isset( $_POST['duration'] ) ? absint( $_POST['duration'] ) : 0;

		global $wpdb;
		$table = $this->get_table_name();

		$request = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table}
				WHERE id = %d
					AND revoked = 0
					AND granted_by = 0
				LIMIT 1",
				$request_id
			)
		);

		if ( ! $request ) {
			wp_send_json_error( __( 'Pending request not found', 'nexifymy-security' ) );
		}

		$approver_id = get_current_user_id();
		$update_data = array(
			'granted_by' => absint( $approver_id ),
		);
		$formats     = array( '%d' );

		$effective_role = $this->sanitize_elevated_role( $request->elevated_role );
		if ( '' === $effective_role ) {
			wp_send_json_error( __( 'Request role is invalid', 'nexifymy-security' ) );
		}

		if ( '' !== $approved_role ) {
			$effective_role           = $this->sanitize_elevated_role( $approved_role );
			if ( '' === $effective_role ) {
				wp_send_json_error( __( 'Invalid approved role', 'nexifymy-security' ) );
			}

			$update_data['elevated_role'] = $effective_role;
			$formats[]               = '%s';
		}

		if ( $duration > 0 ) {
			$duration                  = $this->clamp_duration_minutes( $duration );
			$update_data['expires_at'] = gmdate( 'Y-m-d H:i:s', time() + ( $duration * 60 ) );
			$formats[]                = '%s';
		} elseif ( strtotime( $request->expires_at ) <= time() ) {
			$duration                  = self::DEFAULT_DURATION_MINUTES;
			$update_data['expires_at'] = gmdate( 'Y-m-d H:i:s', time() + ( $duration * 60 ) );
			$formats[]                = '%s';
		}

		$wpdb->update(
			$table,
			$update_data,
			array( 'id' => $request_id ),
			$formats,
			array( '%d' )
		);

		$expires_at  = isset( $update_data['expires_at'] ) ? $update_data['expires_at'] : $request->expires_at;
		$duration_m  = max( 1, (int) floor( ( strtotime( $expires_at ) - time() ) / 60 ) );

		$this->notify_permission_granted(
			(int) $request->user_id,
			$effective_role,
			$duration_m,
			(string) $request->reason,
			$approver_id
		);

		wp_send_json_success(
			array(
				'message' => __( 'Access approved successfully', 'nexifymy-security' ),
			)
		);
	}

	/**
	 * Grant temporary access directly to a specific user (admin only).
	 *
	 * @return void
	 */
	public function ajax_grant_access() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( self::APPROVER_CAPABILITY ) ) {
			wp_send_json_error( __( 'Unauthorized', 'nexifymy-security' ) );
		}

		$target_raw         = isset( $_POST['target_user'] ) ? sanitize_text_field( wp_unslash( $_POST['target_user'] ) ) : '';
		$reason             = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : '';
		$duration           = isset( $_POST['duration'] ) ? absint( $_POST['duration'] ) : self::DEFAULT_DURATION_MINUTES;
		$requested_role_raw = isset( $_POST['requested_role'] ) ? sanitize_key( wp_unslash( $_POST['requested_role'] ) ) : self::$allowed_elevated_roles[0];

		$target = trim( $target_raw );
		if ( '' === $target ) {
			wp_send_json_error( __( 'Target user (username or email) is required.', 'nexifymy-security' ) );
		}

		if ( '' === $reason ) {
			wp_send_json_error( __( 'A reason is required.', 'nexifymy-security' ) );
		}

		$requested_role = $this->sanitize_elevated_role( $requested_role_raw );
		if ( '' === $requested_role ) {
			wp_send_json_error( __( 'Invalid requested role.', 'nexifymy-security' ) );
		}

		$user = false;
		if ( is_email( $target ) ) {
			$user = get_user_by( 'email', $target );
		} elseif ( ctype_digit( $target ) ) {
			$user = get_user_by( 'id', absint( $target ) );
		} else {
			$user = get_user_by( 'login', $target );
			if ( ! $user ) {
				$user = get_user_by( 'slug', sanitize_title( $target ) );
			}
		}

		if ( ! $user || empty( $user->ID ) ) {
			wp_send_json_error( __( 'Target user not found. Use an existing username or email.', 'nexifymy-security' ) );
		}

		$user_id       = (int) $user->ID;
		$duration      = $this->clamp_duration_minutes( $duration );
		$current_role  = $this->get_primary_role( $user );
		$approver_id   = get_current_user_id();

		if ( $current_role === $requested_role ) {
			wp_send_json_error( __( 'User already has this role. Temporary elevation is not needed.', 'nexifymy-security' ) );
		}

		if ( $this->has_pending_or_active_grant( $user_id, $requested_role ) ) {
			wp_send_json_error( __( 'An active or pending grant already exists for this user and role.', 'nexifymy-security' ) );
		}

		$insert_id = $this->grant_temporary_permission( $user_id, $requested_role, $duration, $reason, $approver_id );
		if ( ! $insert_id ) {
			wp_send_json_error( __( 'Unable to grant temporary access.', 'nexifymy-security' ) );
		}

		wp_send_json_success(
			array(
				'message' => sprintf(
					/* translators: 1: username, 2: role, 3: duration in minutes */
					__( 'Temporary %2$s access granted to %1$s for %3$d minutes.', 'nexifymy-security' ),
					(string) $user->user_login,
					$requested_role,
					$duration
				),
			)
		);
	}

	/**
	 * Manually revoke a temporary permission.
	 *
	 * @return void
	 */
	public function ajax_revoke_access() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( self::APPROVER_CAPABILITY ) ) {
			wp_send_json_error( __( 'Unauthorized', 'nexifymy-security' ) );
		}

		$grant_id = isset( $_POST['grant_id'] ) ? absint( $_POST['grant_id'] ) : 0;
		if ( $grant_id <= 0 ) {
			wp_send_json_error( __( 'Invalid grant', 'nexifymy-security' ) );
		}

		global $wpdb;
		$table = $this->get_table_name();

		$grant = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table}
				WHERE id = %d
					AND revoked = 0
				LIMIT 1",
				$grant_id
			)
		);

		if ( ! $grant ) {
			wp_send_json_error( __( 'Grant not found or already revoked', 'nexifymy-security' ) );
		}

		$this->mark_grant_revoked( $grant, 'revoked' );

		wp_send_json_success(
			array(
				'message' => __( 'Permission revoked successfully', 'nexifymy-security' ),
			)
		);
	}

	/**
	 * Get all temporary permissions for admin display.
	 *
	 * @return void
	 */
	public function ajax_get_temp_permissions() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( self::APPROVER_CAPABILITY ) ) {
			wp_send_json_error( __( 'Unauthorized', 'nexifymy-security' ) );
		}

		$grants = $this->get_all_grants();
		$now    = time();
		$data   = array();

		foreach ( $grants as $grant ) {
			$user     = get_userdata( (int) $grant->user_id );
			$approver = (int) $grant->granted_by > 0 ? get_userdata( (int) $grant->granted_by ) : null;

			$status = 'active';
			if ( (int) $grant->revoked === 1 ) {
				$status = 'revoked';
			} elseif ( strtotime( $grant->expires_at ) <= $now ) {
				$status = 'expired';
			} elseif ( (int) $grant->granted_by === 0 ) {
				$status = 'pending';
			}

			$data[] = array(
				'id'            => (int) $grant->id,
				'user_id'       => (int) $grant->user_id,
				'user_login'    => $user ? $user->user_login : 'Unknown',
				'user_email'    => $user ? $user->user_email : '',
				'original_role' => (string) $grant->original_role,
				'elevated_role' => (string) $grant->elevated_role,
				'granted_at'    => (string) $grant->granted_at,
				'expires_at'    => (string) $grant->expires_at,
				'granted_by'    => $approver ? $approver->user_login : ( (int) $grant->granted_by > 0 ? 'Unknown' : 'Pending' ),
				'reason'        => (string) $grant->reason,
				'status'        => $status,
				'can_approve'   => 'pending' === $status,
				'can_revoke'    => in_array( $status, array( 'pending', 'active' ), true ),
			);
		}

		wp_send_json_success( array( 'grants' => $data ) );
	}

	/**
	 * Notify admins that access was requested.
	 *
	 * @param int    $user_id  Requesting user.
	 * @param string $reason   Reason for request.
	 * @param int    $duration Requested duration in minutes.
	 * @param string $role     Requested role.
	 * @return void
	 */
	private function notify_access_requested( $user_id, $reason, $duration, $role ) {
		$user      = get_userdata( $user_id );
		$user_name = $user ? $user->user_login : "User #{$user_id}";
		$subject   = sprintf( '[%s] Temporary %s Access Requested', get_bloginfo( 'name' ), ucfirst( $role ) );
		$message   = sprintf(
			"User: %s\nRequested Role: %s\nReason: %s\nRequested Duration: %d minutes\n\nReview this request in the Temporary Access panel:\n%s",
			$user_name,
			$role,
			$reason,
			$duration,
			admin_url( 'admin.php?page=nexifymy-security-temp-access' )
		);

		$admin_email = get_option( 'admin_email' );
		if ( $admin_email ) {
			wp_mail( $admin_email, $subject, $message );
		}

		$this->dispatch_slack_notification(
			array(
				'title'       => '[ACCESS REQUEST] Temporary Privilege Request',
				'description' => sprintf( '%s requested %s access for %d minutes. Reason: %s', $user_name, $role, $duration, $reason ),
				'severity'    => 'warning',
			)
		);
	}

	/**
	 * Notify user and admin that permission was granted.
	 *
	 * @param int    $user_id          Elevated user.
	 * @param string $role             Elevated role.
	 * @param int    $duration_minutes Duration.
	 * @param string $reason           Reason.
	 * @param int    $granted_by       Approver ID.
	 * @return void
	 */
	private function notify_permission_granted( $user_id, $role, $duration_minutes, $reason, $granted_by ) {
		$user       = get_userdata( $user_id );
		$user_email = $user ? $user->user_email : '';
		$user_name  = $user ? $user->user_login : "User #{$user_id}";

		if ( $user_email ) {
			$subject = sprintf( '[%s] Temporary %s Access Granted', get_bloginfo( 'name' ), ucfirst( $role ) );
			$message = sprintf(
				"Hello %s,\n\nYou have been granted temporary %s capabilities for %d minutes.\nReason: %s\n\nThis access will automatically expire.",
				$user_name,
				$role,
				$duration_minutes,
				$reason
			);
			wp_mail( $user_email, $subject, $message );
		}

		$admin_email = get_option( 'admin_email' );
		if ( $admin_email && $admin_email !== $user_email ) {
			$approver      = $granted_by ? get_userdata( $granted_by ) : null;
			$approver_name = $approver ? $approver->user_login : 'System';
			$subject       = sprintf( '[%s] Temporary Access Granted to %s', get_bloginfo( 'name' ), $user_name );
			$message       = sprintf(
				"Temporary %s access granted to %s for %d minutes.\nApproved by: %s\nReason: %s",
				$role,
				$user_name,
				$duration_minutes,
				$approver_name,
				$reason
			);
			wp_mail( $admin_email, $subject, $message );
		}

		$this->dispatch_slack_notification(
			array(
				'title'       => '[ACCESS GRANTED] Temporary Permission',
				'description' => sprintf( '%s granted %s access for %d minutes. Reason: %s', $user_name, $role, $duration_minutes, $reason ),
				'severity'    => 'info',
			)
		);
	}

	/**
	 * Notify user that a permission has expired or been revoked.
	 *
	 * @param object $grant  The grant row.
	 * @param string $reason Revocation reason.
	 * @return void
	 */
	private function notify_permission_expired( $grant, $reason = 'expired' ) {
		$user       = get_userdata( (int) $grant->user_id );
		$user_email = $user ? $user->user_email : '';
		$user_name  = $user ? $user->user_login : "User #{$grant->user_id}";

		if ( $user_email ) {
			$subject = sprintf( '[%s] Temporary Access %s', get_bloginfo( 'name' ), 'expired' === $reason ? 'Expired' : 'Revoked' );
			$message = sprintf(
				"Hello %s,\n\nYour temporary %s access has %s.\n\nIf you still need elevated privileges, submit a new request.",
				$user_name,
				$grant->elevated_role,
				'expired' === $reason ? 'expired' : 'been revoked'
			);
			wp_mail( $user_email, $subject, $message );
		}

		$this->dispatch_slack_notification(
			array(
				'title'       => '[ACCESS CLOSED] Temporary Permission',
				'description' => sprintf( '%s temporary %s access %s.', $user_name, $grant->elevated_role, 'expired' === $reason ? 'expired' : 'was revoked' ),
				'severity'    => 'info',
			)
		);
	}

	/**
	 * Dispatch notification to Slack via the integrations module.
	 *
	 * @param array $payload Notification payload.
	 * @return void
	 */
	private function dispatch_slack_notification( $payload ) {
		if ( isset( $GLOBALS['nexifymy_integrations'] )
			&& $GLOBALS['nexifymy_integrations'] instanceof NexifyMy_Security_Integrations
			&& method_exists( $GLOBALS['nexifymy_integrations'], 'send_slack' )
		) {
			$GLOBALS['nexifymy_integrations']->send_slack( $payload );
		}
	}
}

