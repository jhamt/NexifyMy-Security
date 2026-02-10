<?php
/**
 * NexifyMy Security Uninstall Script.
 *
 * Fired when the plugin is uninstalled. Cleans up all data created by the plugin.
 *
 * @package NexifyMy_Security
 */

// Exit if not called by WordPress uninstall process.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

/**
 * Check if cleanup is enabled in settings.
 * If not explicitly disabled, we default to cleaning up all data.
 */
$cleanup_enabled = get_option( 'nexifymy_security_cleanup_on_uninstall', true );

if ( ! $cleanup_enabled ) {
	// User opted to keep data.
	return;
}

global $wpdb;

/*
 * =============================================================================
 * 1. DELETE DATABASE TABLES
 * =============================================================================
 */

// Drop all plugin-owned tables.
$tables_to_drop = array(
	$wpdb->prefix . 'nexifymy_security_logs',
	$wpdb->prefix . 'nexifymy_live_traffic',
	$wpdb->prefix . 'nexifymy_activity_log',
	$wpdb->prefix . 'nexifymy_behavior_log',
	$wpdb->prefix . 'sentinel_user_profiles',
	$wpdb->prefix . 'nexifymy_insider_events',
	$wpdb->prefix . 'nexifymy_exfiltration_log',
	$wpdb->prefix . 'nexifymy_temp_permissions',
);
foreach ( $tables_to_drop as $table_name ) {
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery
	$wpdb->query( "DROP TABLE IF EXISTS {$table_name}" );
}

/*
 * =============================================================================
 * 2. DELETE OPTIONS
 * =============================================================================
 */

$options_to_delete = array(
	// Main settings.
	'nexifymy_security_settings',
	'nexifymy_security_activated',
	'nexifymy_security_cleanup_on_uninstall',

	// WAF/Firewall.
	'nexifymy_security_ip_whitelist',
	'nexifymy_security_blocked_ips',
	'nexifymy_security_trusted_proxies',

	// Scanner.
	'nexifymy_scan_schedule',
	'nexifymy_last_scan_timestamp',
	'nexifymy_security_last_scan',
	'nexifymy_last_scheduled_scan',
	'nexifymy_last_scan',

	// Quarantine.
	'nexifymy_quarantine_log',

	// Activity & traffic.
	'nexifymy_activity_log_db_version',
	'nexifymy_live_traffic_db_version',

	// AI detection.
	'nexifymy_ai_behavior_patterns',
	'nexifymy_ai_detected_threats',
	'nexifymy_temp_permissions_legacy_migrated',

	// P2P intelligence.
	'nexifymy_p2p_peers',
	'nexifymy_p2p_node_key',

	// Integrations migration legacy key.
	'nexifymy_integrations',

	// Rate Limiter (transients are handled separately).
);

foreach ( $options_to_delete as $option ) {
	delete_option( $option );
}

/*
 * =============================================================================
 * 3. DELETE TRANSIENTS
 * =============================================================================
 */

$transient_patterns = array(
	'nexifymy_rl_',
	'nexifymy_sbx_',
	'nexifymy_p2p_',
	'nexifymy_geo_',
	'nexifymy_vuln_',
);
foreach ( $transient_patterns as $pattern ) {
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
			'_transient_' . $pattern . '%',
			'_transient_timeout_' . $pattern . '%'
		)
	);
}

/*
 * =============================================================================
 * 4. DELETE SCHEDULED EVENTS
 * =============================================================================
 */

// Clear any scheduled cron events.
$cron_hooks = array(
	'nexifymy_scheduled_scan',
	'nexifymy_daily_summary',
	'nexifymy_log_cleanup',
	'nexifymy_scheduled_backup',
	'nexifymy_p2p_sync',
	'nexifymy_vulnerability_scan',
	'nexifymy_activity_log_cleanup',
	'nexifymy_supply_chain_scan',
	'nexifymy_update_signatures',
	'nexifymy_integrity_check',
	'nexifymy_security_benchmark',
	'nexifymy_auto_patch',
	'nexifymy_traffic_cleanup',
	'nexifymy_generate_report',
	'nexifymy_cleanup_reports',
	'nexifymy_learn_patterns',
	'nexifymy_revoke_expired_permissions',
);

foreach ( $cron_hooks as $hook ) {
	$timestamp = wp_next_scheduled( $hook );
	if ( $timestamp ) {
		wp_unschedule_event( $timestamp, $hook );
	}
}

// Clear all instances (in case multiple were scheduled).
foreach ( $cron_hooks as $hook ) {
	wp_clear_scheduled_hook( $hook );
}

/*
 * =============================================================================
 * 5. DELETE QUARANTINE DIRECTORY
 * =============================================================================
 */

$quarantine_dir = WP_CONTENT_DIR . '/nexifymy-quarantine';
$deleted_dir    = WP_CONTENT_DIR . '/nexifymy-deleted';
$backups_dir    = WP_CONTENT_DIR . '/nexifymy-backups';

if ( is_dir( $quarantine_dir ) ) {
	// Recursively delete the quarantine directory.
	nexifymy_recursive_delete( $quarantine_dir );
}
if ( is_dir( $deleted_dir ) ) {
	nexifymy_recursive_delete( $deleted_dir );
}
if ( is_dir( $backups_dir ) ) {
	nexifymy_recursive_delete( $backups_dir );
}

/**
 * Recursively delete a directory and its contents.
 *
 * @param string $dir Directory path.
 * @return bool
 */
function nexifymy_recursive_delete( $dir ) {
	if ( ! is_dir( $dir ) ) {
		return false;
	}

	$items = scandir( $dir );
	foreach ( $items as $item ) {
		if ( $item === '.' || $item === '..' ) {
			continue;
		}

		$path = $dir . '/' . $item;

		if ( is_dir( $path ) ) {
			nexifymy_recursive_delete( $path );
		} else {
			unlink( $path );
		}
	}

	return rmdir( $dir );
}

/*
 * =============================================================================
 * 6. CLEAN UP USER META (if any was added)
 * =============================================================================
 */

// Currently no user meta is stored, but placeholder for future.

/*
 * =============================================================================
 * DONE
 * =============================================================================
 */
