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

// Drop the security logs table.
$table_name = $wpdb->prefix . 'nexifymy_security_logs';
$wpdb->query( "DROP TABLE IF EXISTS {$table_name}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

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
	'nexifymy_security_trusted_proxies',

	// Scanner.
	'nexifymy_scan_schedule',
	'nexifymy_last_scan_timestamp',
	'nexifymy_security_last_scan',
	'nexifymy_last_scheduled_scan',

	// Quarantine.
	'nexifymy_quarantine_log',

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

// Delete all rate limiter transients.
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
		'_transient_nexifymy_rl_%',
		'_transient_timeout_nexifymy_rl_%'
	)
); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

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

if ( is_dir( $quarantine_dir ) ) {
	// Recursively delete the quarantine directory.
	nexifymy_recursive_delete( $quarantine_dir );
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
