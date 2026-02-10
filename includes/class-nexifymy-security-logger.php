<?php
/**
 * Security Logging Module.
 * Creates custom DB table and logs all security events.
 *
 * DEV NOTES:
 * This module is responsible for the persistent storage of security events.
 * it manages the `nexifymy_security_logs` table and handles log rotation/purging.
 * Last Updated: 2026-02-06
 * Version: 2.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Logger {

	/**
	 * Database table name (without prefix).
	 */
	const TABLE_NAME = 'nexifymy_security_logs';

	/**
	 * Option key used to track schema version.
	 */
	const SCHEMA_OPTION = 'nexifymy_security_logs_schema_version';

	/**
	 * Current logger table schema version.
	 */
	const SCHEMA_VERSION = '1.0.0';

	/**
	 * Initialize the logger.
	 */
	public function init() {
		// Ensure table exists (for manual installs/updates).
		$this->maybe_create_table();

		// AJAX handler to fetch logs.
		add_action( 'wp_ajax_nexifymy_get_logs', array( $this, 'ajax_get_logs' ) );

		// Schedule log cleanup cron.
		add_action( 'nexifymy_log_cleanup', array( $this, 'purge_old_logs' ) );

		if ( ! wp_next_scheduled( 'nexifymy_log_cleanup' ) ) {
			wp_schedule_event( time(), 'daily', 'nexifymy_log_cleanup' );
		}
	}

	/**
	 * Purge logs older than retention period.
	 */
	public function purge_old_logs() {
		global $wpdb;

		// Get retention days from settings option directly (Settings class is not always loaded).
		$retention_days = 30;
		$settings       = get_option( 'nexifymy_security_settings', array() );
		if ( isset( $settings['logging']['retention_days'] ) ) {
			$retention_days = $settings['logging']['retention_days'];
		}

		$retention_days = max( 1, absint( $retention_days ) );
		$cutoff_date    = gmdate( 'Y-m-d H:i:s', strtotime( "-{$retention_days} days" ) );
		$table_name     = self::get_table_name();

		// If the table doesn't exist yet, nothing to purge.
		if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table_name}'" ) !== $table_name ) {
			return 0;
		}

		$deleted = $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table_name} WHERE created_at < %s",
				$cutoff_date
			)
		);

		if ( $deleted > 0 ) {
			// Log the purge event (but don't create infinite loop).
			$wpdb->insert(
				$table_name,
				array(
					'event_type' => 'log_cleanup',
					'severity'   => 'info',
					'message'    => sprintf( 'Purged %d logs older than %d days.', $deleted, $retention_days ),
					'created_at' => current_time( 'mysql' ),
				),
				array( '%s', '%s', '%s', '%s' )
			);
		}

		return $deleted;
	}

	/**
	 * Get the full table name with prefix.
	 *
	 * @return string
	 */
	public static function get_table_name() {
		global $wpdb;
		return $wpdb->prefix . self::TABLE_NAME;
	}

	/**
	 * Check and create table if needed.
	 */
	public function maybe_create_table() {
		$installed_version = get_option( self::SCHEMA_OPTION, '' );
		if ( self::SCHEMA_VERSION !== (string) $installed_version ) {
			$this->create_table();
		}
	}

	/**
	 * Create the logs database table.
	 */
	public function create_table() {
		global $wpdb;
		$table_name      = self::get_table_name();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE $table_name (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			event_type VARCHAR(50) NOT NULL,
			severity VARCHAR(20) NOT NULL DEFAULT 'info',
			message TEXT NOT NULL,
			ip_address VARCHAR(45) DEFAULT NULL,
			user_agent TEXT DEFAULT NULL,
			user_id BIGINT(20) UNSIGNED DEFAULT NULL,
			context LONGTEXT DEFAULT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY event_type (event_type),
			KEY severity (severity),
			KEY ip_address (ip_address),
			KEY created_at (created_at)
		) $charset_collate;";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );

		update_option( self::SCHEMA_OPTION, self::SCHEMA_VERSION, false );
	}

	/**
	 * Get the client IP address securely.
	 * Only trusts X-Forwarded-For/X-Real-IP if the direct requester is a configured trusted proxy.
	 *
	 * @return string|null
	 */
	private static function get_client_ip() {
		$remote_addr     = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$trusted_proxies = get_option( 'nexifymy_security_trusted_proxies', array() );

		if ( $remote_addr && in_array( $remote_addr, (array) $trusted_proxies, true ) ) {
			$forwarded_headers = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP' );
			foreach ( $forwarded_headers as $header ) {
				if ( empty( $_SERVER[ $header ] ) ) {
					continue;
				}

				$raw       = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
				$client_ip = strpos( $raw, ',' ) !== false ? trim( explode( ',', $raw )[0] ) : $raw;
				if ( filter_var( $client_ip, FILTER_VALIDATE_IP ) ) {
					return $client_ip;
				}
			}
		}

		return ( $remote_addr && filter_var( $remote_addr, FILTER_VALIDATE_IP ) ) ? $remote_addr : null;
	}

	/**
	 * Log a security event.
	 *
	 * @param string $event_type Event type (e.g., 'waf_block', 'scan_threat', 'login_failed').
	 * @param string $message Human-readable message.
	 * @param string $severity 'info', 'warning', 'critical'.
	 * @param array  $context Additional context data.
	 * @return int|false Insert ID or false on failure.
	 */
	public static function log( $event_type, $message, $severity = 'info', $context = array() ) {
		global $wpdb;

		if ( ! isset( $wpdb ) || ! is_object( $wpdb ) ) {
			return false;
		}

		$table_name = self::get_table_name();
		// Avoid SQL errors if activation didn't run yet.
		if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table_name}'" ) !== $table_name ) {
			// Best effort: try to create the table once.
			$logger = new self();
			$logger->create_table();

			if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table_name}'" ) !== $table_name ) {
				return false;
			}
		}

		$ip         = self::get_client_ip();
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ) : null;
		$user_id    = function_exists( 'get_current_user_id' ) ? ( get_current_user_id() ?: null ) : null;

		$result = $wpdb->insert(
			$table_name,
			array(
				'event_type' => sanitize_key( $event_type ),
				'severity'   => sanitize_key( $severity ),
				'message'    => sanitize_text_field( $message ),
				'ip_address' => $ip,
				'user_agent' => $user_agent,
				'user_id'    => $user_id,
				'context'    => wp_json_encode( $context ),
				'created_at' => current_time( 'mysql' ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s' )
		);

		if ( $result ) {
			// Trigger email alert for critical events.
			$alert_context = array_merge( $context, array( 'ip_address' => $ip ) );
			do_action( 'nexifymy_security_alert', $event_type, $message, $alert_context );
		}

		return $result ? $wpdb->insert_id : false;
	}

	/**
	 * Fetch logs via AJAX.
	 */
	public function ajax_get_logs() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		global $wpdb;
		$table_name = self::get_table_name();

		// Pagination.
		$page     = isset( $_POST['page'] ) ? absint( $_POST['page'] ) : 1;
		$per_page = 50;
		$offset   = ( $page - 1 ) * $per_page;

		// Filters.
		$severity   = isset( $_POST['severity'] ) ? sanitize_key( $_POST['severity'] ) : '';
		$event_type = isset( $_POST['event_type'] ) ? sanitize_key( $_POST['event_type'] ) : '';

		$where        = array();
		$where_values = array();

		if ( $severity ) {
			$where[]        = 'severity = %s';
			$where_values[] = $severity;
		}
		if ( $event_type ) {
			$where[]        = 'event_type = %s';
			$where_values[] = $event_type;
		}

		$where_clause = ! empty( $where ) ? 'WHERE ' . implode( ' AND ', $where ) : '';

		// Total count.
		$count_query = "SELECT COUNT(*) FROM $table_name $where_clause";
		$total       = empty( $where_values )
			? $wpdb->get_var( $count_query )
			: $wpdb->get_var( $wpdb->prepare( $count_query, $where_values ) );

		// Fetch logs.
		$query        = "SELECT * FROM $table_name $where_clause ORDER BY created_at DESC LIMIT %d OFFSET %d";
		$query_values = array_merge( $where_values, array( $per_page, $offset ) );

		$logs = $wpdb->get_results( $wpdb->prepare( $query, $query_values ), ARRAY_A );

		wp_send_json_success(
			array(
				'logs'        => $logs,
				'total'       => (int) $total,
				'page'        => $page,
				'per_page'    => $per_page,
				'total_pages' => ceil( $total / $per_page ),
			)
		);
	}

	/**
	 * Get recent security events for dashboard.
	 *
	 * @param int $limit Number of events to return.
	 * @return array Recent events.
	 */
	public static function get_recent_events( $limit = 5 ) {
		global $wpdb;

		$table_name = self::get_table_name();

		// Check if table exists.
		if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table_name}'" ) !== $table_name ) {
			return array();
		}

		$limit = max( 1, min( 50, absint( $limit ) ) );

		$events = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, event_type, severity, message, ip_address, created_at 
			 FROM {$table_name} 
			 ORDER BY created_at DESC 
			 LIMIT %d",
				$limit
			),
			ARRAY_A
		);

		// Format events for dashboard display.
		$formatted = array();
		foreach ( $events as $event ) {
			$icon = 'info';
			switch ( $event['severity'] ) {
				case 'critical':
					$icon = 'warning';
					break;
				case 'warning':
					$icon = 'flag';
					break;
			}

			$formatted[] = array(
				'id'       => $event['id'],
				'message'  => $event['message'],
				'severity' => $event['severity'],
				'ip'       => $event['ip_address'],
				'icon'     => $icon,
				'time'     => strtotime( $event['created_at'] ),
			);
		}

		return $formatted;
	}

	/**
	 * Get statistics for the dashboard.
	 *
	 * @param int $days Number of days to look back.
	 * @return array Statistics.
	 */
	public static function get_stats( $days = 7 ) {
		global $wpdb;
		$table_name = self::get_table_name();
		$since_date = date( 'Y-m-d H:i:s', strtotime( "-$days days" ) );

		$stats = array();

		// Total events.
		$stats['total_events'] = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM $table_name WHERE created_at >= %s",
				$since_date
			)
		);

		// Events by severity.
		$severity_counts = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT severity, COUNT(*) as count FROM $table_name WHERE created_at >= %s GROUP BY severity",
				$since_date
			),
			ARRAY_A
		);

		$stats['by_severity'] = array();
		foreach ( $severity_counts as $row ) {
			$stats['by_severity'][ $row['severity'] ] = (int) $row['count'];
		}

		// Top blocked IPs.
		$top_ips = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ip_address, COUNT(*) as count FROM $table_name 
			 WHERE created_at >= %s AND event_type = 'waf_block' 
			 GROUP BY ip_address ORDER BY count DESC LIMIT 10",
				$since_date
			),
			ARRAY_A
		);

		$stats['top_blocked_ips'] = $top_ips;

		return $stats;
	}
}
