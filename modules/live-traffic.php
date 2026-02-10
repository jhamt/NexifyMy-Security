<?php
/**
 * Live Traffic Monitoring Module.
 * Logs and displays real-time HTTP requests.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Live_Traffic {

	/**
	 * Database table name (without prefix).
	 */
	const TABLE_NAME = 'nexifymy_traffic';

	/**
	 * Option key used to track schema version.
	 */
	const SCHEMA_OPTION = 'nexifymy_traffic_schema_version';

	/**
	 * Current table schema version.
	 */
	const SCHEMA_VERSION = '1.0.0';

	/**
	 * Maximum entries to keep.
	 */
	const MAX_ENTRIES = 5000;

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'        => true,
		'log_admin'      => true,
		'log_ajax'       => true,
		'log_cron'       => false,
		'retention_hours' => 24,
		'exclude_ips'    => array(),
		'exclude_urls'   => array(),
	);

	/**
	 * Initialize the module.
	 */
	public function init() {
		// Ensure table exists.
		$this->maybe_create_table();

		// Log requests early.
		add_action( 'init', array( $this, 'log_request' ), 1 );

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_get_live_traffic', array( $this, 'ajax_get_live_traffic' ) );
		add_action( 'wp_ajax_nexifymy_get_traffic_stats', array( $this, 'ajax_get_traffic_stats' ) );
		add_action( 'wp_ajax_nexifymy_get_traffic_analytics', array( $this, 'ajax_get_traffic_analytics' ) );
		add_action( 'wp_ajax_nexifymy_clear_traffic', array( $this, 'ajax_clear_traffic' ) );

		// Cleanup old entries.
		add_action( 'nexifymy_traffic_cleanup', array( $this, 'cleanup_old_entries' ) );

		// Schedule cleanup if not scheduled.
		if ( ! wp_next_scheduled( 'nexifymy_traffic_cleanup' ) ) {
			wp_schedule_event( time(), 'hourly', 'nexifymy_traffic_cleanup' );
		}
	}

	/**
	 * Check if table exists and create if needed.
	 */
	private function maybe_create_table() {
		$installed_version = get_option( self::SCHEMA_OPTION, '' );
		if ( self::SCHEMA_VERSION !== (string) $installed_version ) {
			self::create_table();
		}
	}

	/**
	 * Create database table on activation.
	 */
	public static function create_table() {
		global $wpdb;

		$table_name = $wpdb->prefix . self::TABLE_NAME;
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			ip_address VARCHAR(45) NOT NULL,
			request_uri VARCHAR(2048) NOT NULL,
			request_method VARCHAR(10) NOT NULL,
			user_agent VARCHAR(512) DEFAULT '',
			referrer VARCHAR(512) DEFAULT '',
			response_code SMALLINT(3) DEFAULT 200,
			user_id BIGINT(20) UNSIGNED DEFAULT 0,
			country_code VARCHAR(2) DEFAULT '',
			is_blocked TINYINT(1) DEFAULT 0,
			request_time DATETIME NOT NULL,
			PRIMARY KEY (id),
			KEY ip_address (ip_address),
			KEY request_time (request_time),
			KEY is_blocked (is_blocked)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );

		update_option( self::SCHEMA_OPTION, self::SCHEMA_VERSION, false );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['live_traffic'] ) ) {
				return wp_parse_args( $all_settings['live_traffic'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Log the current request.
	 */
	public function log_request() {
		$all_settings = get_option( 'nexifymy_security_settings', array() );
		if ( isset( $all_settings['modules']['live_traffic_enabled'] ) && ! $all_settings['modules']['live_traffic_enabled'] ) {
			return;
		}

		$settings = $this->get_settings();

		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Skip admin requests if disabled.
		if ( ! $settings['log_admin'] && is_admin() && ! wp_doing_ajax() ) {
			return;
		}

		// Skip AJAX requests if disabled.
		if ( ! $settings['log_ajax'] && wp_doing_ajax() ) {
			return;
		}

		// Skip cron requests if disabled.
		if ( ! $settings['log_cron'] && wp_doing_cron() ) {
			return;
		}

		// Get request data.
		$ip = $this->get_client_ip();
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET';
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$referrer = isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '';

		// Check exclusions.
		if ( $this->is_excluded( $ip, $uri, $settings ) ) {
			return;
		}

		// Insert into database.
		$this->insert_log( array(
			'ip_address'     => $ip,
			'request_uri'    => $uri,
			'request_method' => $method,
			'user_agent'     => substr( $user_agent, 0, 512 ),
			'referrer'       => substr( $referrer, 0, 512 ),
			'user_id'        => get_current_user_id(),
			'country_code'   => $this->resolve_country_code( $ip ),
			'request_time'   => current_time( 'mysql' ),
		) );
	}

	/**
	 * Insert log entry.
	 *
	 * @param array $data Log data.
	 */
	private function insert_log( $data ) {
		global $wpdb;

		$table_name = $wpdb->prefix . self::TABLE_NAME;

		$wpdb->insert(
			$table_name,
			$data,
			array( '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s' )
		);
	}

	/**
	 * Resolve country code for a visitor IP.
	 *
	 * @param string $ip Client IP.
	 * @return string
	 */
	private function resolve_country_code( $ip, $allow_remote_lookup = false ) {
		// Prefer edge-provided country when available.
		if ( ! empty( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) {
			$country = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_IPCOUNTRY'] ) );
			return $this->sanitize_country_code( $country );
		}

		// Reuse cached geo-blocking lookups when available (no network).
		if ( class_exists( 'NexifyMy_Security_Geo_Blocking' ) ) {
			$cache_key = NexifyMy_Security_Geo_Blocking::CACHE_PREFIX . md5( $ip );
			$cached = get_transient( $cache_key );
			if ( false !== $cached ) {
				return $this->sanitize_country_code( $cached );
			}
		}

		if ( ! $allow_remote_lookup ) {
			return '';
		}

		// Reuse geo-blocking resolver for cached API lookups.
		if ( isset( $GLOBALS['nexifymy_geo_blocking'] ) && method_exists( $GLOBALS['nexifymy_geo_blocking'], 'get_country' ) ) {
			$country = $GLOBALS['nexifymy_geo_blocking']->get_country( $ip );
			return $this->sanitize_country_code( $country );
		}

		return '';
	}

	/**
	 * Normalize country code to ISO-2 format.
	 *
	 * @param string $country Country value.
	 * @return string
	 */
	private function sanitize_country_code( $country ) {
		$country = strtoupper( sanitize_text_field( (string) $country ) );
		return preg_match( '/^[A-Z]{2}$/', $country ) ? $country : '';
	}

	/**
	 * Backfill missing country codes for recent entries.
	 *
	 * @param int $days Number of days to look back.
	 * @param int $batch Number of unique IPs to process.
	 * @return int
	 */
	private function backfill_country_codes( $days = 30, $batch = 25 ) {
		global $wpdb;
		$table_name = $wpdb->prefix . self::TABLE_NAME;

		$days = max( 1, absint( $days ) );
		$batch = max( 1, absint( $batch ) );
		$date_limit = gmdate( 'Y-m-d H:i:s', strtotime( "-$days days" ) );

		$ips = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT DISTINCT ip_address
				FROM {$table_name}
				WHERE request_time >= %s
				AND (country_code = '' OR country_code IS NULL)
				LIMIT %d",
				$date_limit,
				$batch
			)
		);

		if ( empty( $ips ) || ! is_array( $ips ) ) {
			return 0;
		}

		$updated_rows = 0;
		foreach ( $ips as $ip ) {
			$country_code = $this->resolve_country_code( $ip, true );
			if ( empty( $country_code ) ) {
				continue;
			}

			$updated_rows += (int) $wpdb->query(
				$wpdb->prepare(
					"UPDATE {$table_name}
					SET country_code = %s
					WHERE ip_address = %s
					AND request_time >= %s
					AND (country_code = '' OR country_code IS NULL)",
					$country_code,
					$ip,
					$date_limit
				)
			);
		}

		return $updated_rows;
	}

	/**
	 * Check if request should be excluded.
	 *
	 * @param string $ip Client IP.
	 * @param string $uri Request URI.
	 * @param array  $settings Module settings.
	 * @return bool
	 */
	private function is_excluded( $ip, $uri, $settings ) {
		// Check excluded IPs.
		if ( ! empty( $settings['exclude_ips'] ) && in_array( $ip, $settings['exclude_ips'], true ) ) {
			return true;
		}

		// Check excluded URLs.
		if ( ! empty( $settings['exclude_urls'] ) ) {
			foreach ( $settings['exclude_urls'] as $pattern ) {
				if ( strpos( $uri, $pattern ) !== false ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Get client IP address.
	 *
	 * @return string
	 */
	private function get_client_ip() {
		$remote_addr     = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$trusted_proxies = get_option( 'nexifymy_security_trusted_proxies', array() );

		if ( $remote_addr && in_array( $remote_addr, (array) $trusted_proxies, true ) ) {
			$headers = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP' );
			foreach ( $headers as $header ) {
				if ( empty( $_SERVER[ $header ] ) ) {
					continue;
				}

				$raw = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
				$ip  = strpos( $raw, ',' ) !== false ? trim( explode( ',', $raw )[0] ) : $raw;
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}

		if ( $remote_addr && filter_var( $remote_addr, FILTER_VALIDATE_IP ) ) {
			return $remote_addr;
		}

		return '0.0.0.0';
	}

	/**
	 * Get recent traffic entries.
	 *
	 * @param array $args Query arguments.
	 * @return array
	 */
	public function get_traffic( $args = array() ) {
		global $wpdb;

		$defaults = array(
			'limit'      => 100,
			'offset'     => 0,
			'ip'         => '',
			'method'     => '',
			'is_blocked' => null,
			'since'      => '',
		);
		$args = wp_parse_args( $args, $defaults );

		$table_name = $wpdb->prefix . self::TABLE_NAME;

		$where = array( '1=1' );
		$params = array();

		if ( ! empty( $args['ip'] ) ) {
			$where[] = 'ip_address = %s';
			$params[] = $args['ip'];
		}

		if ( ! empty( $args['method'] ) ) {
			$where[] = 'request_method = %s';
			$params[] = strtoupper( $args['method'] );
		}

		if ( null !== $args['is_blocked'] ) {
			$where[] = 'is_blocked = %d';
			$params[] = $args['is_blocked'] ? 1 : 0;
		}

		if ( ! empty( $args['since'] ) ) {
			$where[] = 'request_time >= %s';
			$params[] = $args['since'];
		}

		$where_sql = implode( ' AND ', $where );
		$limit = absint( $args['limit'] );
		$offset = absint( $args['offset'] );

		if ( ! empty( $params ) ) {
			$query = $wpdb->prepare(
				"SELECT * FROM {$table_name} WHERE {$where_sql} ORDER BY request_time DESC LIMIT %d OFFSET %d",
				array_merge( $params, array( $limit, $offset ) )
			);
		} else {
			$query = $wpdb->prepare(
				"SELECT * FROM {$table_name} WHERE {$where_sql} ORDER BY request_time DESC LIMIT %d OFFSET %d",
				$limit,
				$offset
			);
		}

		return $wpdb->get_results( $query, ARRAY_A );
	}

	/**
	 * Get traffic statistics.
	 *
	 * @param int $hours Hours to look back.
	 * @return array
	 */
	public function get_stats( $hours = 24 ) {
		global $wpdb;

		$table_name = $wpdb->prefix . self::TABLE_NAME;
		$since = gmdate( 'Y-m-d H:i:s', time() - ( $hours * HOUR_IN_SECONDS ) );

		$stats = array(
			'total_requests'  => 0,
			'unique_ips'      => 0,
			'blocked_count'   => 0,
			'by_method'       => array(),
			'top_ips'         => array(),
			'top_uris'        => array(),
		);

		// Total requests.
		$stats['total_requests'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table_name} WHERE request_time >= %s", $since )
		);

		// Unique IPs.
		$stats['unique_ips'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(DISTINCT ip_address) FROM {$table_name} WHERE request_time >= %s", $since )
		);

		// Blocked count.
		$stats['blocked_count'] = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table_name} WHERE request_time >= %s AND is_blocked = 1", $since )
		);

		// By method.
		$methods = $wpdb->get_results(
			$wpdb->prepare( "SELECT request_method, COUNT(*) as cnt FROM {$table_name} WHERE request_time >= %s GROUP BY request_method", $since ),
			ARRAY_A
		);
		foreach ( $methods as $m ) {
			$stats['by_method'][ $m['request_method'] ] = (int) $m['cnt'];
		}

		// Top IPs.
		$stats['top_ips'] = $wpdb->get_results(
			$wpdb->prepare( "SELECT ip_address, COUNT(*) as cnt FROM {$table_name} WHERE request_time >= %s GROUP BY ip_address ORDER BY cnt DESC LIMIT 10", $since ),
			ARRAY_A
		);

		// Top URIs.
		$stats['top_uris'] = $wpdb->get_results(
			$wpdb->prepare( "SELECT request_uri, COUNT(*) as cnt FROM {$table_name} WHERE request_time >= %s GROUP BY request_uri ORDER BY cnt DESC LIMIT 10", $since ),
			ARRAY_A
		);

		return $stats;
	}

	/**
	 * Cleanup old entries.
	 */
	public function cleanup_old_entries() {
		global $wpdb;

		$settings = $this->get_settings();
		$hours = absint( $settings['retention_hours'] ) ?: 24;

		$table_name = $wpdb->prefix . self::TABLE_NAME;
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( $hours * HOUR_IN_SECONDS ) );

		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table_name} WHERE request_time < %s", $cutoff ) );

		// Also enforce max entries.
		$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" );
		if ( $count > self::MAX_ENTRIES ) {
			$delete_count = $count - self::MAX_ENTRIES;
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name is safe, limit is integer.
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$table_name} ORDER BY request_time ASC LIMIT %d", $delete_count ) );
		}
	}

	/**
	 * Mark request as blocked.
	 *
	 * @param string $ip IP address.
	 * @param string $reason Block reason.
	 */
	public function mark_blocked( $ip, $reason = '' ) {
		global $wpdb;
		$table_name = $wpdb->prefix . self::TABLE_NAME;

		// Update the most recent entry for this IP.
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$table_name} SET is_blocked = 1 WHERE ip_address = %s ORDER BY id DESC LIMIT 1",
				$ip
			)
		);
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	/**
	 * Get live traffic via AJAX.
	 */
	public function ajax_get_live_traffic() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$args = array(
			'limit'  => isset( $_POST['limit'] ) ? absint( $_POST['limit'] ) : 100,
			'ip'     => isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '',
			'method' => isset( $_POST['method'] ) ? sanitize_text_field( wp_unslash( $_POST['method'] ) ) : '',
		);

		$traffic = $this->get_traffic( $args );

		// Format for display.
		foreach ( $traffic as &$entry ) {
			$entry['request_time_formatted'] = date_i18n( 'M j, H:i:s', strtotime( $entry['request_time'] ) );
			$entry['user_agent_short'] = substr( $entry['user_agent'], 0, 50 );
		}

		wp_send_json_success( array( 'traffic' => $traffic ) );
	}

	/**
	 * Get traffic stats via AJAX.
	 */
	public function ajax_get_traffic_stats() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$hours = isset( $_POST['hours'] ) ? absint( $_POST['hours'] ) : 24;
		$stats = $this->get_stats( $hours );

		wp_send_json_success( array( 'stats' => $stats ) );
	}

	/**
	 * Clear traffic log via AJAX.
	 */
	public function ajax_clear_traffic() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		global $wpdb;
		$table_name = $wpdb->prefix . self::TABLE_NAME;
		$wpdb->query( "TRUNCATE TABLE {$table_name}" );

		wp_send_json_success( array( 'message' => 'Traffic log cleared.' ) );
	}

	/**
	 * Get analytics overview stats.
	 *
	 * @return array
	 */
	public function get_analytics() {
		global $wpdb;
		$table_name = $wpdb->prefix . self::TABLE_NAME;

		$today = gmdate( 'Y-m-d' );
		$week_ago = gmdate( 'Y-m-d', strtotime( '-7 days' ) );
		$month_ago = gmdate( 'Y-m-d', strtotime( '-30 days' ) );

		$stats = array(
			'today' => $wpdb->get_var( $wpdb->prepare(
				"SELECT COUNT(*) FROM {$table_name} WHERE DATE(request_time) = %s",
				$today
			) ),
			'week' => $wpdb->get_var( $wpdb->prepare(
				"SELECT COUNT(*) FROM {$table_name} WHERE request_time >= %s",
				$week_ago
			) ),
			'month' => $wpdb->get_var( $wpdb->prepare(
				"SELECT COUNT(*) FROM {$table_name} WHERE request_time >= %s",
				$month_ago
			) ),
			'unique_ips' => $wpdb->get_var( $wpdb->prepare(
				"SELECT COUNT(DISTINCT ip_address) FROM {$table_name} WHERE request_time >= %s",
				$month_ago
			) ),
		);

		return $stats;
	}

	/**
	 * Get traffic analytics data via AJAX.
	 */
	public function ajax_get_traffic_analytics() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$days = isset( $_POST['days'] ) ? absint( $_POST['days'] ) : 30;
		$this->backfill_country_codes( $days, 25 );

		$data = array(
			'chart_data' => $this->get_chart_data( $days ),
			'top_pages' => $this->get_top_pages( 10, $days ),
			'top_referrers' => $this->get_top_referrers( 10, $days ),
			'geo_distribution' => $this->get_geo_distribution( 10, $days ),
			'browser_distribution' => $this->get_browser_distribution( $days ),
			'os_distribution' => $this->get_os_distribution( $days ),
			'device_distribution' => $this->get_device_distribution( $days ),
			'totals' => $this->get_totals( $days ),
		);

		wp_send_json_success( $data );
	}

	/**
	 * Get total stats for the period.
	 *
	 * @param int $days Number of days.
	 * @return array
	 */
	private function get_totals( $days = 30 ) {
		global $wpdb;
		$table_name = $wpdb->prefix . self::TABLE_NAME;
		$date_limit = gmdate( 'Y-m-d H:i:s', strtotime( "-$days days" ) );

		return array(
			'total_views' => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table_name} WHERE request_time >= %s", $date_limit ) ),
			'unique_visitors' => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(DISTINCT ip_address) FROM {$table_name} WHERE request_time >= %s", $date_limit ) ),
			'blocked' => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table_name} WHERE request_time >= %s AND is_blocked = 1", $date_limit ) ),
		);
	}

	/**
	 * Get browser distribution.
	 *
	 * @param int $days Number of days.
	 * @return array
	 */
	private function get_browser_distribution( $days = 30 ) {
		global $wpdb;
		$table_name = $wpdb->prefix . self::TABLE_NAME;
		
		// Get all user agents for processing
		$results = $wpdb->get_results( $wpdb->prepare(
			"SELECT user_agent, COUNT(*) as count FROM {$table_name} 
			WHERE request_time >= DATE_SUB(NOW(), INTERVAL %d DAY) 
			GROUP BY user_agent",
			$days
		) );

		$browsers = array(
			'Chrome' => 0,
			'Firefox' => 0,
			'Safari' => 0,
			'Edge' => 0,
			'Opera' => 0,
			'Other' => 0,
		);

		foreach ( $results as $row ) {
			$ua = $row->user_agent;
			$count = (int) $row->count;

			if ( stripos( $ua, 'Edg' ) !== false ) {
				$browsers['Edge'] += $count;
			} elseif ( stripos( $ua, 'Chrome' ) !== false ) {
				$browsers['Chrome'] += $count;
			} elseif ( stripos( $ua, 'Firefox' ) !== false ) {
				$browsers['Firefox'] += $count;
			} elseif ( stripos( $ua, 'Safari' ) !== false ) {
				$browsers['Safari'] += $count;
			} elseif ( stripos( $ua, 'Opera' ) !== false || stripos( $ua, 'OPR' ) !== false ) {
				$browsers['Opera'] += $count;
			} else {
				$browsers['Other'] += $count;
			}
		}

		arsort( $browsers );
		return $browsers;
	}

	/**
	 * Get OS distribution.
	 *
	 * @param int $days Number of days.
	 * @return array
	 */
	private function get_os_distribution( $days = 30 ) {
		global $wpdb;
		$table_name = $wpdb->prefix . self::TABLE_NAME;
		
		$results = $wpdb->get_results( $wpdb->prepare(
			"SELECT user_agent, COUNT(*) as count FROM {$table_name} 
			WHERE request_time >= DATE_SUB(NOW(), INTERVAL %d DAY) 
			GROUP BY user_agent",
			$days
		) );

		$os = array(
			'Windows' => 0,
			'Mac OS' => 0,
			'Linux' => 0,
			'iOS' => 0,
			'Android' => 0,
			'Other' => 0,
		);

		foreach ( $results as $row ) {
			$ua = $row->user_agent;
			$count = (int) $row->count;

			if ( stripos( $ua, 'Windows' ) !== false ) {
				$os['Windows'] += $count;
			} elseif ( stripos( $ua, 'Android' ) !== false ) {
				$os['Android'] += $count;
			} elseif ( stripos( $ua, 'iPhone' ) !== false || stripos( $ua, 'iPad' ) !== false ) {
				$os['iOS'] += $count;
			} elseif ( stripos( $ua, 'Macintosh' ) !== false || stripos( $ua, 'Mac OS' ) !== false ) {
				$os['Mac OS'] += $count;
			} elseif ( stripos( $ua, 'Linux' ) !== false ) {
				$os['Linux'] += $count;
			} else {
				$os['Other'] += $count;
			}
		}

		arsort( $os );
		return $os;
	}

	/**
	 * Get device distribution.
	 *
	 * @param int $days Number of days.
	 * @return array
	 */
	private function get_device_distribution( $days = 30 ) {
		global $wpdb;
		$table_name = $wpdb->prefix . self::TABLE_NAME;
		
		$results = $wpdb->get_results( $wpdb->prepare(
			"SELECT user_agent, COUNT(*) as count FROM {$table_name} 
			WHERE request_time >= DATE_SUB(NOW(), INTERVAL %d DAY) 
			GROUP BY user_agent",
			$days
		) );

		$devices = array(
			'Desktop' => 0,
			'Mobile' => 0,
			'Tablet' => 0,
			'Bot' => 0,
		);

		foreach ( $results as $row ) {
			$ua = $row->user_agent;
			$count = (int) $row->count;

			if ( stripos( $ua, 'bot' ) !== false || stripos( $ua, 'crawl' ) !== false || stripos( $ua, 'slurp' ) !== false || stripos( $ua, 'spider' ) !== false ) {
				$devices['Bot'] += $count;
			} elseif ( stripos( $ua, 'mobile' ) !== false || stripos( $ua, 'android' ) !== false || stripos( $ua, 'iphone' ) !== false ) {
				$devices['Mobile'] += $count;
			} elseif ( stripos( $ua, 'tablet' ) !== false || stripos( $ua, 'ipad' ) !== false ) {
				$devices['Tablet'] += $count;
			} else {
				$devices['Desktop'] += $count;
			}
		}

		return $devices;
	}

	/**
	 * Get chart data for visitor trends.
	 *
	 * @param int $days Number of days.
	 * @return array
	 */
	private function get_chart_data( $days = 30 ) {
		global $wpdb;
		$table_name = $wpdb->prefix . self::TABLE_NAME;

		$labels = array();
		$page_views = array();
		$unique_visitors = array();

		for ( $i = $days - 1; $i >= 0; $i-- ) {
			$date = gmdate( 'Y-m-d', strtotime( "-$i days" ) );
			$labels[] = gmdate( 'M j', strtotime( $date ) );

			$page_views[] = (int) $wpdb->get_var( $wpdb->prepare(
				"SELECT COUNT(*) FROM {$table_name} WHERE DATE(request_time) = %s",
				$date
			) );

			$unique_visitors[] = (int) $wpdb->get_var( $wpdb->prepare(
				"SELECT COUNT(DISTINCT ip_address) FROM {$table_name} WHERE DATE(request_time) = %s",
				$date
			) );
		}

		return array(
			'labels' => $labels,
			'page_views' => $page_views,
			'unique_visitors' => $unique_visitors,
		);
	}

	/**
	 * Get top visited pages.
	 *
	 * @param int $limit Number of results.
	 * @return array
	 */
	private function get_top_pages( $limit = 10, $days = 30 ) {
		global $wpdb;
		$table_name = $wpdb->prefix . self::TABLE_NAME;
		$days = max( 1, absint( $days ) );

		$results = $wpdb->get_results( $wpdb->prepare(
			"SELECT request_uri as url, COUNT(*) as count
			FROM {$table_name}
			WHERE request_time >= DATE_SUB(NOW(), INTERVAL %d DAY)
			AND request_uri NOT LIKE '%%/wp-admin%%'
			AND request_uri NOT LIKE '%%/wp-json%%'
			GROUP BY request_uri
			ORDER BY count DESC
			LIMIT %d",
			$days,
			$limit
		), ARRAY_A );

		return $results ? $results : array();
	}

	/**
	 * Get top referrers.
	 *
	 * @param int $limit Number of results.
	 * @return array
	 */
	private function get_top_referrers( $limit = 10, $days = 30 ) {
		global $wpdb;
		$table_name = $wpdb->prefix . self::TABLE_NAME;
		$days = max( 1, absint( $days ) );

		$results = $wpdb->get_results( $wpdb->prepare(
			"SELECT
				CASE
					WHEN referrer = '' THEN 'Direct'
					ELSE referrer
				END as referrer,
				COUNT(*) as count
			FROM {$table_name}
			WHERE request_time >= DATE_SUB(NOW(), INTERVAL %d DAY)
			GROUP BY referrer
			ORDER BY count DESC
			LIMIT %d",
			$days,
			$limit
		), ARRAY_A );

		return $results ? $results : array();
	}

	/**
	 * Get geographic distribution.
	 *
	 * @param int $limit Number of results.
	 * @return array
	 */
	private function get_geo_distribution( $limit = 10, $days = 30 ) {
		global $wpdb;
		$table_name = $wpdb->prefix . self::TABLE_NAME;
		$days = max( 1, absint( $days ) );

		$results = $wpdb->get_results( $wpdb->prepare(
			"SELECT
				CASE
					WHEN country_code = '' THEN 'Unknown'
					ELSE country_code
				END as country_code,
				COUNT(*) as count
			FROM {$table_name}
			WHERE request_time >= DATE_SUB(NOW(), INTERVAL %d DAY)
			GROUP BY country_code
			ORDER BY count DESC
			LIMIT %d",
			$days,
			$limit
		), ARRAY_A );

		if ( empty( $results ) || ! is_array( $results ) ) {
			return array();
		}

		// Add country names
		$country_names = $this->get_country_names();
		foreach ( $results as &$row ) {
			$row['country_name'] = isset( $country_names[ $row['country_code'] ] ) ? $country_names[ $row['country_code'] ] : $row['country_code'];
		}

		return $results;
	}

	/**
	 * Get country name mapping.
	 *
	 * @return array
	 */
	private function get_country_names() {
		if ( class_exists( 'NexifyMy_Security_Geo_Blocking' ) && method_exists( 'NexifyMy_Security_Geo_Blocking', 'get_country_list' ) ) {
			$full_list = NexifyMy_Security_Geo_Blocking::get_country_list();
			$full_list['Unknown'] = 'Unknown';
			return $full_list;
		}

		return array(
			'US' => 'United States',
			'GB' => 'United Kingdom',
			'CA' => 'Canada',
			'AU' => 'Australia',
			'DE' => 'Germany',
			'FR' => 'France',
			'IT' => 'Italy',
			'ES' => 'Spain',
			'NL' => 'Netherlands',
			'IN' => 'India',
			'CN' => 'China',
			'JP' => 'Japan',
			'BR' => 'Brazil',
			'MX' => 'Mexico',
			'RU' => 'Russia',
			'Unknown' => 'Unknown',
		);
	}
}
