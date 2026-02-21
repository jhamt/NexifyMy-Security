<?php
/**
 * Performance Optimizer Module.
 * Minimizes security plugin impact on site performance.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Performance {

	/**
	 * Option key for performance stats.
	 */
	const STATS_OPTION = 'nexifymy_performance_stats';

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'             => true,
		'smart_caching'       => true,
		'cache_ttl'           => 3600,        // 1 hour default.
		'throttle_scans'      => true,
		'max_scan_time'       => 30,          // Max seconds per scan batch.
		'max_memory_percent'  => 50,          // Max % of available memory to use.
		'defer_heavy_tasks'   => true,        // Defer to off-peak hours.
		'off_peak_start'      => 2,           // 2 AM.
		'off_peak_end'        => 6,           // 6 AM.
		'lazy_load_modules'   => true,
		'optimize_db_queries' => true,
	);

	/**
	 * Cache prefix.
	 */
	const CACHE_PREFIX = 'nexifymy_perf_';

	/**
	 * Start time for performance tracking.
	 */
	private $start_time;

	/**
	 * Start memory for tracking.
	 */
	private $start_memory;

	/**
	 * Initialize the module.
	 */
	public function init() {
		$this->start_time   = microtime( true );
		$this->start_memory = memory_get_usage();

		$settings = $this->get_settings();

		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Register shutdown to track performance.
		add_action( 'shutdown', array( $this, 'track_performance' ) );

		// Optimize database queries.
		if ( ! empty( $settings['optimize_db_queries'] ) ) {
			add_filter( 'query', array( $this, 'optimize_queries' ), 1 );
		}

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_get_performance_stats', array( $this, 'ajax_get_stats' ) );
		add_action( 'wp_ajax_nexifymy_clear_cache', array( $this, 'ajax_clear_cache' ) );
		add_action( 'wp_ajax_nexifymy_run_optimization', array( $this, 'ajax_run_optimization' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['performance'] ) ) {
				return wp_parse_args( $all_settings['performance'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Smart caching wrapper - get cached value or compute.
	 *
	 * @param string   $key Cache key.
	 * @param callable $callback Function to compute value if not cached.
	 * @param int      $ttl Time to live in seconds.
	 * @return mixed Cached or computed value.
	 */
	public function cache_get_or_set( $key, $callback, $ttl = null ) {
		$settings = $this->get_settings();

		if ( empty( $settings['smart_caching'] ) ) {
			return call_user_func( $callback );
		}

		if ( null === $ttl ) {
			$ttl = $settings['cache_ttl'];
		}

		$cache_key = self::CACHE_PREFIX . md5( $key );
		$cached    = get_transient( $cache_key );

		if ( false !== $cached ) {
			return $cached;
		}

		$value = call_user_func( $callback );
		set_transient( $cache_key, $value, $ttl );

		return $value;
	}

	/**
	 * Check if we should throttle (defer heavy operations).
	 *
	 * @return bool True if operation should be throttled/deferred.
	 */
	public function should_throttle() {
		$settings = $this->get_settings();

		if ( empty( $settings['throttle_scans'] ) ) {
			return false;
		}

		// Check memory usage.
		$memory_limit   = $this->get_memory_limit();
		$current_memory = memory_get_usage( true );
		$memory_percent = ( $current_memory / $memory_limit ) * 100;

		if ( $memory_percent > $settings['max_memory_percent'] ) {
			return true;
		}

		// Check if we're in a high-traffic period (simple heuristic).
		if ( $this->is_high_traffic_period() ) {
			return true;
		}

		return false;
	}

	/**
	 * Check if current time is off-peak.
	 *
	 * @return bool
	 */
	public function is_off_peak() {
		$settings     = $this->get_settings();
		$current_hour = (int) current_time( 'G' );

		return $current_hour >= $settings['off_peak_start'] && $current_hour < $settings['off_peak_end'];
	}

	/**
	 * Simple high-traffic detection.
	 *
	 * @return bool
	 */
	private function is_high_traffic_period() {
		// Business hours heuristic (9 AM - 6 PM weekdays).
		$current_hour = (int) current_time( 'G' );
		$day_of_week  = (int) current_time( 'w' );

		// Weekdays 9-18.
		if ( $day_of_week >= 1 && $day_of_week <= 5 ) {
			if ( $current_hour >= 9 && $current_hour <= 18 ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get PHP memory limit in bytes.
	 *
	 * @return int Memory limit in bytes.
	 */
	private function get_memory_limit() {
		$limit = ini_get( 'memory_limit' );

		if ( preg_match( '/^(\d+)(.)$/', $limit, $matches ) ) {
			$value = (int) $matches[1];
			switch ( strtoupper( $matches[2] ) ) {
				case 'G':
					$value *= 1024 * 1024 * 1024;
					break;
				case 'M':
					$value *= 1024 * 1024;
					break;
				case 'K':
					$value *= 1024;
					break;
			}
			return $value;
		}

		return 128 * 1024 * 1024; // Default 128MB.
	}

	/**
	 * Batched processing with resource limits.
	 *
	 * @param array    $items Items to process.
	 * @param callable $processor Function to process each item.
	 * @param int      $batch_size Items per batch.
	 * @return array Results.
	 */
	public function process_in_batches( $items, $processor, $batch_size = 50 ) {
		$settings   = $this->get_settings();
		$results    = array();
		$start_time = microtime( true );
		$max_time   = $settings['max_scan_time'];
		$processed  = 0;

		foreach ( $items as $item ) {
			// Check time limit.
			if ( ( microtime( true ) - $start_time ) > $max_time ) {
				$results['_truncated'] = true;
				$results['_processed'] = $processed;
				$results['_remaining'] = count( $items ) - $processed;
				break;
			}

			// Check memory.
			if ( $this->should_throttle() ) {
				$results['_throttled'] = true;
				$results['_processed'] = $processed;
				break;
			}

			// Process item.
			$result = call_user_func( $processor, $item );
			if ( null !== $result ) {
				$results[] = $result;
			}

			++$processed;

			// Yield CPU every batch.
			if ( $processed % $batch_size === 0 ) {
				usleep( 10000 ); // 10ms pause.
			}
		}

		return $results;
	}

	/**
	 * Lightweight IP check (cached).
	 *
	 * @param string $ip IP address.
	 * @param string $check_type Type of check.
	 * @return mixed Cached result.
	 */
	public function cached_ip_check( $ip, $check_type ) {
		$key = "ip_{$check_type}_{$ip}";

		return $this->cache_get_or_set(
			$key,
			function () use ( $ip, $check_type ) {
				// Placeholder for actual check.
				return array(
					'ip'      => $ip,
					'type'    => $check_type,
					'checked' => time(),
				);
			},
			3600
		);
	}

	/**
	 * Optimize database queries for our plugin tables.
	 *
	 * @param string $query SQL query.
	 * @return string Potentially optimized query.
	 */
	public function optimize_queries( $query ) {
		// Only optimize our own queries.
		if ( strpos( $query, 'nexifymy_' ) === false ) {
			return $query;
		}

		// Add query hints for large result sets.
		if ( stripos( $query, 'SELECT' ) === 0 && stripos( $query, 'LIMIT' ) === false ) {
			// Add reasonable limit if missing.
			if ( stripos( $query, 'COUNT(' ) === false ) {
				$query = rtrim( $query, ';' ) . ' LIMIT 1000';
			}
		}

		return $query;
	}

	/**
	 * Clear all plugin caches.
	 *
	 * @return int Number of caches cleared.
	 */
	public function clear_all_caches() {
		global $wpdb;

		// Delete all our transients.
		$count = $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
				'_transient_' . self::CACHE_PREFIX . '%',
				'_transient_timeout_' . self::CACHE_PREFIX . '%'
			)
		);

		// Clear object cache if available.
		if ( function_exists( 'wp_cache_flush_group' ) ) {
			wp_cache_flush_group( 'nexifymy_security' );
		}

		return $count;
	}

	/**
	 * Get performance statistics.
	 *
	 * @return array Stats.
	 */
	public function get_performance_stats() {
		global $wpdb;

		// Get stored stats.
		$stats = get_option( self::STATS_OPTION, array() );

		// Get cache count.
		$cache_count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE %s",
				'_transient_' . self::CACHE_PREFIX . '%'
			)
		);

		// Current request stats.
		$current = array(
			'request_time'    => round( ( microtime( true ) - $this->start_time ) * 1000, 2 ),
			'memory_used'     => size_format( memory_get_usage() - $this->start_memory ),
			'peak_memory'     => size_format( memory_get_peak_usage() ),
			'memory_limit'    => size_format( $this->get_memory_limit() ),
			'memory_percent'  => round( ( memory_get_usage( true ) / $this->get_memory_limit() ) * 100, 1 ),
			'cache_entries'   => (int) $cache_count,
			'is_off_peak'     => $this->is_off_peak(),
			'should_throttle' => $this->should_throttle(),
		);

		return array_merge( $stats, array( 'current' => $current ) );
	}

	/**
	 * Track performance on shutdown.
	 */
	public function track_performance() {
		// Only track admin requests to reduce overhead.
		if ( ! is_admin() ) {
			return;
		}

		$execution_time = microtime( true ) - $this->start_time;
		$memory_used    = memory_get_peak_usage() - $this->start_memory;

		// Store rolling average.
		$stats = get_option(
			self::STATS_OPTION,
			array(
				'requests_tracked' => 0,
				'avg_time_ms'      => 0,
				'avg_memory_kb'    => 0,
				'last_updated'     => '',
			)
		);

		$count                     = $stats['requests_tracked'] + 1;
		$stats['avg_time_ms']      = ( ( $stats['avg_time_ms'] * $stats['requests_tracked'] ) + ( $execution_time * 1000 ) ) / $count;
		$stats['avg_memory_kb']    = ( ( $stats['avg_memory_kb'] * $stats['requests_tracked'] ) + ( $memory_used / 1024 ) ) / $count;
		$stats['requests_tracked'] = min( $count, 1000 ); // Cap at 1000 for accuracy.
		$stats['last_updated']     = current_time( 'mysql' );

		update_option( self::STATS_OPTION, $stats, false );
	}

	/**
	 * Run optimization tasks.
	 *
	 * @return array Optimization results.
	 */
	public function run_optimization() {
		$results = array();

		// 1. Clear old caches.
		$cleared                   = $this->clear_all_caches();
		$results['caches_cleared'] = $cleared;

		// 2. Clean up old logs (keep last 7 days).
		global $wpdb;
		$table = $wpdb->prefix . 'nexifymy_security_logs';
		if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ) === $table ) {
			$deleted                     = $wpdb->query(
				"DELETE FROM {$table} WHERE created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)"
			);
			$results['old_logs_deleted'] = $deleted;
		}

		// 3. Clean up old traffic data.
		$traffic_table = $wpdb->prefix . 'nexifymy_traffic_log';
		if ( $wpdb->get_var( "SHOW TABLES LIKE '{$traffic_table}'" ) === $traffic_table ) {
			$deleted                        = $wpdb->query(
				"DELETE FROM {$traffic_table} WHERE timestamp < DATE_SUB(NOW(), INTERVAL 3 DAY)"
			);
			$results['old_traffic_deleted'] = $deleted;
		}

		// 4. Optimize tables.
		$tables = array(
			$wpdb->prefix . 'nexifymy_security_logs',
			$wpdb->prefix . 'nexifymy_traffic_log',
		);

		foreach ( $tables as $table ) {
			if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ) === $table ) {
				$wpdb->query( "OPTIMIZE TABLE {$table}" );
			}
		}
		$results['tables_optimized'] = count( $tables );

		$results['completed_at'] = current_time( 'mysql' );

		return $results;
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	/**
	 * Get performance stats via AJAX.
	 */
	public function ajax_get_stats() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		wp_send_json_success( $this->get_performance_stats() );
	}

	/**
	 * Clear cache via AJAX.
	 */
	public function ajax_clear_cache() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$count = $this->clear_all_caches();
		wp_send_json_success(
			array(
				'message' => sprintf( 'Cleared %d cache entries.', $count ),
				'cleared' => $count,
			)
		);
	}

	/**
	 * Run optimization via AJAX.
	 */
	public function ajax_run_optimization() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$results = $this->run_optimization();
		wp_send_json_success( $results );
	}
}
