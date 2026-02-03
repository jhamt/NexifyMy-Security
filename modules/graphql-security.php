<?php
/**
 * GraphQL Security Module
 * Protects WPGraphQL and headless WordPress GraphQL endpoints.
 *
 * @package    NexifyMy_Security
 * @subpackage NexifyMy_Security/modules
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_GraphQL_Security {

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'                => true,
		'max_query_depth'        => 10,
		'max_query_complexity'   => 1000,
		'disable_introspection'  => false,
		'rate_limit'             => 100,      // queries per minute
		'require_auth'           => false,
		'log_queries'            => true,
		'block_dangerous_queries'=> true,
		'whitelist_queries'      => array(),
	);

	private $query_depth = 0;
	private $query_complexity = 0;

	/**
	 * Initialize the module.
	 */
	public function init() {
		// Check if WPGraphQL is active
		if ( ! class_exists( 'WPGraphQL' ) ) {
			return;
		}

		$all_settings = get_option( 'nexifymy_security_settings', array() );
		if ( isset( $all_settings['modules']['graphql_security_enabled'] ) && ! $all_settings['modules']['graphql_security_enabled'] ) {
			return;
		}

		$settings = $this->get_settings();
		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Query depth limiting
		add_filter( 'graphql_request_results', array( $this, 'validate_query_depth' ), 10, 5 );

		// Disable introspection in production
		if ( ! empty( $settings['disable_introspection'] ) ) {
			add_filter( 'graphql_request_results', array( $this, 'disable_introspection' ), 10, 5 );
		}

		// Authentication requirement
		if ( ! empty( $settings['require_auth'] ) ) {
			add_filter( 'graphql_request_results', array( $this, 'require_authentication' ), 10, 5 );
		}

		// Rate limiting
		add_action( 'graphql_before_resolve_field', array( $this, 'check_rate_limit' ), 10 );

		// Query logging
		if ( ! empty( $settings['log_queries'] ) ) {
			add_action( 'graphql_execute', array( $this, 'log_query' ), 10, 2 );
		}

		// Dangerous query blocking
		if ( ! empty( $settings['block_dangerous_queries'] ) ) {
			add_filter( 'graphql_request_results', array( $this, 'block_dangerous_queries' ), 10, 5 );
		}

		// Query complexity
		add_action( 'graphql_before_resolve_field', array( $this, 'track_query_complexity' ), 10 );

		// AJAX handlers
		add_action( 'wp_ajax_nexifymy_get_graphql_stats', array( $this, 'ajax_get_stats' ) );
	}

	/**
	 * Get module settings.
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['graphql_security'] ) ) {
				return wp_parse_args( $all_settings['graphql_security'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Validate query depth.
	 */
	public function validate_query_depth( $result, $schema, $operation, $query, $variables ) {
		$settings = $this->get_settings();
		$max_depth = $settings['max_query_depth'];

		$depth = $this->calculate_query_depth( $query );

		if ( $depth > $max_depth ) {
			return new \WP_Error(
				'query_too_deep',
				sprintf( __( 'Query depth exceeds maximum allowed depth of %d', 'nexifymy-security' ), $max_depth ),
				array( 'status' => 400 )
			);
		}

		return $result;
	}

	/**
	 * Calculate query depth.
	 */
	private function calculate_query_depth( $query ) {
		$depth = 0;
		$current_depth = 0;
		$in_string = false;

		for ( $i = 0; $i < strlen( $query ); $i++ ) {
			$char = $query[ $i ];

			if ( $char === '"' && ( $i === 0 || $query[ $i - 1 ] !== '\\' ) ) {
				$in_string = ! $in_string;
			}

			if ( ! $in_string ) {
				if ( $char === '{' ) {
					$current_depth++;
					$depth = max( $depth, $current_depth );
				} elseif ( $char === '}' ) {
					$current_depth--;
				}
			}
		}

		return $depth;
	}

	/**
	 * Track query complexity.
	 */
	public function track_query_complexity() {
		$this->query_complexity++;

		$settings = $this->get_settings();
		$max_complexity = $settings['max_query_complexity'];

		if ( $this->query_complexity > $max_complexity ) {
			throw new \Exception( sprintf( __( 'Query complexity exceeds maximum of %d', 'nexifymy-security' ), $max_complexity ) );
		}
	}

	/**
	 * Disable introspection queries.
	 */
	public function disable_introspection( $result, $schema, $operation, $query, $variables ) {
		// Check if query contains introspection
		if ( preg_match( '/__schema|__type/i', $query ) ) {
			return new \WP_Error(
				'introspection_disabled',
				__( 'GraphQL introspection is disabled.', 'nexifymy-security' ),
				array( 'status' => 400 )
			);
		}

		return $result;
	}

	/**
	 * Require authentication for GraphQL.
	 */
	public function require_authentication( $result, $schema, $operation, $query, $variables ) {
		if ( ! is_user_logged_in() ) {
			return new \WP_Error(
				'unauthenticated',
				__( 'Authentication required for GraphQL access.', 'nexifymy-security' ),
				array( 'status' => 401 )
			);
		}

		return $result;
	}

	/**
	 * Check rate limit.
	 */
	public function check_rate_limit() {
		$settings = $this->get_settings();
		$limit = $settings['rate_limit'];

		$ip = $this->get_client_ip();
		$key = 'graphql_rate_' . md5( $ip );
		$count = get_transient( $key );

		if ( false === $count ) {
			set_transient( $key, 1, 60 );
		} else {
			$count++;
			set_transient( $key, $count, 60 );

			if ( $count > $limit ) {
				throw new \Exception( sprintf( __( 'GraphQL rate limit exceeded. Limit: %d queries per minute.', 'nexifymy-security' ), $limit ) );
			}
		}
	}

	/**
	 * Log GraphQL query.
	 */
	public function log_query( $schema, $operation_name ) {
		$query = isset( $_POST['query'] ) ? sanitize_textarea_field( wp_unslash( $_POST['query'] ) ) : '';

		if ( empty( $query ) ) {
			return;
		}

		$log_data = array(
			'ip' => $this->get_client_ip(),
			'query' => substr( $query, 0, 500 ),
			'operation' => $operation_name,
			'user_id' => get_current_user_id(),
			'depth' => $this->calculate_query_depth( $query ),
		);

		do_action( 'nexifymy_graphql_query_logged', $log_data );

		// Store in option for stats
		$logs = get_option( 'nexifymy_graphql_logs', array() );
		$logs[] = array(
			'time' => current_time( 'mysql' ),
			'operation' => $operation_name,
			'user_id' => get_current_user_id(),
		);

		// Keep last 100 logs
		$logs = array_slice( $logs, -100 );
		update_option( 'nexifymy_graphql_logs', $logs, false );
	}

	/**
	 * Block dangerous queries.
	 */
	public function block_dangerous_queries( $result, $schema, $operation, $query, $variables ) {
		$dangerous_patterns = array(
			'mutation.*delete',
			'mutation.*update.*password',
			'mutation.*create.*user',
			'query.*users.*password',
		);

		foreach ( $dangerous_patterns as $pattern ) {
			if ( preg_match( '/' . $pattern . '/i', $query ) && ! current_user_can( 'manage_options' ) ) {
				return new \WP_Error(
					'dangerous_query',
					__( 'This query is not allowed.', 'nexifymy-security' ),
					array( 'status' => 403 )
				);
			}
		}

		return $result;
	}

	/**
	 * Get client IP.
	 */
	private function get_client_ip() {
		$ip_keys = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR' );
		foreach ( $ip_keys as $key ) {
			if ( ! empty( $_SERVER[ $key ] ) ) {
				$ip = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}
		return '0.0.0.0';
	}

	/**
	 * Get GraphQL statistics.
	 */
	public function ajax_get_stats() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$logs = get_option( 'nexifymy_graphql_logs', array() );

		$stats = array(
			'total_queries' => count( $logs ),
			'queries_today' => 0,
			'active' => class_exists( 'WPGraphQL' ),
		);

		$today = gmdate( 'Y-m-d' );
		foreach ( $logs as $log ) {
			if ( isset( $log['time'] ) && strpos( $log['time'], $today ) === 0 ) {
				$stats['queries_today']++;
			}
		}

		wp_send_json_success( $stats );
	}
}
