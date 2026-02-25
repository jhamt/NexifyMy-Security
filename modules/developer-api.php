<?php
/**
 * Developer-First Security Module.
 * REST API, GraphQL Protection, Webhooks, and WP-CLI Integration.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Developer_API {

	/**
	 * REST API namespace.
	 */
	const REST_NAMESPACE = 'nexifymy-security/v1';

	/**
	 * Option key for API keys.
	 */
	const API_KEYS_OPTION = 'nexifymy_api_keys';

	/**
	 * Option key for webhook endpoints.
	 */
	const WEBHOOKS_OPTION = 'nexifymy_webhooks';

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'                  => true,
		'rest_api_enabled'         => true,
		'graphql_protection'       => true,
		'webhooks_enabled'         => true,
		'require_api_key'          => true,
		'rate_limit_api'           => 100,  // Requests per minute.
		'log_api_requests'         => true,
		'graphql_depth_limit'      => 10,
		'graphql_complexity_limit' => 500,
	);

	/**
	 * Webhook event types.
	 */
	private $webhook_events = array(
		'threat_detected'      => 'When AI detects a high-scoring threat',
		'login_failed'         => 'When a login attempt fails',
		'user_locked'          => 'When a user/IP is locked out',
		'malware_found'        => 'When malware is detected in a scan',
		'core_file_modified'   => 'When a core file is modified',
		'plugin_vulnerability' => 'When a plugin vulnerability is found',
		'scan_completed'       => 'When a security scan completes',
		'settings_changed'     => 'When security settings are modified',
	);

	/**
	 * Initialize the module.
	 */
	public function init() {
		$settings = $this->get_settings();

		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Register REST API routes.
		if ( ! empty( $settings['rest_api_enabled'] ) ) {
			add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );
		}

		// GraphQL protection.
		if ( ! empty( $settings['graphql_protection'] ) ) {
			add_action( 'init', array( $this, 'init_graphql_protection' ) );
		}

		// Webhook dispatcher hooks.
		if ( ! empty( $settings['webhooks_enabled'] ) ) {
			$this->register_webhook_listeners();
		}

		// Admin AJAX handlers.
		add_action( 'wp_ajax_nexifymy_generate_api_key', array( $this, 'ajax_generate_api_key' ) );
		add_action( 'wp_ajax_nexifymy_revoke_api_key', array( $this, 'ajax_revoke_api_key' ) );
		add_action( 'wp_ajax_nexifymy_get_api_keys', array( $this, 'ajax_get_api_keys' ) );
		add_action( 'wp_ajax_nexifymy_save_webhook', array( $this, 'ajax_save_webhook' ) );
		add_action( 'wp_ajax_nexifymy_delete_webhook', array( $this, 'ajax_delete_webhook' ) );
		add_action( 'wp_ajax_nexifymy_test_webhook', array( $this, 'ajax_test_webhook' ) );
		add_action( 'wp_ajax_nexifymy_get_webhooks', array( $this, 'ajax_get_webhooks' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['developer_api'] ) ) {
				return wp_parse_args( $all_settings['developer_api'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/*
	 * =========================================================================
	 * REST API
	 * =========================================================================
	 */

	/**
	 * Register REST API routes.
	 */
	public function register_rest_routes() {
		// Security Status.
		register_rest_route(
			self::REST_NAMESPACE,
			'/status',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'api_get_status' ),
				'permission_callback' => array( $this, 'api_permission_check' ),
			)
		);

		// Security Score.
		register_rest_route(
			self::REST_NAMESPACE,
			'/score',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'api_get_score' ),
				'permission_callback' => array( $this, 'api_permission_check' ),
			)
		);

		// Recent Threats.
		register_rest_route(
			self::REST_NAMESPACE,
			'/threats',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'api_get_threats' ),
				'permission_callback' => array( $this, 'api_permission_check' ),
			)
		);

		// Blocked IPs.
		register_rest_route(
			self::REST_NAMESPACE,
			'/blocked',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'api_get_blocked' ),
				'permission_callback' => array( $this, 'api_permission_check' ),
			)
		);

		// Block IP.
		register_rest_route(
			self::REST_NAMESPACE,
			'/block',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'api_block_ip' ),
				'permission_callback' => array( $this, 'api_permission_check' ),
				'args'                => array(
					'ip'     => array(
						'required'          => true,
						'validate_callback' => function ( $param ) {
							return filter_var( $param, FILTER_VALIDATE_IP );
						},
					),
					'reason' => array(
						'required' => false,
						'default'  => 'API request',
					),
				),
			)
		);

		// Unblock IP.
		register_rest_route(
			self::REST_NAMESPACE,
			'/unblock',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'api_unblock_ip' ),
				'permission_callback' => array( $this, 'api_permission_check' ),
				'args'                => array(
					'ip' => array(
						'required'          => true,
						'validate_callback' => function ( $param ) {
							return filter_var( $param, FILTER_VALIDATE_IP );
						},
					),
				),
			)
		);

		// Trigger Scan.
		register_rest_route(
			self::REST_NAMESPACE,
			'/scan',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'api_trigger_scan' ),
				'permission_callback' => array( $this, 'api_permission_check' ),
			)
		);

		// Get Scan Results.
		register_rest_route(
			self::REST_NAMESPACE,
			'/scan/results',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'api_get_scan_results' ),
				'permission_callback' => array( $this, 'api_permission_check' ),
			)
		);

		// Generate Report.
		register_rest_route(
			self::REST_NAMESPACE,
			'/report',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'api_generate_report' ),
				'permission_callback' => array( $this, 'api_permission_check' ),
			)
		);

		// Get Settings.
		register_rest_route(
			self::REST_NAMESPACE,
			'/settings',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'api_get_settings' ),
				'permission_callback' => array( $this, 'api_permission_check' ),
			)
		);

		// Update Settings.
		register_rest_route(
			self::REST_NAMESPACE,
			'/settings',
			array(
				'methods'             => 'PUT',
				'callback'            => array( $this, 'api_update_settings' ),
				'permission_callback' => array( $this, 'api_permission_check' ),
			)
		);

		// Audit Log.
		register_rest_route(
			self::REST_NAMESPACE,
			'/logs',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'api_get_logs' ),
				'permission_callback' => array( $this, 'api_permission_check' ),
				'args'                => array(
					'limit'  => array(
						'default' => 50,
					),
					'offset' => array(
						'default' => 0,
					),
					'type'   => array(
						'default' => '',
					),
				),
			)
		);
	}

	/**
	 * API permission check.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return bool|WP_Error
	 */
	public function api_permission_check( $request ) {
		$settings = $this->get_settings();

		// Check rate limit.
		if ( ! $this->check_rate_limit() ) {
			return new WP_Error( 'rate_limit_exceeded', 'API rate limit exceeded.', array( 'status' => 429 ) );
		}

		// If API key required, validate it.
		if ( ! empty( $settings['require_api_key'] ) ) {
			$api_key = $request->get_header( 'X-NexifyMy-API-Key' );
			$api_key = is_string( $api_key ) ? trim( $api_key ) : '';

			if ( empty( $api_key ) ) {
				return new WP_Error(
					'missing_api_key_header',
					'Missing API key. Send the key using the X-NexifyMy-API-Key header.',
					array( 'status' => 401 )
				);
			}

			if ( ! $this->validate_api_key( $api_key ) ) {
				return new WP_Error( 'invalid_api_key', 'Invalid or missing API key.', array( 'status' => 401 ) );
			}

			return true;
		}

		// Otherwise check if user is logged in as admin.
		return current_user_can( 'manage_options' );
	}

	/**
	 * Check API rate limit.
	 *
	 * @return bool
	 */
	private function check_rate_limit() {
		$settings = $this->get_settings();
		$limit    = $settings['rate_limit_api'];
		$ip       = $this->get_client_ip();
		$key      = 'nexifymy_api_rate_' . md5( $ip );

		$count = get_transient( $key );

		if ( $count === false ) {
			set_transient( $key, 1, 60 );
			return true;
		}

		if ( $count >= $limit ) {
			return false;
		}

		set_transient( $key, $count + 1, 60 );
		return true;
	}

	/**
	 * Validate API key.
	 *
	 * @param string $key API key.
	 * @return bool
	 */
	private function validate_api_key( $key ) {
		if ( empty( $key ) ) {
			return false;
		}

		$keys     = get_option( self::API_KEYS_OPTION, array() );
		$key_hash = hash( 'sha256', $key );

		foreach ( $keys as $key_id => $stored_key ) {
			if ( ! isset( $stored_key['hash'] ) ) {
				continue;
			}

			if ( hash_equals( $stored_key['hash'], $key_hash ) ) {
				// Update last used.
				$keys[ $key_id ]['last_used'] = current_time( 'mysql' );
				update_option( self::API_KEYS_OPTION, $keys, false );
				return true;
			}
		}

		return false;
	}

	/**
	 * Generate a new API key.
	 *
	 * @param string $name Key name/label.
	 * @return array Key data.
	 */
	public function generate_api_key( $name ) {
		$key      = 'nxs_' . bin2hex( random_bytes( 32 ) );
		$key_hash = hash( 'sha256', $key );

		$keys   = get_option( self::API_KEYS_OPTION, array() );
		$key_id = uniqid( 'key_' );

		$keys[ $key_id ] = array(
			'id'         => $key_id,
			'name'       => sanitize_text_field( $name ),
			'hash'       => $key_hash,
			'prefix'     => substr( $key, 0, 12 ) . '...',
			'created_at' => current_time( 'mysql' ),
			'last_used'  => null,
		);

		update_option( self::API_KEYS_OPTION, $keys, false );

		return array(
			'id'   => $key_id,
			'key'  => $key,  // Only shown once!
			'name' => $name,
		);
	}

	/**
	 * Revoke an API key.
	 *
	 * @param string $key_id Key ID.
	 * @return bool
	 */
	public function revoke_api_key( $key_id ) {
		$keys = get_option( self::API_KEYS_OPTION, array() );

		if ( isset( $keys[ $key_id ] ) ) {
			unset( $keys[ $key_id ] );
			update_option( self::API_KEYS_OPTION, $keys, false );
			return true;
		}

		return false;
	}

	/*
	 * =========================================================================
	 * REST API ENDPOINTS
	 * =========================================================================
	 */

	public function api_get_status( $request ) {
		$status = array(
			'healthy'          => true,
			'version'          => defined( 'NEXIFYMY_SECURITY_VERSION' ) ? NEXIFYMY_SECURITY_VERSION : '1.0.0',
			'wordpress'        => get_bloginfo( 'version' ),
			'php'              => PHP_VERSION,
			'modules_active'   => $this->count_active_modules(),
			'last_scan'        => get_option( 'nexifymy_last_scan_time', null ),
			'threats_today'    => $this->count_threats_today(),
			'firewall_enabled' => $this->is_module_enabled( 'waf' ),
			'ai_enabled'       => $this->is_module_enabled( 'ai_detection' ),
		);

		return rest_ensure_response( $status );
	}

	public function api_get_score( $request ) {
		$score = get_option( 'nexifymy_security_score', array() );
		return rest_ensure_response( $score );
	}

	public function api_get_threats( $request ) {
		$limit   = $request->get_param( 'limit' ) ?: 50;
		$threats = get_option( 'nexifymy_ai_detected_threats', array() );
		$threats = array_slice( array_reverse( $threats ), 0, $limit );
		return rest_ensure_response( $threats );
	}

	public function api_get_blocked( $request ) {
		if ( class_exists( 'NexifyMy_Security_Firewall' ) && method_exists( 'NexifyMy_Security_Firewall', 'get_blocked_ips' ) ) {
			$blocked = NexifyMy_Security_Firewall::get_blocked_ips();
		} else {
			$blocked = get_option( 'nexifymy_security_blocked_ips', array() );
		}
		return rest_ensure_response( $blocked );
	}

	public function api_block_ip( $request ) {
		$ip     = $request->get_param( 'ip' );
		$reason = $request->get_param( 'reason' );

		if ( class_exists( 'NexifyMy_Security_Firewall' ) && method_exists( 'NexifyMy_Security_Firewall', 'block_ip' ) ) {
			NexifyMy_Security_Firewall::block_ip( $ip, $reason );
		}

		// Trigger webhook.
		$this->dispatch_webhook(
			'user_locked',
			array(
				'ip'     => $ip,
				'reason' => $reason,
				'source' => 'api',
			)
		);

		return rest_ensure_response(
			array(
				'success' => true,
				'message' => "IP {$ip} blocked.",
			)
		);
	}

	public function api_unblock_ip( $request ) {
		$ip = $request->get_param( 'ip' );

		if ( class_exists( 'NexifyMy_Security_Firewall' ) && method_exists( 'NexifyMy_Security_Firewall', 'unblock_ip' ) ) {
			NexifyMy_Security_Firewall::unblock_ip( $ip );
		}

		return rest_ensure_response(
			array(
				'success' => true,
				'message' => "IP {$ip} unblocked.",
			)
		);
	}

	public function api_trigger_scan( $request ) {
		if ( isset( $GLOBALS['nexifymy_bg_scanner'] ) && method_exists( $GLOBALS['nexifymy_bg_scanner'], 'start_scan' ) ) {
			$GLOBALS['nexifymy_bg_scanner']->start_scan();
			return rest_ensure_response(
				array(
					'success' => true,
					'message' => 'Scan started.',
				)
			);
		}

		return rest_ensure_response(
			array(
				'success' => false,
				'message' => 'Scanner not available.',
			)
		);
	}

	public function api_get_scan_results( $request ) {
		$results = get_option( 'nexifymy_last_scan_results', array() );
		return rest_ensure_response( $results );
	}

	public function api_generate_report( $request ) {
		if ( isset( $GLOBALS['nexifymy_compliance'] ) && method_exists( $GLOBALS['nexifymy_compliance'], 'generate_report' ) ) {
			$report = $GLOBALS['nexifymy_compliance']->generate_report();
			return rest_ensure_response( $report );
		}

		return rest_ensure_response(
			array(
				'success' => false,
				'message' => 'Compliance module not available.',
			)
		);
	}

	public function api_get_settings( $request ) {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$settings = NexifyMy_Security_Settings::get_all();
			// Remove sensitive data.
			unset( $settings['api_keys'] );
			return rest_ensure_response( $settings );
		}

		return rest_ensure_response( array() );
	}

	public function api_update_settings( $request ) {
		$raw_body = $request->get_json_params();

		if ( empty( $raw_body ) || ! is_array( $raw_body ) ) {
			return new WP_Error( 'invalid_body', 'Request body is required.', array( 'status' => 400 ) );
		}

		$body = ( isset( $raw_body['settings'] ) && is_array( $raw_body['settings'] ) ) ? $raw_body['settings'] : $raw_body;
		if ( empty( $body ) || ! is_array( $body ) ) {
			return new WP_Error( 'invalid_settings', 'Settings payload must be a non-empty object.', array( 'status' => 400 ) );
		}

		if ( ! class_exists( 'NexifyMy_Security_Settings' ) ) {
			return new WP_Error( 'settings_unavailable', 'Settings module not available.', array( 'status' => 503 ) );
		}

		$current_settings = NexifyMy_Security_Settings::get_all();

		// Support both full settings payloads and flat developer_api payloads.
		$developer_api_keys           = array_keys( self::$defaults );
		$body_keys                    = array_keys( $body );
		$is_flat_developer_api_update = ! isset( $body['developer_api'] ) && ! empty( $body_keys ) && empty( array_diff( $body_keys, $developer_api_keys ) );
		$payload                      = $is_flat_developer_api_update ? array( 'developer_api' => $body ) : $body;

		NexifyMy_Security_Settings::save( $payload );
		$updated_settings = NexifyMy_Security_Settings::get_all();

		$changed_keys = array();
		foreach ( $updated_settings as $key => $value ) {
			if ( ! array_key_exists( $key, $current_settings ) || $current_settings[ $key ] !== $value ) {
				$changed_keys[] = $key;
			}
		}

		// Hide Login relies on rewrite rules when slug/enabled state changes.
		if (
			in_array( 'hide_login', $changed_keys, true ) &&
			class_exists( 'NexifyMy_Security_Hide_Login' ) &&
			method_exists( 'NexifyMy_Security_Hide_Login', 'flush_rules' )
		) {
			NexifyMy_Security_Hide_Login::flush_rules();
		}

		$response_settings = $updated_settings;
		unset( $response_settings['api_keys'] );

		return rest_ensure_response(
			array(
				'success'      => true,
				'message'      => 'Settings updated.',
				'changed_keys' => $changed_keys,
				'settings'     => $response_settings,
			)
		);
	}

	public function api_get_logs( $request ) {
		global $wpdb;

		$limit  = (int) $request->get_param( 'limit' );
		$offset = (int) $request->get_param( 'offset' );
		$type   = sanitize_text_field( $request->get_param( 'type' ) );

		$table        = $wpdb->prefix . 'nexifymy_logs';
		$table_exists = $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ) === $table;

		if ( ! $table_exists ) {
			return rest_ensure_response( array() );
		}

		$where = '';
		if ( $type ) {
			$where = $wpdb->prepare( ' WHERE event_type = %s', $type );
		}

		$logs = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} {$where} ORDER BY created_at DESC LIMIT %d OFFSET %d",
				$limit,
				$offset
			),
			ARRAY_A
		);

		return rest_ensure_response( $logs );
	}

	/*
	 * =========================================================================
	 * GRAPHQL PROTECTION
	 * =========================================================================
	 */

	/**
	 * Initialize GraphQL protection.
	 */
	public function init_graphql_protection() {
		// Hook into WPGraphQL if available.
		add_filter( 'graphql_request_data', array( $this, 'validate_graphql_request' ), 10, 2 );
		add_filter( 'graphql_max_query_depth', array( $this, 'set_graphql_depth_limit' ) );
		add_filter( 'graphql_max_query_complexity', array( $this, 'set_graphql_complexity_limit' ) );

		// Block introspection in production.
		add_filter( 'graphql_introspection_disabled', array( $this, 'disable_graphql_introspection' ) );
	}

	/**
	 * Validate GraphQL request for security.
	 *
	 * @param array  $data Request data.
	 * @param object $request Request object.
	 * @return array
	 */
	public function validate_graphql_request( $data, $request ) {
		$query = $data['query'] ?? '';

		// Block potentially dangerous operations.
		$dangerous_patterns = array(
			'__schema',      // Schema introspection (unless allowed).
			'__type',        // Type introspection.
			'mutation.*delete', // Batch deletions.
		);

		// Log GraphQL requests.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'graphql_request',
				'GraphQL query executed',
				'info',
				array( 'query_preview' => substr( $query, 0, 200 ) )
			);
		}

		return $data;
	}

	/**
	 * Set GraphQL depth limit.
	 *
	 * @param int $depth Default depth.
	 * @return int
	 */
	public function set_graphql_depth_limit( $depth ) {
		$settings = $this->get_settings();
		return $settings['graphql_depth_limit'];
	}

	/**
	 * Set GraphQL complexity limit.
	 *
	 * @param int $complexity Default complexity.
	 * @return int
	 */
	public function set_graphql_complexity_limit( $complexity ) {
		$settings = $this->get_settings();
		return $settings['graphql_complexity_limit'];
	}

	/**
	 * Disable introspection in production.
	 *
	 * @param bool $disabled Default.
	 * @return bool
	 */
	public function disable_graphql_introspection( $disabled ) {
		// Disable in production.
		return ! defined( 'WP_DEBUG' ) || ! WP_DEBUG;
	}

	/*
	 * =========================================================================
	 * WEBHOOKS
	 * =========================================================================
	 */

	/**
	 * Register webhook listeners.
	 */
	private function register_webhook_listeners() {
		// Threat detected.
		add_action(
			'nexifymy_threat_detected',
			function ( $threat_data, $reason = '', $score = 0 ) {
				if ( ! is_array( $threat_data ) ) {
					$threat_data = array(
						'ip'     => sanitize_text_field( (string) $threat_data ),
						'reason' => sanitize_text_field( (string) $reason ),
						'score'  => absint( $score ),
					);
				}

				$this->dispatch_webhook( 'threat_detected', $threat_data );
			},
			10,
			3
		);

		// Login failed.
		add_action(
			'wp_login_failed',
			function ( $username ) {
				$this->dispatch_webhook(
					'login_failed',
					array(
						'username' => $username,
						'ip'       => $this->get_client_ip(),
					)
				);
			}
		);

		// User locked.
		add_action(
			'nexifymy_user_locked',
			function ( $data ) {
				$this->dispatch_webhook( 'user_locked', $data );
			}
		);

		// Malware found.
		add_action(
			'nexifymy_malware_found',
			function ( $findings ) {
				$this->dispatch_webhook( 'malware_found', $findings );
			}
		);

		// Scan completed.
		add_action(
			'nexifymy_scan_completed',
			function ( $results ) {
				$this->dispatch_webhook( 'scan_completed', $results );
			}
		);

		// Settings changed.
		add_action(
			'update_option_nexifymy_security_settings',
			function ( $old, $new ) {
				$old = is_array( $old ) ? $old : array();
				$new = is_array( $new ) ? $new : array();

				$this->dispatch_webhook(
					'settings_changed',
					array(
						'changed' => array_keys( array_diff_assoc( $new, $old ) ),
						'source'  => ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ? 'api' : 'runtime',
					)
				);
			},
			10,
			2
		);
	}

	/**
	 * Dispatch webhook to all registered endpoints.
	 *
	 * @param string $event Event type.
	 * @param array  $data Event data.
	 */
	public function dispatch_webhook( $event, $data ) {
		$webhooks = get_option( self::WEBHOOKS_OPTION, array() );

		foreach ( $webhooks as $webhook ) {
			if ( ! in_array( $event, $webhook['events'], true ) ) {
				continue;
			}

			if ( empty( $webhook['enabled'] ) ) {
				continue;
			}

			$payload = array(
				'event'     => $event,
				'timestamp' => current_time( 'c' ),
				'site_url'  => home_url(),
				'data'      => $data,
			);

			// Sign payload if secret is set.
			$headers = array(
				'Content-Type' => 'application/json',
			);

			if ( ! empty( $webhook['secret'] ) ) {
				$signature                       = hash_hmac( 'sha256', wp_json_encode( $payload ), $webhook['secret'] );
				$headers['X-NexifyMy-Signature'] = $signature;
			}

			// Send async using wp_remote_post.
			wp_remote_post(
				$webhook['url'],
				array(
					'body'     => wp_json_encode( $payload ),
					'headers'  => $headers,
					'timeout'  => 5,
					'blocking' => false,
				)
			);

			// Log webhook dispatch.
			if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
				NexifyMy_Security_Logger::log(
					'webhook_dispatched',
					sprintf( 'Webhook dispatched: %s to %s', $event, $webhook['url'] ),
					'info'
				);
			}
		}
	}

	/**
	 * Save/update a webhook.
	 *
	 * @param array $webhook_data Webhook data.
	 * @return string Webhook ID.
	 */
	public function save_webhook( $webhook_data ) {
		$webhooks = get_option( self::WEBHOOKS_OPTION, array() );

		$id = $webhook_data['id'] ?? uniqid( 'wh_' );

		$webhooks[ $id ] = array(
			'id'         => $id,
			'name'       => sanitize_text_field( $webhook_data['name'] ?? 'Webhook' ),
			'url'        => esc_url_raw( $webhook_data['url'] ),
			'secret'     => sanitize_text_field( $webhook_data['secret'] ?? '' ),
			'events'     => array_map( 'sanitize_key', $webhook_data['events'] ?? array() ),
			'enabled'    => ! empty( $webhook_data['enabled'] ),
			'created_at' => $webhooks[ $id ]['created_at'] ?? current_time( 'mysql' ),
		);

		update_option( self::WEBHOOKS_OPTION, $webhooks, false );

		return $id;
	}

	/**
	 * Delete a webhook.
	 *
	 * @param string $id Webhook ID.
	 * @return bool
	 */
	public function delete_webhook( $id ) {
		$webhooks = get_option( self::WEBHOOKS_OPTION, array() );

		if ( isset( $webhooks[ $id ] ) ) {
			unset( $webhooks[ $id ] );
			update_option( self::WEBHOOKS_OPTION, $webhooks, false );
			return true;
		}

		return false;
	}

	/**
	 * Get available webhook events.
	 *
	 * @return array
	 */
	public function get_webhook_events() {
		return $this->webhook_events;
	}

	/*
	 * =========================================================================
	 * WP-CLI COMMANDS
	 * =========================================================================
	 */

	/**
	 * Register WP-CLI commands.
	 */
	public static function register_cli_commands() {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}

		WP_CLI::add_command( 'nexifymy', 'NexifyMy_Security_CLI' );
	}

	/*
	 * =========================================================================
	 * HELPER METHODS
	 * =========================================================================
	 */

	private function count_active_modules() {
		$count   = 0;
		$modules = array( 'waf', 'scanner', 'rate_limiter', 'two_factor', 'ai_detection', 'passkey' );

		foreach ( $modules as $module ) {
			if ( $this->is_module_enabled( $module ) ) {
				++$count;
			}
		}

		return $count;
	}

	private function is_module_enabled( $module ) {
		if ( ! class_exists( 'NexifyMy_Security_Settings' ) ) {
			return false;
		}

		$settings = NexifyMy_Security_Settings::get_all();
		$aliases  = array(
			'2fa' => 'two_factor',
		);
		$module   = $aliases[ $module ] ?? $module;

		$module_flag_map = array(
			'waf'          => 'waf_enabled',
			'scanner'      => 'scanner_enabled',
			'rate_limiter' => 'rate_limiter_enabled',
			'two_factor'   => 'two_factor_enabled',
			'ai_detection' => 'ai_detection_enabled',
			'passkey'      => 'passkey_enabled',
		);

		if ( isset( $module_flag_map[ $module ] ) ) {
			$flag = $module_flag_map[ $module ];
			if ( isset( $settings['modules'][ $flag ] ) ) {
				return ! empty( $settings['modules'][ $flag ] );
			}
		}

		if ( ! empty( $settings[ $module ]['enabled'] ) ) {
			return true;
		}

		if ( 'two_factor' === $module && ! empty( $settings['2fa']['enabled'] ) ) {
			return true;
		}

		return false;
	}

	private function count_threats_today() {
		global $wpdb;
		$table        = $wpdb->prefix . 'nexifymy_behavior_log';
		$table_exists = $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ) === $table;

		if ( ! $table_exists ) {
			return 0;
		}

		return (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$table} WHERE threat_score >= 75 AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)"
		);
	}

	private function get_client_ip() {
		$remote_addr     = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$trusted_proxies = get_option( 'nexifymy_security_trusted_proxies', array() );

		if ( $remote_addr && in_array( $remote_addr, (array) $trusted_proxies, true ) ) {
			$ip_keys = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP' );
			foreach ( $ip_keys as $key ) {
				if ( empty( $_SERVER[ $key ] ) ) {
					continue;
				}

				$ip = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
				if ( strpos( $ip, ',' ) !== false ) {
					$ip = trim( explode( ',', $ip )[0] );
				}
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

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	public function ajax_generate_api_key() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$name     = isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : 'API Key';
		$key_data = $this->generate_api_key( $name );

		wp_send_json_success( $key_data );
	}

	public function ajax_revoke_api_key() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$key_id  = isset( $_POST['key_id'] ) ? sanitize_text_field( wp_unslash( $_POST['key_id'] ) ) : '';
		$revoked = $this->revoke_api_key( $key_id );

		wp_send_json_success( array( 'revoked' => $revoked ) );
	}

	public function ajax_get_api_keys() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$keys = get_option( self::API_KEYS_OPTION, array() );

		// Remove hashes before sending.
		foreach ( $keys as &$key ) {
			unset( $key['hash'] );
		}

		wp_send_json_success( $keys );
	}

	public function ajax_save_webhook() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$webhook_data = array(
			'id'      => isset( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : '',
			'name'    => isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : 'Webhook',
			'url'     => isset( $_POST['url'] ) ? esc_url_raw( wp_unslash( $_POST['url'] ) ) : '',
			'secret'  => isset( $_POST['secret'] ) ? sanitize_text_field( wp_unslash( $_POST['secret'] ) ) : '',
			'events'  => isset( $_POST['events'] ) ? array_map( 'sanitize_key', (array) $_POST['events'] ) : array(),
			'enabled' => ! empty( $_POST['enabled'] ),
		);

		$id = $this->save_webhook( $webhook_data );
		wp_send_json_success( array( 'id' => $id ) );
	}

	public function ajax_delete_webhook() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$id      = isset( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : '';
		$deleted = $this->delete_webhook( $id );

		wp_send_json_success( array( 'deleted' => $deleted ) );
	}

	public function ajax_test_webhook() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$url = isset( $_POST['url'] ) ? esc_url_raw( wp_unslash( $_POST['url'] ) ) : '';

		if ( empty( $url ) ) {
			wp_send_json_error( 'URL is required.' );
		}

		$payload = array(
			'event'     => 'test',
			'timestamp' => current_time( 'c' ),
			'site_url'  => home_url(),
			'data'      => array( 'message' => 'This is a test webhook from SecureWP360.' ),
		);

		$response = wp_remote_post(
			$url,
			array(
				'body'    => wp_json_encode( $payload ),
				'headers' => array( 'Content-Type' => 'application/json' ),
				'timeout' => 10,
			)
		);

		if ( is_wp_error( $response ) ) {
			wp_send_json_error( $response->get_error_message() );
		}

		wp_send_json_success(
			array(
				'status_code' => wp_remote_retrieve_response_code( $response ),
				'body'        => wp_remote_retrieve_body( $response ),
			)
		);
	}

	public function ajax_get_webhooks() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$webhooks = get_option( self::WEBHOOKS_OPTION, array() );

		// Remove secrets before sending.
		foreach ( $webhooks as &$webhook ) {
			$webhook['secret'] = ! empty( $webhook['secret'] ) ? '********' : '';
		}

		wp_send_json_success(
			array(
				'webhooks' => $webhooks,
				'events'   => $this->webhook_events,
			)
		);
	}
}

/*
 * =========================================================================
 * WP-CLI COMMAND CLASS
 * =========================================================================
 */

if ( defined( 'WP_CLI' ) && WP_CLI ) {

	class NexifyMy_Security_CLI {

		/**
		 * Get security status.
		 *
		 * ## EXAMPLES
		 *     wp nexifymy status
		 *
		 * @when after_wp_load
		 */
		public function status( $args, $assoc_args ) {
			$status = array(
				'Version'      => defined( 'NEXIFYMY_SECURITY_VERSION' ) ? NEXIFYMY_SECURITY_VERSION : 'N/A',
				'WordPress'    => get_bloginfo( 'version' ),
				'PHP'          => PHP_VERSION,
				'Firewall'     => $this->check_enabled( 'waf' ) ? 'Enabled' : 'Disabled',
				'Scanner'      => $this->check_enabled( 'scanner' ) ? 'Enabled' : 'Disabled',
				'2FA'          => $this->check_enabled( 'two_factor' ) ? 'Enabled' : 'Disabled',
				'AI Detection' => $this->check_enabled( 'ai_detection' ) ? 'Enabled' : 'Disabled',
			);

			WP_CLI::success( 'SecureWP360 Status:' );
			foreach ( $status as $key => $value ) {
				WP_CLI::log( sprintf( '  %s: %s', $key, $value ) );
			}
		}

		/**
		 * Run a security scan.
		 *
		 * ## EXAMPLES
		 *     wp nexifymy scan
		 *
		 * @when after_wp_load
		 */
		public function scan( $args, $assoc_args ) {
			WP_CLI::log( 'Starting security scan...' );

			if ( isset( $GLOBALS['nexifymy_bg_scanner'] ) && method_exists( $GLOBALS['nexifymy_bg_scanner'], 'start_scan' ) ) {
				$GLOBALS['nexifymy_bg_scanner']->start_scan();
				WP_CLI::success( 'Scan initiated. Check the dashboard for results.' );
			} else {
				WP_CLI::error( 'Scanner module not available.' );
			}
		}

		/**
		 * Block an IP address.
		 *
		 * ## OPTIONS
		 *
		 * <ip>
		 * : The IP address to block.
		 *
		 * [--reason=<reason>]
		 * : Reason for blocking.
		 *
		 * ## EXAMPLES
		 *     wp nexifymy block 192.168.1.100 --reason="Suspicious activity"
		 *
		 * @when after_wp_load
		 */
		public function block( $args, $assoc_args ) {
			$ip     = $args[0];
			$reason = $assoc_args['reason'] ?? 'CLI block';

			if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				WP_CLI::error( 'Invalid IP address.' );
			}

			if ( isset( $GLOBALS['nexifymy_waf'] ) && method_exists( $GLOBALS['nexifymy_waf'], 'add_to_blocklist' ) ) {
				$GLOBALS['nexifymy_waf']->add_to_blocklist( $ip, $reason );
				WP_CLI::success( "IP {$ip} has been blocked." );
			} else {
				WP_CLI::error( 'Firewall module not available.' );
			}
		}

		/**
		 * Unblock an IP address.
		 *
		 * ## OPTIONS
		 *
		 * <ip>
		 * : The IP address to unblock.
		 *
		 * ## EXAMPLES
		 *     wp nexifymy unblock 192.168.1.100
		 *
		 * @when after_wp_load
		 */
		public function unblock( $args, $assoc_args ) {
			$ip = $args[0];

			if ( isset( $GLOBALS['nexifymy_waf'] ) && method_exists( $GLOBALS['nexifymy_waf'], 'remove_from_blocklist' ) ) {
				$GLOBALS['nexifymy_waf']->remove_from_blocklist( $ip );
				WP_CLI::success( "IP {$ip} has been unblocked." );
			} else {
				WP_CLI::error( 'Firewall module not available.' );
			}
		}

		/**
		 * Generate a security report.
		 *
		 * ## EXAMPLES
		 *     wp nexifymy report
		 *
		 * @when after_wp_load
		 */
		public function report( $args, $assoc_args ) {
			WP_CLI::log( 'Generating security report...' );

			if ( isset( $GLOBALS['nexifymy_compliance'] ) && method_exists( $GLOBALS['nexifymy_compliance'], 'generate_report' ) ) {
				$report = $GLOBALS['nexifymy_compliance']->generate_report();
				WP_CLI::success(
					sprintf(
						'Report generated! Grade: %s, Score: %d%%',
						$report['summary']['grade'],
						$report['summary']['score']
					)
				);
			} else {
				WP_CLI::error( 'Compliance module not available.' );
			}
		}

		/**
		 * Show security score.
		 *
		 * ## EXAMPLES
		 *     wp nexifymy score
		 *
		 * @when after_wp_load
		 */
		public function score( $args, $assoc_args ) {
			$score = get_option( 'nexifymy_security_score', array() );

			if ( empty( $score ) ) {
				WP_CLI::warning( 'No security score available. Run a benchmark first.' );
				return;
			}

			WP_CLI::success(
				sprintf(
					'Security Grade: %s (%d%%)',
					$score['grade'] ?? 'N/A',
					$score['score'] ?? 0
				)
			);
		}

		/**
		 * Generate API key.
		 *
		 * ## OPTIONS
		 *
		 * [--name=<name>]
		 * : Name for the API key.
		 *
		 * ## EXAMPLES
		 *     wp nexifymy apikey --name="CI/CD Pipeline"
		 *
		 * @when after_wp_load
		 */
		public function apikey( $args, $assoc_args ) {
			$name = $assoc_args['name'] ?? 'CLI Generated Key';

			if ( isset( $GLOBALS['nexifymy_dev_api'] ) && method_exists( $GLOBALS['nexifymy_dev_api'], 'generate_api_key' ) ) {
				$key_data = $GLOBALS['nexifymy_dev_api']->generate_api_key( $name );
				WP_CLI::success( 'API Key generated:' );
				WP_CLI::log( sprintf( '  Name: %s', $key_data['name'] ) );
				WP_CLI::log( sprintf( '  Key:  %s', $key_data['key'] ) );
				WP_CLI::warning( 'Save this key now! It will not be shown again.' );
			} else {
				WP_CLI::error( 'Developer API module not available.' );
			}
		}

		private function check_enabled( $module ) {
			if ( ! class_exists( 'NexifyMy_Security_Settings' ) ) {
				return false;
			}

			$settings = NexifyMy_Security_Settings::get_all();
			$aliases  = array(
				'2fa' => 'two_factor',
			);
			$module   = $aliases[ $module ] ?? $module;

			$module_flag_map = array(
				'waf'          => 'waf_enabled',
				'scanner'      => 'scanner_enabled',
				'rate_limiter' => 'rate_limiter_enabled',
				'two_factor'   => 'two_factor_enabled',
				'ai_detection' => 'ai_detection_enabled',
				'passkey'      => 'passkey_enabled',
			);

			if ( isset( $module_flag_map[ $module ] ) ) {
				$flag = $module_flag_map[ $module ];
				if ( isset( $settings['modules'][ $flag ] ) ) {
					return ! empty( $settings['modules'][ $flag ] );
				}
			}

			if ( ! empty( $settings[ $module ]['enabled'] ) ) {
				return true;
			}

			return 'two_factor' === $module && ! empty( $settings['2fa']['enabled'] );
		}
	}
}

// Register CLI commands on load.
add_action( 'cli_init', array( 'NexifyMy_Security_Developer_API', 'register_cli_commands' ) );

