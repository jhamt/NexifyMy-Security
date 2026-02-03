<?php
/**
 * Advanced API Security Module
 * Protects REST API, GraphQL, and headless WordPress setups.
 *
 * @package    NexifyMy_Security
 * @subpackage NexifyMy_Security/modules
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_API_Security {

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'                => true,
		'require_auth_rest'      => false,
		'jwt_auth_enabled'       => true,
		'jwt_secret_key'         => '',
		'api_rate_limit'         => 100,      // requests per minute
		'api_rate_window'        => 60,       // seconds
		'block_user_enumeration' => true,
		'restrict_endpoints'     => array(),
		'allowed_origins'        => array(),
		'log_api_requests'       => true,
	);

	/**
	 * Initialize the module.
	 */
	public function init() {
		$all_settings = get_option( 'nexifymy_security_settings', array() );
		if ( isset( $all_settings['modules']['api_security_enabled'] ) && ! $all_settings['modules']['api_security_enabled'] ) {
			return;
		}

		$settings = $this->get_settings();
		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// REST API security
		add_filter( 'rest_authentication_errors', array( $this, 'check_rest_authentication' ), 10 );
		add_filter( 'rest_pre_dispatch', array( $this, 'check_api_rate_limit' ), 10, 3 );

		// JWT Authentication
		if ( ! empty( $settings['jwt_auth_enabled'] ) ) {
			add_filter( 'rest_authentication_errors', array( $this, 'jwt_authenticate' ), 20 );
			add_action( 'rest_api_init', array( $this, 'register_jwt_endpoints' ) );
		}

		// Block user enumeration
		if ( ! empty( $settings['block_user_enumeration'] ) ) {
			add_filter( 'rest_endpoints', array( $this, 'filter_user_endpoints' ) );
			add_action( 'init', array( $this, 'block_author_enumeration' ) );
		}

		// CORS headers
		add_action( 'rest_api_init', array( $this, 'add_cors_headers' ) );

		// API request logging
		if ( ! empty( $settings['log_api_requests'] ) ) {
			add_action( 'rest_api_init', array( $this, 'log_api_request' ) );
		}

		// AJAX handlers
		add_action( 'wp_ajax_nexifymy_get_api_stats', array( $this, 'ajax_get_api_stats' ) );
		add_action( 'wp_ajax_nexifymy_save_api_settings', array( $this, 'ajax_save_settings' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['api_security'] ) ) {
				return wp_parse_args( $all_settings['api_security'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Check REST API authentication.
	 *
	 * @param WP_Error|null|bool $result Authentication result.
	 * @return WP_Error|null|bool
	 */
	public function check_rest_authentication( $result ) {
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$settings = $this->get_settings();

		// Require authentication for all REST requests
		if ( ! empty( $settings['require_auth_rest'] ) && ! is_user_logged_in() ) {
			return new WP_Error(
				'rest_authentication_required',
				__( 'Authentication required for API access.', 'nexifymy-security' ),
				array( 'status' => 401 )
			);
		}

		return $result;
	}

	/**
	 * JWT Authentication.
	 *
	 * @param WP_Error|null|bool $result Authentication result.
	 * @return WP_Error|null|bool
	 */
	public function jwt_authenticate( $result ) {
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		// Check for JWT token in Authorization header
		$auth_header = isset( $_SERVER['HTTP_AUTHORIZATION'] ) ? $_SERVER['HTTP_AUTHORIZATION'] : '';
		if ( empty( $auth_header ) ) {
			$auth_header = isset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] : '';
		}

		if ( empty( $auth_header ) ) {
			return $result;
		}

		// Extract token
		list( $token ) = sscanf( $auth_header, 'Bearer %s' );
		if ( empty( $token ) ) {
			return $result;
		}

		// Verify JWT token
		$user_id = $this->verify_jwt_token( $token );
		if ( ! $user_id ) {
			return new WP_Error(
				'jwt_auth_invalid_token',
				__( 'Invalid JWT token.', 'nexifymy-security' ),
				array( 'status' => 403 )
			);
		}

		// Set current user
		wp_set_current_user( $user_id );

		return true;
	}

	/**
	 * Register JWT authentication endpoints.
	 */
	public function register_jwt_endpoints() {
		register_rest_route( 'nexifymy-security/v1', '/token', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'generate_jwt_token' ),
			'permission_callback' => '__return_true',
		) );

		register_rest_route( 'nexifymy-security/v1', '/token/validate', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'validate_jwt_endpoint' ),
			'permission_callback' => '__return_true',
		) );
	}

	/**
	 * Generate JWT token endpoint.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function generate_jwt_token( $request ) {
		$username = $request->get_param( 'username' );
		$password = $request->get_param( 'password' );

		if ( empty( $username ) || empty( $password ) ) {
			return new WP_Error( 'jwt_auth_bad_request', __( 'Username and password required.', 'nexifymy-security' ), array( 'status' => 400 ) );
		}

		$user = wp_authenticate( $username, $password );

		if ( is_wp_error( $user ) ) {
			return new WP_Error( 'jwt_auth_failed', __( 'Invalid credentials.', 'nexifymy-security' ), array( 'status' => 403 ) );
		}

		$token = $this->create_jwt_token( $user->ID );

		return rest_ensure_response( array(
			'token'      => $token,
			'user_email' => $user->user_email,
			'user_nicename' => $user->user_nicename,
			'user_display_name' => $user->display_name,
		) );
	}

	/**
	 * Create JWT token.
	 *
	 * @param int $user_id User ID.
	 * @return string JWT token.
	 */
	private function create_jwt_token( $user_id ) {
		$settings = $this->get_settings();
		$secret_key = ! empty( $settings['jwt_secret_key'] ) ? $settings['jwt_secret_key'] : wp_salt( 'auth' );

		$issued_at = time();
		$expiration = $issued_at + ( DAY_IN_SECONDS * 7 ); // 7 days

		$payload = array(
			'iss' => get_bloginfo( 'url' ),
			'iat' => $issued_at,
			'exp' => $expiration,
			'data' => array(
				'user' => array(
					'id' => $user_id,
				),
			),
		);

		return $this->jwt_encode( $payload, $secret_key );
	}

	/**
	 * Simple JWT encode (header.payload.signature).
	 *
	 * @param array  $payload Payload data.
	 * @param string $key Secret key.
	 * @return string JWT token.
	 */
	private function jwt_encode( $payload, $key ) {
		$header = array( 'typ' => 'JWT', 'alg' => 'HS256' );

		$segments = array();
		$segments[] = $this->base64url_encode( wp_json_encode( $header ) );
		$segments[] = $this->base64url_encode( wp_json_encode( $payload ) );
		$signing_input = implode( '.', $segments );

		$signature = hash_hmac( 'sha256', $signing_input, $key, true );
		$segments[] = $this->base64url_encode( $signature );

		return implode( '.', $segments );
	}

	/**
	 * Verify JWT token.
	 *
	 * @param string $token JWT token.
	 * @return int|false User ID or false.
	 */
	private function verify_jwt_token( $token ) {
		$settings = $this->get_settings();
		$secret_key = ! empty( $settings['jwt_secret_key'] ) ? $settings['jwt_secret_key'] : wp_salt( 'auth' );

		$segments = explode( '.', $token );
		if ( count( $segments ) !== 3 ) {
			return false;
		}

		list( $header64, $payload64, $signature64 ) = $segments;

		$header = json_decode( $this->base64url_decode( $header64 ), true );
		$payload = json_decode( $this->base64url_decode( $payload64 ), true );

		if ( empty( $header ) || empty( $payload ) ) {
			return false;
		}

		// Verify signature
		$signing_input = $header64 . '.' . $payload64;
		$signature = $this->base64url_decode( $signature64 );
		$expected = hash_hmac( 'sha256', $signing_input, $secret_key, true );

		if ( ! hash_equals( $expected, $signature ) ) {
			return false;
		}

		// Check expiration
		if ( isset( $payload['exp'] ) && time() > $payload['exp'] ) {
			return false;
		}

		// Return user ID
		return isset( $payload['data']['user']['id'] ) ? $payload['data']['user']['id'] : false;
	}

	/**
	 * Base64 URL encode.
	 */
	private function base64url_encode( $data ) {
		return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
	}

	/**
	 * Base64 URL decode.
	 */
	private function base64url_decode( $data ) {
		return base64_decode( strtr( $data, '-_', '+/' ) );
	}

	/**
	 * Validate JWT token endpoint.
	 */
	public function validate_jwt_endpoint( $request ) {
		$token = $request->get_param( 'token' );
		$user_id = $this->verify_jwt_token( $token );

		if ( ! $user_id ) {
			return new WP_Error( 'jwt_invalid', 'Token is invalid', array( 'status' => 403 ) );
		}

		$user = get_userdata( $user_id );
		return rest_ensure_response( array(
			'valid' => true,
			'user_id' => $user_id,
			'user_login' => $user->user_login,
		) );
	}

	/**
	 * Check API rate limit.
	 */
	public function check_api_rate_limit( $result, $server, $request ) {
		$settings = $this->get_settings();
		$limit = isset( $settings['api_rate_limit'] ) ? $settings['api_rate_limit'] : 100;

		$ip = $this->get_client_ip();
		$key = 'api_rate_' . md5( $ip );
		$count = get_transient( $key );

		if ( false === $count ) {
			set_transient( $key, 1, $settings['api_rate_window'] );
		} else {
			$count++;
			set_transient( $key, $count, $settings['api_rate_window'] );

			if ( $count > $limit ) {
				return new WP_Error(
					'rest_rate_limit_exceeded',
					sprintf( __( 'API rate limit exceeded. Limit: %d requests per minute.', 'nexifymy-security' ), $limit ),
					array( 'status' => 429 )
				);
			}
		}

		return $result;
	}

	/**
	 * Filter user endpoints.
	 */
	public function filter_user_endpoints( $endpoints ) {
		if ( ! is_user_logged_in() ) {
			if ( isset( $endpoints['/wp/v2/users'] ) ) {
				unset( $endpoints['/wp/v2/users'] );
			}
			if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) {
				unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
			}
		}
		return $endpoints;
	}

	/**
	 * Block author enumeration via URL.
	 */
	public function block_author_enumeration() {
		if ( is_admin() || ! isset( $_GET['author'] ) ) {
			return;
		}

		wp_die( 'Author enumeration is disabled.', 'Forbidden', array( 'response' => 403 ) );
	}

	/**
	 * Add CORS headers.
	 */
	public function add_cors_headers() {
		$settings = $this->get_settings();
		$allowed_origins = ! empty( $settings['allowed_origins'] ) ? $settings['allowed_origins'] : array();

		if ( empty( $allowed_origins ) ) {
			return;
		}

		$origin = isset( $_SERVER['HTTP_ORIGIN'] ) ? $_SERVER['HTTP_ORIGIN'] : '';

		if ( in_array( $origin, $allowed_origins, true ) || in_array( '*', $allowed_origins, true ) ) {
			header( 'Access-Control-Allow-Origin: ' . $origin );
			header( 'Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS' );
			header( 'Access-Control-Allow-Credentials: true' );
			header( 'Access-Control-Allow-Headers: Authorization, Content-Type' );
		}
	}

	/**
	 * Log API request.
	 */
	public function log_api_request() {
		$route = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		if ( strpos( $route, '/wp-json/' ) === false ) {
			return;
		}

		$log_data = array(
			'ip' => $this->get_client_ip(),
			'route' => $route,
			'method' => isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : 'GET',
			'user_id' => get_current_user_id(),
		);

		do_action( 'nexifymy_api_request_logged', $log_data );
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
	 * Get API statistics.
	 */
	public function ajax_get_api_stats() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		// Get stats from logs
		$stats = array(
			'total_requests' => 0,
			'authenticated' => 0,
			'rate_limited' => 0,
		);

		wp_send_json_success( $stats );
	}

	/**
	 * Save API settings via AJAX.
	 */
	public function ajax_save_settings() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$settings = isset( $_POST['settings'] ) ? $_POST['settings'] : array();

		// Sanitize
		$sanitized = array(
			'enabled' => ! empty( $settings['enabled'] ),
			'require_auth_rest' => ! empty( $settings['require_auth_rest'] ),
			'jwt_auth_enabled' => ! empty( $settings['jwt_auth_enabled'] ),
			'jwt_secret_key' => sanitize_text_field( $settings['jwt_secret_key'] ?? '' ),
			'api_rate_limit' => absint( $settings['api_rate_limit'] ?? 100 ),
			'block_user_enumeration' => ! empty( $settings['block_user_enumeration'] ),
		);

		$all_settings = get_option( 'nexifymy_security_settings', array() );
		$all_settings['api_security'] = $sanitized;
		update_option( 'nexifymy_security_settings', $all_settings );

		wp_send_json_success( array( 'message' => 'Settings saved.' ) );
	}
}
