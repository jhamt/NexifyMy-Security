<?php
/**
 * Rate Limiting / Brute Force Protection Module.
 * Tracks failed login attempts and blocks IPs exceeding thresholds.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_RateLimiter {

	/**
	 * Default settings.
	 */
	const DEFAULT_MAX_ATTEMPTS = 5;
	const DEFAULT_LOCKOUT_DURATION = 900; // 15 minutes in seconds
	const DEFAULT_ATTEMPT_WINDOW = 300;   // 5 minutes in seconds

	/**
	 * Effective settings (from plugin settings with safe defaults).
	 * @var bool
	 */
	private $enabled = true;

	/**
	 * @var int
	 */
	private $max_attempts = self::DEFAULT_MAX_ATTEMPTS;

	/**
	 * @var int
	 */
	private $lockout_duration = self::DEFAULT_LOCKOUT_DURATION;

	/**
	 * @var int
	 */
	private $attempt_window = self::DEFAULT_ATTEMPT_WINDOW;

	/**
	 * Transient prefix for tracking.
	 */
	const TRANSIENT_PREFIX = 'nexifymy_rl_';

	/**
	 * Initialize the rate limiter.
	 */
	public function init() {
		$this->load_settings();

		// Admin AJAX to check/unblock IPs (must be available even if module is disabled).
		add_action( 'wp_ajax_nexifymy_get_blocked_ips', array( $this, 'ajax_get_blocked_ips' ) );
		add_action( 'wp_ajax_nexifymy_unblock_ip', array( $this, 'ajax_unblock_ip' ) );

		if ( ! $this->enabled ) {
			return;
		}

		// Hook into WordPress login authentication.
		add_filter( 'authenticate', array( $this, 'check_rate_limit' ), 30, 3 );
		add_action( 'wp_login_failed', array( $this, 'record_failed_attempt' ) );
		add_action( 'wp_login', array( $this, 'clear_attempts_on_success' ), 10, 2 );

		// Check if IP is locked out on every request (runs immediately).
		$this->check_request_rate();
	}

	/**
	 * Load effective settings for the rate limiter.
	 */
	private function load_settings() {
		$settings = get_option( 'nexifymy_security_settings', array() );

		// Module toggle.
		if ( isset( $settings['modules']['rate_limiter_enabled'] ) && ! $settings['modules']['rate_limiter_enabled'] ) {
			$this->enabled = false;
			return;
		}

		$rate_limiter = isset( $settings['rate_limiter'] ) && is_array( $settings['rate_limiter'] ) ? $settings['rate_limiter'] : array();

		$max_attempts = absint( $rate_limiter['max_attempts'] ?? self::DEFAULT_MAX_ATTEMPTS );
		$lockout_duration = absint( $rate_limiter['lockout_duration'] ?? self::DEFAULT_LOCKOUT_DURATION );
		$attempt_window = absint( $rate_limiter['attempt_window'] ?? self::DEFAULT_ATTEMPT_WINDOW );

		// Clamp to sane ranges.
		$this->max_attempts = max( 1, min( 50, $max_attempts ?: self::DEFAULT_MAX_ATTEMPTS ) );
		$this->lockout_duration = max( 60, min( DAY_IN_SECONDS, $lockout_duration ?: self::DEFAULT_LOCKOUT_DURATION ) );
		$this->attempt_window = max( 60, min( DAY_IN_SECONDS, $attempt_window ?: self::DEFAULT_ATTEMPT_WINDOW ) );
	}

	/**
	 * Check if an IP is whitelisted.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	private function is_ip_whitelisted( $ip ) {
		$whitelist = get_option( 'nexifymy_security_ip_whitelist', array() );
		return $ip && in_array( $ip, (array) $whitelist, true );
	}

	/**
	 * Get the client IP address securely.
	 * Only trusts X-Forwarded-For/X-Real-IP if the direct requester is a configured trusted proxy.
	 *
	 * @return string
	 */
	private function get_client_ip() {
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( $_SERVER['REMOTE_ADDR'] ) : '';

		// Get list of trusted proxies from settings.
		$trusted_proxies = get_option( 'nexifymy_security_trusted_proxies', array() );

		// Only trust forwarded headers if the request comes from a trusted proxy.
		if ( in_array( $remote_addr, (array) $trusted_proxies, true ) ) {
			// X-Forwarded-For: client, proxy1, proxy2 - first one is the real client.
			if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
				$ips = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] );
				$client_ip = trim( $ips[0] );
				// Validate it's a real IP.
				if ( filter_var( $client_ip, FILTER_VALIDATE_IP ) ) {
					return sanitize_text_field( $client_ip );
				}
			}
			// X-Real-IP is set by some proxies like nginx.
			if ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
				$client_ip = $_SERVER['HTTP_X_REAL_IP'];
				if ( filter_var( $client_ip, FILTER_VALIDATE_IP ) ) {
					return sanitize_text_field( $client_ip );
				}
			}
		}

		// Default to REMOTE_ADDR (direct connection IP).
		return $remote_addr;
	}

	/**
	 * Get transient key for IP.
	 *
	 * @param string $ip IP address.
	 * @param string $type 'attempts' or 'lockout'.
	 * @return string
	 */
	private function get_transient_key( $ip, $type = 'attempts' ) {
		return self::TRANSIENT_PREFIX . $type . '_' . md5( $ip );
	}

	/**
	 * Check if IP is currently locked out.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	private function is_locked_out( $ip ) {
		$lockout_key = $this->get_transient_key( $ip, 'lockout' );
		return (bool) get_transient( $lockout_key );
	}

	/**
	 * Get remaining lockout time.
	 *
	 * @param string $ip IP address.
	 * @return int Seconds remaining.
	 */
	private function get_lockout_remaining( $ip ) {
		$lockout_key = $this->get_transient_key( $ip, 'lockout' );
		$timeout = get_option( '_transient_timeout_' . $lockout_key );

		if ( $timeout ) {
			return max( 0, $timeout - time() );
		}

		return 0;
	}

	/**
	 * Record a failed login attempt.
	 *
	 * @param string $username The attempted username.
	 */
	public function record_failed_attempt( $username ) {
		$ip = $this->get_client_ip();
		if ( $this->is_ip_whitelisted( $ip ) ) {
			return;
		}

		$attempts_key = $this->get_transient_key( $ip, 'attempts' );

		$attempts = (int) get_transient( $attempts_key );
		$attempts++;

		set_transient( $attempts_key, $attempts, $this->attempt_window );

		// Log the attempt.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'login_failed',
				sprintf( 'Failed login attempt for user: %s (Attempt #%d)', $username, $attempts ),
				'warning',
				array( 'username' => $username, 'attempt_count' => $attempts )
			);
		}

		// Check if lockout threshold exceeded.
		if ( $attempts >= $this->max_attempts ) {
			$this->lockout_ip( $ip );
		}
	}

	/**
	 * Lockout an IP address.
	 *
	 * @param string $ip IP address.
	 */
	private function lockout_ip( $ip ) {
		$lockout_key = $this->get_transient_key( $ip, 'lockout' );
		set_transient( $lockout_key, time(), $this->lockout_duration );

		// Log the lockout.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'ip_lockout',
				sprintf( 'IP locked out due to excessive failed login attempts: %s', $ip ),
				'critical',
				array(
					'duration'      => $this->lockout_duration,
					'max_attempts'  => $this->max_attempts,
					'attempt_window' => $this->attempt_window,
				)
			);
		}
	}

	/**
	 * Check rate limit before authentication.
	 *
	 * @param WP_User|WP_Error|null $user WP_User if auth succeeded, WP_Error on fail.
	 * @param string $username Username.
	 * @param string $password Password.
	 * @return WP_User|WP_Error
	 */
	public function check_rate_limit( $user, $username, $password ) {
		// Skip if no username provided.
		if ( empty( $username ) ) {
			return $user;
		}

		$ip = $this->get_client_ip();
		if ( $this->is_ip_whitelisted( $ip ) ) {
			return $user;
		}

		if ( $this->is_locked_out( $ip ) ) {
			$remaining = $this->get_lockout_remaining( $ip );
			$minutes = ceil( $remaining / 60 );

			return new WP_Error(
				'nexifymy_lockout',
				sprintf(
					__( 'Too many failed login attempts. Please try again in %d minute(s).', 'nexifymy-security' ),
					$minutes
				)
			);
		}

		return $user;
	}

	/**
	 * Clear attempts on successful login.
	 *
	 * @param string $user_login Username.
	 * @param WP_User $user User object.
	 */
	public function clear_attempts_on_success( $user_login, $user ) {
		$ip = $this->get_client_ip();
		$attempts_key = $this->get_transient_key( $ip, 'attempts' );
		delete_transient( $attempts_key );
	}

	/**
	 * Check general request rate (WAF integration).
	 */
	public function check_request_rate() {
		// Skip for admins.
		if ( function_exists( 'is_admin' ) && is_admin() && function_exists( 'current_user_can' ) && current_user_can( 'manage_options' ) ) {
			return;
		}

		$ip = $this->get_client_ip();
		if ( $this->is_ip_whitelisted( $ip ) ) {
			return;
		}

		// Check if IP is locked out.
		if ( $this->is_locked_out( $ip ) ) {
			$remaining = $this->get_lockout_remaining( $ip );
			$minutes = ceil( $remaining / 60 );

			status_header( 403 );
			nocache_headers();

			echo '<html><head><title>Access Denied</title></head><body>';
			echo '<h1>Access Temporarily Blocked</h1>';
			echo '<p>Your IP has been temporarily blocked due to suspicious activity.</p>';
			echo '<p>Please try again in <strong>' . esc_html( $minutes ) . '</strong> minute(s).</p>';
			echo '<p><small>Protected by NexifyMy Security</small></p>';
			echo '</body></html>';
			exit;
		}
	}

	/**
	 * Get list of currently blocked IPs via AJAX.
	 */
	public function ajax_get_blocked_ips() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		global $wpdb;

		// Query transients for lockouts.
		$results = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_name, option_value FROM {$wpdb->options} 
				 WHERE option_name LIKE %s",
				'_transient_' . self::TRANSIENT_PREFIX . 'lockout_%'
			),
			ARRAY_A
		);

		$blocked_ips = array();
		foreach ( $results as $row ) {
			$timeout_key = str_replace( '_transient_', '_transient_timeout_', $row['option_name'] );
			$timeout = get_option( $timeout_key );

			if ( $timeout && $timeout > time() ) {
				$blocked_ips[] = array(
					'transient' => $row['option_name'],
					'locked_at' => date( 'Y-m-d H:i:s', (int) $row['option_value'] ),
					'expires_at' => date( 'Y-m-d H:i:s', (int) $timeout ),
					'remaining' => $timeout - time(),
				);
			}
		}

		wp_send_json_success( array(
			'blocked_count' => count( $blocked_ips ),
			'blocked_ips' => $blocked_ips,
		) );
	}

	/**
	 * Unblock an IP via AJAX.
	 */
	public function ajax_unblock_ip() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$transient_name = isset( $_POST['transient'] ) ? sanitize_text_field( $_POST['transient'] ) : '';

		if ( empty( $transient_name ) ) {
			wp_send_json_error( 'Invalid transient' );
		}

		// Extract actual transient key.
		$key = str_replace( '_transient_', '', $transient_name );
		delete_transient( $key );

		wp_send_json_success( 'IP unblocked successfully' );
	}
}
