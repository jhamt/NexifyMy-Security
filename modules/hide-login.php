<?php
/**
 * Hide Login URL Module.
 * Hides the default wp-admin and wp-login.php URLs.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Hide_Login {

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'       => false,
		'login_slug'    => 'secure-login',
		'redirect_slug' => '404',
		'redirect_url'  => '',
	);

	/**
	 * Initialize the module.
	 */
	public function init() {
		$all_settings = get_option( 'nexifymy_security_settings', array() );
		if ( isset( $all_settings['modules']['hide_login_enabled'] ) && ! $all_settings['modules']['hide_login_enabled'] ) {
			return;
		}

		$settings = $this->get_settings();

		if ( empty( $settings['enabled'] ) || empty( $settings['login_slug'] ) ) {
			return;
		}

		// Add rewrite rules.
		add_action( 'init', array( $this, 'add_rewrite_rules' ), 1 );

		// Filter login URL.
		add_filter( 'login_url', array( $this, 'filter_login_url' ), 10, 3 );
		add_filter( 'logout_url', array( $this, 'filter_logout_url' ), 10, 2 );
		add_filter( 'lostpassword_url', array( $this, 'filter_lostpassword_url' ), 10, 2 );
		add_filter( 'register_url', array( $this, 'filter_register_url' ) );

		// Block default login.
		add_action( 'wp_loaded', array( $this, 'block_default_login' ) );

		// Handle custom login slug.
		add_action( 'template_redirect', array( $this, 'handle_custom_login' ) );

		// Admin notice if using default slug.
		add_action( 'admin_notices', array( $this, 'admin_notice' ) );

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_get_hide_login_settings', array( $this, 'ajax_get_settings' ) );
		add_action( 'wp_ajax_nexifymy_save_hide_login_settings', array( $this, 'ajax_save_settings' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['hide_login'] ) ) {
				return wp_parse_args( $all_settings['hide_login'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Add rewrite rules for custom login slug.
	 */
	public function add_rewrite_rules() {
		$settings = $this->get_settings();
		$slug = sanitize_title( $settings['login_slug'] );

		add_rewrite_rule(
			'^' . $slug . '/?$',
			'index.php?nexifymy_login=1',
			'top'
		);

		add_rewrite_tag( '%nexifymy_login%', '([^&]+)' );
	}

	/**
	 * Block access to default login URLs.
	 */
	public function block_default_login() {
		if ( is_admin() ) {
			return;
		}

		$settings = $this->get_settings();
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$request_path = wp_parse_url( $request_uri, PHP_URL_PATH );

		// Check if accessing default login/admin URLs.
		$blocked_paths = array(
			'/wp-login.php',
			'/wp-admin/',
		);

		$is_blocked = false;
		foreach ( $blocked_paths as $path ) {
			if ( strpos( $request_path, $path ) !== false ) {
				$is_blocked = true;
				break;
			}
		}

		if ( ! $is_blocked ) {
			return;
		}

		// Allow if user is already logged in and accessing admin.
		if ( is_user_logged_in() && strpos( $request_path, '/wp-admin/' ) !== false ) {
			return;
		}

		// Allow admin-ajax.php.
		if ( strpos( $request_path, 'admin-ajax.php' ) !== false ) {
			return;
		}

		// Allow admin-post.php.
		if ( strpos( $request_path, 'admin-post.php' ) !== false ) {
			return;
		}

		// Allow if accessing via custom slug.
		if ( isset( $_GET['nexifymy_login'] ) ) {
			return;
		}

		// Log blocked attempt.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			$ip = $this->get_client_ip();
			NexifyMy_Security_Logger::log(
				'login_url_blocked',
				sprintf( 'Blocked access to default login URL from IP: %s', $ip ),
				'warning',
				array( 'ip' => $ip, 'path' => $request_path )
			);
		}

		// Redirect or show 404.
		if ( ! empty( $settings['redirect_url'] ) ) {
			wp_safe_redirect( esc_url( $settings['redirect_url'] ) );
			exit;
		}

		// Show 404.
		global $wp_query;
		$wp_query->set_404();
		status_header( 404 );
		nocache_headers();

		if ( file_exists( get_404_template() ) ) {
			include get_404_template();
		} else {
			wp_die(
				__( 'Page not found.', 'nexifymy-security' ),
				__( '404 Not Found', 'nexifymy-security' ),
				array( 'response' => 404 )
			);
		}
		exit;
	}

	/**
	 * Handle custom login slug.
	 */
	public function handle_custom_login() {
		global $wp_query;

		if ( ! isset( $wp_query->query_vars['nexifymy_login'] ) ) {
			return;
		}

		// Include login page.
		require_once ABSPATH . 'wp-login.php';
		exit;
	}

	/**
	 * Filter login URL.
	 *
	 * @param string $login_url Original URL.
	 * @param string $redirect Redirect URL.
	 * @param bool   $force_reauth Force reauth.
	 * @return string
	 */
	public function filter_login_url( $login_url, $redirect = '', $force_reauth = false ) {
		$settings = $this->get_settings();
		$slug = sanitize_title( $settings['login_slug'] );

		$new_url = home_url( '/' . $slug . '/' );

		if ( ! empty( $redirect ) ) {
			$new_url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $new_url );
		}

		if ( $force_reauth ) {
			$new_url = add_query_arg( 'reauth', '1', $new_url );
		}

		return $new_url;
	}

	/**
	 * Filter logout URL.
	 *
	 * @param string $logout_url Original URL.
	 * @param string $redirect Redirect URL.
	 * @return string
	 */
	public function filter_logout_url( $logout_url, $redirect = '' ) {
		$settings = $this->get_settings();
		$slug = sanitize_title( $settings['login_slug'] );

		$new_url = home_url( '/' . $slug . '/' );
		$new_url = add_query_arg( 'action', 'logout', $new_url );
		$new_url = wp_nonce_url( $new_url, 'log-out' );

		if ( ! empty( $redirect ) ) {
			$new_url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $new_url );
		}

		return $new_url;
	}

	/**
	 * Filter lost password URL.
	 *
	 * @param string $lostpassword_url Original URL.
	 * @param string $redirect Redirect URL.
	 * @return string
	 */
	public function filter_lostpassword_url( $lostpassword_url, $redirect = '' ) {
		$settings = $this->get_settings();
		$slug = sanitize_title( $settings['login_slug'] );

		$new_url = home_url( '/' . $slug . '/' );
		$new_url = add_query_arg( 'action', 'lostpassword', $new_url );

		if ( ! empty( $redirect ) ) {
			$new_url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $new_url );
		}

		return $new_url;
	}

	/**
	 * Filter register URL.
	 *
	 * @param string $register_url Original URL.
	 * @return string
	 */
	public function filter_register_url( $register_url ) {
		$settings = $this->get_settings();
		$slug = sanitize_title( $settings['login_slug'] );

		return add_query_arg( 'action', 'register', home_url( '/' . $slug . '/' ) );
	}

	/**
	 * Admin notice for default slug.
	 */
	public function admin_notice() {
		$settings = $this->get_settings();

		if ( ! $settings['enabled'] ) {
			return;
		}

		$screen = get_current_screen();
		if ( ! $screen || strpos( $screen->id, 'nexifymy-security' ) === false ) {
			return;
		}

		if ( $settings['login_slug'] === 'secure-login' ) {
			echo '<div class="notice notice-warning"><p>';
			echo '<strong>' . esc_html__( 'Hide Login URL:', 'nexifymy-security' ) . '</strong> ';
			echo esc_html__( 'You are using the default login slug. Consider changing it to something unique.', 'nexifymy-security' );
			echo '</p></div>';
		}
	}

	/**
	 * Get the client IP address securely.
	 * Only trusts X-Forwarded-For/X-Real-IP if the direct requester is a configured trusted proxy.
	 *
	 * @return string
	 */
	private function get_client_ip() {
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$trusted_proxies = get_option( 'nexifymy_security_trusted_proxies', array() );

		// Only trust forwarded headers if request comes from a trusted proxy.
		if ( $remote_addr && in_array( $remote_addr, (array) $trusted_proxies, true ) ) {
			// Check Cloudflare header first.
			if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
				$client_ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
				if ( filter_var( $client_ip, FILTER_VALIDATE_IP ) ) {
					return $client_ip;
				}
			}

			$headers = array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP' );
			foreach ( $headers as $header ) {
				if ( ! empty( $_SERVER[ $header ] ) ) {
					$ips = explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) ) );
					$client_ip = trim( $ips[0] );
					if ( filter_var( $client_ip, FILTER_VALIDATE_IP ) ) {
						return $client_ip;
					}
				}
			}
		}

		return $remote_addr ?: '0.0.0.0';
	}

	/**
	 * Flush rewrite rules on settings change.
	 */
	public static function flush_rules() {
		flush_rewrite_rules();
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	/**
	 * Get settings via AJAX.
	 */
	public function ajax_get_settings() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$settings = $this->get_settings();
		$settings['current_login_url'] = home_url( '/' . sanitize_title( $settings['login_slug'] ) . '/' );

		wp_send_json_success( array( 'settings' => $settings ) );
	}

	/**
	 * Save settings via AJAX.
	 */
	public function ajax_save_settings() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$login_slug = isset( $_POST['login_slug'] ) ? sanitize_title( wp_unslash( $_POST['login_slug'] ) ) : 'secure-login';

		// Prevent common reserved slugs.
		$reserved = array( 'admin', 'login', 'wp-admin', 'wp-login', 'dashboard', 'wp', 'wordpress' );
		if ( in_array( $login_slug, $reserved, true ) ) {
			wp_send_json_error( 'Reserved slug. Please choose a different one.' );
		}

		$settings = array(
			'enabled'       => ! empty( $_POST['enabled'] ),
			'login_slug'    => $login_slug,
			'redirect_slug' => isset( $_POST['redirect_slug'] ) ? sanitize_text_field( wp_unslash( $_POST['redirect_slug'] ) ) : '404',
			'redirect_url'  => isset( $_POST['redirect_url'] ) ? esc_url_raw( wp_unslash( $_POST['redirect_url'] ) ) : '',
		);

		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			$all_settings['hide_login'] = $settings;
			update_option( 'nexifymy_security_settings', $all_settings );
		}

		// Flush rewrite rules.
		self::flush_rules();

		wp_send_json_success( array(
			'message'   => 'Settings saved.',
			'login_url' => home_url( '/' . $login_slug . '/' ),
		) );
	}
}
