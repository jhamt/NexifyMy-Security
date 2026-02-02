<?php
/**
 * CDN Integration Module.
 * Provides CDN detection, real IP extraction, and Cloudflare API integration.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_CDN {

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'             => false,
		'provider'            => 'auto', // auto, cloudflare, sucuri, generic
		'cloudflare_email'    => '',
		'cloudflare_api_key'  => '',
		'cloudflare_zone_id'  => '',
		'trust_proxy_headers' => true,
	);

	/**
	 * Detected CDN provider cache.
	 */
	private $detected_provider = null;

	/**
	 * Initialize the module.
	 */
	public function init() {
		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_get_cdn_status', array( $this, 'ajax_get_status' ) );
		add_action( 'wp_ajax_nexifymy_purge_cdn_cache', array( $this, 'ajax_purge_cache' ) );
		add_action( 'wp_ajax_nexifymy_test_cdn_connection', array( $this, 'ajax_test_connection' ) );
		add_action( 'wp_ajax_nexifymy_save_cdn_settings', array( $this, 'ajax_save_settings' ) );

		$settings = $this->get_settings();

		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Detect CDN and extract real IP early.
		add_action( 'muplugins_loaded', array( $this, 'detect_and_fix_ip' ), 1 );
		add_action( 'plugins_loaded', array( $this, 'detect_and_fix_ip' ), 1 );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['cdn'] ) ) {
				return wp_parse_args( $all_settings['cdn'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Detect CDN and fix the client IP.
	 */
	public function detect_and_fix_ip() {
		$provider = $this->detect_provider();

		if ( ! $provider ) {
			return;
		}

		$real_ip = $this->get_real_ip( $provider );

		if ( $real_ip && filter_var( $real_ip, FILTER_VALIDATE_IP ) ) {
			$_SERVER['REMOTE_ADDR'] = $real_ip;
		}
	}

	/**
	 * Detect CDN provider.
	 *
	 * @return string|null Provider name or null.
	 */
	public function detect_provider() {
		if ( null !== $this->detected_provider ) {
			return $this->detected_provider;
		}

		$settings = $this->get_settings();

		if ( 'auto' !== $settings['provider'] && ! empty( $settings['provider'] ) ) {
			$this->detected_provider = $settings['provider'];
			return $this->detected_provider;
		}

		// Auto-detect based on headers.
		if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			$this->detected_provider = 'cloudflare';
		} elseif ( ! empty( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) ) {
			$this->detected_provider = 'sucuri';
		} elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$this->detected_provider = 'generic';
		}

		return $this->detected_provider;
	}

	/**
	 * Get real client IP based on CDN provider.
	 *
	 * @param string $provider CDN provider.
	 * @return string|null Real IP or null.
	 */
	private function get_real_ip( $provider ) {
		switch ( $provider ) {
			case 'cloudflare':
				if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
					return sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
				}
				break;

			case 'sucuri':
				if ( ! empty( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) ) {
					return sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) );
				}
				break;

			case 'generic':
				if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
					$ips = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
					return trim( $ips[0] );
				}
				if ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
					return sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
				}
				break;
		}

		return null;
	}

	/**
	 * Get CDN status information.
	 *
	 * @return array
	 */
	public function get_status() {
		$settings = $this->get_settings();
		$provider = $this->detect_provider();

		$status = array(
			'enabled'           => ! empty( $settings['enabled'] ),
			'detected_provider' => $provider,
			'provider_name'     => $this->get_provider_name( $provider ),
			'real_ip'           => isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '',
			'is_cloudflare'     => 'cloudflare' === $provider,
			'cloudflare_configured' => ! empty( $settings['cloudflare_api_key'] ) && ! empty( $settings['cloudflare_zone_id'] ),
		);

		// Add Cloudflare-specific info.
		if ( 'cloudflare' === $provider ) {
			$status['cf_ray'] = isset( $_SERVER['HTTP_CF_RAY'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_RAY'] ) ) : '';
			$status['cf_country'] = isset( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) : '';
		}

		return $status;
	}

	/**
	 * Get human-readable provider name.
	 *
	 * @param string $provider Provider key.
	 * @return string
	 */
	private function get_provider_name( $provider ) {
		$names = array(
			'cloudflare' => 'Cloudflare',
			'sucuri'     => 'Sucuri',
			'generic'    => 'Generic CDN/Proxy',
		);
		return isset( $names[ $provider ] ) ? $names[ $provider ] : 'None detected';
	}

	/**
	 * Purge Cloudflare cache.
	 *
	 * @param bool $purge_all Whether to purge all cache.
	 * @param array $urls Specific URLs to purge (if not purge_all).
	 * @return array|WP_Error Result or error.
	 */
	public function purge_cloudflare_cache( $purge_all = true, $urls = array() ) {
		$settings = $this->get_settings();

		if ( empty( $settings['cloudflare_api_key'] ) || empty( $settings['cloudflare_zone_id'] ) ) {
			return new WP_Error( 'not_configured', 'Cloudflare API credentials not configured.' );
		}

		$zone_id = sanitize_text_field( $settings['cloudflare_zone_id'] );
		$api_url = 'https://api.cloudflare.com/client/v4/zones/' . $zone_id . '/purge_cache';

		$body = $purge_all ? array( 'purge_everything' => true ) : array( 'files' => $urls );

		$response = wp_remote_post( $api_url, array(
			'headers' => array(
				'Authorization' => 'Bearer ' . $settings['cloudflare_api_key'],
				'Content-Type'  => 'application/json',
			),
			'body'    => wp_json_encode( $body ),
			'timeout' => 15,
		) );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( isset( $body['success'] ) && $body['success'] ) {
			// Log success.
			if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
				NexifyMy_Security_Logger::log(
					'cdn_cache_purged',
					'Cloudflare cache purged successfully.',
					'info',
					array( 'purge_all' => $purge_all )
				);
			}

			return array( 'success' => true, 'message' => 'Cache purged successfully.' );
		}

		$error_msg = isset( $body['errors'][0]['message'] ) ? $body['errors'][0]['message'] : 'Unknown error';
		return new WP_Error( 'api_error', $error_msg );
	}

	/**
	 * Test Cloudflare API connection.
	 *
	 * @return array|WP_Error Result or error.
	 */
	public function test_cloudflare_connection() {
		$settings = $this->get_settings();

		if ( empty( $settings['cloudflare_api_key'] ) || empty( $settings['cloudflare_zone_id'] ) ) {
			return new WP_Error( 'not_configured', 'Cloudflare API credentials not configured.' );
		}

		$zone_id = sanitize_text_field( $settings['cloudflare_zone_id'] );
		$api_url = 'https://api.cloudflare.com/client/v4/zones/' . $zone_id;

		$response = wp_remote_get( $api_url, array(
			'headers' => array(
				'Authorization' => 'Bearer ' . $settings['cloudflare_api_key'],
				'Content-Type'  => 'application/json',
			),
			'timeout' => 15,
		) );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( isset( $body['success'] ) && $body['success'] ) {
			$zone_name = isset( $body['result']['name'] ) ? $body['result']['name'] : 'Unknown';
			return array(
				'success'   => true,
				'zone_name' => $zone_name,
				'message'   => 'Successfully connected to Cloudflare.',
			);
		}

		$error_msg = isset( $body['errors'][0]['message'] ) ? $body['errors'][0]['message'] : 'Unknown error';
		return new WP_Error( 'api_error', $error_msg );
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	/**
	 * Get CDN status via AJAX.
	 */
	public function ajax_get_status() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		wp_send_json_success( array(
			'status'   => $this->get_status(),
			'settings' => $this->get_settings(),
		) );
	}

	/**
	 * Purge CDN cache via AJAX.
	 */
	public function ajax_purge_cache() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$result = $this->purge_cloudflare_cache( true );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( $result->get_error_message() );
		}

		wp_send_json_success( $result );
	}

	/**
	 * Test CDN connection via AJAX.
	 */
	public function ajax_test_connection() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$result = $this->test_cloudflare_connection();

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( $result->get_error_message() );
		}

		wp_send_json_success( $result );
	}

	/**
	 * Save CDN settings via AJAX.
	 */
	public function ajax_save_settings() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$settings = array(
			'enabled'             => ! empty( $_POST['enabled'] ),
			'provider'            => isset( $_POST['provider'] ) ? sanitize_key( $_POST['provider'] ) : 'auto',
			'cloudflare_email'    => isset( $_POST['cloudflare_email'] ) ? sanitize_email( wp_unslash( $_POST['cloudflare_email'] ) ) : '',
			'cloudflare_api_key'  => isset( $_POST['cloudflare_api_key'] ) ? sanitize_text_field( wp_unslash( $_POST['cloudflare_api_key'] ) ) : '',
			'cloudflare_zone_id'  => isset( $_POST['cloudflare_zone_id'] ) ? sanitize_text_field( wp_unslash( $_POST['cloudflare_zone_id'] ) ) : '',
			'trust_proxy_headers' => ! empty( $_POST['trust_proxy_headers'] ),
		);

		// Save to main settings.
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			$all_settings['cdn'] = $settings;
			update_option( 'nexifymy_security_settings', $all_settings );
		}

		wp_send_json_success( array( 'message' => 'CDN settings saved.' ) );
	}
}
