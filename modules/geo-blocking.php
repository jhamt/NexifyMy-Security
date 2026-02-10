<?php
/**
 * Country/Geo Blocking Module.
 * Blocks or allows traffic based on geographic location.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Geo_Blocking {

	/**
	 * Cache key prefix for geo lookups.
	 */
	const CACHE_PREFIX = 'nexifymy_geo_';

	/**
	 * Cache expiry in seconds (24 hours).
	 */
	const CACHE_EXPIRY = 86400;

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'       => false,
		'mode'          => 'blacklist', // blacklist or whitelist
		'countries'     => array(),
		'block_message' => 'Access denied from your region.',
		'log_blocked'   => true,
	);

	/**
	 * Country codes and names.
	 */
	private static $country_list = null;

	/**
	 * Initialize the module.
	 */
	public function init() {
		// Check geo blocking early.
		add_action( 'init', array( $this, 'check_geo_block' ), 0 );

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_get_geo_settings', array( $this, 'ajax_get_settings' ) );
		add_action( 'wp_ajax_nexifymy_save_geo_settings', array( $this, 'ajax_save_settings' ) );
		add_action( 'wp_ajax_nexifymy_lookup_ip_country', array( $this, 'ajax_lookup_ip' ) );
		add_action( 'wp_ajax_nexifymy_get_country_list', array( $this, 'ajax_get_country_list' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['geo_blocking'] ) ) {
				return wp_parse_args( $all_settings['geo_blocking'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Check if current request should be blocked by geo.
	 */
	public function check_geo_block() {
		$all_settings = get_option( 'nexifymy_security_settings', array() );
		if ( isset( $all_settings['modules']['geo_blocking_enabled'] ) && ! $all_settings['modules']['geo_blocking_enabled'] ) {
			return;
		}

		$settings = $this->get_settings();

		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Skip admin and logged-in users.
		if ( is_admin() || is_user_logged_in() ) {
			return;
		}

		// Skip AJAX and cron.
		if ( wp_doing_ajax() || wp_doing_cron() ) {
			return;
		}

		$ip = $this->get_client_ip();
		$country = $this->get_country( $ip );

		if ( empty( $country ) ) {
			return; // Unknown country, allow by default.
		}

		$should_block = false;
		$mode = $settings['mode'];
		$countries = (array) $settings['countries'];

		if ( 'blacklist' === $mode ) {
			// Block if country is in the list.
			$should_block = in_array( $country, $countries, true );
		} elseif ( 'whitelist' === $mode ) {
			// Block if country is NOT in the list.
			$should_block = ! in_array( $country, $countries, true );
		}

		if ( $should_block ) {
			$this->block_request( $ip, $country, $settings );
		}
	}

	/**
	 * Block the request.
	 *
	 * @param string $ip Client IP.
	 * @param string $country Country code.
	 * @param array  $settings Module settings.
	 */
	private function block_request( $ip, $country, $settings ) {
		// Log if enabled.
		if ( ! empty( $settings['log_blocked'] ) && class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'geo_blocked',
				sprintf( 'Request blocked from %s (%s)', $country, $ip ),
				'warning',
				array( 'ip' => $ip, 'country' => $country )
			);
		}

		// Mark in live traffic if available.
		if ( isset( $GLOBALS['nexifymy_live_traffic'] ) ) {
			$GLOBALS['nexifymy_live_traffic']->mark_blocked( $ip, 'geo_blocked' );
		}

		// Send blocked response.
		status_header( 403 );
		nocache_headers();

		$message = ! empty( $settings['block_message'] ) ? $settings['block_message'] : 'Access denied.';

		wp_die(
			esc_html( $message ),
			__( 'Access Denied', 'nexifymy-security' ),
			array( 'response' => 403 )
		);
	}

	/**
	 * Get country code for an IP address.
	 *
	 * @param string $ip IP address.
	 * @return string Country code (2 letters) or empty string.
	 */
	public function get_country( $ip ) {
		// Check cache first.
		$cache_key = self::CACHE_PREFIX . md5( $ip );
		$cached = get_transient( $cache_key );

		if ( false !== $cached ) {
			return $cached;
		}

		// Lookup via ip-api.com (free, no key required).
		$country = $this->lookup_ip_api( $ip );

		// Cache the result.
		set_transient( $cache_key, $country, self::CACHE_EXPIRY );

		return $country;
	}

	/**
	 * Lookup IP using a TLS-protected geo endpoint.
	 *
	 * @param string $ip IP address.
	 * @return string Country code or empty string.
	 */
	private function lookup_ip_api( $ip ) {
		// Skip local IPs.
		if ( $this->is_local_ip( $ip ) ) {
			return '';
		}

		$url = 'https://ipwho.is/' . rawurlencode( $ip ) . '?fields=success,country_code';

		$response = wp_remote_get( $url, array(
			'timeout' => 5,
		) );

		if ( is_wp_error( $response ) ) {
			return '';
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( ! empty( $data['success'] ) && ! empty( $data['country_code'] ) ) {
			return strtoupper( sanitize_text_field( $data['country_code'] ) );
		}

		return '';
	}

	/**
	 * Check if IP is local/private.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	private function is_local_ip( $ip ) {
		return filter_var(
			$ip,
			FILTER_VALIDATE_IP,
			FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
		) === false;
	}

	/**
	 * Get client IP address.
	 *
	 * @return string
	 */
	private function get_client_ip() {
		$remote_addr     = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$trusted_proxies = get_option( 'nexifymy_security_trusted_proxies', array() );

		// Only trust forwarded headers if the direct requester is an explicitly trusted proxy.
		if ( $remote_addr && in_array( $remote_addr, (array) $trusted_proxies, true ) ) {
			if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
				$client_ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
				if ( filter_var( $client_ip, FILTER_VALIDATE_IP ) ) {
					return $client_ip;
				}
			}

			$headers = array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP' );
			foreach ( $headers as $header ) {
				if ( ! empty( $_SERVER[ $header ] ) ) {
					$ips       = explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) ) );
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
	 * Get list of all countries.
	 *
	 * @return array Country code => name pairs.
	 */
	public static function get_country_list() {
		if ( null !== self::$country_list ) {
			return self::$country_list;
		}

		self::$country_list = array(
			'AF' => 'Afghanistan', 'AL' => 'Albania', 'DZ' => 'Algeria', 'AR' => 'Argentina',
			'AU' => 'Australia', 'AT' => 'Austria', 'BD' => 'Bangladesh', 'BE' => 'Belgium',
			'BR' => 'Brazil', 'CA' => 'Canada', 'CL' => 'Chile', 'CN' => 'China',
			'CO' => 'Colombia', 'HR' => 'Croatia', 'CZ' => 'Czech Republic', 'DK' => 'Denmark',
			'EG' => 'Egypt', 'FI' => 'Finland', 'FR' => 'France', 'DE' => 'Germany',
			'GR' => 'Greece', 'HK' => 'Hong Kong', 'HU' => 'Hungary', 'IN' => 'India',
			'ID' => 'Indonesia', 'IR' => 'Iran', 'IQ' => 'Iraq', 'IE' => 'Ireland',
			'IL' => 'Israel', 'IT' => 'Italy', 'JP' => 'Japan', 'KE' => 'Kenya',
			'KR' => 'South Korea', 'KW' => 'Kuwait', 'MY' => 'Malaysia', 'MX' => 'Mexico',
			'MA' => 'Morocco', 'NL' => 'Netherlands', 'NZ' => 'New Zealand', 'NG' => 'Nigeria',
			'NO' => 'Norway', 'PK' => 'Pakistan', 'PH' => 'Philippines', 'PL' => 'Poland',
			'PT' => 'Portugal', 'QA' => 'Qatar', 'RO' => 'Romania', 'RU' => 'Russia',
			'SA' => 'Saudi Arabia', 'SG' => 'Singapore', 'ZA' => 'South Africa', 'ES' => 'Spain',
			'SE' => 'Sweden', 'CH' => 'Switzerland', 'TW' => 'Taiwan', 'TH' => 'Thailand',
			'TR' => 'Turkey', 'UA' => 'Ukraine', 'AE' => 'United Arab Emirates', 'GB' => 'United Kingdom',
			'US' => 'United States', 'VN' => 'Vietnam',
		);

		return self::$country_list;
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

		wp_send_json_success( array( 'settings' => $this->get_settings() ) );
	}

	/**
	 * Save settings via AJAX.
	 */
	public function ajax_save_settings() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$settings = array(
			'enabled'       => ! empty( $_POST['enabled'] ),
			'mode'          => isset( $_POST['mode'] ) && in_array( $_POST['mode'], array( 'blacklist', 'whitelist' ), true ) ? $_POST['mode'] : 'blacklist',
			'countries'     => isset( $_POST['countries'] ) ? array_map( 'sanitize_text_field', (array) $_POST['countries'] ) : array(),
			'block_message' => isset( $_POST['block_message'] ) ? sanitize_text_field( wp_unslash( $_POST['block_message'] ) ) : '',
			'log_blocked'   => ! empty( $_POST['log_blocked'] ),
		);

		// Save to main settings.
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			$all_settings['geo_blocking'] = $settings;
			update_option( 'nexifymy_security_settings', $all_settings );
		}

		wp_send_json_success( array( 'message' => 'Settings saved.' ) );
	}

	/**
	 * Lookup IP country via AJAX.
	 */
	public function ajax_lookup_ip() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : $this->get_client_ip();
		$country = $this->get_country( $ip );
		$country_name = '';

		if ( $country ) {
			$list = self::get_country_list();
			$country_name = isset( $list[ $country ] ) ? $list[ $country ] : $country;
		}

		wp_send_json_success( array(
			'ip'           => $ip,
			'country_code' => $country,
			'country_name' => $country_name,
		) );
	}

	/**
	 * Get country list via AJAX.
	 */
	public function ajax_get_country_list() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		wp_send_json_success( array( 'countries' => self::get_country_list() ) );
	}
}
