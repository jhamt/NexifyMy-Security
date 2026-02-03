<?php
/**
 * Security Hardening Module.
 * Applies various security hardening measures to WordPress.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Hardening {

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'disable_xmlrpc'       => true,
		'hide_wp_version'      => true,
		'disable_file_editor'  => true,
		'security_headers'     => true,
		'disable_rest_api'     => false,
		'disable_rss'          => false,
		'remove_rsd_link'      => true,
		'remove_wlwmanifest'   => true,
		'remove_shortlink'     => true,
		'disable_embeds'       => false,
		'disable_pingback'     => true,
	);

	/**
	 * Initialize the module.
	 */
	public function init() {
		$all_settings = get_option( 'nexifymy_security_settings', array() );
		if ( isset( $all_settings['modules']['hardening_enabled'] ) && ! $all_settings['modules']['hardening_enabled'] ) {
			return;
		}

		$settings = $this->get_settings();

		// Disable XML-RPC.
		if ( ! empty( $settings['disable_xmlrpc'] ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'wp_headers', array( $this, 'remove_x_pingback' ) );
		}

		// Hide WordPress version.
		if ( ! empty( $settings['hide_wp_version'] ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
			add_filter( 'style_loader_src', array( $this, 'remove_version_query' ), 10, 2 );
			add_filter( 'script_loader_src', array( $this, 'remove_version_query' ), 10, 2 );
		}

		// Disable file editor.
		if ( ! empty( $settings['disable_file_editor'] ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}

		// Add security headers.
		if ( ! empty( $settings['security_headers'] ) ) {
			add_action( 'send_headers', array( $this, 'add_security_headers' ) );
		}

		// Disable REST API for non-logged users.
		if ( ! empty( $settings['disable_rest_api'] ) ) {
			add_filter( 'rest_authentication_errors', array( $this, 'restrict_rest_api' ) );
		}

		// Disable RSS feeds.
		if ( ! empty( $settings['disable_rss'] ) ) {
			add_action( 'do_feed', array( $this, 'disable_feed' ), 1 );
			add_action( 'do_feed_rdf', array( $this, 'disable_feed' ), 1 );
			add_action( 'do_feed_rss', array( $this, 'disable_feed' ), 1 );
			add_action( 'do_feed_rss2', array( $this, 'disable_feed' ), 1 );
			add_action( 'do_feed_atom', array( $this, 'disable_feed' ), 1 );
			remove_action( 'wp_head', 'feed_links', 2 );
			remove_action( 'wp_head', 'feed_links_extra', 3 );
		}

		// Remove RSD link.
		if ( ! empty( $settings['remove_rsd_link'] ) ) {
			remove_action( 'wp_head', 'rsd_link' );
		}

		// Remove WLW manifest.
		if ( ! empty( $settings['remove_wlwmanifest'] ) ) {
			remove_action( 'wp_head', 'wlwmanifest_link' );
		}

		// Remove shortlink.
		if ( ! empty( $settings['remove_shortlink'] ) ) {
			remove_action( 'wp_head', 'wp_shortlink_wp_head' );
			remove_action( 'template_redirect', 'wp_shortlink_header', 11 );
		}

		// Disable embeds.
		if ( ! empty( $settings['disable_embeds'] ) ) {
			$this->disable_embeds();
		}

		// Disable pingback.
		if ( ! empty( $settings['disable_pingback'] ) ) {
			add_filter( 'pings_open', '__return_false', 20, 2 );
		}

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_get_hardening_status', array( $this, 'ajax_get_status' ) );
		add_action( 'wp_ajax_nexifymy_apply_hardening', array( $this, 'ajax_apply_hardening' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['hardening'] ) ) {
				return wp_parse_args( $all_settings['hardening'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Remove X-Pingback header.
	 *
	 * @param array $headers HTTP headers.
	 * @return array
	 */
	public function remove_x_pingback( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	/**
	 * Remove version query strings from styles/scripts.
	 *
	 * @param string $src Source URL.
	 * @param string $handle Asset handle.
	 * @return string
	 */
	public function remove_version_query( $src, $handle ) {
		if ( strpos( $src, 'ver=' ) ) {
			$src = remove_query_arg( 'ver', $src );
		}
		return $src;
	}

	/**
	 * Add security headers.
	 */
	public function add_security_headers() {
		if ( headers_sent() ) {
			return;
		}

		// X-Frame-Options - prevent clickjacking.
		header( 'X-Frame-Options: SAMEORIGIN' );

		// X-Content-Type-Options - prevent MIME sniffing.
		header( 'X-Content-Type-Options: nosniff' );

		// X-XSS-Protection.
		header( 'X-XSS-Protection: 1; mode=block' );

		// Referrer Policy.
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );

		// Permissions Policy.
		header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );
	}

	/**
	 * Restrict REST API to logged-in users.
	 *
	 * @param WP_Error|null|bool $result Authentication result.
	 * @return WP_Error|null|bool
	 */
	public function restrict_rest_api( $result ) {
		if ( ! is_user_logged_in() ) {
			return new WP_Error(
				'rest_not_logged_in',
				__( 'You must be logged in to access the REST API.', 'nexifymy-security' ),
				array( 'status' => 401 )
			);
		}
		return $result;
	}

	/**
	 * Disable RSS feeds.
	 */
	public function disable_feed() {
		wp_die(
			__( 'RSS feeds are disabled on this site.', 'nexifymy-security' ),
			'',
			array( 'response' => 403 )
		);
	}

	/**
	 * Disable embeds completely.
	 */
	private function disable_embeds() {
		// Remove embed rewrite rules.
		add_action( 'init', function() {
			global $wp;
			$wp->public_query_vars = array_diff( $wp->public_query_vars, array( 'embed' ) );
		}, 9999 );

		// Remove embed-related JavaScript.
		remove_action( 'wp_head', 'wp_oembed_add_discovery_links' );
		remove_action( 'wp_head', 'wp_oembed_add_host_js' );

		// Remove embed REST endpoint.
		remove_action( 'rest_api_init', 'wp_oembed_register_route' );

		// Remove embed filter.
		remove_filter( 'oembed_dataparse', 'wp_filter_oembed_result', 10 );

		// Remove TinyMCE embed plugin.
		add_filter( 'tiny_mce_plugins', function( $plugins ) {
			return array_diff( $plugins, array( 'wpembed' ) );
		} );
	}

	/**
	 * Get current hardening status.
	 *
	 * @return array
	 */
	public function get_status() {
		$settings = $this->get_settings();

		$status = array(
			'xmlrpc' => array(
				'label'   => 'XML-RPC',
				'enabled' => ! empty( $settings['disable_xmlrpc'] ),
				'status'  => ! empty( $settings['disable_xmlrpc'] ) ? 'disabled' : 'enabled',
			),
			'wp_version' => array(
				'label'   => 'WordPress Version',
				'enabled' => ! empty( $settings['hide_wp_version'] ),
				'status'  => ! empty( $settings['hide_wp_version'] ) ? 'hidden' : 'visible',
			),
			'file_editor' => array(
				'label'   => 'File Editor',
				'enabled' => ! empty( $settings['disable_file_editor'] ),
				'status'  => defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ? 'disabled' : 'enabled',
			),
			'security_headers' => array(
				'label'   => 'Security Headers',
				'enabled' => ! empty( $settings['security_headers'] ),
				'status'  => ! empty( $settings['security_headers'] ) ? 'active' : 'inactive',
			),
			'rest_api' => array(
				'label'   => 'REST API (Public)',
				'enabled' => ! empty( $settings['disable_rest_api'] ),
				'status'  => ! empty( $settings['disable_rest_api'] ) ? 'restricted' : 'public',
			),
			'pingback' => array(
				'label'   => 'Pingback',
				'enabled' => ! empty( $settings['disable_pingback'] ),
				'status'  => ! empty( $settings['disable_pingback'] ) ? 'disabled' : 'enabled',
			),
		);

		return $status;
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	/**
	 * Get hardening status via AJAX.
	 */
	public function ajax_get_status() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		wp_send_json_success( array(
			'settings' => $this->get_settings(),
			'status'   => $this->get_status(),
		) );
	}

	/**
	 * Apply hardening settings via AJAX.
	 */
	public function ajax_apply_hardening() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$settings = array();

		foreach ( array_keys( self::$defaults ) as $key ) {
			$settings[ $key ] = ! empty( $_POST[ $key ] );
		}

		// Save to main settings.
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			$all_settings['hardening'] = $settings;
			update_option( 'nexifymy_security_settings', $all_settings );
		}

		// Log the action.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'hardening_updated',
				'Security hardening settings updated.',
				'info',
				$settings
			);
		}

		wp_send_json_success( array( 'message' => 'Hardening settings applied.' ) );
	}
}
