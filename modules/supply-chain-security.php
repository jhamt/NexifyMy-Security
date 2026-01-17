<?php
/**
 * Supply Chain Security Module.
 * Monitors dependencies, third-party scripts, and package vulnerabilities.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Supply_Chain {

	/**
	 * Option key for scan results.
	 */
	const SCAN_RESULTS_OPTION = 'nexifymy_supply_chain_results';

	/**
	 * Transient key for CDN integrity cache.
	 */
	const CDN_CACHE_KEY = 'nexifymy_cdn_integrity_cache';

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'                => true,
		'scan_plugins'           => true,
		'scan_themes'            => true,
		'scan_composer'          => true,
		'scan_npm'               => true,
		'monitor_external_scripts' => true,
		'verify_cdn_integrity'   => true,
		'auto_scan_schedule'     => 'weekly',
		'notify_on_issues'       => true,
	);

	/**
	 * Known CDN domains for integrity checking.
	 */
	private $known_cdns = array(
		'cdnjs.cloudflare.com',
		'cdn.jsdelivr.net',
		'unpkg.com',
		'ajax.googleapis.com',
		'code.jquery.com',
		'stackpath.bootstrapcdn.com',
		'maxcdn.bootstrapcdn.com',
		'fonts.googleapis.com',
		'use.fontawesome.com',
	);

	/**
	 * Initialize the module.
	 */
	public function init() {
		// Schedule automatic scans.
		add_action( 'nexifymy_supply_chain_scan', array( $this, 'run_full_scan' ) );

		$settings = $this->get_settings();
		if ( ! empty( $settings['enabled'] ) && ! wp_next_scheduled( 'nexifymy_supply_chain_scan' ) ) {
			$schedule = $settings['auto_scan_schedule'] === 'daily' ? 'daily' : 'weekly';
			wp_schedule_event( time(), $schedule, 'nexifymy_supply_chain_scan' );
		}

		// Hook to detect enqueued scripts.
		if ( ! empty( $settings['monitor_external_scripts'] ) ) {
			add_action( 'wp_print_scripts', array( $this, 'capture_external_scripts' ), 999 );
			add_action( 'admin_print_scripts', array( $this, 'capture_external_scripts' ), 999 );
		}

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_supply_chain_scan', array( $this, 'ajax_run_scan' ) );
		add_action( 'wp_ajax_nexifymy_get_supply_chain_status', array( $this, 'ajax_get_status' ) );
		add_action( 'wp_ajax_nexifymy_verify_cdn_script', array( $this, 'ajax_verify_cdn_script' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['supply_chain'] ) ) {
				return wp_parse_args( $all_settings['supply_chain'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Run full supply chain scan.
	 *
	 * @return array Scan results.
	 */
	public function run_full_scan() {
		$results = array(
			'scanned_at'        => current_time( 'mysql' ),
			'plugins'           => array(),
			'themes'            => array(),
			'composer'          => array(),
			'npm'               => array(),
			'external_scripts'  => array(),
			'issues'            => array(),
			'total_issues'      => 0,
		);

		$settings = $this->get_settings();

		// 1. Scan plugins for vulnerabilities.
		if ( ! empty( $settings['scan_plugins'] ) ) {
			$results['plugins'] = $this->scan_plugins();
		}

		// 2. Scan themes.
		if ( ! empty( $settings['scan_themes'] ) ) {
			$results['themes'] = $this->scan_themes();
		}

		// 3. Scan composer dependencies.
		if ( ! empty( $settings['scan_composer'] ) ) {
			$results['composer'] = $this->scan_composer_dependencies();
		}

		// 4. Scan npm dependencies.
		if ( ! empty( $settings['scan_npm'] ) ) {
			$results['npm'] = $this->scan_npm_dependencies();
		}

		// 5. Get external scripts.
		$results['external_scripts'] = $this->get_cached_external_scripts();

		// Count total issues.
		$results['total_issues'] = count( $results['plugins']['vulnerable'] ?? array() )
			+ count( $results['themes']['vulnerable'] ?? array() )
			+ count( $results['composer']['vulnerable'] ?? array() )
			+ count( $results['npm']['vulnerable'] ?? array() )
			+ count( $results['external_scripts']['unverified'] ?? array() );

		// Store results.
		update_option( self::SCAN_RESULTS_OPTION, $results, false );

		// Notify if enabled and issues found.
		if ( ! empty( $settings['notify_on_issues'] ) && $results['total_issues'] > 0 ) {
			$this->send_notification( $results );
		}

		return $results;
	}

	/**
	 * Scan installed plugins for known vulnerabilities.
	 *
	 * @return array Plugin scan results.
	 */
	public function scan_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugins = get_plugins();
		$results = array(
			'total'      => count( $plugins ),
			'scanned'    => array(),
			'vulnerable' => array(),
			'outdated'   => array(),
			'abandoned'  => array(),
		);

		foreach ( $plugins as $file => $data ) {
			$slug = dirname( $file );
			if ( $slug === '.' ) {
				$slug = basename( $file, '.php' );
			}

			$plugin_info = array(
				'name'    => $data['Name'],
				'version' => $data['Version'],
				'slug'    => $slug,
				'file'    => $file,
				'active'  => is_plugin_active( $file ),
			);

			// Check WordPress.org API for updates.
			$api_info = $this->get_plugin_api_info( $slug );

			if ( $api_info ) {
				$plugin_info['latest_version'] = $api_info['version'] ?? null;
				$plugin_info['last_updated'] = $api_info['last_updated'] ?? null;

				// Check if outdated.
				if ( ! empty( $api_info['version'] ) && version_compare( $data['Version'], $api_info['version'], '<' ) ) {
					$plugin_info['status'] = 'outdated';
					$results['outdated'][] = $plugin_info;
				}

				// Check if abandoned (not updated in 2 years).
				if ( ! empty( $api_info['last_updated'] ) ) {
					$last_update = strtotime( $api_info['last_updated'] );
					$two_years_ago = strtotime( '-2 years' );
					if ( $last_update < $two_years_ago ) {
						$plugin_info['status'] = 'abandoned';
						$results['abandoned'][] = $plugin_info;
					}
				}
			}

			$results['scanned'][] = $plugin_info;
		}

		return $results;
	}

	/**
	 * Get plugin info from WordPress.org API.
	 *
	 * @param string $slug Plugin slug.
	 * @return array|null Plugin info or null.
	 */
	private function get_plugin_api_info( $slug ) {
		$cache_key = 'nexifymy_plugin_info_' . $slug;
		$cached = get_transient( $cache_key );

		if ( false !== $cached ) {
			return $cached;
		}

		$url = 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&slug=' . urlencode( $slug );
		$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

		if ( is_wp_error( $response ) ) {
			return null;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( empty( $body ) || isset( $body['error'] ) ) {
			return null;
		}

		$info = array(
			'version'      => $body['version'] ?? null,
			'last_updated' => $body['last_updated'] ?? null,
			'tested'       => $body['tested'] ?? null,
			'requires'     => $body['requires'] ?? null,
		);

		set_transient( $cache_key, $info, DAY_IN_SECONDS );

		return $info;
	}

	/**
	 * Scan installed themes.
	 *
	 * @return array Theme scan results.
	 */
	public function scan_themes() {
		$themes = wp_get_themes();
		$results = array(
			'total'      => count( $themes ),
			'scanned'    => array(),
			'vulnerable' => array(),
			'outdated'   => array(),
			'abandoned'  => array(),
		);

		foreach ( $themes as $slug => $theme ) {
			$theme_info = array(
				'name'    => $theme->get( 'Name' ),
				'version' => $theme->get( 'Version' ),
				'slug'    => $slug,
				'active'  => $slug === get_stylesheet(),
			);

			$results['scanned'][] = $theme_info;
		}

		return $results;
	}

	/**
	 * Scan Composer dependencies (composer.lock).
	 *
	 * @return array Composer scan results.
	 */
	public function scan_composer_dependencies() {
		$results = array(
			'found'      => false,
			'packages'   => array(),
			'vulnerable' => array(),
		);

		// Check common locations for composer.lock.
		$locations = array(
			ABSPATH . 'composer.lock',
			WP_CONTENT_DIR . '/composer.lock',
			dirname( ABSPATH ) . '/composer.lock',
		);

		$lock_file = null;
		foreach ( $locations as $path ) {
			if ( file_exists( $path ) ) {
				$lock_file = $path;
				break;
			}
		}

		if ( ! $lock_file ) {
			return $results;
		}

		$results['found'] = true;
		$content = file_get_contents( $lock_file );
		$data = json_decode( $content, true );

		if ( empty( $data['packages'] ) ) {
			return $results;
		}

		foreach ( $data['packages'] as $package ) {
			$pkg_info = array(
				'name'    => $package['name'] ?? 'unknown',
				'version' => $package['version'] ?? 'unknown',
				'type'    => $package['type'] ?? 'library',
			);

			// Check against Packagist security advisories (simplified).
			$is_vulnerable = $this->check_composer_vulnerability( $pkg_info['name'], $pkg_info['version'] );

			if ( $is_vulnerable ) {
				$pkg_info['vulnerable'] = true;
				$results['vulnerable'][] = $pkg_info;
			}

			$results['packages'][] = $pkg_info;
		}

		return $results;
	}

	/**
	 * Check Composer package for vulnerabilities.
	 *
	 * @param string $name Package name.
	 * @param string $version Package version.
	 * @return bool True if vulnerable.
	 */
	private function check_composer_vulnerability( $name, $version ) {
		// Known vulnerable packages (simplified database).
		$known_vulnerable = array(
			'symfony/http-foundation' => array( '<2.8.52', '<3.4.35', '<4.2.12', '<4.3.8' ),
			'guzzlehttp/guzzle' => array( '<6.5.8', '<7.4.5' ),
			'monolog/monolog' => array( '<1.26.1', '<2.3.5' ),
			'phpmailer/phpmailer' => array( '<6.1.6' ),
		);

		if ( ! isset( $known_vulnerable[ $name ] ) ) {
			return false;
		}

		foreach ( $known_vulnerable[ $name ] as $vuln_constraint ) {
			// Simple version comparison.
			$operator = preg_replace( '/[0-9.]/', '', $vuln_constraint );
			$vuln_version = preg_replace( '/[^0-9.]/', '', $vuln_constraint );

			if ( empty( $operator ) ) {
				$operator = '<';
			}

			if ( version_compare( $version, $vuln_version, $operator ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Scan npm dependencies (package-lock.json).
	 *
	 * @return array NPM scan results.
	 */
	public function scan_npm_dependencies() {
		$results = array(
			'found'      => false,
			'packages'   => array(),
			'vulnerable' => array(),
		);

		// Check for package-lock.json in theme or plugin directories.
		$theme_path = get_stylesheet_directory() . '/package-lock.json';

		if ( file_exists( $theme_path ) ) {
			$results['found'] = true;
			$content = file_get_contents( $theme_path );
			$data = json_decode( $content, true );

			if ( ! empty( $data['packages'] ) ) {
				foreach ( $data['packages'] as $name => $info ) {
					if ( empty( $name ) || $name === '' ) {
						continue;
					}

					$pkg_info = array(
						'name'    => ltrim( $name, 'node_modules/' ),
						'version' => $info['version'] ?? 'unknown',
					);

					// Check against known vulnerable packages.
					$is_vulnerable = $this->check_npm_vulnerability( $pkg_info['name'], $pkg_info['version'] );

					if ( $is_vulnerable ) {
						$pkg_info['vulnerable'] = true;
						$results['vulnerable'][] = $pkg_info;
					}

					$results['packages'][] = $pkg_info;
				}
			}
		}

		return $results;
	}

	/**
	 * Check NPM package for vulnerabilities.
	 *
	 * @param string $name Package name.
	 * @param string $version Package version.
	 * @return bool True if vulnerable.
	 */
	private function check_npm_vulnerability( $name, $version ) {
		// Known vulnerable npm packages (simplified).
		$known_vulnerable = array(
			'lodash'         => array( '<4.17.21' ),
			'minimist'       => array( '<1.2.6' ),
			'axios'          => array( '<0.21.2' ),
			'serialize-javascript' => array( '<3.1.0' ),
			'jquery'         => array( '<3.5.0' ),
			'moment'         => array( '<2.29.4' ),
		);

		if ( ! isset( $known_vulnerable[ $name ] ) ) {
			return false;
		}

		foreach ( $known_vulnerable[ $name ] as $vuln_constraint ) {
			$vuln_version = preg_replace( '/[^0-9.]/', '', $vuln_constraint );
			if ( version_compare( $version, $vuln_version, '<' ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Capture external scripts from enqueued assets.
	 */
	public function capture_external_scripts() {
		global $wp_scripts;

		if ( empty( $wp_scripts->registered ) ) {
			return;
		}

		$external = array();
		$site_host = wp_parse_url( home_url(), PHP_URL_HOST );

		foreach ( $wp_scripts->registered as $handle => $script ) {
			if ( empty( $script->src ) ) {
				continue;
			}

			$src = $script->src;

			// Make absolute URL.
			if ( strpos( $src, '//' ) === 0 ) {
				$src = 'https:' . $src;
			} elseif ( strpos( $src, '/' ) === 0 ) {
				continue; // Local script.
			}

			$parsed = wp_parse_url( $src );
			$host = $parsed['host'] ?? '';

			// Skip local scripts.
			if ( $host === $site_host || empty( $host ) ) {
				continue;
			}

			$is_cdn = in_array( $host, $this->known_cdns, true );
			$has_integrity = ! empty( $script->extra['integrity'] );

			$external[] = array(
				'handle'    => $handle,
				'src'       => $src,
				'host'      => $host,
				'is_cdn'    => $is_cdn,
				'integrity' => $has_integrity,
				'version'   => $script->ver ?? 'unknown',
			);
		}

		// Store for later retrieval.
		if ( ! empty( $external ) ) {
			$existing = get_transient( 'nexifymy_external_scripts' ) ?: array();
			$merged = array_merge( $existing, $external );

			// Deduplicate by handle.
			$unique = array();
			foreach ( $merged as $script ) {
				$unique[ $script['handle'] ] = $script;
			}

			set_transient( 'nexifymy_external_scripts', array_values( $unique ), HOUR_IN_SECONDS );
		}
	}

	/**
	 * Get cached external scripts.
	 *
	 * @return array External scripts data.
	 */
	public function get_cached_external_scripts() {
		$scripts = get_transient( 'nexifymy_external_scripts' ) ?: array();

		$verified = array();
		$unverified = array();

		foreach ( $scripts as $script ) {
			if ( $script['integrity'] || $script['is_cdn'] ) {
				$verified[] = $script;
			} else {
				$unverified[] = $script;
			}
		}

		return array(
			'total'      => count( $scripts ),
			'verified'   => $verified,
			'unverified' => $unverified,
		);
	}

	/**
	 * Verify CDN script integrity.
	 *
	 * @param string $url Script URL.
	 * @return array Verification result.
	 */
	public function verify_cdn_script( $url ) {
		$response = wp_remote_get( $url, array( 'timeout' => 15 ) );

		if ( is_wp_error( $response ) ) {
			return array(
				'success' => false,
				'error'   => $response->get_error_message(),
			);
		}

		$body = wp_remote_retrieve_body( $response );
		$hash = hash( 'sha384', $body );

		return array(
			'success'   => true,
			'url'       => $url,
			'sha384'    => 'sha384-' . base64_encode( hex2bin( $hash ) ),
			'size'      => strlen( $body ),
			'integrity' => 'sha384-' . base64_encode( hex2bin( $hash ) ),
		);
	}

	/**
	 * Send notification for supply chain issues.
	 *
	 * @param array $results Scan results.
	 */
	private function send_notification( $results ) {
		$to = get_option( 'admin_email' );
		$subject = sprintf( '[%s] Supply Chain Security Alert', get_bloginfo( 'name' ) );

		$message = "Supply Chain Security Scan Results\n\n";
		$message .= sprintf( "Site: %s\n", home_url() );
		$message .= sprintf( "Scanned: %s\n\n", $results['scanned_at'] );
		$message .= sprintf( "Total Issues Found: %d\n\n", $results['total_issues'] );

		if ( ! empty( $results['plugins']['vulnerable'] ) ) {
			$message .= "Vulnerable Plugins:\n";
			foreach ( $results['plugins']['vulnerable'] as $plugin ) {
				$message .= "  - {$plugin['name']} v{$plugin['version']}\n";
			}
		}

		if ( ! empty( $results['plugins']['outdated'] ) ) {
			$message .= "\nOutdated Plugins:\n";
			foreach ( $results['plugins']['outdated'] as $plugin ) {
				$message .= "  - {$plugin['name']} v{$plugin['version']} (Latest: {$plugin['latest_version']})\n";
			}
		}

		if ( ! empty( $results['composer']['vulnerable'] ) ) {
			$message .= "\nVulnerable Composer Packages:\n";
			foreach ( $results['composer']['vulnerable'] as $pkg ) {
				$message .= "  - {$pkg['name']} v{$pkg['version']}\n";
			}
		}

		if ( ! empty( $results['npm']['vulnerable'] ) ) {
			$message .= "\nVulnerable NPM Packages:\n";
			foreach ( $results['npm']['vulnerable'] as $pkg ) {
				$message .= "  - {$pkg['name']} v{$pkg['version']}\n";
			}
		}

		$message .= "\n\nPlease update these dependencies as soon as possible.";

		wp_mail( $to, $subject, $message );
	}

	/**
	 * Get last scan results.
	 *
	 * @return array Scan results.
	 */
	public function get_last_results() {
		return get_option( self::SCAN_RESULTS_OPTION, array() );
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	/**
	 * Run scan via AJAX.
	 */
	public function ajax_run_scan() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$results = $this->run_full_scan();
		wp_send_json_success( $results );
	}

	/**
	 * Get status via AJAX.
	 */
	public function ajax_get_status() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		wp_send_json_success( $this->get_last_results() );
	}

	/**
	 * Verify CDN script via AJAX.
	 */
	public function ajax_verify_cdn_script() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$url = isset( $_POST['url'] ) ? esc_url_raw( wp_unslash( $_POST['url'] ) ) : '';

		if ( empty( $url ) ) {
			wp_send_json_error( 'No URL provided.' );
		}

		$result = $this->verify_cdn_script( $url );
		wp_send_json_success( $result );
	}
}
