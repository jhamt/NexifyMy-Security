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
	 * OSV.dev API endpoint.
	 */
	const OSV_API_URL = 'https://api.osv.dev/v1';

	/**
	 * OSV API cache TTL in seconds (1 hour).
	 */
	const OSV_CACHE_TTL = 3600;

	/**
	 * SRI registry cache TTL in seconds (24 hours).
	 */
	const SRI_REGISTRY_CACHE_TTL = 86400;

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
	 * Mapping of CDN domains to their SRI registry source.
	 */
	private $sri_registries = array(
		'cdnjs.cloudflare.com' => 'cdnjs',
		'cdn.jsdelivr.net'     => 'jsdelivr',
		'unpkg.com'            => 'unpkg',
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
		add_action( 'wp_ajax_nexifymy_check_package_vuln', array( $this, 'ajax_check_package_vuln' ) );
		add_action( 'wp_ajax_nexifymy_verify_sri', array( $this, 'ajax_verify_sri' ) );
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
	/**
	 * Scan Composer dependencies (composer.lock) including dev packages.
	 *
	 * @return array Composer scan results.
	 */
	public function scan_composer_dependencies() {
		$results = array(
			'found'         => false,
			'files_scanned' => 0,
			'packages'      => array(),
			'vulnerable'    => array(),
		);

		$lock_files = $this->find_lock_files( 'composer.lock' );

		if ( empty( $lock_files ) ) {
			return $results;
		}

		$results['found'] = true;
		$results['files_scanned'] = count( $lock_files );
		$all_packages = array();

		foreach ( $lock_files as $lock_file ) {
			$content = file_get_contents( $lock_file );
			$data = json_decode( $content, true );
			if ( ! is_array( $data ) ) {
				continue;
			}

			// Support both production and dev packages.
			$packages = array_merge(
				$data['packages'] ?? array(),
				$data['packages-dev'] ?? array()
			);

			foreach ( $packages as $pkg ) {
				if ( empty( $pkg['name'] ) || empty( $pkg['version'] ) ) {
					continue;
				}

				$key = $pkg['name'] . '@' . $pkg['version'];
				if ( ! isset( $all_packages[ $key ] ) ) {
					$all_packages[ $key ] = array(
						'name'    => $pkg['name'],
						'version' => $pkg['version'],
						'file'    => str_replace( ABSPATH, '', $lock_file ),
					);
				}
			}
		}

		if ( empty( $all_packages ) ) {
			return $results;
		}

		// Batch query OSV.
		$vuln_data = $this->batch_query_osv( array_values( $all_packages ), 'Packagist' );

		foreach ( $all_packages as $key => $pkg ) {
			if ( isset( $vuln_data[ $key ] ) ) {
				$pkg['vulnerable'] = true;
				$pkg['vulnerabilities'] = $vuln_data[ $key ];
				$results['vulnerable'][] = $pkg;
			}
			$results['packages'][] = $pkg;
		}

		return $results;
	}

	/**
	 * Check Composer package for vulnerabilities via OSV.dev API.
	 *
	 * @param string $name Package name.
	 * @param string $version Package version.
	 * @return array|false Vulnerability data or false if none found.
	 */
	private function check_composer_vulnerability( $name, $version ) {
		return $this->query_osv_vulnerabilities( 'Packagist', $name, $version );
	}

	/**
	 * Query OSV.dev API for vulnerabilities.
	 *
	 * @param string $ecosystem Package ecosystem (npm, Packagist, PyPI, etc.).
	 * @param string $name Package name.
	 * @param string $version Package version.
	 * @return array|false Vulnerability data or false if none found.
	 */
	public function query_osv_vulnerabilities( $ecosystem, $name, $version ) {
		$cache_key = $this->get_osv_cache_key( $ecosystem, $name, $version );
		$cached = get_transient( $cache_key );

		if ( false !== $cached ) {
			return ! empty( $cached ) ? $cached : false;
		}

		$url = self::OSV_API_URL . '/query';
		$body = wp_json_encode( array(
			'package' => array(
				'name'      => $name,
				'ecosystem' => $ecosystem,
			),
			'version' => $version,
		) );

		$response = wp_remote_post( $url, array(
			'timeout' => 15,
			'headers' => array( 'Content-Type' => 'application/json' ),
			'body'    => $body,
		) );

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		if ( $status_code !== 200 ) {
			return false;
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( empty( $data['vulns'] ) ) {
			set_transient( $cache_key, array(), self::OSV_CACHE_TTL );
			return false;
		}

		$vulnerabilities = $this->parse_osv_vulns( $data['vulns'] );

		set_transient( $cache_key, $vulnerabilities, self::OSV_CACHE_TTL );
		return $vulnerabilities;
	}

	/**
	 * Batch query OSV.dev API for multiple packages.
	 *
	 * @param array  $packages Array of packages with 'name' and 'version' keys.
	 * @param string $ecosystem Package ecosystem.
	 * @return array Results keyed by package name.
	 */
	public function batch_query_osv( $packages, $ecosystem ) {
		$results = array();
		$uncached_packages = array();

		foreach ( $packages as $pkg ) {
			if ( empty( $pkg['name'] ) || empty( $pkg['version'] ) ) {
				continue;
			}

			$key = $pkg['name'] . '@' . $pkg['version'];
			$cache_key = $this->get_osv_cache_key( $ecosystem, $pkg['name'], $pkg['version'] );
			$cached = get_transient( $cache_key );

			if ( false !== $cached ) {
				if ( ! empty( $cached ) ) {
					$results[ $key ] = $cached;
				}
				continue;
			}

			$pkg['cache_key'] = $cache_key;
			$pkg['result_key'] = $key;
			$uncached_packages[] = $pkg;
		}

		if ( empty( $uncached_packages ) ) {
			return $results;
		}

		// OSV.dev batch endpoint supports up to 1000 queries.
		$batches = array_chunk( $uncached_packages, 1000 );

		foreach ( $batches as $batch ) {
			$queries = array();
			foreach ( $batch as $pkg ) {
				$queries[] = array(
					'package' => array(
						'name'      => $pkg['name'],
						'ecosystem' => $ecosystem,
					),
					'version' => $pkg['version'],
				);
			}

			$url = self::OSV_API_URL . '/querybatch';
			$response = wp_remote_post( $url, array(
				'timeout' => 30,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode( array( 'queries' => $queries ) ),
			) );

			if ( is_wp_error( $response ) ) {
				continue;
			}

			if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
				continue;
			}

			$data = json_decode( wp_remote_retrieve_body( $response ), true );
			$batch_results = $data['results'] ?? array();

			foreach ( $batch as $index => $pkg ) {
				$parsed_vulns = array();
				$result = $batch_results[ $index ] ?? array();
				if ( ! empty( $result['vulns'] ) ) {
					$parsed_vulns = $this->parse_osv_vulns( $result['vulns'] );
					$results[ $pkg['result_key'] ] = $parsed_vulns;
				}

				set_transient( $pkg['cache_key'], $parsed_vulns, self::OSV_CACHE_TTL );
			}
		}

		return $results;
	}

	/**
	 * Parse OSV vulnerability data.
	 *
	 * @param array $vulns Raw vulnerability data from OSV.
	 * @return array Parsed vulnerabilities.
	 */
	private function parse_osv_vulns( $vulns ) {
		$parsed = array();
		foreach ( $vulns as $vuln ) {
			$severity = 'UNKNOWN';
			$cvss_score = null;
			$fixed_version = null;
			$aliases = $vuln['aliases'] ?? array();
			$cve = null;

			if ( ! empty( $vuln['database_specific']['severity'] ) ) {
				$severity = strtoupper( sanitize_text_field( $vuln['database_specific']['severity'] ) );
			}

			foreach ( $aliases as $alias ) {
				if ( is_string( $alias ) && preg_match( '/^CVE-\d{4}-\d+$/', $alias ) ) {
					$cve = $alias;
					break;
				}
			}

			if ( ! empty( $vuln['severity'] ) && is_array( $vuln['severity'] ) ) {
				foreach ( $vuln['severity'] as $sev ) {
					if ( empty( $sev['score'] ) ) {
						continue;
					}

					$raw_score = $sev['score'];
					if ( is_numeric( $raw_score ) ) {
						$cvss_score = (float) $raw_score;
					} elseif ( is_string( $raw_score ) && preg_match( '/([0-9]+(?:\.[0-9]+)?)/', $raw_score, $matches ) ) {
						$cvss_score = (float) $matches[1];
					}

					if ( null !== $cvss_score ) {
						if ( $cvss_score >= 9.0 ) {
							$severity = 'CRITICAL';
						} elseif ( $cvss_score >= 7.0 ) {
							$severity = 'HIGH';
						} elseif ( $cvss_score >= 4.0 ) {
							$severity = 'MEDIUM';
						} else {
							$severity = 'LOW';
						}
						break;
					}
				}
			}

			if ( ! empty( $vuln['affected'] ) ) {
				foreach ( $vuln['affected'] as $affected ) {
					if ( ! empty( $affected['ranges'] ) ) {
						foreach ( $affected['ranges'] as $range ) {
							if ( ! empty( $range['events'] ) ) {
								foreach ( $range['events'] as $event ) {
									if ( ! empty( $event['fixed'] ) ) {
										$fixed_version = $event['fixed'];
										break 3;
									}
								}
							}
						}
					}
				}
			}

			$parsed[] = array(
				'id'            => $vuln['id'] ?? 'UNKNOWN',
				'cve'           => $cve,
				'aliases'       => $aliases,
				'summary'       => $vuln['summary'] ?? $vuln['details'] ?? 'No description available.',
				'severity'      => $severity,
				'cvss_score'    => $cvss_score,
				'fixed_version' => $fixed_version,
				'published'     => $vuln['published'] ?? null,
				'modified'      => $vuln['modified'] ?? null,
				'references'    => array_slice( $vuln['references'] ?? array(), 0, 3 ),
			);
		}
		return $parsed;
	}

	/**
	 * Build deterministic transient cache key for OSV queries.
	 *
	 * @param string $ecosystem Package ecosystem.
	 * @param string $name Package name.
	 * @param string $version Package version.
	 * @return string Cache key.
	 */
	private function get_osv_cache_key( $ecosystem, $name, $version ) {
		return 'nexifymy_osv_' . md5( $ecosystem . '|' . $name . '|' . $version );
	}

	/**
	 * Scan npm dependencies (package-lock.json).
	 *
	 * @return array NPM scan results.
	 */
	/**
	 * Scan npm dependencies (package-lock.json) in multiple locations.
	 *
	 * @return array NPM scan results.
	 */
	public function scan_npm_dependencies() {
		$results = array(
			'found'         => false,
			'files_scanned' => 0,
			'packages'      => array(),
			'vulnerable'    => array(),
		);

		$lock_files = $this->find_lock_files( 'package-lock.json' );

		if ( empty( $lock_files ) ) {
			return $results;
		}

		$results['found'] = true;
		$results['files_scanned'] = count( $lock_files );
		$all_packages = array();

		foreach ( $lock_files as $file ) {
			$content = file_get_contents( $file );
			$data = json_decode( $content, true );
			if ( ! is_array( $data ) ) {
				continue;
			}

			// Handle legacy (v1) and modern (v2/v3) lockfile formats.
			if ( ! empty( $data['dependencies'] ) && is_array( $data['dependencies'] ) ) {
				$this->collect_npm_v1_dependencies( $data['dependencies'], $file, $all_packages );
			}

			if ( ! empty( $data['packages'] ) && is_array( $data['packages'] ) ) {
				foreach ( $data['packages'] as $name => $info ) {
					// v2/v3 use empty string for root, and paths like "node_modules/foo".
					if ( empty( $name ) ) {
						continue;
					}

					$clean_name = preg_replace( '/^.*node_modules\//', '', $name );
					if ( empty( $clean_name ) && ! empty( $info['name'] ) ) {
						$clean_name = $info['name'];
					}

					$this->collect_npm_package( $clean_name, $info, $file, $all_packages );
				}
			}
		}

		if ( empty( $all_packages ) ) {
			return $results;
		}

		// Batch query OSV.
		$vuln_data = $this->batch_query_osv( array_values( $all_packages ), 'npm' );

		foreach ( $all_packages as $key => $pkg ) {
			if ( isset( $vuln_data[ $key ] ) ) {
				$pkg['vulnerable'] = true;
				$pkg['vulnerabilities'] = $vuln_data[ $key ];
				$results['vulnerable'][] = $pkg;
			}
			$results['packages'][] = $pkg;
		}

		return $results;
	}

	/**
	 * Helper to collect npm package info.
	 *
	 * @param string $name Package name.
	 * @param array  $info Package info.
	 * @param string $file Source file.
	 * @param array  $all_packages Reference to collector array.
	 */
	private function collect_npm_package( $name, $info, $file, &$all_packages ) {
		if ( empty( $name ) || empty( $info['version'] ) ) {
			return;
		}

		$version = $info['version'];
		$key = $name . '@' . $version;

		if ( ! isset( $all_packages[ $key ] ) ) {
			$all_packages[ $key ] = array(
				'name'    => $name,
				'version' => $version,
				'file'    => str_replace( ABSPATH, '', $file ),
			);
		}
	}

	/**
	 * Recursively collect npm v1 dependencies (nested dependency tree).
	 *
	 * @param array  $dependencies Dependency tree.
	 * @param string $file Source lockfile.
	 * @param array  $all_packages Collector.
	 */
	private function collect_npm_v1_dependencies( $dependencies, $file, &$all_packages ) {
		foreach ( $dependencies as $name => $info ) {
			if ( ! is_array( $info ) ) {
				continue;
			}

			$this->collect_npm_package( $name, $info, $file, $all_packages );

			if ( ! empty( $info['dependencies'] ) && is_array( $info['dependencies'] ) ) {
				$this->collect_npm_v1_dependencies( $info['dependencies'], $file, $all_packages );
			}
		}
	}

	/**
	 * Find lock files in project.
	 *
	 * @param string $filename Filename to search for.
	 * @return array List of absolute paths.
	 */
	private function find_lock_files( $filename ) {
		// Root and content directories.
		$locations = array(
			trailingslashit( ABSPATH ) . $filename,
			trailingslashit( dirname( ABSPATH ) ) . $filename,
			trailingslashit( WP_CONTENT_DIR ) . $filename,
		);

		// Active theme.
		$locations[] = trailingslashit( get_stylesheet_directory() ) . $filename;

		// Parent theme (when child theme is active).
		$template_dir = get_template_directory();
		if ( $template_dir && $template_dir !== get_stylesheet_directory() ) {
			$locations[] = trailingslashit( $template_dir ) . $filename;
		}

		// All plugin directories.
		$plugin_dirs = glob( trailingslashit( WP_PLUGIN_DIR ) . '*', GLOB_ONLYDIR );
		if ( is_array( $plugin_dirs ) ) {
			foreach ( $plugin_dirs as $plugin_dir ) {
				$locations[] = trailingslashit( $plugin_dir ) . $filename;
			}
		}

		// MU plugins.
		if ( defined( 'WPMU_PLUGIN_DIR' ) && is_dir( WPMU_PLUGIN_DIR ) ) {
			$locations[] = trailingslashit( WPMU_PLUGIN_DIR ) . $filename;

			$mu_plugin_dirs = glob( trailingslashit( WPMU_PLUGIN_DIR ) . '*', GLOB_ONLYDIR );
			if ( is_array( $mu_plugin_dirs ) ) {
				foreach ( $mu_plugin_dirs as $mu_plugin_dir ) {
					$locations[] = trailingslashit( $mu_plugin_dir ) . $filename;
				}
			}
		}

		$found = array();
		foreach ( $locations as $loc ) {
			if ( file_exists( $loc ) ) {
				$found[] = $loc;
			}
		}

		return array_unique( $found );
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
	/**
	 * Verify CDN script integrity (legacy/simple wrapper).
	 *
	 * @param string $url Script URL.
	 * @return array Verification result.
	 */
	public function verify_cdn_script( $url ) {
		$result = $this->fetch_and_calculate_hash( $url, 'sha384' );
		if ( ! $result['success'] ) {
			return $result;
		}
		// Map 'integrity' to 'sha384' key for backward compat.
		$result['sha384'] = $result['integrity'];
		return $result;
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

	/**
	 * AJAX: Check single package vulnerability (e.g. for real-time check).
	 */
	public function ajax_check_package_vuln() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$ecosystem = sanitize_text_field( $_POST['ecosystem'] ?? '' );
		$name      = sanitize_text_field( $_POST['name'] ?? '' );
		$version   = sanitize_text_field( $_POST['version'] ?? '' );

		if ( empty( $ecosystem ) || empty( $name ) || empty( $version ) ) {
			wp_send_json_error( 'Missing parameters.' );
		}

		$vulns = $this->query_osv_vulnerabilities( $ecosystem, $name, $version );

		if ( $vulns ) {
			wp_send_json_success( array( 'vulnerable' => true, 'vulns' => $vulns ) );
		} else {
			wp_send_json_success( array( 'vulnerable' => false ) );
		}
	}

	/**
	 * AJAX: Verify SRI.
	 */
	public function ajax_verify_sri() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$url = isset( $_POST['url'] ) ? esc_url_raw( wp_unslash( $_POST['url'] ) ) : '';

		if ( empty( $url ) ) {
			wp_send_json_error( 'No URL provided.' );
		}

		$result = $this->verify_script_integrity( $url );
		wp_send_json_success( $result );
	}

	/**
	 * Verify script integrity against trusted registries.
	 *
	 * @param string $url Script URL.
	 * @return array Verification result.
	 */
	public function verify_script_integrity( $url ) {
		$registry_info = $this->parse_cdn_url( $url );

		if ( ! $registry_info ) {
			return array(
				'url'            => $url,
				'expected_hash'  => null,
				'actual_hash'    => null,
				'match'          => false,
				'drift_detected' => false,
				'source'         => 'unknown',
				'error'          => 'Unsupported or unrecognized CDN URL.',
			);
		}

		$expected_hash = $this->get_registry_sri( $registry_info );
		if ( ! $expected_hash ) {
			return array(
				'url'            => $url,
				'expected_hash'  => null,
				'actual_hash'    => null,
				'match'          => false,
				'drift_detected' => false,
				'source'         => $registry_info['source'],
				'error'          => 'Could not retrieve expected SRI hash from trusted registry.',
			);
		}

		$parts = explode( '-', $expected_hash, 2 );
		$algo = ! empty( $parts[0] ) ? strtolower( $parts[0] ) : 'sha384';

		$actual_info = $this->fetch_and_calculate_hash( $url, $algo );
		if ( empty( $actual_info['success'] ) ) {
			return array(
				'url'            => $url,
				'expected_hash'  => $expected_hash,
				'actual_hash'    => null,
				'match'          => false,
				'drift_detected' => false,
				'source'         => $registry_info['source'],
				'error'          => $actual_info['error'] ?? 'Unable to fetch script for hash verification.',
			);
		}

		$match = hash_equals( $expected_hash, $actual_info['integrity'] );

		return array(
			'url'            => $url,
			'expected_hash'  => $expected_hash,
			'actual_hash'    => $actual_info['integrity'],
			'match'          => $match,
			'drift_detected' => ! $match,
			'source'         => $registry_info['source'],
		);
	}

	/**
	 * Backward-compatible wrapper for legacy callers.
	 *
	 * @param string $url Script URL.
	 * @return array Verification result.
	 */
	public function verify_sri_against_registry( $url ) {
		return $this->verify_script_integrity( $url );
	}

	/**
	 * Parse CDN URL and map it to a supported registry source.
	 *
	 * @param string $url Script URL.
	 * @return array|false Parsed registry payload or false.
	 */
	private function parse_cdn_url( $url ) {
		$host = strtolower( (string) parse_url( $url, PHP_URL_HOST ) );
		$path = (string) parse_url( $url, PHP_URL_PATH );
		$host = preg_replace( '/^www\./', '', $host );

		if ( ! $host || ! $path ) {
			return false;
		}

		$source = $this->sri_registries[ $host ] ?? null;
		if ( empty( $source ) ) {
			return false;
		}

		if ( 'cdnjs' === $source && preg_match( '#^/ajax/libs/([^/]+)/([^/]+)/(.+)$#', $path, $matches ) ) {
			return array(
				'source'  => 'cdnjs',
				'library' => $matches[1],
				'version' => $matches[2],
				'file'    => $matches[3],
			);
		}

		if ( 'jsdelivr' === $source && preg_match( '#^/npm/((?:@[^/]+/)?[^@/]+)@([^/]+)/(.+)$#', $path, $matches ) ) {
			return array(
				'source'  => 'jsdelivr',
				'package' => $matches[1],
				'version' => $matches[2],
				'file'    => $matches[3],
			);
		}

		if ( 'unpkg' === $source && preg_match( '#^/((?:@[^/]+/)?[^@/]+)@([^/]+)/(.+)$#', $path, $matches ) ) {
			return array(
				'source'  => 'unpkg',
				'package' => $matches[1],
				'version' => $matches[2],
				'file'    => $matches[3],
			);
		}

		return false;
	}

	/**
	 * Get SRI hash from selected registry source.
	 *
	 * @param array $info Parsed registry payload.
	 * @return string|false
	 */
	private function get_registry_sri( $info ) {
		$cache_key = 'nexifymy_sri_' . md5( wp_json_encode( $info ) );
		$cached = get_transient( $cache_key );
		if ( false !== $cached ) {
			return ! empty( $cached ) ? $cached : false;
		}

		$hash = false;
		switch ( $info['source'] ) {
			case 'cdnjs':
				$hash = $this->get_sri_from_cdnjs( $info['library'], $info['version'], $info['file'] );
				break;
			case 'jsdelivr':
				$hash = $this->get_sri_from_jsdelivr( $info['package'], $info['version'], $info['file'] );
				break;
			case 'unpkg':
				$hash = $this->get_sri_from_unpkg( $info['package'], $info['version'], $info['file'] );
				break;
		}

		set_transient( $cache_key, $hash ?: '', self::SRI_REGISTRY_CACHE_TTL );
		return $hash ?: false;
	}

	/**
	 * Query cdnjs registry for trusted SRI hash.
	 *
	 * @param string $library Library name.
	 * @param string $version Version.
	 * @param string $file File path.
	 * @return string|false
	 */
	public function get_sri_from_cdnjs( $library, $version, $file ) {
		$url = sprintf(
			'https://api.cdnjs.com/libraries/%s/%s?fields=sri',
			rawurlencode( $library ),
			rawurlencode( $version )
		);

		$response = wp_remote_get( $url, array( 'timeout' => 15 ) );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $data['sri'] ) || ! is_array( $data['sri'] ) ) {
			return false;
		}

		$file_path = ltrim( $file, '/' );
		if ( ! empty( $data['sri'][ $file_path ] ) ) {
			return $data['sri'][ $file_path ];
		}

		$alt_file_path = '/' . $file_path;
		if ( ! empty( $data['sri'][ $alt_file_path ] ) ) {
			return $data['sri'][ $alt_file_path ];
		}

		return false;
	}

	/**
	 * Query jsDelivr registry for trusted SRI hash.
	 *
	 * @param string $package Package name.
	 * @param string $version Version.
	 * @param string $file File path.
	 * @return string|false
	 */
	public function get_sri_from_jsdelivr( $package, $version, $file ) {
		$url = sprintf(
			'https://data.jsdelivr.com/v1/package/npm/%s@%s/flat',
			rawurlencode( $package ),
			rawurlencode( $version )
		);

		$response = wp_remote_get( $url, array( 'timeout' => 15 ) );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $data['files'] ) || ! is_array( $data['files'] ) ) {
			return false;
		}

		$file_path = '/' . ltrim( $file, '/' );
		foreach ( $data['files'] as $entry ) {
			if ( empty( $entry['name'] ) || empty( $entry['hash'] ) || $entry['name'] !== $file_path ) {
				continue;
			}

			$hash = $entry['hash'];
			if ( is_string( $hash ) && preg_match( '/^sha(256|384|512)-/i', $hash ) ) {
				return $hash;
			}

			return 'sha256-' . $hash;
		}

		return false;
	}

	/**
	 * Query unpkg metadata endpoint for trusted SRI hash.
	 *
	 * @param string $package Package name.
	 * @param string $version Version.
	 * @param string $file File path.
	 * @return string|false
	 */
	private function get_sri_from_unpkg( $package, $version, $file ) {
		$url = sprintf(
			'https://unpkg.com/%s@%s/%s?meta',
			rawurlencode( $package ),
			rawurlencode( $version ),
			ltrim( $file, '/' )
		);

		$response = wp_remote_get( $url, array( 'timeout' => 15 ) );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! empty( $data['integrity'] ) ) {
			return $data['integrity'];
		}

		if ( ! empty( $data['files'] ) && is_array( $data['files'] ) ) {
			$file_path = '/' . ltrim( $file, '/' );
			foreach ( $data['files'] as $entry ) {
				if ( ! empty( $entry['path'] ) && $entry['path'] === $file_path && ! empty( $entry['integrity'] ) ) {
					return $entry['integrity'];
				}
			}
		}

		return false;
	}

	/**
	 * Helper: Fetch URL and calculate hash.
	 */
	private function fetch_and_calculate_hash( $url, $algo = 'sha384' ) {
		$response = wp_remote_get( $url, array( 'timeout' => 15 ) );
		if ( is_wp_error( $response ) ) {
			return array(
				'success' => false,
				'error'   => $response->get_error_message(),
			);
		}
		$body = wp_remote_retrieve_body( $response );
		$binary_hash = hash( $algo, $body, true );
		$integrity = $algo . '-' . base64_encode( $binary_hash );

		return array(
			'success'   => true,
			'url'       => $url,
			'integrity' => $integrity,
			'size'      => strlen( $body ),
		);
	}
}
