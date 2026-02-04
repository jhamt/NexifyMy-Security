<?php
/**
 * Advanced Malware Scanner Module.
 * Implements heuristic analysis inspired by YARA & PHP Malware Finder.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Scanner {

	/**
	 * Option key for storing last scan state.
	 */
	const SCAN_STATE_OPTION = 'nexifymy_security_last_scan';

	/**
	 * Heuristic rules for malware detection.
	 * @var array
	 */
	private $heuristics = array();

	/**
	 * Cached scanner settings.
	 * @var array
	 */
	private $scanner_settings = array();

	/**
	 * Cached excluded path prefixes (absolute, normalized).
	 * @var string[]
	 */
	private $excluded_path_prefixes = array();

	/**
	 * Cached excluded extensions (lowercase, no dots).
	 * @var string[]
	 */
	private $excluded_extensions = array();

	/**
	 * Known safe plugin/theme slugs (from WordPress.org).
	 * These will have reduced confidence scoring.
	 * @var array
	 */
	private $known_safe_plugins = array(
		'woocommerce',
		'yoast-seo',
		'wordpress-seo',
		'elementor',
		'contact-form-7',
		'akismet',
		'jetpack',
		'wordfence',
		'wp-super-cache',
		'w3-total-cache',
		'wpforms-lite',
		'classic-editor',
		'gutenberg',
		'advanced-custom-fields',
		'duplicate-post',
		'updraftplus',
		'all-in-one-seo-pack',
		'google-analytics-for-wordpress',
		'really-simple-ssl',
		'redirection',
		'query-monitor',
	);

	/**
	 * Safe context patterns - these are legitimate uses of potentially dangerous functions.
	 * @var array
	 */
	private $safe_contexts = array(
		// WordPress core patterns
		'/wp-includes/',
		'/wp-admin/',
		'wp-config.php',
		// Common legitimate uses
		'vendor/',
		'node_modules/',
		// Development/testing
		'phpunit',
		'tests/',
		'test-',
	);

	/**
	 * Scan mode configurations.
	 * @var array
	 */
	private $scan_modes = array(
		'quick' => array(
			'name'        => 'Quick Scan',
			'description' => 'Fast scan of high-risk areas only (uploads folder). Checks for critical threats.',
			'directories' => array( 'uploads' ),
			'severity_levels' => array( 'critical' ),
			'max_file_size' => 512000, // 500KB
			'check_core' => false,
			'incremental' => false,
		),
		'standard' => array(
			'name'        => 'Standard Scan',
			'description' => 'Balanced scan of plugins, themes, and uploads. Checks critical and high threats.',
			'directories' => array( 'uploads', 'plugins', 'themes' ),
			'severity_levels' => array( 'critical', 'high' ),
			'max_file_size' => 2097152, // 2MB
			'check_core' => false,
			'incremental' => false, // Full scan by default for reliable results
		),
		'deep' => array(
			'name'        => 'Deep Scan',
			'description' => 'Comprehensive scan of entire WordPress installation including core files integrity check.',
			'directories' => array( 'uploads', 'plugins', 'themes', 'root' ),
			'severity_levels' => array( 'critical', 'high', 'medium', 'low' ),
			'max_file_size' => 10485760, // 10MB
			'check_core' => true,
			'incremental' => false, // Deep scan always scans everything
		),
	);

	/**
	 * Transient key for scan progress.
	 */
	const SCAN_PROGRESS_KEY = 'nexifymy_scan_progress';

	/**
	 * Initialize the scanner.
	 */
	public function init() {
		$this->load_signatures();

		// Always register AJAX endpoints so the UI gets a JSON error (instead of admin-ajax.php returning "0").
		add_action( 'wp_ajax_nexifymy_scan', array( $this, 'ajax_scan' ) );
		add_action( 'wp_ajax_nexifymy_scan_progress', array( $this, 'ajax_get_progress' ) );
		add_action( 'wp_ajax_nexifymy_scan_results', array( $this, 'ajax_get_results' ) );
		add_action( 'wp_ajax_nexifymy_core_integrity', array( $this, 'ajax_core_integrity_check' ) );
	}

	/**
	 * Update scan progress transient.
	 *
	 * @param array $progress Progress data.
	 */
	private function update_progress( $progress ) {
		set_transient( self::SCAN_PROGRESS_KEY, $progress, 300 ); // 5 min expiry
	}

	/**
	 * Get current scan progress.
	 *
	 * @return array Progress data.
	 */
	public function get_progress() {
		return get_transient( self::SCAN_PROGRESS_KEY ) ?: array(
			'phase'          => 'idle',
			'status'         => 'Not scanning',
			'current_file'   => '',
			'files_scanned'  => 0,
			'total_files'    => 0,
			'percent'        => 0,
			'threats_found'  => 0,
			'critical'       => 0,
			'high'           => 0,
			'medium'         => 0,
			'low'            => 0,
		);
	}

	/**
	 * AJAX handler to get scan progress.
	 */
	public function ajax_get_progress() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		if ( ! $this->is_scanner_enabled() ) {
			wp_send_json_error( 'Scanner module is disabled in settings.' );
		}

		wp_send_json_success( $this->get_progress() );
	}

	/**
	 * Load signatures from Signature Updater module or fallback to built-in.
	 */
	private function load_signatures() {
		// Try to get dynamic signatures from Signature Updater.
		if ( isset( $GLOBALS['nexifymy_signatures'] ) && method_exists( $GLOBALS['nexifymy_signatures'], 'get_scan_patterns' ) ) {
			$this->heuristics = $GLOBALS['nexifymy_signatures']->get_scan_patterns();
		}

		// Fallback to built-in if empty.
		if ( empty( $this->heuristics ) ) {
			$this->define_heuristics();
		}
	}

	/**
	 * Determine whether scanner module is enabled.
	 *
	 * @return bool
	 */
	private function is_scanner_enabled() {
		$settings = get_option( 'nexifymy_security_settings', array() );

		// If modules array doesn't exist yet, scanner is enabled by default
		if ( ! isset( $settings['modules'] ) ) {
			return true;
		}

		// If scanner_enabled is not set, enable by default
		if ( ! isset( $settings['modules']['scanner_enabled'] ) ) {
			return true;
		}

		// Otherwise, return the actual setting value
		return (bool) $settings['modules']['scanner_enabled'];
	}

	/**
	 * Load scanner settings and build caches for exclusions.
	 *
	 * @return array
	 */
	private function load_scanner_settings() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$scanner = isset( $settings['scanner'] ) && is_array( $settings['scanner'] ) ? $settings['scanner'] : array();

		$default_mode = sanitize_key( $scanner['default_mode'] ?? 'standard' );
		if ( ! isset( $this->scan_modes[ $default_mode ] ) ) {
			$default_mode = 'standard';
		}

		$max_file_size_kb = absint( $scanner['max_file_size_kb'] ?? 2048 );
		$max_file_size_kb = max( 100, min( 51200, $max_file_size_kb ?: 2048 ) ); // 100KB..50MB

		$excluded_paths = $scanner['excluded_paths'] ?? array();
		if ( is_string( $excluded_paths ) ) {
			$excluded_paths = array_filter( array_map( 'trim', preg_split( "/\r\n|\n|\r/", $excluded_paths ) ) );
		}

		$excluded_extensions = $scanner['excluded_extensions'] ?? array();
		if ( is_string( $excluded_extensions ) ) {
			$excluded_extensions = array_filter( array_map( 'trim', preg_split( "/\r\n|\n|\r/", $excluded_extensions ) ) );
		}

		$excluded_extensions = array_map(
			static function ( $ext ) {
				$ext = strtolower( ltrim( (string) $ext, ". \t\n\r\0\x0B" ) );
				return preg_replace( '/[^a-z0-9]+/', '', $ext );
			},
			(array) $excluded_extensions
		);
		$excluded_extensions = array_values( array_filter( array_unique( $excluded_extensions ) ) );

		$this->scanner_settings = array(
			'default_mode'     => $default_mode,
			'max_file_size'    => $max_file_size_kb * 1024,
			'excluded_paths'   => (array) $excluded_paths,
			'excluded_extensions' => $excluded_extensions,
		);

		$this->excluded_extensions = $excluded_extensions;
		$this->excluded_path_prefixes = $this->build_excluded_prefixes( (array) $excluded_paths );

		return $this->scanner_settings;
	}

	/**
	 * Build absolute path prefixes for exclusion checks.
	 *
	 * @param string[] $excluded_paths Paths (relative to ABSPATH or absolute).
	 * @return string[]
	 */
	private function build_excluded_prefixes( $excluded_paths ) {
		$prefixes = array();

		foreach ( $excluded_paths as $path ) {
			$path = trim( (string) $path );
			if ( $path === '' ) {
				continue;
			}

			// Convert to absolute path.
			$is_windows_abs = preg_match( '/^[a-zA-Z]:\\\\/', $path ) === 1;
			$is_unix_abs = strpos( $path, '/' ) === 0;
			if ( ! $is_windows_abs && ! $is_unix_abs && strpos( $path, ABSPATH ) !== 0 ) {
				$path = ABSPATH . ltrim( $path, "/\\" );
			}

			$real = realpath( $path );
			if ( ! $real ) {
				continue;
			}

			$real = rtrim( $real, "/\\" ) . DIRECTORY_SEPARATOR;
			$prefixes[] = $real;
		}

		return array_values( array_unique( $prefixes ) );
	}

	/**
	 * Check whether a path is excluded by prefix.
	 *
	 * @param string $path Absolute path.
	 * @return bool
	 */
	private function is_path_excluded( $path ) {
		if ( empty( $this->excluded_path_prefixes ) ) {
			return false;
		}

		// Avoid calling realpath() on every file for performance; iterator paths are already absolute.
		$real = rtrim( (string) $path, "/\\" ) . DIRECTORY_SEPARATOR;

		foreach ( $this->excluded_path_prefixes as $prefix ) {
			if ( DIRECTORY_SEPARATOR === '\\' ) {
				if ( stripos( $real, $prefix ) === 0 ) {
					return true;
				}
			} else {
				if ( strpos( $real, $prefix ) === 0 ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Check whether a file extension is excluded.
	 *
	 * @param string $extension File extension (lowercase, no dot).
	 * @return bool
	 */
	private function is_extension_excluded( $extension ) {
		if ( empty( $this->excluded_extensions ) ) {
			return false;
		}

		$extension = strtolower( ltrim( (string) $extension, '.' ) );

		return in_array( $extension, $this->excluded_extensions, true );
	}

	/**
	 * Define heuristic rules (Inspired by YARA/PHP Malware Finder).
	 */
	private function define_heuristics() {
		$this->heuristics = array(
			// Category: Obfuscation
			'eval_base64' => array(
				'severity'    => 'critical',
				'description' => 'eval(base64_decode()) - Common obfuscation',
				'pattern'     => '/eval\s*\(\s*base64_decode\s*\(/i',
			),
			'gzinflate_base64' => array(
				'severity'    => 'critical',
				'description' => 'gzinflate(base64_decode()) - Compressed obfuscation',
				'pattern'     => '/gzinflate\s*\(\s*base64_decode\s*\(/i',
			),
			'str_rot13' => array(
				'severity'    => 'high',
				'description' => 'str_rot13() obfuscation',
				'pattern'     => '/str_rot13\s*\(/i',
			),
			'hex_encoding' => array(
				'severity'    => 'medium',
				'description' => 'Heavy hex encoding (\\x usage)',
				'pattern'     => '/(\\\\x[0-9a-f]{2}){10,}/i', // 10+ consecutive hex chars
			),
			'long_base64' => array(
				'severity'    => 'medium',
				'description' => 'Long base64 string (possible encoded payload)',
				'pattern'     => '/[a-zA-Z0-9+\/=]{500,}/',
			),

			// Category: Dangerous Functions
			'shell_exec' => array(
				'severity'    => 'critical',
				'description' => 'shell_exec() - Command execution',
				'pattern'     => '/shell_exec\s*\(/i',
			),
			'exec' => array(
				'severity'    => 'critical',
				'description' => 'exec() - Command execution',
				'pattern'     => '/\bexec\s*\(/i',
			),
			'passthru' => array(
				'severity'    => 'critical',
				'description' => 'passthru() - Command execution',
				'pattern'     => '/passthru\s*\(/i',
			),
			'system' => array(
				'severity'    => 'critical',
				'description' => 'system() - Command execution',
				'pattern'     => '/\bsystem\s*\(/i',
			),
			'proc_open' => array(
				'severity'    => 'critical',
				'description' => 'proc_open() - Process control',
				'pattern'     => '/proc_open\s*\(/i',
			),
			'popen' => array(
				'severity'    => 'high',
				'description' => 'popen() - Process control',
				'pattern'     => '/\bpopen\s*\(/i',
			),
			'assert' => array(
				'severity'    => 'high',
				'description' => 'assert() - Possible code execution',
				'pattern'     => '/\bassert\s*\(/i',
			),
			'create_function' => array(
				'severity'    => 'high',
				'description' => 'create_function() - Dynamic code creation',
				'pattern'     => '/create_function\s*\(/i',
			),

			// Category: Webshell Indicators
			'globals_obfuscation' => array(
				'severity'    => 'high',
				'description' => '$GLOBALS obfuscation pattern',
				'pattern'     => '/\$GLOBALS\s*\[\s*[\'"][a-z0-9_]+[\'"]\s*\]\s*\(/i',
			),
			'php_uname' => array(
				'severity'    => 'medium',
				'description' => 'php_uname() - System info gathering',
				'pattern'     => '/php_uname\s*\(/i',
			),
			'getcwd' => array(
				'severity'    => 'low',
				'description' => 'getcwd() - Path discovery',
				'pattern'     => '/getcwd\s*\(/i',
			),
			'file_put_contents' => array(
				'severity'    => 'medium',
				'description' => 'file_put_contents() - File write capability',
				'pattern'     => '/file_put_contents\s*\(/i',
			),

			// Category: Suspicious Patterns
			'hidden_input' => array(
				'severity'    => 'medium',
				'description' => 'Hidden input with suspicious name',
				'pattern'     => '/<input[^>]+type\s*=\s*["\']hidden["\'][^>]+name\s*=\s*["\'](?:cmd|c|pass|password)["\'][^>]*>/i',
			),
			'suspicious_long_line' => array(
				'severity'    => 'medium',
				'description' => 'Suspiciously long single line (obfuscation)',
				'check_type'  => 'line_length',
				'threshold'   => 5000,
			),
		);
	}

	/**
	 * Handle AJAX scan request.
	 */
	public function ajax_scan() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized: You do not have permission to run scans.' );
		}

		if ( ! $this->is_scanner_enabled() ) {
			wp_send_json_error( 'Scanner module is disabled. Please enable it in Settings > Modules.' );
		}

		// Reload signatures to ensure we have the latest definitions
		$this->load_signatures();
		$this->load_scanner_settings();

		$mode = isset( $_POST['mode'] ) ? sanitize_key( $_POST['mode'] ) : '';
		if ( $mode === '' ) {
			$mode = $this->scanner_settings['default_mode'] ?? 'standard';
		}

		// Validate mode
		if ( ! isset( $this->scan_modes[ $mode ] ) ) {
			wp_send_json_error( 'Invalid scan mode: ' . esc_html( $mode ) );
		}

		try {
			$results = $this->perform_scan( $mode );
			wp_send_json_success( $results );
		} catch ( \Exception $e ) {
			wp_send_json_error( 'Scan failed: ' . esc_html( $e->getMessage() ) );
		} catch ( \Error $e ) {
			wp_send_json_error( 'Critical error: ' . esc_html( $e->getMessage() ) );
		}
	}

	/**
	 * AJAX handler to get stored scan results.
	 * Used to recover results if the main scan AJAX times out.
	 */
	public function ajax_get_results() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$results = get_option( 'nexifymy_last_scan_results', array() );
		if ( empty( $results ) ) {
			wp_send_json_error( 'No scan results available' );
		}

		wp_send_json_success( $results );
	}

	/**
	 * Perform the malware scan.
	 *
	 * @param string $mode 'quick', 'standard', or 'deep'.
	 * @return array Scan results.
	 */
	public function perform_scan( $mode = 'standard' ) {
		if ( empty( $this->heuristics ) ) {
			$this->define_heuristics();
		}

		// Respect module toggle for all entry points (AJAX, cron, direct calls).
		if ( ! $this->is_scanner_enabled() ) {
			return array(
				'scanned_at'     => current_time( 'mysql' ),
				'mode'           => sanitize_key( $mode ),
				'mode_name'      => 'Scanner Disabled',
				'files_scanned'  => 0,
				'threats_found'  => 0,
				'threats'        => array(),
				'core_integrity' => null,
				'error'          => 'Scanner module is disabled in settings.',
			);
		}

		// Increase limits for large scans
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 3600 ); // 1 hour for deep scans
		}
		if ( function_exists( 'ini_set' ) ) {
			@ini_set( 'memory_limit', '512M' );
		}

		$this->load_scanner_settings();

		$suspicious_files = array();
		$upload_dir = wp_upload_dir();
		$last_scan = get_option( self::SCAN_STATE_OPTION, 0 );
		$files_scanned = 0;
		$core_results = null;
		$threat_counts = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0 );

		// Validate mode.
		if ( ! isset( $this->scan_modes[ $mode ] ) ) {
			$mode = $this->scanner_settings['default_mode'] ?? 'standard';
		}

		$mode_config = $this->scan_modes[ $mode ];

		// Apply global max file size override.
		if ( ! empty( $this->scanner_settings['max_file_size'] ) ) {
			$mode_config['max_file_size'] = (int) $this->scanner_settings['max_file_size'];
		}

		// Initialize progress - Phase 1: Initialization
		$this->update_progress( array(
			'phase'          => 'initializing',
			'status'         => 'Initializing ' . $mode_config['name'] . '...',
			'current_file'   => '',
			'files_scanned'  => 0,
			'total_files'    => 0,
			'percent'        => 5,
			'threats_found'  => 0,
			'critical'       => 0,
			'high'           => 0,
			'medium'         => 0,
			'low'            => 0,
			'mode'           => $mode,
			'start_time'     => time(),
		) );

		// Build directories list based on mode.
		$directories_to_scan = array();
		foreach ( $mode_config['directories'] as $dir_key ) {
			switch ( $dir_key ) {
				case 'uploads':
					$directories_to_scan[] = $upload_dir['basedir'];
					break;
				case 'plugins':
					$directories_to_scan[] = WP_PLUGIN_DIR;
					break;
				case 'themes':
					$directories_to_scan[] = get_theme_root();
					break;
				case 'root':
					$directories_to_scan[] = ABSPATH;
					break;
			}
		}

		// Phase 2: Discovery - Count total files first
		$this->update_progress( array(
			'phase'          => 'discovery',
			'status'         => 'Discovering files to scan...',
			'current_file'   => '',
			'files_scanned'  => 0,
			'total_files'    => 0,
			'percent'        => 10,
			'threats_found'  => 0,
			'critical'       => 0,
			'high'           => 0,
			'medium'         => 0,
			'low'            => 0,
			'mode'           => $mode,
			'start_time'     => time(),
		) );

		// Count total files for progress calculation
		$total_files = 0;
		foreach ( $directories_to_scan as $dir ) {
			if ( is_dir( $dir ) && ! $this->is_path_excluded( $dir ) ) {
				$total_files += $this->count_files_in_directory( $dir, $mode_config );
			}
		}

		// Phase 3: Scanning
		$this->update_progress( array(
			'phase'          => 'scanning',
			'status'         => 'Scanning files for threats...',
			'current_file'   => '',
			'files_scanned'  => 0,
			'total_files'    => $total_files,
			'percent'        => 15,
			'threats_found'  => 0,
			'critical'       => 0,
			'high'           => 0,
			'medium'         => 0,
			'low'            => 0,
			'mode'           => $mode,
			'start_time'     => time(),
		) );

		// Perform file scan with progress updates.
		foreach ( $directories_to_scan as $dir ) {
			if ( ! is_dir( $dir ) ) {
				continue;
			}
			if ( $this->is_path_excluded( $dir ) ) {
				continue;
			}
			$scan_result = $this->scan_directory_with_progress( $dir, $mode_config, $last_scan, $files_scanned, $total_files, $suspicious_files, $threat_counts );
			$suspicious_files = $scan_result['threats'];
			$files_scanned = $scan_result['files_scanned'];
			$threat_counts = $scan_result['threat_counts'];
		}

		// Phase 4: Core Integrity (if deep scan)
		if ( $mode_config['check_core'] ) {
			$this->update_progress( array(
				'phase'          => 'core_check',
				'status'         => 'Verifying WordPress core integrity...',
				'current_file'   => 'wp-includes/',
				'files_scanned'  => $files_scanned,
				'total_files'    => $total_files,
				'percent'        => 90,
				'threats_found'  => array_sum( $threat_counts ),
				'critical'       => $threat_counts['critical'],
				'high'           => $threat_counts['high'],
				'medium'         => $threat_counts['medium'],
				'low'            => $threat_counts['low'],
				'mode'           => $mode,
			) );
			$core_results = $this->check_core_integrity();
		}

		// Phase 5: Complete
		$this->update_progress( array(
			'phase'          => 'complete',
			'status'         => 'Scan complete!',
			'current_file'   => '',
			'files_scanned'  => $files_scanned,
			'total_files'    => $total_files,
			'percent'        => 100,
			'threats_found'  => array_sum( $threat_counts ),
			'critical'       => $threat_counts['critical'],
			'high'           => $threat_counts['high'],
			'medium'         => $threat_counts['medium'],
			'low'            => $threat_counts['low'],
			'mode'           => $mode,
			'end_time'       => time(),
		) );

		// Update last scan time.
		update_option( self::SCAN_STATE_OPTION, time() );

		// Store results for later retrieval
		$results = array(
			'scanned_at'     => current_time( 'mysql' ),
			'mode'           => $mode,
			'mode_name'      => $mode_config['name'],
			'files_scanned'  => $files_scanned,
			'threats_found'  => array_sum( $threat_counts ),
			'threats'        => $suspicious_files,
			'threat_counts'  => $threat_counts,
			'core_integrity' => $core_results,
		);

		// Save for API access
		update_option( 'nexifymy_last_scan_results', $results );
		
		// Save for dashboard display (with structure admin.php expects)
		update_option( 'nexifymy_last_scan', array(
			'files_scanned' => $files_scanned,
			'time'          => current_time( 'mysql' ),
			'mode'          => $mode,
			'mode_name'     => $mode_config['name'],
		) );
		
		update_option( 'nexifymy_scan_results', array(
			'threats' => array_sum( $threat_counts ),
			'items'   => $suspicious_files,
			'counts'  => $threat_counts,
		) );

		return $results;
	}


	/**
	 * Count files in a directory for progress tracking.
	 *
	 * @param string $dir Directory path.
	 * @param array $mode_config Mode configuration.
	 * @return int File count.
	 */
	private function count_files_in_directory( $dir, $mode_config ) {
		$count = 0;
		$max_file_size = $mode_config['max_file_size'] ?? 2097152;

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);

			foreach ( $iterator as $file ) {
				if ( $file->isFile() ) {
					$ext = strtolower( pathinfo( $file->getFilename(), PATHINFO_EXTENSION ) );
					if ( in_array( $ext, array( 'php', 'js', 'html', 'htm' ), true ) ) {
						if ( $file->getSize() <= $max_file_size ) {
							$count++;
						}
					}
				}
			}
		} catch ( Exception $e ) {
			// Silently handle permission errors
		}

		return max( 1, $count ); // Ensure at least 1 to avoid division by zero
	}

	/**
	 * Scan a directory with progress updates.
	 *
	 * @param string $dir Directory path.
	 * @param array $mode_config Mode configuration.
	 * @param int $last_scan Timestamp of last scan.
	 * @param int $files_scanned Current files scanned count.
	 * @param int $total_files Total files to scan.
	 * @param array $existing_threats Already found threats.
	 * @param array $threat_counts Threat counts by severity.
	 * @return array Results with threats, files_scanned, threat_counts.
	 */
	private function scan_directory_with_progress( $dir, $mode_config, $last_scan, $files_scanned, $total_files, $existing_threats, $threat_counts ) {
		$results = $existing_threats;
		$update_interval = 10; // Update progress every 10 files

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);

			foreach ( $iterator as $file ) {
				if ( ! $file->isFile() ) {
					continue;
				}

				$filepath = $file->getPathname();

				// Skip excluded paths
				if ( $this->is_path_excluded( $filepath ) ) {
					continue;
				}

				// Skip excluded extensions
				$ext = strtolower( pathinfo( $filepath, PATHINFO_EXTENSION ) );
				if ( $this->is_extension_excluded( $ext ) ) {
					continue;
				}

				// Only scan PHP, JS, HTML files
				if ( ! in_array( $ext, array( 'php', 'js', 'html', 'htm' ), true ) ) {
					continue;
				}

				// Skip files larger than max size
				if ( $file->getSize() > ( $mode_config['max_file_size'] ?? 2097152 ) ) {
					continue;
				}

				// Incremental scanning - skip unmodified files
				if ( ! empty( $mode_config['incremental'] ) && $file->getMTime() < $last_scan ) {
					continue;
				}

				$files_scanned++;

				// Update progress periodically
				if ( $files_scanned % $update_interval === 0 ) {
					$percent = min( 85, 15 + ( ( $files_scanned / max( 1, $total_files ) ) * 70 ) );
					$relative_path = str_replace( ABSPATH, '', $filepath );

					$this->update_progress( array(
						'phase'          => 'scanning',
						'status'         => 'Scanning: ' . basename( $filepath ),
						'current_file'   => $relative_path,
						'files_scanned'  => $files_scanned,
						'total_files'    => $total_files,
						'percent'        => round( $percent ),
						'threats_found'  => array_sum( $threat_counts ),
						'critical'       => $threat_counts['critical'],
						'high'           => $threat_counts['high'],
						'medium'         => $threat_counts['medium'],
						'low'            => $threat_counts['low'],
						'mode'           => $mode_config['name'] ?? 'standard',
					) );
				}

				// Scan the file
				$threats = $this->scan_file( $filepath, $mode_config );

				if ( ! empty( $threats ) ) {
					$results[] = array(
						'file'    => str_replace( ABSPATH, '', $filepath ),
						'threats' => $threats,
					);

					foreach ( $threats as $threat ) {
						$severity = strtolower( $threat['severity'] ?? 'medium' );
						if ( isset( $threat_counts[ $severity ] ) ) {
							$threat_counts[ $severity ]++;
						}
					}
				}
			}
		} catch ( Exception $e ) {
			// Silently handle permission errors
		}

		return array(
			'threats'       => $results,
			'files_scanned' => $files_scanned,
			'threat_counts' => $threat_counts,
		);
	}

	/**
	 * Scan a directory recursively.
	 *
	 * @param string $dir Directory path.
	 * @param array $mode_config Mode configuration.
	 * @param int $last_scan Timestamp of last scan.
	 * @return array Array with 'threats' and 'files_scanned'.
	 */
	private function scan_directory( $dir, $mode_config, $last_scan ) {
		$results = array();
		$files_scanned = 0;
		$files_skipped = 0;
		$scannable_extensions = array( 'php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'ico' );
		$use_incremental = isset( $mode_config['incremental'] ) && $mode_config['incremental'] && $last_scan > 0;

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);

			foreach ( $iterator as $file ) {
				if ( ! $file->isFile() ) {
					continue;
				}

				// Excluded paths.
				if ( $this->is_path_excluded( $file->getPathname() ) ) {
					$files_skipped++;
					continue;
				}

				$ext = strtolower( $file->getExtension() );
				if ( ! in_array( $ext, $scannable_extensions, true ) ) {
					continue;
				}

				// Excluded extensions (settings).
				if ( ! empty( $this->excluded_extensions ) && in_array( $ext, $this->excluded_extensions, true ) ) {
					continue;
				}

				// Skip files larger than mode's max size.
				if ( $file->getSize() > $mode_config['max_file_size'] ) {
					continue;
				}

				// Whitelist self.
				if ( strpos( $file->getPathname(), NEXIFYMY_SECURITY_PATH ) !== false ) {
					continue;
				}

				// Incremental: Skip files not modified since last scan.
				if ( $use_incremental && $file->getMTime() < $last_scan ) {
					$files_skipped++;
					continue;
				}

				$files_scanned++;
				$threats = $this->analyze_file( $file, $mode_config['severity_levels'] );
				if ( ! empty( $threats ) ) {
					$results[] = array(
						'file'     => str_replace( ABSPATH, '', $file->getPathname() ),
						'size'     => size_format( $file->getSize() ),
						'modified' => date( 'Y-m-d H:i:s', $file->getMTime() ),
						'threats'  => $threats,
					);
				}
			}
		} catch ( Exception $e ) {
			error_log( '[NexifyMy Scanner] Error: ' . $e->getMessage() );
		}

		return array(
			'threats'       => $results,
			'files_scanned' => $files_scanned,
			'files_skipped' => $files_skipped,
		);
	}

	/**
	 * Analyze a single file for threats.
	 *
	 * @param SplFileInfo $file File object.
	 * @param array $severity_levels Severity levels to check.
	 * @return array Found threats.
	 */
	private function analyze_file( $file, $severity_levels = array( 'critical', 'high', 'medium', 'low' ) ) {
		$threats = array();
		$content = @file_get_contents( $file->getPathname() );

		if ( $content === false ) {
			return $threats;
		}

		foreach ( $this->heuristics as $key => $rule ) {
			// Skip rules not matching our severity filter.
			if ( ! in_array( $rule['severity'], $severity_levels, true ) ) {
				continue;
			}

			// Handle line length check separately.
			if ( isset( $rule['check_type'] ) && $rule['check_type'] === 'line_length' ) {
				$lines = explode( "\n", $content );
				foreach ( $lines as $line_num => $line ) {
					if ( strlen( $line ) > $rule['threshold'] ) {
						$threats[] = array(
							'rule'        => $key,
							'severity'    => $rule['severity'],
							'category'    => isset( $rule['category'] ) ? $rule['category'] : 'malware',
							'title'       => isset( $rule['title'] ) ? $rule['title'] : $key,
							'description' => $rule['description'],
							'line'        => $line_num + 1,
						);
						break; // Only report once per file.
					}
				}
				continue;
			}

			// Standard regex pattern matching.
			if ( preg_match( $rule['pattern'], $content ) ) {
				$threats[] = array(
					'rule'        => $key,
					'severity'    => $rule['severity'],
					'category'    => isset( $rule['category'] ) ? $rule['category'] : 'malware',
					'title'       => isset( $rule['title'] ) ? $rule['title'] : $key,
					'description' => $rule['description'],
				);
			}
		}

		return $threats;
	}

	/**
	 * Scan a single file with false positive prevention and confidence scoring.
	 *
	 * @param string $filepath Full path to the file.
	 * @param array $mode_config Mode configuration.
	 * @return array Found threats with confidence scores.
	 */
	private function scan_file( $filepath, $mode_config ) {
		$threats = array();
		$content = @file_get_contents( $filepath );

		if ( $content === false ) {
			return $threats;
		}

		$relative_path = str_replace( ABSPATH, '', $filepath );
		$severity_levels = $mode_config['severity_levels'] ?? array( 'critical', 'high', 'medium', 'low' );

		// Check if file is in a known safe plugin/theme
		$is_known_safe = $this->is_known_safe_plugin( $relative_path );

		// Check if file is in a safe context (WordPress core, vendor, etc.)
		$is_safe_context = $this->is_safe_context( $relative_path );

		foreach ( $this->heuristics as $key => $rule ) {
			// Skip rules not matching our severity filter.
			if ( ! in_array( $rule['severity'], $severity_levels, true ) ) {
				continue;
			}

			// Handle line length check separately.
			if ( isset( $rule['check_type'] ) && $rule['check_type'] === 'line_length' ) {
				$lines = explode( "\n", $content );
				foreach ( $lines as $line_num => $line ) {
					if ( strlen( $line ) > $rule['threshold'] ) {
						$confidence = $this->calculate_confidence( $rule, $relative_path, $is_known_safe, $is_safe_context, $line );
						if ( $confidence >= 40 ) { // Only report if confidence is high enough
							$threats[] = array(
								'file'         => $relative_path,
								'rule'         => $key,
								'severity'     => $rule['severity'],
								'category'     => isset( $rule['category'] ) ? $rule['category'] : 'malware',
								'title'        => isset( $rule['title'] ) ? $rule['title'] : $key,
								'description'  => $rule['description'],
								'line'         => $line_num + 1,
								'confidence'   => $confidence,
								'context'      => $this->get_threat_context( $rule, $is_known_safe, $is_safe_context ),
							);
						}
						break;
					}
				}
				continue;
			}

			// Standard regex pattern matching.
			if ( isset( $rule['pattern'] ) && preg_match( $rule['pattern'], $content, $matches ) ) {
				$confidence = $this->calculate_confidence( $rule, $relative_path, $is_known_safe, $is_safe_context, $matches[0] ?? '' );

				// Only report if confidence is above threshold
				// For known safe plugins, require higher confidence
				$threshold = $is_known_safe ? 60 : 40;

				if ( $confidence >= $threshold ) {
					$threats[] = array(
						'file'         => $relative_path,
						'rule'         => $key,
						'severity'     => $rule['severity'],
						'category'     => isset( $rule['category'] ) ? $rule['category'] : 'malware',
						'title'        => isset( $rule['title'] ) ? $rule['title'] : $key,
						'description'  => $rule['description'],
						'confidence'   => $confidence,
						'context'      => $this->get_threat_context( $rule, $is_known_safe, $is_safe_context ),
						'recommendation' => $this->get_recommendation( $confidence, $rule['severity'] ),
					);
				}
			}
		}

		return $threats;
	}

	/**
	 * Check if file is in a known safe plugin directory.
	 *
	 * @param string $relative_path Relative file path.
	 * @return bool
	 */
	private function is_known_safe_plugin( $relative_path ) {
		foreach ( $this->known_safe_plugins as $plugin_slug ) {
			if ( strpos( $relative_path, 'wp-content/plugins/' . $plugin_slug . '/' ) !== false ) {
				return true;
			}
			if ( strpos( $relative_path, 'wp-content/themes/' . $plugin_slug . '/' ) !== false ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check if file is in a safe context.
	 *
	 * @param string $relative_path Relative file path.
	 * @return bool
	 */
	private function is_safe_context( $relative_path ) {
		foreach ( $this->safe_contexts as $context ) {
			if ( strpos( $relative_path, $context ) !== false ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Calculate confidence score for a threat detection.
	 *
	 * @param array $rule The detection rule.
	 * @param string $path File path.
	 * @param bool $is_known_safe Is in known safe plugin.
	 * @param bool $is_safe_context Is in safe context.
	 * @param string $matched_content The matched content.
	 * @return int Confidence score (0-100).
	 */
	private function calculate_confidence( $rule, $path, $is_known_safe, $is_safe_context, $matched_content = '' ) {
		$confidence = 70; // Base confidence

		// Increase confidence based on severity
		switch ( $rule['severity'] ) {
			case 'critical':
				$confidence += 20;
				break;
			case 'high':
				$confidence += 10;
				break;
			case 'medium':
				$confidence += 0;
				break;
			case 'low':
				$confidence -= 10;
				break;
		}

		// Decrease confidence for known safe plugins
		if ( $is_known_safe ) {
			$confidence -= 30;
		}

		// Decrease confidence for safe contexts (WordPress core, etc.)
		if ( $is_safe_context ) {
			$confidence -= 25;
		}

		// Increase confidence if file is in uploads directory (higher risk area)
		if ( strpos( $path, 'wp-content/uploads/' ) !== false ) {
			$confidence += 15;
		}

		// Increase confidence for obfuscation patterns in non-standard locations
		if ( isset( $rule['category'] ) && $rule['category'] === 'obfuscation' ) {
			if ( strpos( $path, 'wp-content/uploads/' ) !== false ) {
				$confidence += 20; // Obfuscated code in uploads is very suspicious
			}
		}

		// Cap confidence between 0 and 100
		return max( 0, min( 100, $confidence ) );
	}

	/**
	 * Get human-readable context for a threat.
	 *
	 * @param array $rule Detection rule.
	 * @param bool $is_known_safe Is in known safe plugin.
	 * @param bool $is_safe_context Is in safe context.
	 * @return string Context description.
	 */
	private function get_threat_context( $rule, $is_known_safe, $is_safe_context ) {
		if ( $is_known_safe ) {
			return __( 'Found in known safe plugin - likely legitimate use', 'nexifymy-security' );
		}
		if ( $is_safe_context ) {
			return __( 'Found in system directory - may be legitimate', 'nexifymy-security' );
		}
		return $rule['description'] ?? __( 'Potential security threat detected', 'nexifymy-security' );
	}

	/**
	 * Get recommendation based on confidence and severity.
	 *
	 * @param int $confidence Confidence score.
	 * @param string $severity Threat severity.
	 * @return string Recommendation.
	 */
	private function get_recommendation( $confidence, $severity ) {
		if ( $confidence >= 80 ) {
			if ( $severity === 'critical' || $severity === 'high' ) {
				return __( 'Quarantine recommended', 'nexifymy-security' );
			}
			return __( 'Review immediately', 'nexifymy-security' );
		}
		if ( $confidence >= 60 ) {
			return __( 'Manual review recommended', 'nexifymy-security' );
		}
		return __( 'Likely safe - verify if needed', 'nexifymy-security' );
	}

	/**
	 * Check WordPress core file integrity via AJAX.
	 */
	public function ajax_core_integrity_check() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		if ( ! $this->is_scanner_enabled() ) {
			wp_send_json_error( 'Scanner module is disabled in settings.' );
		}

		$results = $this->check_core_integrity();
		wp_send_json_success( $results );
	}

	/**
	 * Verify WordPress core files against official checksums.
	 *
	 * @return array Integrity check results.
	 */
	private function check_core_integrity() {
		global $wp_version;
		$locale = get_locale();

		// Fetch checksums from WordPress.org API.
		$url = sprintf(
			'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s',
			$wp_version,
			$locale
		);

		$response = wp_remote_get( $url, array( 'timeout' => 15 ) );

		if ( is_wp_error( $response ) ) {
			return array( 'error' => 'Could not fetch checksums from WordPress.org' );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( empty( $body['checksums'] ) ) {
			return array( 'error' => 'Invalid checksum data received' );
		}

		$modified_files = array();
		$missing_files = array();

		foreach ( $body['checksums'] as $file => $expected_md5 ) {
			$file_path = ABSPATH . $file;

			if ( ! file_exists( $file_path ) ) {
				$missing_files[] = $file;
				continue;
			}

			$actual_md5 = md5_file( $file_path );
			if ( $actual_md5 !== $expected_md5 ) {
				$modified_files[] = array(
					'file'     => $file,
					'expected' => $expected_md5,
					'actual'   => $actual_md5,
				);
			}
		}

		return array(
			'version'        => $wp_version,
			'checked_at'     => current_time( 'mysql' ),
			'total_files'    => count( $body['checksums'] ),
			'modified_count' => count( $modified_files ),
			'missing_count'  => count( $missing_files ),
			'modified_files' => $modified_files,
			'missing_files'  => $missing_files,
		);
	}
}
