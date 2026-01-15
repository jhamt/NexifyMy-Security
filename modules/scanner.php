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
			'incremental' => true, // Standard uses incremental for performance
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
	 * Initialize the scanner.
	 */
	public function init() {
		$this->define_heuristics();

		// Only register admin/AJAX endpoints when the module is enabled.
		if ( ! $this->is_scanner_enabled() ) {
			return;
		}

		add_action( 'wp_ajax_nexifymy_scan', array( $this, 'ajax_scan' ) );
		add_action( 'wp_ajax_nexifymy_core_integrity', array( $this, 'ajax_core_integrity_check' ) );
	}

	/**
	 * Determine whether scanner module is enabled.
	 *
	 * @return bool
	 */
	private function is_scanner_enabled() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		return ! isset( $settings['modules']['scanner_enabled'] ) || (bool) $settings['modules']['scanner_enabled'];
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
			wp_send_json_error( 'Unauthorized' );
		}

		if ( ! $this->is_scanner_enabled() ) {
			wp_send_json_error( 'Scanner module is disabled in settings.' );
		}

		$this->load_scanner_settings();

		$mode = isset( $_POST['mode'] ) ? sanitize_key( $_POST['mode'] ) : '';
		if ( $mode === '' ) {
			$mode = $this->scanner_settings['default_mode'] ?? 'standard';
		}
		$results = $this->perform_scan( $mode );
		
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

		$this->load_scanner_settings();

		$suspicious_files = array();
		$upload_dir = wp_upload_dir();
		$last_scan = get_option( self::SCAN_STATE_OPTION, 0 );
		$files_scanned = 0;
		$core_results = null;

		// Validate mode.
		if ( ! isset( $this->scan_modes[ $mode ] ) ) {
			$mode = $this->scanner_settings['default_mode'] ?? 'standard';
		}

		$mode_config = $this->scan_modes[ $mode ];

		// Apply global max file size override.
		if ( ! empty( $this->scanner_settings['max_file_size'] ) ) {
			$mode_config['max_file_size'] = (int) $this->scanner_settings['max_file_size'];
		}

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

		// Perform file scan.
		foreach ( $directories_to_scan as $dir ) {
			if ( ! is_dir( $dir ) ) {
				continue;
			}
			if ( $this->is_path_excluded( $dir ) ) {
				continue;
			}
			$scan_result = $this->scan_directory( $dir, $mode_config, $last_scan );
			$suspicious_files = array_merge( $suspicious_files, $scan_result['threats'] );
			$files_scanned += $scan_result['files_scanned'];
		}

		// Perform core integrity check if mode requires it.
		if ( $mode_config['check_core'] ) {
			$core_results = $this->check_core_integrity();
		}

		// Update last scan time.
		update_option( self::SCAN_STATE_OPTION, time() );

		return array(
			'scanned_at'     => current_time( 'mysql' ),
			'mode'           => $mode,
			'mode_name'      => $mode_config['name'],
			'files_scanned'  => $files_scanned,
			'threats_found'  => count( $suspicious_files ),
			'threats'        => $suspicious_files,
			'core_integrity' => $core_results,
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
					'description' => $rule['description'],
				);
			}
		}

		return $threats;
	}

	/**
	 * Check WordPress core file integrity via AJAX.
	 */
	public function ajax_core_integrity_check() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
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
