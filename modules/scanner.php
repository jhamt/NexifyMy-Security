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
	 * Threat classification constants - 5-tier system.
	 */
	const CLASSIFICATION_CONFIRMED_MALWARE = 'CONFIRMED_MALWARE';
	const CLASSIFICATION_SUSPICIOUS_CODE = 'SUSPICIOUS_CODE';
	const CLASSIFICATION_SECURITY_VULNERABILITY = 'SECURITY_VULNERABILITY';
	const CLASSIFICATION_CODE_SMELL = 'CODE_SMELL';
	const CLASSIFICATION_CLEAN = 'CLEAN';

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
	 * Context analyzer instance.
	 * @var NexifyMy_Security_Context_Analyzer
	 */
	private $context_analyzer = null;

	/**
	 * Reputation checker instance.
	 * @var NexifyMy_Security_Reputation_Checker
	 */
	private $reputation_checker = null;

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
	 * Enhanced with classification, base_confidence, and context_rules.
	 */
	private function define_heuristics() {
		$this->heuristics = array(
			// Category: Obfuscation
			'eval_base64' => array(
				'severity'        => 'critical',
				'description'     => 'eval(base64_decode()) - Common obfuscation',
				'pattern'         => '/eval\s*\(\s*base64_decode\s*\(/i',
				'classification'  => self::CLASSIFICATION_CONFIRMED_MALWARE,
				'base_confidence' => 85,
				'category'        => 'obfuscation',
				'context_rules'   => array(
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 15,
						'/uploads\//' => 10,
					),
				),
			),
			'gzinflate_base64' => array(
				'severity'        => 'critical',
				'description'     => 'gzinflate(base64_decode()) - Compressed obfuscation',
				'pattern'         => '/gzinflate\s*\(\s*base64_decode\s*\(/i',
				'classification'  => self::CLASSIFICATION_CONFIRMED_MALWARE,
				'base_confidence' => 85,
				'category'        => 'obfuscation',
				'context_rules'   => array(
					'dangerous_contexts' => array(
						'/uploads\//' => 15,
					),
				),
			),
			'str_rot13' => array(
				'severity'        => 'high',
				'description'     => 'str_rot13() obfuscation',
				'pattern'         => '/str_rot13\s*\(/i',
				'classification'  => self::CLASSIFICATION_SUSPICIOUS_CODE,
				'base_confidence' => 60,
				'category'        => 'obfuscation',
				'context_rules'   => array(
					'safe_contexts' => array(
						'/vendor/' => -30,
					),
					'dangerous_contexts' => array(
						'/uploads\//' => 25,
					),
				),
			),
			'hex_encoding' => array(
				'severity'        => 'medium',
				'description'     => 'Heavy hex encoding (\\x usage)',
				'pattern'         => '/(\\\\x[0-9a-f]{2}){10,}/i', // 10+ consecutive hex chars
				'classification'  => self::CLASSIFICATION_SUSPICIOUS_CODE,
				'base_confidence' => 55,
				'category'        => 'obfuscation',
				'context_rules'   => array(
					'dangerous_contexts' => array(
						'/uploads\//' => 30,
					),
				),
			),
			'long_base64' => array(
				'severity'        => 'medium',
				'description'     => 'Long base64 string (possible encoded payload)',
				'pattern'         => '/[a-zA-Z0-9+\/=]{500,}/',
				'classification'  => self::CLASSIFICATION_CODE_SMELL,
				'base_confidence' => 45,
				'category'        => 'obfuscation',
				'context_rules'   => array(
					'dangerous_contexts' => array(
						'/uploads\//' => 25,
					),
				),
			),

			// Category: Dangerous Functions (context-aware classification)
			'shell_exec' => array(
				'severity'        => 'critical',
				'description'     => 'shell_exec() - Command execution',
				'pattern'         => '/shell_exec\s*\(/i',
				'classification'  => 'dynamic', // Context determines tier
				'base_confidence' => 50,
				'category'        => 'command_execution',
				'context_rules'   => array(
					'safe_contexts' => array(
						'/wp-cli/' => -40,
						'/WP_CLI::/' => -100,
						'/vendor/' => -30,
						'/escapeshellarg|escapeshellcmd/' => -25,
					),
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 35,
						'/uploads\//' => 40,
					),
				),
			),
			'exec' => array(
				'severity'        => 'critical',
				'description'     => 'exec() - Command execution',
				'pattern'         => '/\bexec\s*\(/i',
				'classification'  => 'dynamic', // Context determines tier
				'base_confidence' => 50,
				'category'        => 'command_execution',
				'context_rules'   => array(
					'safe_contexts' => array(
						'/wp-cli/' => -40,
						'/WP_CLI::/' => -100,
						'/vendor/' => -30,
						'/escapeshellarg|escapeshellcmd/' => -25,
					),
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 35,
						'/uploads\//' => 40,
					),
				),
			),
			'passthru' => array(
				'severity'        => 'critical',
				'description'     => 'passthru() - Command execution',
				'pattern'         => '/passthru\s*\(/i',
				'classification'  => 'dynamic',
				'base_confidence' => 50,
				'category'        => 'command_execution',
				'context_rules'   => array(
					'safe_contexts' => array(
						'/wp-cli/' => -40,
						'/vendor/' => -30,
						'/escapeshellarg|escapeshellcmd/' => -25,
					),
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 35,
						'/uploads\//' => 40,
					),
				),
			),
			'system' => array(
				'severity'        => 'critical',
				'description'     => 'system() - Command execution',
				'pattern'         => '/\bsystem\s*\(/i',
				'classification'  => 'dynamic',
				'base_confidence' => 50,
				'category'        => 'command_execution',
				'context_rules'   => array(
					'safe_contexts' => array(
						'/wp-cli/' => -40,
						'/vendor/' => -30,
						'/escapeshellarg|escapeshellcmd/' => -25,
					),
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 35,
						'/uploads\//' => 40,
					),
				),
			),
			'proc_open' => array(
				'severity'        => 'critical',
				'description'     => 'proc_open() - Process control',
				'pattern'         => '/proc_open\s*\(/i',
				'classification'  => 'dynamic',
				'base_confidence' => 50,
				'category'        => 'command_execution',
				'context_rules'   => array(
					'safe_contexts' => array(
						'/wp-cli/' => -40,
						'/vendor/' => -30,
					),
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 35,
						'/uploads\//' => 40,
					),
				),
			),
			'popen' => array(
				'severity'        => 'high',
				'description'     => 'popen() - Process control',
				'pattern'         => '/\bpopen\s*\(/i',
				'classification'  => 'dynamic',
				'base_confidence' => 50,
				'category'        => 'command_execution',
				'context_rules'   => array(
					'safe_contexts' => array(
						'/vendor/' => -30,
					),
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 30,
						'/uploads\//' => 35,
					),
				),
			),
			'assert' => array(
				'severity'        => 'high',
				'description'     => 'assert() - Possible code execution',
				'pattern'         => '/\bassert\s*\(/i',
				'classification'  => 'dynamic',
				'base_confidence' => 45,
				'category'        => 'command_execution',
				'context_rules'   => array(
					'safe_contexts' => array(
						'/vendor/' => -30,
						'/tests?\//' => -40,
					),
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 35,
					),
				),
			),
			'create_function' => array(
				'severity'        => 'high',
				'description'     => 'create_function() - Dynamic code creation',
				'pattern'         => '/create_function\s*\(/i',
				'classification'  => self::CLASSIFICATION_SUSPICIOUS_CODE,
				'base_confidence' => 60,
				'category'        => 'obfuscation',
				'context_rules'   => array(
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 30,
						'/uploads\//' => 25,
					),
				),
			),

			// Category: Webshell Indicators
			'globals_obfuscation' => array(
				'severity'        => 'high',
				'description'     => '$GLOBALS obfuscation pattern',
				'pattern'         => '/\$GLOBALS\s*\[\s*[\'"][a-z0-9_]+[\'"]\s*\]\s*\(/i',
				'classification'  => self::CLASSIFICATION_SUSPICIOUS_CODE,
				'base_confidence' => 65,
				'category'        => 'obfuscation',
				'context_rules'   => array(
					'dangerous_contexts' => array(
						'/uploads\//' => 25,
					),
				),
			),
			'php_uname' => array(
				'severity'        => 'medium',
				'description'     => 'php_uname() - System info gathering',
				'pattern'         => '/php_uname\s*\(/i',
				'classification'  => self::CLASSIFICATION_CODE_SMELL,
				'base_confidence' => 40,
				'category'        => 'reconnaissance',
				'context_rules'   => array(
					'dangerous_contexts' => array(
						'/uploads\//' => 30,
					),
				),
			),
			'getcwd' => array(
				'severity'        => 'low',
				'description'     => 'getcwd() - Path discovery',
				'pattern'         => '/getcwd\s*\(/i',
				'classification'  => self::CLASSIFICATION_CODE_SMELL,
				'base_confidence' => 25,
				'category'        => 'reconnaissance',
			),
			'file_put_contents' => array(
				'severity'        => 'medium',
				'description'     => 'file_put_contents() - File write capability',
				'pattern'         => '/file_put_contents\s*\(/i',
				'classification'  => 'dynamic',
				'base_confidence' => 40,
				'category'        => 'file_operation',
				'context_rules'   => array(
					'safe_contexts' => array(
						'/vendor/' => -25,
						'/WP_Filesystem/' => -35,
					),
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 35,
						'/\.php[\'"]/' => 30, // Writing PHP files
						'/uploads\//' => 25,
					),
				),
			),

			// Category: Suspicious Patterns
			'hidden_input' => array(
				'severity'        => 'medium',
				'description'     => 'Hidden input with suspicious name',
				'pattern'         => '/<input[^>]+type\s*=\s*["\']hidden["\'][^>]+name\s*=\s*["\'](?:cmd|c|pass|password)["\'][^>]*>/i',
				'classification'  => self::CLASSIFICATION_SUSPICIOUS_CODE,
				'base_confidence' => 55,
				'category'        => 'webshell',
				'context_rules'   => array(
					'dangerous_contexts' => array(
						'/uploads\//' => 30,
					),
				),
			),
			'suspicious_long_line' => array(
				'severity'        => 'medium',
				'description'     => 'Suspiciously long single line (obfuscation)',
				'check_type'      => 'line_length',
				'threshold'       => 5000,
				'classification'  => self::CLASSIFICATION_CODE_SMELL,
				'base_confidence' => 45,
				'category'        => 'obfuscation',
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
		$quarantined_count = 0;
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
			$scan_result = $this->scan_directory_with_progress( $dir, $mode_config, $last_scan, $files_scanned, $total_files, $suspicious_files, $threat_counts, $quarantined_count );
			$suspicious_files = $scan_result['threats'];
			$files_scanned = $scan_result['files_scanned'];
			$threat_counts = $scan_result['threat_counts'];
			$quarantined_count = $scan_result['quarantined_count'];
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

		// Calculate site health metrics
		require_once NEXIFYMY_SECURITY_PATH . 'modules/site-health-calculator.php';
		$health_calculator = new NexifyMy_Security_Site_Health_Calculator();

		$health_metrics = $health_calculator->calculate_health_metrics( array(
			'files_scanned' => $files_scanned,
			'threats'       => $suspicious_files,
		) );

		// Count threats by classification for enhanced results
		$classification_counts = array(
			'CONFIRMED_MALWARE'        => 0,
			'SUSPICIOUS_CODE'          => 0,
			'SECURITY_VULNERABILITY'   => 0,
			'CODE_SMELL'               => 0,
		);

		$classification_percentages = array(
			'CONFIRMED_MALWARE'        => 0,
			'SUSPICIOUS_CODE'          => 0,
			'SECURITY_VULNERABILITY'   => 0,
			'CODE_SMELL'               => 0,
		);

		foreach ( $suspicious_files as $threat_file ) {
			// Each file may have multiple threats, count by highest classification
			$file_classification = 'CODE_SMELL';
			$classification_priority = array(
				'CONFIRMED_MALWARE'      => 4,
				'SUSPICIOUS_CODE'        => 3,
				'SECURITY_VULNERABILITY' => 2,
				'CODE_SMELL'             => 1,
			);

			$highest_priority = 0;

			if ( isset( $threat_file['threats'] ) && is_array( $threat_file['threats'] ) ) {
				foreach ( $threat_file['threats'] as $threat ) {
					$classification = isset( $threat['classification'] ) ? $threat['classification'] : 'CODE_SMELL';
					$priority = isset( $classification_priority[ $classification ] ) ? $classification_priority[ $classification ] : 0;

					if ( $priority > $highest_priority ) {
						$highest_priority = $priority;
						$file_classification = $classification;
					}
				}
			}

			if ( isset( $classification_counts[ $file_classification ] ) ) {
				$classification_counts[ $file_classification ]++;
			}
		}

		// Calculate classification percentages
		if ( $files_scanned > 0 ) {
			foreach ( $classification_counts as $classification => $count ) {
				$classification_percentages[ $classification ] = round( ( $count / $files_scanned ) * 100, 2 );
			}
		}

		// Store results for later retrieval (enhanced structure)
		$results = array(
			'scanned_at'     => current_time( 'mysql' ),
			'mode'           => $mode,
			'mode_name'      => $mode_config['name'],
			'files_scanned'  => $files_scanned,
			'threats_found'  => array_sum( $threat_counts ),
			'threats'        => $suspicious_files,
			'threat_counts'  => $threat_counts,
			'core_integrity' => $core_results,
			'scan_summary'   => array(
				'total_files_scanned'       => $files_scanned,
				'files_with_threats'        => $health_metrics['affected_files'],
				'clean_files'               => $health_metrics['clean_files'],
				'clean_percentage'          => $health_metrics['clean_percentage'],
				'affected_percentage'       => $health_metrics['affected_percentage'],
				'health_score'              => $health_metrics['health_score'],
				'health_status'             => $health_metrics['health_status'],
				'recommendation'            => $health_metrics['recommendation'],
			),
			'classification_counts' => $classification_counts,
			'classification_percentages' => $classification_percentages,
			'quarantined'   => $quarantined_count,
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
			'classification_counts' => $classification_counts,
			'scan_summary' => $results['scan_summary'],
			'quarantined' => $quarantined_count,
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
	private function scan_directory_with_progress( $dir, $mode_config, $last_scan, $files_scanned, $total_files, $existing_threats, $threat_counts, $quarantined_count = 0 ) {
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

				// Never scan this plugin's own files to avoid accidental self-quarantine.
				if ( strpos( $filepath, NEXIFYMY_SECURITY_PATH ) !== false ) {
					continue;
				}

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
					$auto_quarantined = false;
					if ( $this->should_auto_quarantine( $threats ) && isset( $GLOBALS['nexifymy_quarantine'] ) && $GLOBALS['nexifymy_quarantine'] instanceof NexifyMy_Security_Quarantine ) {
						$quarantine_result = $GLOBALS['nexifymy_quarantine']->quarantine_file( $filepath, 'Auto quarantine from scanner', false );
						if ( ! is_wp_error( $quarantine_result ) ) {
							$auto_quarantined = true;
							$quarantined_count++;
						}
					}

					$results[] = array(
						'file'    => str_replace( ABSPATH, '', $filepath ),
						'threats' => $threats,
						'auto_quarantined' => $auto_quarantined,
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
			'quarantined_count' => $quarantined_count,
		);
	}

	/**
	 * Determine whether a threat set should be auto-quarantined.
	 *
	 * @param array $threats Detected threats for a file.
	 * @return bool
	 */
	private function should_auto_quarantine( $threats ) {
		if ( ! isset( $GLOBALS['nexifymy_quarantine'] ) || ! ( $GLOBALS['nexifymy_quarantine'] instanceof NexifyMy_Security_Quarantine ) ) {
			return false;
		}

		if ( ! $GLOBALS['nexifymy_quarantine']->is_auto_quarantine_enabled() ) {
			return false;
		}

		foreach ( (array) $threats as $threat ) {
			$classification = $threat['classification'] ?? '';
			$confidence = (int) ( $threat['confidence'] ?? 0 );
			if ( $classification === self::CLASSIFICATION_CONFIRMED_MALWARE && $confidence >= 85 ) {
				return true;
			}
		}

		return false;
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
	 * Scan a single file with context-aware classification and smart confidence scoring.
	 *
	 * @param string $filepath Full path to the file.
	 * @param array $mode_config Mode configuration.
	 * @return array Found threats with confidence scores and classifications.
	 */
	private function scan_file( $filepath, $mode_config ) {
		$threats = array();
		$content = @file_get_contents( $filepath );

		if ( $content === false ) {
			return $threats;
		}

		$relative_path = str_replace( ABSPATH, '', $filepath );
		$severity_levels = $mode_config['severity_levels'] ?? array( 'critical', 'high', 'medium', 'low' );

		// Initialize modules (lazy loading)
		if ( ! isset( $this->context_analyzer ) ) {
			require_once NEXIFYMY_SECURITY_PATH . 'modules/context-analyzer.php';
			$this->context_analyzer = new NexifyMy_Security_Context_Analyzer();
		}

		if ( ! isset( $this->reputation_checker ) ) {
			require_once NEXIFYMY_SECURITY_PATH . 'modules/reputation-checker.php';
			$this->reputation_checker = new NexifyMy_Security_Reputation_Checker();
		}

		// Check allowlist first (skip scanning entirely if allowlisted)
		if ( $this->reputation_checker->is_allowlisted( $filepath ) ) {
			return array(); // Skip this file
		}

		// Check blocklist (force CONFIRMED_MALWARE if blocklisted)
		if ( $this->reputation_checker->is_blocklisted( $filepath ) ) {
			return array(
				array(
					'file'           => $relative_path,
					'rule'           => 'blocklist',
					'severity'       => 'critical',
					'category'       => 'blocklist',
					'title'          => 'Blocklisted File',
					'description'    => 'File is in user blocklist',
					'classification' => self::CLASSIFICATION_CONFIRMED_MALWARE,
					'confidence'     => 100,
					'context'        => 'File matches user-defined blocklist pattern',
					'recommendation' => __( 'Quarantine immediately', 'nexifymy-security' ),
				),
			);
		}

		// Check reputation (plugin, hash, core verification)
		$reputation_data = array();

		// Check plugin reputation
		$plugin_reputation = $this->reputation_checker->check_plugin_reputation( $filepath );
		if ( $plugin_reputation['has_reputation'] ) {
			$reputation_data = $plugin_reputation;
		}

		// Check file hash against malware databases
		$hash_check = $this->reputation_checker->check_file_hash( $filepath );
		if ( $hash_check['is_malware'] ) {
			// Known malware hash - return immediately with max confidence
			return array(
				array(
					'file'           => $relative_path,
					'rule'           => 'malware_hash',
					'severity'       => 'critical',
					'category'       => 'malware',
					'title'          => 'Known Malware Hash',
					'description'    => $hash_check['reason'],
					'classification' => self::CLASSIFICATION_CONFIRMED_MALWARE,
					'confidence'     => 100,
					'context'        => sprintf( 'Known malware: %s', $hash_check['malware_name'] ),
					'recommendation' => __( 'Quarantine immediately', 'nexifymy-security' ),
				),
			);
		}

		// Check WordPress core file verification
		$core_check = $this->reputation_checker->verify_wp_core_file( $filepath );
		if ( isset( $core_check['is_core_file'] ) && $core_check['is_core_file'] ) {
			if ( $core_check['verified'] ) {
				// Verified core file - skip scanning
				return array();
			} else {
				// Modified core file - add to reputation data
				$reputation_data = $core_check;
			}
		}

		// Legacy compatibility
		$is_known_safe = $this->is_known_safe_plugin( $relative_path );
		$is_safe_context = $this->is_safe_context( $relative_path );

		// Scan for patterns
		$detected_patterns = array();

		foreach ( $this->heuristics as $key => $rule ) {
			// Skip rules not matching our severity filter
			if ( ! in_array( $rule['severity'], $severity_levels, true ) ) {
				continue;
			}

			// Handle line length check separately
			if ( isset( $rule['check_type'] ) && $rule['check_type'] === 'line_length' ) {
				$lines = explode( "\n", $content );
				foreach ( $lines as $line_num => $line ) {
					if ( strlen( $line ) > $rule['threshold'] ) {
						$detected_patterns[] = array(
							'rule'            => $key,
							'rule_data'       => $rule,
							'matched_content' => substr( $line, 0, 100 ) . '...',
							'line'            => $line_num + 1,
						);
						break;
					}
				}
				continue;
			}

			// Standard regex pattern matching
			if ( isset( $rule['pattern'] ) && preg_match( $rule['pattern'], $content, $matches ) ) {
				$detected_patterns[] = array(
					'rule'            => $key,
					'rule_data'       => $rule,
					'matched_content' => $matches[0] ?? '',
				);
			}
		}

		// Process each detected pattern with context analysis
		foreach ( $detected_patterns as $pattern ) {
			$rule = $pattern['rule_data'];
			$matched_content = $pattern['matched_content'];

			// Analyze code context
			$context_data = $this->context_analyzer->analyze_code_context( $rule, $filepath, $content, $matched_content );

			// Calculate confidence with all factors
			$confidence = $this->calculate_confidence(
				$rule,
				$relative_path,
				$is_known_safe,
				$is_safe_context,
				$matched_content,
				$context_data,
				$reputation_data
			);

			// Determine classification
			$classification = $this->determine_classification( $confidence, $rule, $context_data );

			// Skip CLEAN files (don't show in results)
			if ( $classification === self::CLASSIFICATION_CLEAN ) {
				continue;
			}

			// Check if confidence meets threshold for this classification
			$threshold = $this->get_threshold_for_classification( $classification );
			if ( $confidence < $threshold ) {
				continue; // Skip this threat
			}

			// Build context summary
			$context_summary = '';
			if ( ! empty( $context_data['context_summary'] ) ) {
				$context_summary = implode( '; ', $context_data['context_summary'] );
			} else {
				$context_summary = $this->get_threat_context( $rule, $is_known_safe, $is_safe_context );
			}

			// Add threat to results
			$threat = array(
				'file'           => $relative_path,
				'rule'           => $pattern['rule'],
				'severity'       => $rule['severity'],
				'category'       => isset( $rule['category'] ) ? $rule['category'] : 'malware',
				'title'          => isset( $rule['title'] ) ? $rule['title'] : $pattern['rule'],
				'description'    => $rule['description'],
				'classification' => $classification,
				'confidence'     => $confidence,
				'context'        => $context_summary,
				'recommendation' => $this->get_recommendation( $confidence, $rule['severity'] ),
			);

			// Add line number if available
			if ( isset( $pattern['line'] ) ) {
				$threat['line'] = $pattern['line'];
			}

			$threats[] = $threat;
		}

		// Multi-pattern correlation bonus
		if ( count( $threats ) >= 3 ) {
			// Multiple patterns detected - increase confidence for all
			foreach ( $threats as &$threat ) {
				$threat['confidence'] = min( 100, $threat['confidence'] + 15 );
				$threat['context'] .= ' [Multiple threat patterns detected]';
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
	 * Calculate confidence score for a threat detection (Enhanced Multi-Factor Algorithm).
	 *
	 * @param array  $rule            The detection rule.
	 * @param string $path            File path.
	 * @param bool   $is_known_safe   Is in known safe plugin (deprecated - use reputation).
	 * @param bool   $is_safe_context Is in safe context (deprecated - use context_data).
	 * @param string $matched_content The matched content.
	 * @param array  $context_data    Context analysis data (optional).
	 * @param array  $reputation_data Reputation data (optional).
	 * @return int Confidence score (0-100).
	 */
	private function calculate_confidence( $rule, $path, $is_known_safe, $is_safe_context, $matched_content = '', $context_data = null, $reputation_data = null ) {
		// Start with rule's base confidence (default 50 if not set)
		$confidence = isset( $rule['base_confidence'] ) ? (int) $rule['base_confidence'] : 50;

		// Factor 1: Severity modifier
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

		// Factor 2: Context analysis (highest priority)
		if ( $context_data !== null && isset( $context_data['confidence_modifier'] ) ) {
			$confidence += $context_data['confidence_modifier'];

			// If context suggests CLEAN, force low confidence
			if ( isset( $context_data['suggested_classification'] ) &&
			     $context_data['suggested_classification'] === self::CLASSIFICATION_CLEAN ) {
				$confidence = min( $confidence, 20 ); // Cap at 20 for clean files
			}
		} else {
			// Fallback to legacy behavior for backward compatibility
			if ( $is_known_safe ) {
				$confidence -= 30;
			}
			if ( $is_safe_context ) {
				$confidence -= 25;
			}

			// Legacy location risk
			if ( strpos( $path, 'wp-content/uploads/' ) !== false ) {
				$confidence += 15;
			}
		}

		// Factor 3: Reputation data
		if ( $reputation_data !== null ) {
			if ( isset( $reputation_data['modifier'] ) ) {
				$confidence += $reputation_data['modifier'];
			}

			// If known malware hash, force maximum confidence
			if ( isset( $reputation_data['is_malware'] ) && $reputation_data['is_malware'] === true ) {
				return 100; // Absolute certainty
			}

			// If WordPress core verified, force minimum confidence
			if ( isset( $reputation_data['verified'] ) && $reputation_data['verified'] === true ) {
				return 0; // Verified clean
			}
		}

		// Factor 4: Multi-pattern correlation bonus
		// (This will be applied at file level in scan_file)

		// Factor 5: Category-specific adjustments
		if ( isset( $rule['category'] ) ) {
			switch ( $rule['category'] ) {
				case 'obfuscation':
					// Obfuscation in uploads is highly suspicious
					if ( strpos( $path, 'wp-content/uploads/' ) !== false ) {
						$confidence += 20;
					}
					break;
				case 'webshell':
					// Webshell indicators are high confidence
					$confidence += 15;
					break;
				case 'backdoor':
					// Backdoor patterns are high confidence
					$confidence += 15;
					break;
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
	 * Determine classification tier based on confidence and context.
	 *
	 * @param int    $confidence   Confidence score (0-100).
	 * @param array  $rule         Detection rule.
	 * @param array  $context_data Context analysis data.
	 * @return string Classification tier constant.
	 */
	private function determine_classification( $confidence, $rule, $context_data ) {
		// If context suggests a classification, use it
		if ( isset( $context_data['suggested_classification'] ) && ! empty( $context_data['suggested_classification'] ) ) {
			return $context_data['suggested_classification'];
		}

		// If rule has fixed classification, use it
		if ( isset( $rule['classification'] ) && $rule['classification'] !== 'dynamic' ) {
			return $rule['classification'];
		}

		$category = $rule['category'] ?? '';
		if ( in_array( $category, array( 'command_execution', 'file_operation', 'injection' ), true ) ) {
			if ( $confidence >= 85 ) {
				return self::CLASSIFICATION_CONFIRMED_MALWARE;
			}
			if ( $confidence >= 60 ) {
				return self::CLASSIFICATION_SECURITY_VULNERABILITY;
			}
			if ( $confidence >= 40 ) {
				return self::CLASSIFICATION_CODE_SMELL;
			}
			return self::CLASSIFICATION_CLEAN;
		}

		// Dynamic classification based on confidence thresholds
		if ( $confidence >= 75 ) {
			return self::CLASSIFICATION_CONFIRMED_MALWARE;
		} elseif ( $confidence >= 60 ) {
			return self::CLASSIFICATION_SUSPICIOUS_CODE;
		} elseif ( $confidence >= 40 ) {
			return self::CLASSIFICATION_CODE_SMELL;
		}

		return self::CLASSIFICATION_CLEAN;
	}

	/**
	 * Get minimum confidence threshold for a classification tier.
	 *
	 * @param string $classification Classification tier.
	 * @return int Minimum confidence threshold.
	 */
	private function get_threshold_for_classification( $classification ) {
		$thresholds = array(
			self::CLASSIFICATION_CONFIRMED_MALWARE        => 75,
			self::CLASSIFICATION_SUSPICIOUS_CODE          => 60,
			self::CLASSIFICATION_SECURITY_VULNERABILITY   => 70,
			self::CLASSIFICATION_CODE_SMELL               => 40,
			self::CLASSIFICATION_CLEAN                    => 0,
		);

		return isset( $thresholds[ $classification ] ) ? $thresholds[ $classification ] : 40;
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
