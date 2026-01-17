<?php
/**
 * Signature Updater Module.
 * Fetches and manages malware/vulnerability signatures from trusted sources.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Signature_Updater {

	/**
	 * Option key for storing signatures.
	 */
	const SIGNATURES_OPTION = 'nexifymy_malware_signatures';

	/**
	 * Option key for last update time.
	 */
	const LAST_UPDATE_OPTION = 'nexifymy_signatures_updated';

	/**
	 * Wordfence Intelligence API (free, public).
	 */
	const WORDFENCE_VULN_API = 'https://www.wordfence.com/api/intelligence/v2/vulnerabilities/scanner';

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'         => true,
		'auto_update'     => true,
		'update_interval' => 'daily',
	);

	/**
	 * Built-in heuristic patterns (fallback).
	 */
	private $builtin_patterns = array();

	/**
	 * Initialize the module.
	 */
	public function init() {
		$this->define_builtin_patterns();

		// Schedule automatic updates.
		add_action( 'nexifymy_update_signatures', array( $this, 'update_signatures' ) );

		$settings = $this->get_settings();
		if ( ! empty( $settings['auto_update'] ) && ! wp_next_scheduled( 'nexifymy_update_signatures' ) ) {
			wp_schedule_event( time(), 'daily', 'nexifymy_update_signatures' );
		}

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_update_signatures', array( $this, 'ajax_update_signatures' ) );
		add_action( 'wp_ajax_nexifymy_get_signature_status', array( $this, 'ajax_get_status' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['signatures'] ) ) {
				return wp_parse_args( $all_settings['signatures'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Define built-in malware patterns (fallback if API unavailable).
	 */
	private function define_builtin_patterns() {
		$this->builtin_patterns = array(
			// Critical: Remote Code Execution
			array(
				'id'          => 'eval_base64',
				'severity'    => 'critical',
				'title'       => 'Obfuscated eval() with base64',
				'description' => 'eval(base64_decode()) - Common malware obfuscation technique',
				'pattern'     => '/eval\s*\(\s*base64_decode\s*\(/i',
				'category'    => 'obfuscation',
			),
			array(
				'id'          => 'shell_exec',
				'severity'    => 'critical',
				'title'       => 'Shell Command Execution',
				'description' => 'shell_exec() allows running system commands',
				'pattern'     => '/shell_exec\s*\(/i',
				'category'    => 'command_execution',
			),
			array(
				'id'          => 'exec_function',
				'severity'    => 'critical',
				'title'       => 'Command Execution',
				'description' => 'exec() function for running commands',
				'pattern'     => '/\bexec\s*\(/i',
				'category'    => 'command_execution',
			),
			array(
				'id'          => 'passthru',
				'severity'    => 'critical',
				'title'       => 'Passthru Command Execution',
				'description' => 'passthru() for command execution',
				'pattern'     => '/passthru\s*\(/i',
				'category'    => 'command_execution',
			),
			array(
				'id'          => 'system_function',
				'severity'    => 'critical',
				'title'       => 'System Command Execution',
				'description' => 'system() for running system commands',
				'pattern'     => '/\bsystem\s*\(/i',
				'category'    => 'command_execution',
			),
			array(
				'id'          => 'proc_open',
				'severity'    => 'critical',
				'title'       => 'Process Control',
				'description' => 'proc_open() for process manipulation',
				'pattern'     => '/proc_open\s*\(/i',
				'category'    => 'command_execution',
			),

			// High: Obfuscation
			array(
				'id'          => 'gzinflate_base64',
				'severity'    => 'high',
				'title'       => 'Compressed Obfuscation',
				'description' => 'gzinflate(base64_decode()) - Compressed malware payload',
				'pattern'     => '/gzinflate\s*\(\s*base64_decode\s*\(/i',
				'category'    => 'obfuscation',
			),
			array(
				'id'          => 'str_rot13',
				'severity'    => 'high',
				'title'       => 'ROT13 Obfuscation',
				'description' => 'str_rot13() text obfuscation',
				'pattern'     => '/str_rot13\s*\(/i',
				'category'    => 'obfuscation',
			),
			array(
				'id'          => 'create_function',
				'severity'    => 'high',
				'title'       => 'Dynamic Code Creation',
				'description' => 'create_function() for dynamic code',
				'pattern'     => '/create_function\s*\(/i',
				'category'    => 'obfuscation',
			),
			array(
				'id'          => 'assert_function',
				'severity'    => 'high',
				'title'       => 'Assert Code Execution',
				'description' => 'assert() can execute arbitrary code',
				'pattern'     => '/\bassert\s*\(/i',
				'category'    => 'command_execution',
			),
			array(
				'id'          => 'preg_replace_e',
				'severity'    => 'high',
				'title'       => 'Deprecated eval in preg_replace',
				'description' => 'preg_replace with /e modifier (deprecated, dangerous)',
				'pattern'     => '/preg_replace\s*\(\s*[\'"].*\/e[\'"]/i',
				'category'    => 'obfuscation',
			),

			// Medium: Suspicious
			array(
				'id'          => 'file_put_contents',
				'severity'    => 'medium',
				'title'       => 'File Write Operation',
				'description' => 'file_put_contents() can create/modify files',
				'pattern'     => '/file_put_contents\s*\(/i',
				'category'    => 'file_operation',
			),
			array(
				'id'          => 'hex_encoded',
				'severity'    => 'medium',
				'title'       => 'Heavy Hex Encoding',
				'description' => 'Long hex-encoded strings (obfuscation)',
				'pattern'     => '/(\\\\x[0-9a-f]{2}){10,}/i',
				'category'    => 'obfuscation',
			),
			array(
				'id'          => 'long_base64',
				'severity'    => 'medium',
				'title'       => 'Long Base64 String',
				'description' => 'Unusually long base64 encoded payload',
				'pattern'     => '/[a-zA-Z0-9+\/=]{500,}/',
				'category'    => 'obfuscation',
			),
			array(
				'id'          => 'php_uname',
				'severity'    => 'medium',
				'title'       => 'System Information Gathering',
				'description' => 'php_uname() gathers system info',
				'pattern'     => '/php_uname\s*\(/i',
				'category'    => 'reconnaissance',
			),
			array(
				'id'          => 'curl_exec',
				'severity'    => 'medium',
				'title'       => 'External Request',
				'description' => 'curl_exec() for external connections',
				'pattern'     => '/curl_exec\s*\(/i',
				'category'    => 'network',
			),

			// Webshell Indicators
			array(
				'id'          => 'webshell_c99',
				'severity'    => 'critical',
				'title'       => 'C99 Webshell Indicator',
				'description' => 'C99 shell signature detected',
				'pattern'     => '/c99shell|r57shell|wso\s*shell/i',
				'category'    => 'webshell',
			),
			array(
				'id'          => 'webshell_filesman',
				'severity'    => 'critical',
				'title'       => 'FilesMan Webshell',
				'description' => 'FilesMan shell signature',
				'pattern'     => '/FilesMan|WSO_VERSION/i',
				'category'    => 'webshell',
			),
			array(
				'id'          => 'backdoor_post',
				'severity'    => 'high',
				'title'       => 'Backdoor via POST',
				'description' => 'Executing code from POST data',
				'pattern'     => '/\$_(POST|GET|REQUEST)\s*\[\s*[\'"][^\'"]+[\'"]\s*\]\s*\(/i',
				'category'    => 'backdoor',
			),
		);
	}

	/**
	 * Fetch latest signatures from Wordfence Intelligence.
	 *
	 * @return array|WP_Error Signatures or error.
	 */
	public function fetch_remote_signatures() {
		// Note: Wordfence public vulnerability API gives vulnerability data.
		// For malware patterns, we use a combination approach.
		$response = wp_remote_get( self::WORDFENCE_VULN_API, array(
			'timeout' => 30,
			'headers' => array(
				'Accept' => 'application/json',
			),
		) );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( $code !== 200 ) {
			return new WP_Error( 'api_error', 'API returned status ' . $code );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $body ) ) {
			return new WP_Error( 'parse_error', 'Could not parse API response' );
		}

		return $body;
	}

	/**
	 * Update signatures from remote source.
	 *
	 * @return array Update result.
	 */
	public function update_signatures() {
		$remote = $this->fetch_remote_signatures();

		$result = array(
			'updated_at'      => current_time( 'mysql' ),
			'source'          => 'wordfence_intelligence',
			'builtin_count'   => count( $this->builtin_patterns ),
			'remote_count'    => 0,
			'total_count'     => count( $this->builtin_patterns ),
			'success'         => false,
			'error'           => null,
		);

		if ( is_wp_error( $remote ) ) {
			$result['error'] = $remote->get_error_message();
			$result['source'] = 'builtin_only';

			// Store built-in patterns as fallback.
			$this->store_signatures( $this->builtin_patterns );
		} else {
			// Process remote vulnerabilities into scannable patterns.
			$remote_patterns = $this->process_remote_data( $remote );
			$result['remote_count'] = count( $remote_patterns );

			// Merge with built-in patterns.
			$all_patterns = array_merge( $this->builtin_patterns, $remote_patterns );
			$result['total_count'] = count( $all_patterns );
			$result['success'] = true;

			$this->store_signatures( $all_patterns );
		}

		// Update timestamp.
		update_option( self::LAST_UPDATE_OPTION, $result, false );

		// Log the update.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'signatures_updated',
				sprintf( 'Malware signatures updated: %d total patterns', $result['total_count'] ),
				'info',
				$result
			);
		}

		return $result;
	}

	/**
	 * Process remote vulnerability data into scannable patterns.
	 *
	 * @param array $data Remote API data.
	 * @return array Processed patterns.
	 */
	private function process_remote_data( $data ) {
		$patterns = array();

		// Wordfence vulnerability API provides plugin/theme vulnerability info.
		// We convert relevant entries into detection patterns.
		if ( isset( $data['vulnerabilities'] ) && is_array( $data['vulnerabilities'] ) ) {
			foreach ( $data['vulnerabilities'] as $vuln ) {
				if ( empty( $vuln['software'] ) ) {
					continue;
				}

				// Create a pattern for vulnerable plugin/theme detection.
				foreach ( $vuln['software'] as $software ) {
					if ( empty( $software['slug'] ) ) {
						continue;
					}

					$patterns[] = array(
						'id'          => 'vuln_' . sanitize_key( $software['slug'] ),
						'severity'    => $this->map_cvss_to_severity( $vuln['cvss']['score'] ?? 5 ),
						'title'       => $vuln['title'] ?? 'Known Vulnerability',
						'description' => $vuln['description'] ?? '',
						'type'        => 'vulnerability',
						'software'    => $software['slug'],
						'affected'    => $software['affected_versions'] ?? '*',
						'patched'     => $software['patched_versions'] ?? null,
						'cve'         => $vuln['cve'] ?? null,
					);
				}
			}
		}

		return $patterns;
	}

	/**
	 * Map CVSS score to severity level.
	 *
	 * @param float $score CVSS score.
	 * @return string Severity level.
	 */
	private function map_cvss_to_severity( $score ) {
		if ( $score >= 9.0 ) {
			return 'critical';
		} elseif ( $score >= 7.0 ) {
			return 'high';
		} elseif ( $score >= 4.0 ) {
			return 'medium';
		}
		return 'low';
	}

	/**
	 * Store signatures in database.
	 *
	 * @param array $signatures Signature patterns.
	 */
	private function store_signatures( $signatures ) {
		update_option( self::SIGNATURES_OPTION, $signatures, false );
	}

	/**
	 * Get all current signatures.
	 * Priority: 1) Database (latest cached), 2) Bundled JSON file, 3) Built-in hardcoded
	 *
	 * @return array Signatures.
	 */
	public function get_signatures() {
		// First try database (contains latest fetched signatures).
		$stored = get_option( self::SIGNATURES_OPTION, array() );

		if ( ! empty( $stored ) ) {
			return $stored;
		}

		// Second try: Load from bundled JSON file (ships with plugin for offline use).
		$bundled = $this->load_bundled_signatures();
		if ( ! empty( $bundled ) ) {
			// Store in database for faster future access.
			$this->store_signatures( $bundled );
			return $bundled;
		}

		// Last resort: Built-in hardcoded patterns.
		$this->define_builtin_patterns();
		$this->store_signatures( $this->builtin_patterns );
		return $this->builtin_patterns;
	}

	/**
	 * Load signatures from bundled JSON file.
	 *
	 * @return array Signatures or empty array.
	 */
	private function load_bundled_signatures() {
		$json_file = NEXIFYMY_SECURITY_PATH . 'assets/signatures.json';

		if ( ! file_exists( $json_file ) || ! is_readable( $json_file ) ) {
			return array();
		}

		$content = file_get_contents( $json_file );
		if ( empty( $content ) ) {
			return array();
		}

		$data = json_decode( $content, true );

		if ( ! is_array( $data ) || empty( $data['signatures'] ) ) {
			return array();
		}

		return $data['signatures'];
	}

	/**
	 * Get only regex patterns for scanning.
	 *
	 * @param array $severity_filter Filter by severity levels.
	 * @return array Patterns with id, severity, description, pattern.
	 */
	public function get_scan_patterns( $severity_filter = array( 'critical', 'high', 'medium', 'low' ) ) {
		$signatures = $this->get_signatures();
		$patterns = array();

		foreach ( $signatures as $sig ) {
			// Skip if no pattern (vulnerability-type entries).
			if ( empty( $sig['pattern'] ) ) {
				continue;
			}

			// Filter by severity.
			if ( ! in_array( $sig['severity'], $severity_filter, true ) ) {
				continue;
			}

			$patterns[ $sig['id'] ] = array(
				'severity'    => $sig['severity'],
				'description' => $sig['description'] ?? $sig['title'],
				'pattern'     => $sig['pattern'],
			);
		}

		return $patterns;
	}

	/**
	 * Get update status.
	 *
	 * @return array Status info.
	 */
	public function get_status() {
		$last_update = get_option( self::LAST_UPDATE_OPTION, array() );
		$signatures = $this->get_signatures();

		// Count by severity.
		$by_severity = array(
			'critical' => 0,
			'high'     => 0,
			'medium'   => 0,
			'low'      => 0,
		);

		foreach ( $signatures as $sig ) {
			$sev = $sig['severity'] ?? 'low';
			if ( isset( $by_severity[ $sev ] ) ) {
				$by_severity[ $sev ]++;
			}
		}

		return array(
			'total_signatures' => count( $signatures ),
			'by_severity'      => $by_severity,
			'last_update'      => $last_update,
			'next_update'      => wp_next_scheduled( 'nexifymy_update_signatures' ),
		);
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	/**
	 * Update signatures via AJAX.
	 */
	public function ajax_update_signatures() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$result = $this->update_signatures();
		wp_send_json_success( $result );
	}

	/**
	 * Get signature status via AJAX.
	 */
	public function ajax_get_status() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		wp_send_json_success( $this->get_status() );
	}
}
