<?php
/**
 * Signature Updater Module.
 * Fetches and manages malware/vulnerability signatures from trusted sources.
 *
 * Sources:
 * 1. Wordfence Intelligence API (free, public) - WordPress vulnerabilities
 * 2. Built-in malware regex patterns - PHP malware detection
 * 3. Bundled signatures.json - Extended patterns (ships with plugin)
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
	 * Option key for vulnerability data.
	 */
	const VULN_OPTION = 'nexifymy_vulnerability_data';

	/**
	 * Option key for last update time.
	 */
	const LAST_UPDATE_OPTION = 'nexifymy_signatures_updated';

	/**
	 * Wordfence Intelligence Scanner Feed API (free, public, no auth required).
	 * Returns vulnerability data for WordPress plugins/themes.
	 * Docs: https://www.wordfence.com/help/wordfence-intelligence/v2-accessing-and-consuming-the-vulnerability-data-feed/
	 */
	const WORDFENCE_SCANNER_API = 'https://www.wordfence.com/api/intelligence/v2/vulnerabilities/scanner';

	/**
	 * GitHub raw URL for community malware signatures (scr34m/php-malware-scanner).
	 * Contains 47+ regex patterns for detecting PHP malware and webshells.
	 */
	const MALWARE_PATTERNS_URL = 'https://raw.githubusercontent.com/scr34m/php-malware-scanner/master/definitions/patterns_re.txt';

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
	 * Fetched vulnerability count.
	 */
	private $vuln_count = 0;

	/**
	 * Initialize the module.
	 */
	public function init() {
		$this->define_builtin_patterns();

		// Schedule automatic updates.
		add_action( 'nexifymy_update_signatures', array( $this, 'update_signatures' ) );

		// Auto-update scheduling
		$settings    = $this->get_settings();
		$auto_update = isset( $settings['auto_update'] ) ? $settings['auto_update'] : true;

		if ( $auto_update ) {
			// Schedule if not already scheduled
			if ( ! wp_next_scheduled( 'nexifymy_update_signatures' ) ) {
				wp_schedule_event( time() + 60, 'daily', 'nexifymy_update_signatures' );
			}
		} else {
			// Clear schedule if auto-update is disabled
			wp_clear_scheduled_hook( 'nexifymy_update_signatures' );
		}

		// Check if we should update on first load (if never updated before)
		$last_update = get_option( self::LAST_UPDATE_OPTION );
		if ( empty( $last_update ) && is_admin() ) {
			// First time - trigger an update
			add_action( 'admin_init', array( $this, 'maybe_initial_update' ), 100 );
		}

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_update_signatures', array( $this, 'ajax_update_signatures' ) );
		add_action( 'wp_ajax_nexifymy_get_signature_status', array( $this, 'ajax_get_status' ) );
		add_action( 'wp_ajax_nexifymy_toggle_auto_update', array( $this, 'ajax_toggle_auto_update' ) );
	}

	/**
	 * Maybe perform initial update if never updated.
	 */
	public function maybe_initial_update() {
		$last_update = get_option( self::LAST_UPDATE_OPTION );
		if ( empty( $last_update ) ) {
			// Perform initial update in background
			$this->update_signatures();
		}
	}

	/**
	 * Toggle auto-update setting via AJAX.
	 */
	public function ajax_toggle_auto_update() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$enabled = isset( $_POST['enabled'] ) ? absint( $_POST['enabled'] ) : 0;

		$settings = get_option( 'nexifymy_security_settings', array() );
		if ( ! isset( $settings['signatures'] ) ) {
			$settings['signatures'] = array();
		}
		$settings['signatures']['auto_update'] = (bool) $enabled;
		update_option( 'nexifymy_security_settings', $settings );

		if ( $enabled ) {
			if ( ! wp_next_scheduled( 'nexifymy_update_signatures' ) ) {
				wp_schedule_event( time() + 60, 'daily', 'nexifymy_update_signatures' );
			}
		} else {
			wp_clear_scheduled_hook( 'nexifymy_update_signatures' );
		}

		wp_send_json_success( array( 'auto_update' => $enabled ) );
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
				'id'              => 'eval_base64',
				'severity'        => 'critical',
				'title'           => 'Obfuscated eval() with base64',
				'description'     => 'eval(base64_decode()) - Common malware obfuscation technique',
				'pattern'         => '/eval\s*\(\s*base64_decode\s*\(/i',
				'category'        => 'obfuscation',
				'classification'  => 'CONFIRMED_MALWARE',
				'base_confidence' => 85,
				'context_rules'   => array(
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 15,
						'/uploads\//'             => 10,
					),
				),
			),
			array(
				'id'              => 'shell_exec',
				'severity'        => 'critical',
				'title'           => 'Shell Command Execution',
				'description'     => 'shell_exec() allows running system commands',
				'pattern'         => '/shell_exec\s*\(/i',
				'category'        => 'command_execution',
				'classification'  => 'dynamic',
				'base_confidence' => 50,
				'context_rules'   => array(
					'safe_contexts'      => array(
						'/wp-cli/'                        => -40,
						'/WP_CLI::/'                      => -100,
						'/vendor/'                        => -30,
						'/escapeshellarg|escapeshellcmd/' => -25,
					),
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 35,
						'/uploads\//'             => 40,
					),
				),
			),
			array(
				'id'              => 'exec_function',
				'severity'        => 'critical',
				'title'           => 'Command Execution',
				'description'     => 'exec() function for running commands',
				'pattern'         => '/\bexec\s*\(/i',
				'category'        => 'command_execution',
				'classification'  => 'dynamic',
				'base_confidence' => 50,
				'context_rules'   => array(
					'safe_contexts'      => array(
						'/wp-cli/'                        => -40,
						'/WP_CLI::/'                      => -100,
						'/vendor/'                        => -30,
						'/escapeshellarg|escapeshellcmd/' => -25,
					),
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 35,
						'/uploads\//'             => 40,
					),
				),
			),
			array(
				'id'              => 'passthru',
				'severity'        => 'critical',
				'title'           => 'Passthru Command Execution',
				'description'     => 'passthru() for command execution',
				'pattern'         => '/passthru\s*\(/i',
				'category'        => 'command_execution',
				'classification'  => 'dynamic',
				'base_confidence' => 50,
				'context_rules'   => array(
					'safe_contexts'      => array(
						'/wp-cli/'                        => -40,
						'/vendor/'                        => -30,
						'/escapeshellarg|escapeshellcmd/' => -25,
					),
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 35,
						'/uploads\//'             => 40,
					),
				),
			),
			array(
				'id'              => 'system_function',
				'severity'        => 'critical',
				'title'           => 'System Command Execution',
				'description'     => 'system() for running system commands',
				'pattern'         => '/\bsystem\s*\(/i',
				'category'        => 'command_execution',
				'classification'  => 'dynamic',
				'base_confidence' => 50,
				'context_rules'   => array(
					'safe_contexts'      => array(
						'/wp-cli/'                        => -40,
						'/vendor/'                        => -30,
						'/escapeshellarg|escapeshellcmd/' => -25,
					),
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 35,
						'/uploads\//'             => 40,
					),
				),
			),
			array(
				'id'              => 'proc_open',
				'severity'        => 'critical',
				'title'           => 'Process Control',
				'description'     => 'proc_open() for process manipulation',
				'pattern'         => '/proc_open\s*\(/i',
				'category'        => 'command_execution',
				'classification'  => 'dynamic',
				'base_confidence' => 50,
				'context_rules'   => array(
					'safe_contexts'      => array(
						'/wp-cli/' => -40,
						'/vendor/' => -30,
					),
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 35,
						'/uploads\//'             => 40,
					),
				),
			),

			// High: Obfuscation
			array(
				'id'              => 'gzinflate_base64',
				'severity'        => 'high',
				'title'           => 'Compressed Obfuscation',
				'description'     => 'gzinflate(base64_decode()) - Compressed malware payload',
				'pattern'         => '/gzinflate\s*\(\s*base64_decode\s*\(/i',
				'category'        => 'obfuscation',
				'classification'  => 'CONFIRMED_MALWARE',
				'base_confidence' => 85,
				'context_rules'   => array(
					'dangerous_contexts' => array(
						'/uploads\//' => 15,
					),
				),
			),
			array(
				'id'              => 'str_rot13',
				'severity'        => 'high',
				'title'           => 'ROT13 Obfuscation',
				'description'     => 'str_rot13() text obfuscation',
				'pattern'         => '/str_rot13\s*\(/i',
				'category'        => 'obfuscation',
				'classification'  => 'SUSPICIOUS_CODE',
				'base_confidence' => 60,
				'context_rules'   => array(
					'safe_contexts'      => array(
						'/vendor/' => -30,
					),
					'dangerous_contexts' => array(
						'/uploads\//' => 25,
					),
				),
			),
			array(
				'id'              => 'create_function',
				'severity'        => 'high',
				'title'           => 'Dynamic Code Creation',
				'description'     => 'create_function() for dynamic code',
				'pattern'         => '/create_function\s*\(/i',
				'category'        => 'obfuscation',
				'classification'  => 'SUSPICIOUS_CODE',
				'base_confidence' => 60,
				'context_rules'   => array(
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 30,
						'/uploads\//'             => 25,
					),
				),
			),
			array(
				'id'              => 'assert_function',
				'severity'        => 'high',
				'title'           => 'Assert Code Execution',
				'description'     => 'assert() can execute arbitrary code',
				'pattern'         => '/\bassert\s*\(/i',
				'category'        => 'command_execution',
				'classification'  => 'dynamic',
				'base_confidence' => 45,
				'context_rules'   => array(
					'safe_contexts'      => array(
						'/vendor/'   => -30,
						'/tests?\//' => -40,
					),
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 35,
					),
				),
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
				'id'              => 'file_put_contents',
				'severity'        => 'medium',
				'title'           => 'File Write Operation',
				'description'     => 'file_put_contents() can create/modify files',
				'pattern'         => '/file_put_contents\s*\(/i',
				'category'        => 'file_operation',
				'classification'  => 'dynamic',
				'base_confidence' => 40,
				'context_rules'   => array(
					'safe_contexts'      => array(
						'/vendor/'        => -25,
						'/WP_Filesystem/' => -35,
					),
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 35,
						'/\.php[\'"]/'            => 30,
						'/uploads\//'             => 25,
					),
				),
			),
			array(
				'id'              => 'hex_encoded',
				'severity'        => 'medium',
				'title'           => 'Heavy Hex Encoding',
				'description'     => 'Long hex-encoded strings (obfuscation)',
				'pattern'         => '/(\\\\x[0-9a-f]{2}){10,}/i',
				'category'        => 'obfuscation',
				'classification'  => 'SUSPICIOUS_CODE',
				'base_confidence' => 55,
				'context_rules'   => array(
					'dangerous_contexts' => array(
						'/uploads\//' => 30,
					),
				),
			),
			array(
				'id'              => 'long_base64',
				'severity'        => 'medium',
				'title'           => 'Long Base64 String',
				'description'     => 'Unusually long base64 encoded payload',
				'pattern'         => '/[a-zA-Z0-9+\/=]{500,}/',
				'category'        => 'obfuscation',
				'classification'  => 'CODE_SMELL',
				'base_confidence' => 45,
				'context_rules'   => array(
					'dangerous_contexts' => array(
						'/uploads\//' => 25,
					),
				),
			),
			array(
				'id'              => 'php_uname',
				'severity'        => 'medium',
				'title'           => 'System Information Gathering',
				'description'     => 'php_uname() gathers system info',
				'pattern'         => '/php_uname\s*\(/i',
				'category'        => 'reconnaissance',
				'classification'  => 'CODE_SMELL',
				'base_confidence' => 40,
				'context_rules'   => array(
					'dangerous_contexts' => array(
						'/uploads\//' => 30,
					),
				),
			),
			array(
				'id'              => 'curl_exec',
				'severity'        => 'medium',
				'title'           => 'External Request',
				'description'     => 'curl_exec() for external connections',
				'pattern'         => '/curl_exec\s*\(/i',
				'category'        => 'network',
				'classification'  => 'CODE_SMELL',
				'base_confidence' => 35,
				'context_rules'   => array(
					'safe_contexts'      => array(
						'/vendor/' => -25,
					),
					'dangerous_contexts' => array(
						'/\$_(GET|POST|REQUEST)/' => 30,
					),
				),
			),

			// Webshell Indicators
			array(
				'id'              => 'webshell_c99',
				'severity'        => 'critical',
				'title'           => 'C99 Webshell Indicator',
				'description'     => 'C99 shell signature detected',
				'pattern'         => '/c99shell|r57shell|wso\s*shell/i',
				'category'        => 'webshell',
				'classification'  => 'CONFIRMED_MALWARE',
				'base_confidence' => 95,
				'context_rules'   => array(
					'dangerous_contexts' => array(
						'/uploads\//' => 5,
					),
				),
			),
			array(
				'id'              => 'webshell_filesman',
				'severity'        => 'critical',
				'title'           => 'FilesMan Webshell',
				'description'     => 'FilesMan shell signature',
				'pattern'         => '/FilesMan|WSO_VERSION/i',
				'category'        => 'webshell',
				'classification'  => 'CONFIRMED_MALWARE',
				'base_confidence' => 95,
				'context_rules'   => array(
					'dangerous_contexts' => array(
						'/uploads\//' => 5,
					),
				),
			),
			array(
				'id'              => 'backdoor_post',
				'severity'        => 'high',
				'title'           => 'Backdoor via POST',
				'description'     => 'Executing code from POST data',
				'pattern'         => '/\$_(POST|GET|REQUEST)\s*\[\s*[\'"][^\'"]+[\'"]\s*\]\s*\(/i',
				'category'        => 'backdoor',
				'classification'  => 'SUSPICIOUS_CODE',
				'base_confidence' => 70,
				'context_rules'   => array(
					'dangerous_contexts' => array(
						'/uploads\//' => 20,
					),
				),
			),

			// Additional Critical Patterns
			array(
				'id'          => 'popen_function',
				'severity'    => 'critical',
				'title'       => 'Process Open',
				'description' => 'popen() for process control',
				'pattern'     => '/popen\s*\(/i',
				'category'    => 'command_execution',
			),
			array(
				'id'          => 'pcntl_exec',
				'severity'    => 'critical',
				'title'       => 'PCNTL Execution',
				'description' => 'pcntl_exec() process execution',
				'pattern'     => '/pcntl_exec\s*\(/i',
				'category'    => 'command_execution',
			),
			array(
				'id'          => 'eval_gzuncompress',
				'severity'    => 'critical',
				'title'       => 'Eval with Compression',
				'description' => 'eval(gzuncompress()) malware pattern',
				'pattern'     => '/eval\s*\(\s*gzuncompress\s*\(/i',
				'category'    => 'obfuscation',
			),
			array(
				'id'          => 'eval_strrev',
				'severity'    => 'high',
				'title'       => 'Eval with String Reverse',
				'description' => 'eval(strrev()) obfuscation',
				'pattern'     => '/eval\s*\(\s*strrev\s*\(/i',
				'category'    => 'obfuscation',
			),
			array(
				'id'          => 'base64_shell',
				'severity'    => 'critical',
				'title'       => 'Base64 Encoded Shell',
				'description' => 'Shell command in base64',
				'pattern'     => '/base64_decode\s*\([\'"][A-Za-z0-9+\/=]{100,}[\'"]\)/i',
				'category'    => 'obfuscation',
			),

			// File Inclusion Attacks
			array(
				'id'          => 'include_remote',
				'severity'    => 'critical',
				'title'       => 'Remote File Inclusion',
				'description' => 'Including files via HTTP/FTP',
				'pattern'     => '/(include|require|include_once|require_once)\s*\(\s*[\'"]https?:\/\//i',
				'category'    => 'file_inclusion',
			),
			array(
				'id'          => 'include_input',
				'severity'    => 'high',
				'title'       => 'User Input in Include',
				'description' => 'Including files from user input',
				'pattern'     => '/(include|require)\s*\(\s*\$_(GET|POST|REQUEST)/i',
				'category'    => 'file_inclusion',
			),

			// Database Attacks
			array(
				'id'          => 'sql_union',
				'severity'    => 'high',
				'title'       => 'SQL UNION Attack',
				'description' => 'UNION-based SQL injection pattern',
				'pattern'     => '/UNION\s+(ALL\s+)?SELECT/i',
				'category'    => 'sql_injection',
			),
			array(
				'id'          => 'sql_drop',
				'severity'    => 'critical',
				'title'       => 'SQL DROP Statement',
				'description' => 'Destructive SQL DROP command',
				'pattern'     => '/DROP\s+(TABLE|DATABASE|INDEX)/i',
				'category'    => 'sql_injection',
			),

			// Encoding/Decoding
			array(
				'id'          => 'chr_obfuscation',
				'severity'    => 'medium',
				'title'       => 'Chr() Obfuscation',
				'description' => 'Multiple chr() for obfuscation',
				'pattern'     => '/(chr\s*\(\s*\d+\s*\)\s*\.?\s*){5,}/i',
				'category'    => 'obfuscation',
			),
			array(
				'id'          => 'ord_decode',
				'severity'    => 'medium',
				'title'       => 'Ord() String Decode',
				'description' => 'String decoding via ord()',
				'pattern'     => '/ord\s*\(\s*substr/i',
				'category'    => 'obfuscation',
			),

			// Network Patterns
			array(
				'id'          => 'fsockopen',
				'severity'    => 'medium',
				'title'       => 'Socket Connection',
				'description' => 'fsockopen() network connection',
				'pattern'     => '/fsockopen\s*\(/i',
				'category'    => 'network',
			),
			array(
				'id'          => 'stream_socket',
				'severity'    => 'medium',
				'title'       => 'Stream Socket',
				'description' => 'stream_socket_client() connection',
				'pattern'     => '/stream_socket_client\s*\(/i',
				'category'    => 'network',
			),

			// Spam/SEO Injection
			array(
				'id'          => 'hidden_links',
				'severity'    => 'medium',
				'title'       => 'Hidden Links Injection',
				'description' => 'Hidden spam links pattern',
				'pattern'     => '/style\s*=\s*[\'"].*display\s*:\s*none.*<a\s+href/is',
				'category'    => 'spam',
			),
			array(
				'id'          => 'seo_spam',
				'severity'    => 'medium',
				'title'       => 'SEO Spam Keywords',
				'description' => 'Common pharma/casino spam',
				'pattern'     => '/(viagra|cialis|casino|poker|porn)\s*</i',
				'category'    => 'spam',
			),

			// Crypto Miners
			array(
				'id'          => 'crypto_miner',
				'severity'    => 'high',
				'title'       => 'Cryptocurrency Miner',
				'description' => 'Crypto mining script detected',
				'pattern'     => '/(coinhive|cryptonight|minero|coin-?hive)/i',
				'category'    => 'cryptominer',
			),
			array(
				'id'          => 'crypto_webminer',
				'severity'    => 'high',
				'title'       => 'Web Miner Script',
				'description' => 'Browser-based mining script',
				'pattern'     => '/(CoinHive\.Anonymous|CryptoLoot|deepMiner)/i',
				'category'    => 'cryptominer',
			),

			// WordPress Specific
			array(
				'id'          => 'wp_user_create',
				'severity'    => 'high',
				'title'       => 'Backdoor User Creation',
				'description' => 'Suspicious admin user creation',
				'pattern'     => '/wp_insert_user\s*\(\s*array\s*\(\s*[\'"]user_login[\'"]\s*=>/i',
				'category'    => 'backdoor',
			),
			array(
				'id'          => 'wp_options_inject',
				'severity'    => 'high',
				'title'       => 'Options Table Injection',
				'description' => 'Direct options table manipulation',
				'pattern'     => '/update_option\s*\(\s*[\'"]active_plugins[\'"]/i',
				'category'    => 'backdoor',
			),
			array(
				'id'          => 'theme_header_inject',
				'severity'    => 'high',
				'title'       => 'Theme Header Injection',
				'description' => 'Injected code in theme header',
				'pattern'     => '/<\?php\s+\/\*\*\s*\n\s*\*\s*@package.*\*\/\s*\n.*eval\s*\(/is',
				'category'    => 'injection',
			),

			// Obfuscation Techniques
			array(
				'id'          => 'variable_function',
				'severity'    => 'high',
				'title'       => 'Variable Function Call',
				'description' => 'Dynamic function via variable',
				'pattern'     => '/\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*\$_(GET|POST|REQUEST)/i',
				'category'    => 'obfuscation',
			),
			array(
				'id'          => 'call_user_func_array',
				'severity'    => 'high',
				'title'       => 'Dynamic Function Array Call',
				'description' => 'call_user_func_array with user input',
				'pattern'     => '/call_user_func(_array)?\s*\(\s*\$_(GET|POST|REQUEST)/i',
				'category'    => 'obfuscation',
			),
			array(
				'id'          => 'preg_callback',
				'severity'    => 'high',
				'title'       => 'Preg Callback Execution',
				'description' => 'Code execution via preg callback',
				'pattern'     => '/preg_replace_callback\s*\(.*\$_(GET|POST|REQUEST)/i',
				'category'    => 'obfuscation',
			),

			// File Operations
			array(
				'id'          => 'fwrite_php',
				'severity'    => 'high',
				'title'       => 'PHP File Write',
				'description' => 'Writing PHP code to file',
				'pattern'     => '/fwrite\s*\([^,]+,\s*[\'"]<\?php/i',
				'category'    => 'file_operation',
			),
			array(
				'id'          => 'move_uploaded',
				'severity'    => 'medium',
				'title'       => 'File Upload Handler',
				'description' => 'move_uploaded_file() operation',
				'pattern'     => '/move_uploaded_file\s*\(/i',
				'category'    => 'file_operation',
			),
			array(
				'id'          => 'chmod_operation',
				'severity'    => 'medium',
				'title'       => 'Permission Change',
				'description' => 'chmod() permission modification',
				'pattern'     => '/chmod\s*\(\s*[^,]+,\s*0?7[0-7]{2}\s*\)/i',
				'category'    => 'file_operation',
			),

			// Mailer Abuse
			array(
				'id'          => 'mail_injection',
				'severity'    => 'high',
				'title'       => 'Mail Header Injection',
				'description' => 'Email header injection attempt',
				'pattern'     => '/mail\s*\([^,]+,\s*\$_(GET|POST|REQUEST)/i',
				'category'    => 'spam',
			),
			array(
				'id'          => 'mass_mailer',
				'severity'    => 'high',
				'title'       => 'Mass Mailer Script',
				'description' => 'Bulk email sending script',
				'pattern'     => '/(PHPMailer|SwiftMailer).*while.*mail\s*\(/is',
				'category'    => 'spam',
			),

			// Iframe Injection
			array(
				'id'          => 'hidden_iframe',
				'severity'    => 'high',
				'title'       => 'Hidden Iframe',
				'description' => 'Zero-size hidden iframe',
				'pattern'     => '/<iframe[^>]*(width|height)\s*=\s*[\'"]?0/i',
				'category'    => 'injection',
			),
			array(
				'id'          => 'iframe_inject',
				'severity'    => 'high',
				'title'       => 'Iframe Injection',
				'description' => 'Dynamically injected iframe',
				'pattern'     => '/document\.write\s*\([^)]*<iframe/i',
				'category'    => 'injection',
			),

			// Redirect Attacks
			array(
				'id'          => 'js_redirect',
				'severity'    => 'medium',
				'title'       => 'JavaScript Redirect',
				'description' => 'Malicious JS redirect',
				'pattern'     => '/window\.location\s*=\s*[\'"]https?:\/\/(?!.*wordpress)/i',
				'category'    => 'redirect',
			),
			array(
				'id'          => 'meta_refresh',
				'severity'    => 'medium',
				'title'       => 'Meta Refresh Redirect',
				'description' => 'Meta tag redirect injection',
				'pattern'     => '/<meta[^>]*http-equiv\s*=\s*[\'"]refresh[\'"][^>]*url\s*=/i',
				'category'    => 'redirect',
			),

			// Information Disclosure
			array(
				'id'          => 'phpinfo_call',
				'severity'    => 'medium',
				'title'       => 'PHPInfo Disclosure',
				'description' => 'phpinfo() information leak',
				'pattern'     => '/phpinfo\s*\(\s*\)/i',
				'category'    => 'reconnaissance',
			),
			array(
				'id'          => 'error_reporting_off',
				'severity'    => 'low',
				'title'       => 'Error Reporting Disabled',
				'description' => 'Hiding errors (common in malware)',
				'pattern'     => '/error_reporting\s*\(\s*0\s*\)/i',
				'category'    => 'evasion',
			),
			array(
				'id'          => 'ini_set_errors',
				'severity'    => 'low',
				'title'       => 'Display Errors Modified',
				'description' => 'Error display manipulation',
				'pattern'     => '/ini_set\s*\(\s*[\'"]display_errors[\'"]\s*,\s*[\'"]?(0|off|false)/i',
				'category'    => 'evasion',
			),
		);
	}

	/**
	 * Fetch WordPress vulnerability data from Wordfence Intelligence.
	 * The scanner feed is ~5-10MB and contains detection info.
	 *
	 * @return array|WP_Error Vulnerability data or error.
	 */
	public function fetch_wordfence_vulnerabilities() {
		$response = wp_remote_get(
			self::WORDFENCE_SCANNER_API,
			array(
				'timeout'   => 60, // Large response needs more time
				'sslverify' => true,
				'headers'   => array(
					'Accept'          => 'application/json',
					'Accept-Encoding' => 'gzip, deflate',
					'User-Agent'      => 'NexifyMy-Security/' . NEXIFYMY_SECURITY_VERSION . ' (WordPress Security Plugin)',
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( $code !== 200 ) {
			return new WP_Error( 'api_error', 'Wordfence API returned status ' . $code );
		}

		$body = wp_remote_retrieve_body( $response );
		if ( empty( $body ) ) {
			return new WP_Error( 'empty_response', 'Wordfence API returned empty response' );
		}

		$data = json_decode( $body, true );
		if ( json_last_error() !== JSON_ERROR_NONE ) {
			return new WP_Error( 'parse_error', 'JSON parse error: ' . json_last_error_msg() );
		}

		if ( ! is_array( $data ) ) {
			return new WP_Error( 'invalid_data', 'Wordfence API returned invalid data format' );
		}

		return $data;
	}

	/**
	 * Fetch malware regex patterns from scr34m/php-malware-scanner (community project).
	 * This file contains ~50 regex patterns for detecting PHP malware.
	 *
	 * @return array|WP_Error Pattern array or error.
	 */
	public function fetch_malware_patterns() {
		$response = wp_remote_get(
			self::MALWARE_PATTERNS_URL,
			array(
				'timeout'   => 30,
				'sslverify' => true,
				'headers'   => array(
					'Accept'     => 'text/plain',
					'User-Agent' => 'NexifyMy-Security/' . NEXIFYMY_SECURITY_VERSION,
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( $code !== 200 ) {
			return new WP_Error( 'api_error', 'Malware patterns fetch returned status ' . $code );
		}

		$body = wp_remote_retrieve_body( $response );
		if ( empty( $body ) ) {
			return new WP_Error( 'empty_response', 'No malware patterns received' );
		}

		// Parse the patterns file (one regex per line)
		$lines    = explode( "\n", $body );
		$patterns = array();
		$count    = 0;

		foreach ( $lines as $line ) {
			$line = trim( $line );

			// Skip empty lines
			if ( empty( $line ) ) {
				continue;
			}

			// Validate it looks like a regex (basic check)
			if ( strlen( $line ) < 3 ) {
				continue;
			}

			// Wrap the pattern with delimiters for PHP preg_match
			$php_pattern = '/' . str_replace( '/', '\\/', $line ) . '/i';

			// Test if it's a valid regex
			if ( @preg_match( $php_pattern, '' ) === false ) {
				continue; // Skip invalid patterns
			}

			$patterns[] = array(
				'id'          => 'pms_' . $count,
				'severity'    => $this->guess_pattern_severity( $line ),
				'title'       => 'Community Pattern #' . ( $count + 1 ),
				'description' => 'Malware signature from php-malware-scanner',
				'pattern'     => $php_pattern,
				'category'    => 'community_malware',
				'source'      => 'php-malware-scanner',
			);
			++$count;
		}

		return $patterns;
	}

	/**
	 * Guess severity based on pattern content.
	 *
	 * @param string $pattern Regex pattern.
	 * @return string Severity level.
	 */
	private function guess_pattern_severity( $pattern ) {
		$critical_indicators = array( 'eval', 'exec', 'shell', 'passthru', 'system', 'base64_decode', 'proc_open' );
		$high_indicators     = array( 'file_put_contents', 'fwrite', 'curl', 'fsockopen', 'popen' );

		$pattern_lower = strtolower( $pattern );

		foreach ( $critical_indicators as $indicator ) {
			if ( strpos( $pattern_lower, $indicator ) !== false ) {
				return 'critical';
			}
		}

		foreach ( $high_indicators as $indicator ) {
			if ( strpos( $pattern_lower, $indicator ) !== false ) {
				return 'high';
			}
		}

		return 'medium';
	}

	/**
	 * Update signatures from all remote sources.
	 *
	 * @return array Update result.
	 */
	public function update_signatures() {
		// Initialize built-in patterns
		$this->define_builtin_patterns();

		$result = array(
			'updated_at'            => current_time( 'mysql' ),
			'sources'               => array(),
			'builtin_count'         => count( $this->builtin_patterns ),
			'vulnerability_count'   => 0,
			'malware_pattern_count' => 0,
			'total_signatures'      => count( $this->builtin_patterns ),
			'success'               => false,
			'errors'                => array(),
		);

		$all_patterns = $this->builtin_patterns;

		// ── Source 1: Wordfence Vulnerability Data ──
		$wordfence_data = $this->fetch_wordfence_vulnerabilities();
		if ( is_wp_error( $wordfence_data ) ) {
			$result['errors']['wordfence'] = $wordfence_data->get_error_message();
		} else {
			// Process Wordfence data - root is object with UUID keys
			$vuln_data                     = $this->process_wordfence_data( $wordfence_data );
			$result['vulnerability_count'] = count( $vuln_data['vulnerabilities'] );
			$result['sources'][]           = 'wordfence_intelligence';

			// Store vulnerability data separately (for version checking)
			update_option(
				self::VULN_OPTION,
				array(
					'count'      => count( $vuln_data['vulnerabilities'] ),
					'updated_at' => current_time( 'mysql' ),
					'plugins'    => $vuln_data['affected_plugins'],
					'themes'     => $vuln_data['affected_themes'],
				),
				false
			);

			// Add vulnerability-based patterns
			$all_patterns = array_merge( $all_patterns, $vuln_data['patterns'] );
		}

		// ── Source 2: Community Malware Patterns ──
		$malware_patterns = $this->fetch_malware_patterns();
		if ( is_wp_error( $malware_patterns ) ) {
			$result['errors']['malware_patterns'] = $malware_patterns->get_error_message();
		} else {
			$result['malware_pattern_count'] = count( $malware_patterns );
			$result['sources'][]             = 'php_malware_finder';
			$all_patterns                    = array_merge( $all_patterns, $malware_patterns );
		}

		// ── Store Combined Results ──
		$result['total_signatures'] = count( $all_patterns );
		$result['success']          = ! empty( $result['sources'] ) || count( $this->builtin_patterns ) > 0;

		// Store signatures
		$this->store_signatures( $all_patterns );

		// Update metadata options
		update_option( self::LAST_UPDATE_OPTION, $result, false );
		update_option( 'nexifymy_signature_version', '2.0.' . date( 'ymd.His' ), false );
		update_option( 'nexifymy_signature_last_update', current_time( 'mysql' ), false );
		update_option( 'nexifymy_signature_count', $result['total_signatures'], false );

		// Log the update
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			$log_msg = sprintf(
				'Signatures updated: %d builtin + %d vulnerabilities + %d malware patterns = %d total',
				$result['builtin_count'],
				$result['vulnerability_count'],
				$result['malware_pattern_count'],
				$result['total_signatures']
			);
			NexifyMy_Security_Logger::log( 'signatures_updated', $log_msg, 'info', $result );
		}

		return $result;
	}

	/**
	 * Process Wordfence vulnerability data.
	 * The API returns an object where keys are UUIDs and values are vulnerability records.
	 *
	 * @param array $data Raw API response (object with UUID keys).
	 * @return array Processed data with vulnerabilities, patterns, affected plugins/themes.
	 */
	private function process_wordfence_data( $data ) {
		$result = array(
			'vulnerabilities'  => array(),
			'patterns'         => array(),
			'affected_plugins' => array(),
			'affected_themes'  => array(),
		);

		// Wordfence scanner feed: root is object with UUID keys
		// Each entry has: id, title, software (array), cvss, cwe, etc.
		foreach ( $data as $uuid => $vuln ) {
			// Skip if no software info
			if ( empty( $vuln['software'] ) || ! is_array( $vuln['software'] ) ) {
				continue;
			}

			$severity = 'medium';
			if ( isset( $vuln['cvss']['score'] ) ) {
				$severity = $this->map_cvss_to_severity( (float) $vuln['cvss']['score'] );
			}

			// Process each affected software
			foreach ( $vuln['software'] as $software ) {
				if ( empty( $software['slug'] ) ) {
					continue;
				}

				$slug = sanitize_key( $software['slug'] );
				$type = isset( $software['type'] ) ? $software['type'] : 'plugin';

				// Track affected software
				if ( $type === 'theme' ) {
					$result['affected_themes'][ $slug ] = array(
						'affected' => $software['affected_versions'] ?? '*',
						'patched'  => $software['patched_versions'] ?? null,
					);
				} else {
					$result['affected_plugins'][ $slug ] = array(
						'affected' => $software['affected_versions'] ?? '*',
						'patched'  => $software['patched_versions'] ?? null,
					);
				}

				// Store vulnerability record
				$result['vulnerabilities'][] = array(
					'uuid'        => $uuid,
					'slug'        => $slug,
					'type'        => $type,
					'title'       => $vuln['title'] ?? 'Unknown Vulnerability',
					'description' => $vuln['description'] ?? '',
					'severity'    => $severity,
					'cvss_score'  => $vuln['cvss']['score'] ?? null,
					'cwe'         => $vuln['cwe']['id'] ?? null,
					'affected'    => $software['affected_versions'] ?? '*',
					'patched'     => $software['patched_versions'] ?? null,
					'references'  => $vuln['references'] ?? array(),
				);

				// Create detection pattern for version checking
				// This helps scanner identify vulnerable versions
				$result['patterns'][] = array(
					'id'            => 'vuln_' . $slug . '_' . substr( $uuid, 0, 8 ),
					'severity'      => $severity,
					'title'         => $vuln['title'] ?? 'Vulnerable Software',
					'description'   => sprintf(
						'%s %s - Affected versions: %s',
						ucfirst( $type ),
						$slug,
						$software['affected_versions'] ?? 'unknown'
					),
					'type'          => 'vulnerability',
					'software'      => $slug,
					'software_type' => $type,
					'affected'      => $software['affected_versions'] ?? '*',
					'patched'       => $software['patched_versions'] ?? null,
					'cve'           => isset( $vuln['cve'] ) ? $vuln['cve'] : null,
				);
			}
		}

		return $result;
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
		$patterns   = array();

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
		$vuln_data   = get_option( self::VULN_OPTION, array() );
		$signatures  = $this->get_signatures();

		// Count by severity
		$by_severity = array(
			'critical' => 0,
			'high'     => 0,
			'medium'   => 0,
			'low'      => 0,
		);

		// Count by category
		$by_category = array(
			'malware'       => 0,
			'vulnerability' => 0,
			'community'     => 0,
		);

		foreach ( $signatures as $sig ) {
			$sev = isset( $sig['severity'] ) ? $sig['severity'] : 'low';
			if ( isset( $by_severity[ $sev ] ) ) {
				++$by_severity[ $sev ];
			}

			// Categorize
			if ( isset( $sig['type'] ) && $sig['type'] === 'vulnerability' ) {
				++$by_category['vulnerability'];
			} elseif ( isset( $sig['source'] ) && $sig['source'] === 'php-malware-finder' ) {
				++$by_category['community'];
			} else {
				++$by_category['malware'];
			}
		}

		return array(
			'total_signatures'    => count( $signatures ),
			'by_severity'         => $by_severity,
			'by_category'         => $by_category,
			'vulnerability_count' => isset( $vuln_data['count'] ) ? $vuln_data['count'] : 0,
			'affected_plugins'    => isset( $vuln_data['plugins'] ) ? count( $vuln_data['plugins'] ) : 0,
			'affected_themes'     => isset( $vuln_data['themes'] ) ? count( $vuln_data['themes'] ) : 0,
			'last_update'         => $last_update,
			'next_update'         => wp_next_scheduled( 'nexifymy_update_signatures' ),
			'version'             => get_option( 'nexifymy_signature_version', '1.0.0' ),
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

		// Increase memory/time for large fetches
		if ( function_exists( 'wp_raise_memory_limit' ) ) {
			wp_raise_memory_limit( 'admin' );
		}
		set_time_limit( 120 );

		$result = $this->update_signatures();

		// Format response for UI
		$response = array(
			'success'               => $result['success'],
			'total_count'           => $result['total_signatures'],
			'builtin_count'         => $result['builtin_count'],
			'vulnerability_count'   => $result['vulnerability_count'],
			'malware_pattern_count' => $result['malware_pattern_count'],
			'sources'               => $result['sources'],
			'updated_at'            => $result['updated_at'],
			'version'               => get_option( 'nexifymy_signature_version', '1.0.0' ),
			'errors'                => $result['errors'],
			'message'               => $this->format_update_message( $result ),
		);

		wp_send_json_success( $response );
	}

	/**
	 * Format a human-readable update message.
	 *
	 * @param array $result Update result.
	 * @return string Message.
	 */
	private function format_update_message( $result ) {
		$parts = array();

		if ( $result['builtin_count'] > 0 ) {
			$parts[] = $result['builtin_count'] . ' built-in patterns';
		}
		if ( $result['vulnerability_count'] > 0 ) {
			$parts[] = $result['vulnerability_count'] . ' WordPress vulnerabilities (Wordfence)';
		}
		if ( $result['malware_pattern_count'] > 0 ) {
			$parts[] = $result['malware_pattern_count'] . ' community malware signatures';
		}

		if ( empty( $parts ) ) {
			return 'No signatures loaded.';
		}

		return 'Loaded: ' . implode( ', ', $parts ) . '. Total: ' . $result['total_signatures'] . ' signatures.';
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
