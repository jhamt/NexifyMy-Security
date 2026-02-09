<?php
/**
 * Advanced Firewall Module (WAF).
 * Implements a Rule Engine based on OWASP & ModSecurity logic.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Firewall {

	/**
	 * Rules definitions.
	 * @var array
	 */
	private $rules = array();

	/**
	 * Whether to log only (do not block).
	 * @var bool
	 */
	private $log_only_mode = false;

	/**
	 * Per-rule enable toggles.
	 * @var array<string,bool>
	 */
	private $enabled_rules = array();

	/**
	 * Identity-aware protected endpoints (Zero-Trust).
	 * @var array
	 */
	private $identity_aware_endpoints = array(
		'/wp-json/wp/v2/users',
		'/wp-json/wp/v2/settings',
		'/wp-json/wp/v2/plugins',
		'/wp-json/wp/v2/themes',
		'/wp-json/wp/v2/block-types',
		'/wp-json/wp/v2/global-styles',
	);

	/**
	 * Risk threshold for identity-aware blocking.
	 * @var int
	 */
	const IDENTITY_RISK_THRESHOLD = 50;

	/**
	 * Initialize the firewall rules.
	 * NOTE: run_firewall() is called directly from main plugin file for early execution.
	 */
	public function init() {
		$this->define_rules();
	}

	/**
	 * Define the security rules (Inspired by OWASP CRS).
	 */
	private function define_rules() {
		$this->rules = array(
			// SQL Injection (SQLi) - tightened to reduce false positives.
			'sqli' => array(
				'description' => 'SQL Injection Attempt',
				'patterns'    => array(
					'/union\s+(all\s+)?select\s+/i',       // UNION SELECT with trailing space.
					'/\)\s*union\s+select/i',             // Closing paren before UNION.
					'/information_schema\./i',            // Must have dot after.
					'/(?:\x27;|--|#)\s*$/i',                 // SQL comment terminators.
					'/(?:benchmark|sleep)\s*\(\s*\d/i',   // Time-based with number arg.
					'/\/\*![0-9]+/i',                     // MySQL version comments.
					'/load_file\s*\(/i',                  // File read.
					'/into\s+(out|dump)file/i',           // File write.
				),
			),

			// Cross-Site Scripting (XSS)
			'xss' => array(
				'description' => 'Cross-Site Scripting (XSS) Attempt',
				'patterns'    => array(
					'/<script[^>]*>.*<\/script>/is',
					'/<script/i',
					'/javascript:/i',
					'/vbscript:/i',
					'/onload\s*=/i',
					'/onerror\s*=/i',
					'/onclick\s*=/i',
					'/onmouseover\s*=/i',
					'/alert\s*\(/i',
					'/document\.cookie/i',
					'/document\.location/i',
					'/base64_decode\s*\(/i',
					'/eval\s*\(/i',
				),
			),

			// Local/Remote File Inclusion (LFI/RFI)
			'fi' => array(
				'description' => 'File Inclusion Attempt',
				'patterns'    => array(
					'/\.\.\//', // Path Traversal
					'/\.\.\\\\/', // Path Traversal Win
					'/etc\/passwd/i',
					'/proc\/self\/environ/i',
					// Context-aware RFI patterns (avoid blocking normal URLs)
					'/\b(?:include|require)(?:_once)?\s*\(\s*[\'"]?(?:https?|ftp):\/\//i',  // RFI via include/require
					'/\b(?:file_get_contents|fopen|readfile|curl_exec)\s*\(\s*[\'"]?(?:https?|ftp):\/\//i',  // RFI via file functions
					'/=\s*(?:https?|ftp|php):\/\/[^\s&]*(?:\.php|\.phtml|\.inc)/i',  // URL params pointing to PHP files
					'/php:\/\/input/i',
					'/php:\/\/filter/i',
					'/data:\s*(?:text\/html|application)/i',  // Data URI attacks
					'/expect:\/\//i',  // expect:// wrapper attacks
				),
			),

			// Common Bad User Agents
			'bad_ua' => array(
				'description' => 'Bad User Agent',
				'type'        => 'user_agent',
				'patterns'    => array(
					'wget', 'curl', 'libwww-perl', 'python', 'nikto', 
					'sqlmap', 'nmap', 'havij', 'netsparker', 'acunetix'
				),
			),
		);
	}

	/**
	 * Run all firewall checks.
	 */
	public function run_firewall() {
		// Apply settings (if present) and define rules.
		$this->apply_settings();
		$this->define_rules();
		if ( function_exists( 'add_action' ) ) {
			// Re-evaluate identity-aware access once WordPress auth context is available.
			add_action( 'init', array( $this, 'apply_identity_aware_rules' ), 0 );
		}

		// Skip for whitelisted IPs (configurable in settings).
		if ( $this->is_ip_whitelisted() ) {
			return;
		}

		// Apply identity-aware rules (Zero-Trust) before URL allowlist checks.
		// This ensures protected REST endpoints are still enforced.
		$this->apply_identity_aware_rules();

		// Skip for allowlisted URLs (admin AJAX, REST API, etc).
		if ( $this->is_url_allowlisted() ) {
			return;
		}

		// Skip very large payloads (performance protection).
		$max_body_size = 512 * 1024; // 512KB.
		$content_length = isset( $_SERVER['CONTENT_LENGTH'] ) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
		if ( $content_length > $max_body_size ) {
			if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
				NexifyMy_Security_Logger::log( 'waf_skip', 'Skipped: request too large', 'info', array( 'size' => $content_length ) );
			}
			return;
		}


		// Skip for logged-in admins in admin area.
		if ( function_exists( 'is_admin' ) && is_admin() && function_exists( 'current_user_can' ) && current_user_can( 'manage_options' ) ) {
			return;
		}

		$request_data = $this->get_request_data();
		$user_agent   = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';

		foreach ( $this->rules as $rule_key => $rule ) {
			// Skip disabled rules (from settings).
			if ( isset( $this->enabled_rules[ $rule_key ] ) && ! $this->enabled_rules[ $rule_key ] ) {
				continue;
			}

			// Handle User Agent Rules.
			if ( isset( $rule['type'] ) && $rule['type'] === 'user_agent' ) {
				foreach ( $rule['patterns'] as $pattern ) {
					if ( stripos( $user_agent, $pattern ) !== false ) {
						$this->block_request( $rule['description'] . ': ' . esc_html( $pattern ) );
					}
				}
				continue;
			}

			// Handle Regular Payload Rules - scan all collected data.
			$this->scan_data_recursive( $request_data, $rule );
		}
	}

	/**
	 * Apply WAF settings from the centralized settings option (if available).
	 */
	private function apply_settings() {
		$settings = get_option( 'nexifymy_security_settings', array() );

		// Module toggle.
		if ( isset( $settings['modules']['waf_enabled'] ) && ! $settings['modules']['waf_enabled'] ) {
			// Disable WAF entirely.
			$this->enabled_rules = array(
				'sqli'   => false,
				'xss'    => false,
				'fi'     => false,
				'bad_ua' => false,
			);
			return;
		}

		$waf = isset( $settings['waf'] ) && is_array( $settings['waf'] ) ? $settings['waf'] : array();

		$this->log_only_mode = ! empty( $waf['log_only_mode'] );
		$this->enabled_rules = array(
			'sqli'   => ! isset( $waf['block_sqli'] ) || (bool) $waf['block_sqli'],
			'xss'    => ! isset( $waf['block_xss'] ) || (bool) $waf['block_xss'],
			'fi'     => ! isset( $waf['block_lfi'] ) || (bool) $waf['block_lfi'],
			'bad_ua' => ! isset( $waf['block_bad_bots'] ) || (bool) $waf['block_bad_bots'],
		);
	}

	/**
	 * Apply identity-aware rules based on user risk scores (Zero-Trust).
	 * Blocks non-admin users with high risk from sensitive endpoints.
	 */
	public function apply_identity_aware_rules() {
		if ( ! function_exists( 'get_current_user_id' ) || ! function_exists( 'current_user_can' ) ) {
			return;
		}

		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';

		// Check if this is a protected endpoint.
		$is_protected = false;
		foreach ( $this->identity_aware_endpoints as $endpoint ) {
			if ( strpos( $request_uri, $endpoint ) !== false ) {
				$is_protected = true;
				break;
			}
		}

		if ( ! $is_protected ) {
			return;
		}

		// Get current user.
		$user_id = function_exists( 'get_current_user_id' ) ? get_current_user_id() : 0;

		// Anonymous users on protected endpoints = high risk.
		if ( ! $user_id ) {
			// Allow reading users endpoint for login discovery (common).
			if ( strpos( $request_uri, '/wp-json/wp/v2/users' ) !== false && isset( $_SERVER['REQUEST_METHOD'] ) && $_SERVER['REQUEST_METHOD'] === 'GET' ) {
				return; // Allow GET for user enumeration protection elsewhere.
			}
			$this->block_request( 'Identity-Aware: Unauthenticated access to protected endpoint' );
		}

		// Skip admins.
		if ( function_exists( 'current_user_can' ) && current_user_can( 'manage_options' ) ) {
			return;
		}

		// Get user risk score from AI threat detection.
		$risk_score = $this->get_user_risk_score( $user_id );

		// Block if risk score exceeds threshold.
		if ( $risk_score >= self::IDENTITY_RISK_THRESHOLD ) {
			if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
				NexifyMy_Security_Logger::log(
					'identity_aware_block',
					sprintf( 'Blocked high-risk user %d (score: %d) from %s', $user_id, $risk_score, $request_uri ),
					'warning',
					array(
						'user_id'    => $user_id,
						'risk_score' => $risk_score,
						'endpoint'   => $request_uri,
					)
				);
			}
			$this->block_request( sprintf( 'Identity-Aware: High risk score (%d) for protected endpoint', $risk_score ) );
		}
	}

	/**
	 * Get user risk score from AI threat detection module.
	 *
	 * @param int $user_id User ID.
	 * @return int Risk score (0-100).
	 */
	private function get_user_risk_score( $user_id ) {
		$ai_module = null;
		if ( isset( $GLOBALS['nexifymy_ai_detection'] ) ) {
			$ai_module = $GLOBALS['nexifymy_ai_detection'];
		} elseif ( isset( $GLOBALS['nexifymy_ai_threat'] ) ) {
			$ai_module = $GLOBALS['nexifymy_ai_threat'];
		}

		if ( $ai_module && method_exists( $ai_module, 'get_user_last_risk_score' ) ) {
			return (int) $ai_module->get_user_last_risk_score( $user_id );
		}
		return 0;
	}

	/**
	 * Recursively scan data for malicious patterns.
	 *
	 * @param mixed $data Data to scan.
	 * @param array $rule Rule to apply.
	 * @param string $key_path Current key path for logging.
	 */
	private function scan_data_recursive( $data, $rule, $key_path = '' ) {
		if ( is_array( $data ) ) {
			foreach ( $data as $key => $value ) {
				$new_path = $key_path ? $key_path . '[' . $key . ']' : $key;
				$this->scan_data_recursive( $value, $rule, $new_path );
			}
		} elseif ( is_string( $data ) ) {
			foreach ( $rule['patterns'] as $pattern ) {
				if ( preg_match( $pattern, $data ) ) {
					$this->block_request( $rule['description'], $key_path, $data );
				}
			}
		}
	}

	/**
	 * Check if current IP is whitelisted.
	 *
	 * @return bool
	 */
	private function is_ip_whitelisted() {
		$whitelist = get_option( 'nexifymy_security_ip_whitelist', array() );
		$client_ip = $this->get_client_ip();

		return in_array( $client_ip, (array) $whitelist, true );
	}

	/**
	 * Get the client IP address securely.
	 * Only trusts X-Forwarded-For/X-Real-IP if the direct requester is a configured trusted proxy.
	 *
	 * @return string
	 */
	private function get_client_ip() {
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( $_SERVER['REMOTE_ADDR'] ) : '';
		$trusted_proxies = get_option( 'nexifymy_security_trusted_proxies', array() );

		if ( $remote_addr && in_array( $remote_addr, (array) $trusted_proxies, true ) ) {
			if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
				$ips = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] );
				$client_ip = trim( $ips[0] );
				if ( filter_var( $client_ip, FILTER_VALIDATE_IP ) ) {
					return sanitize_text_field( $client_ip );
				}
			}
			if ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
				$client_ip = $_SERVER['HTTP_X_REAL_IP'];
				if ( filter_var( $client_ip, FILTER_VALIDATE_IP ) ) {
					return sanitize_text_field( $client_ip );
				}
			}
		}

		return $remote_addr;
	}

	/**
	 * Check if current URL is allowlisted (safe paths that shouldn't trigger WAF).
	 *
	 * @return bool
	 */
	private function is_url_allowlisted() {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';

		// Core WordPress safe paths.
		$safe_patterns = array(
			'/wp-admin/admin-ajax.php',
			'/wp-json/',
			'/wp-cron.php',
		);

		// Custom allowlist from settings.
		$custom_allowlist = get_option( 'nexifymy_security_waf_url_allowlist', array() );
		$safe_patterns = array_merge( $safe_patterns, (array) $custom_allowlist );

		foreach ( $safe_patterns as $pattern ) {
			if ( strpos( $request_uri, $pattern ) !== false ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Aggregate all request data for scanning.
	 * Includes: GET, POST, COOKIE, REQUEST_URI, QUERY_STRING, JSON body, and headers.
	 *
	 * @return array
	 */
	private function get_request_data() {
		$data = array();

		// Standard superglobals.
		$data = array_merge( $data, $_GET, $_POST, $_COOKIE );

		// REQUEST_URI and QUERY_STRING.
		if ( isset( $_SERVER['REQUEST_URI'] ) ) {
			$data['__request_uri'] = $_SERVER['REQUEST_URI'];
		}
		if ( isset( $_SERVER['QUERY_STRING'] ) ) {
			$data['__query_string'] = $_SERVER['QUERY_STRING'];
		}

		// JSON body (common in REST API attacks).
		$content_type = isset( $_SERVER['CONTENT_TYPE'] ) ? $_SERVER['CONTENT_TYPE'] : '';
		if ( strpos( $content_type, 'application/json' ) !== false ) {
			$json_input = file_get_contents( 'php://input' );
			if ( $json_input ) {
				$json_data = json_decode( $json_input, true );
				if ( is_array( $json_data ) ) {
					$data['__json_body'] = $json_data;
				}
			}
		}

		// Scan key headers that are often attack vectors.
		$headers_to_scan = array( 'HTTP_REFERER', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED_HOST' );
		foreach ( $headers_to_scan as $header ) {
			if ( isset( $_SERVER[ $header ] ) ) {
				$data[ '__header_' . strtolower( $header ) ] = $_SERVER[ $header ];
			}
		}

		return $data;
	}

	/**
	 * Block the request and exit.
	 *
	 * @param string $reason The reason for blocking.
	 * @param string $key The key that triggered the block (optional).
	 * @param string $value The value that triggered the block (optional).
	 */
	private function block_request( $reason, $key = '', $value = '' ) {
		// Log to database using our Logger class.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'waf_block',
				$reason,
				$this->log_only_mode ? 'warning' : 'critical',
				array(
					'key'         => $key,
					'value'       => substr( $value, 0, 200 ), // Truncate to avoid massive logs.
					'request_uri' => isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '',
				)
			);
		}

		if ( $this->log_only_mode ) {
			return;
		}

		// Send 403 Forbidden.
		status_header( 403 );
		nocache_headers();
		
		// Styled Block Page.
		$ip = esc_html( $_SERVER['REMOTE_ADDR'] );
		$reason_safe = esc_html( $reason );
		$block_css_url = esc_url( NEXIFYMY_SECURITY_URL . 'assets/css/firewall-block.css' );
		
		echo <<<HTML
<!DOCTYPE html>
<html>
<head>
	<title>Access Denied</title>
	<link rel="stylesheet" href="{$block_css_url}">
</head>
<body>
	<div class="block-container">
		<h1>Security Check</h1>
		<p>Your request was blocked by <strong>NexifyMy Security</strong> firewall because it triggered a security rule.</p>
		<p>If you believe this is a mistake, please contact the site administrator.</p>
		<div class="meta">
			Reason: $reason_safe<br>
			Your IP: $ip
		</div>
		<div class="footer">Protected by NexifyMy Security</div>
	</div>
</body>
</html>
HTML;
		exit;
	}
}
