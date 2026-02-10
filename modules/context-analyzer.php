<?php
/**
 * Context Analyzer Module.
 * Analyzes code context around pattern matches to reduce false positives.
 * Checks for sanitization, user input sources, safe namespaces, and location risk.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Context_Analyzer {

	/**
	 * Context extraction - lines before/after match.
	 */
	const CONTEXT_LINES = 5;

	/**
	 * Location risk scores by directory pattern.
	 *
	 * @var array
	 */
	private $location_risk_map = array(
		// High risk zones
		'wp-content/uploads/'        => 40,
		'wp-content/cache/'          => 35,
		'wp-content/upgrade/'        => 30,

		// Medium risk zones
		'wp-content/plugins/[^/]+/$' => 10, // Root of plugin directory

		// Safe zones (negative scores = reduce confidence)
		'wp-includes/'               => -25,
		'wp-admin/'                  => -25,
		'vendor/'                    => -25,
		'node_modules/'              => -30,
		'/wp-cli/'                   => -40,
		'/tests?/'                   => -35,
	);

	/**
	 * Sanitization function patterns (presence reduces confidence).
	 *
	 * @var array
	 */
	private $sanitization_patterns = array(
		'escapeshellarg' => -25,
		'escapeshellcmd' => -25,
		'esc_sql'        => -20,
		'esc_html'       => -15,
		'esc_attr'       => -15,
		'esc_url'        => -15,
		'sanitize_'      => -20,
		'wp_kses'        => -20,
		'intval'         => -10,
		'absint'         => -10,
	);

	/**
	 * Dangerous input source patterns (presence increases confidence).
	 *
	 * @var array
	 */
	private $dangerous_input_patterns = array(
		'$_GET'     => 35,
		'$_POST'    => 35,
		'$_REQUEST' => 35,
		'$_COOKIE'  => 25,
		'$_SERVER'  => 15,
	);

	/**
	 * Safe namespace patterns (presence forces CLEAN or reduces confidence dramatically).
	 *
	 * @var array
	 */
	private $safe_namespace_patterns = array(
		'WP_CLI::'         => -100, // Force CLEAN
		'namespace WP_CLI' => -100, // Force CLEAN
		'class WP_CLI'     => -100, // Force CLEAN
		'Composer\\'       => -50,
		'use PHPUnit'      => -50,
		'namespace Tests'  => -50,
	);

	/**
	 * Analyze code context around a pattern match.
	 *
	 * @param array  $rule           The detection rule.
	 * @param string $filepath       File path.
	 * @param string $file_content   Full file content.
	 * @param string $matched_content The matched pattern content.
	 * @return array Context analysis with confidence modifier and metadata.
	 */
	public function analyze_code_context( $rule, $filepath, $file_content, $matched_content ) {
		$context_data = array(
			'confidence_modifier'      => 0,
			'context_summary'          => array(),
			'suggested_classification' => null,
			'is_safe_context'          => false,
			'has_sanitization'         => false,
			'has_user_input'           => false,
			'location_risk'            => 0,
		);

		// Extract surrounding code context
		$surrounding_code = $this->extract_surrounding_code( $file_content, $matched_content );

		// Check for safe namespaces (highest priority)
		$namespace_check = $this->check_safe_namespaces( $surrounding_code );
		if ( $namespace_check['is_safe'] ) {
			$context_data['confidence_modifier']      = $namespace_check['modifier'];
			$context_data['suggested_classification'] = NexifyMy_Security_Scanner::CLASSIFICATION_CLEAN;
			$context_data['is_safe_context']          = true;
			$context_data['context_summary'][]        = $namespace_check['reason'];
			return $context_data; // Early return - force CLEAN
		}

		// Check for sanitization functions
		$sanitization_check = $this->check_sanitization( $surrounding_code );
		if ( $sanitization_check['has_sanitization'] ) {
			$context_data['confidence_modifier'] += $sanitization_check['modifier'];
			$context_data['has_sanitization']     = true;
			$context_data['context_summary'][]    = $sanitization_check['reason'];
		}

		// Check for dangerous user input
		$input_check = $this->check_user_input( $surrounding_code );
		if ( $input_check['has_user_input'] ) {
			$context_data['confidence_modifier'] += $input_check['modifier'];
			$context_data['has_user_input']       = true;
			$context_data['context_summary'][]    = $input_check['reason'];
		}

		// Apply rule-specific context rules
		if ( isset( $rule['context_rules'] ) ) {
			$rule_context                         = $this->apply_rule_context_rules( $rule['context_rules'], $filepath, $surrounding_code );
			$context_data['confidence_modifier'] += $rule_context['modifier'];
			$context_data['context_summary']      = array_merge( $context_data['context_summary'], $rule_context['summary'] );
		}

		// Calculate location risk
		$location_risk                        = $this->calculate_location_risk( $filepath );
		$context_data['confidence_modifier'] += $location_risk['modifier'];
		$context_data['location_risk']        = $location_risk['risk_score'];
		if ( ! empty( $location_risk['reason'] ) ) {
			$context_data['context_summary'][] = $location_risk['reason'];
		}

		return $context_data;
	}

	/**
	 * Extract surrounding code around a pattern match.
	 *
	 * @param string $file_content   Full file content.
	 * @param string $matched_content The matched content.
	 * @return string Surrounding code (5 lines before/after).
	 */
	private function extract_surrounding_code( $file_content, $matched_content ) {
		// Find position of matched content
		$pos = strpos( $file_content, $matched_content );
		if ( $pos === false ) {
			return $file_content; // Fallback to full content
		}

		// Split content into lines
		$lines = explode( "\n", $file_content );

		// Find line number of match
		$match_line = substr_count( substr( $file_content, 0, $pos ), "\n" );

		// Extract context lines
		$start_line = max( 0, $match_line - self::CONTEXT_LINES );
		$end_line   = min( count( $lines ) - 1, $match_line + self::CONTEXT_LINES );

		$context_lines = array_slice( $lines, $start_line, $end_line - $start_line + 1 );

		return implode( "\n", $context_lines );
	}

	/**
	 * Check for safe namespace patterns (WP-CLI, Composer, tests, etc.).
	 *
	 * @param string $code Code context.
	 * @return array Result with is_safe, modifier, reason.
	 */
	private function check_safe_namespaces( $code ) {
		foreach ( $this->safe_namespace_patterns as $pattern => $modifier ) {
			if ( stripos( $code, $pattern ) !== false ) {
				return array(
					'is_safe'  => true,
					'modifier' => $modifier,
					'reason'   => sprintf( 'Found in safe namespace: %s', $pattern ),
				);
			}
		}

		return array(
			'is_safe'  => false,
			'modifier' => 0,
			'reason'   => '',
		);
	}

	/**
	 * Check for sanitization functions in context.
	 *
	 * @param string $code Code context.
	 * @return array Result with has_sanitization, modifier, reason.
	 */
	private function check_sanitization( $code ) {
		$total_modifier  = 0;
		$found_functions = array();

		foreach ( $this->sanitization_patterns as $pattern => $modifier ) {
			if ( stripos( $code, $pattern ) !== false ) {
				$total_modifier   += $modifier;
				$found_functions[] = $pattern;
			}
		}

		if ( ! empty( $found_functions ) ) {
			return array(
				'has_sanitization' => true,
				'modifier'         => $total_modifier,
				'reason'           => sprintf( 'Sanitization detected: %s', implode( ', ', $found_functions ) ),
			);
		}

		return array(
			'has_sanitization' => false,
			'modifier'         => 0,
			'reason'           => '',
		);
	}

	/**
	 * Check for user input sources in context.
	 *
	 * @param string $code Code context.
	 * @return array Result with has_user_input, modifier, reason.
	 */
	private function check_user_input( $code ) {
		$total_modifier = 0;
		$found_inputs   = array();

		foreach ( $this->dangerous_input_patterns as $pattern => $modifier ) {
			if ( stripos( $code, $pattern ) !== false ) {
				$total_modifier += $modifier;
				$found_inputs[]  = $pattern;
			}
		}

		if ( ! empty( $found_inputs ) ) {
			return array(
				'has_user_input' => true,
				'modifier'       => $total_modifier,
				'reason'         => sprintf( 'User input detected: %s', implode( ', ', $found_inputs ) ),
			);
		}

		return array(
			'has_user_input' => false,
			'modifier'       => 0,
			'reason'         => '',
		);
	}

	/**
	 * Apply rule-specific context rules.
	 *
	 * @param array  $context_rules Rule context rules.
	 * @param string $filepath      File path.
	 * @param string $code          Code context.
	 * @return array Result with modifier and summary.
	 */
	private function apply_rule_context_rules( $context_rules, $filepath, $code ) {
		$total_modifier = 0;
		$summary        = array();

		// Apply safe context rules
		if ( isset( $context_rules['safe_contexts'] ) && is_array( $context_rules['safe_contexts'] ) ) {
			foreach ( $context_rules['safe_contexts'] as $pattern => $modifier ) {
				if ( preg_match( $pattern, $filepath ) || preg_match( $pattern, $code ) ) {
					$total_modifier += $modifier;
					$summary[]       = sprintf( 'Safe context: %s', trim( $pattern, '/' ) );
				}
			}
		}

		// Apply dangerous context rules
		if ( isset( $context_rules['dangerous_contexts'] ) && is_array( $context_rules['dangerous_contexts'] ) ) {
			foreach ( $context_rules['dangerous_contexts'] as $pattern => $modifier ) {
				if ( preg_match( $pattern, $filepath ) || preg_match( $pattern, $code ) ) {
					$total_modifier += $modifier;
					$summary[]       = sprintf( 'Dangerous context: %s', trim( $pattern, '/' ) );
				}
			}
		}

		return array(
			'modifier' => $total_modifier,
			'summary'  => $summary,
		);
	}

	/**
	 * Calculate location-based risk score.
	 *
	 * @param string $filepath File path.
	 * @return array Result with modifier, risk_score, reason.
	 */
	public function calculate_location_risk( $filepath ) {
		$relative_path = str_replace( ABSPATH, '', $filepath );
		$risk_score    = 0;
		$reason        = '';

		// Check location patterns
		foreach ( $this->location_risk_map as $pattern => $score ) {
			// Handle regex patterns (ending with $)
			if ( substr( $pattern, -1 ) === '$' ) {
				if ( preg_match( '/' . preg_quote( rtrim( $pattern, '$' ), '/' ) . '$/i', $relative_path ) ) {
					$risk_score = $score;
					$reason     = sprintf( 'Location risk: %s', trim( $pattern, '$/i' ) );
					break;
				}
			} else {
				// Simple string match
				if ( stripos( $relative_path, $pattern ) !== false ) {
					$risk_score = $score;
					if ( $score > 0 ) {
						$reason = sprintf( 'High-risk location: %s', $pattern );
					} else {
						$reason = sprintf( 'Safe location: %s', $pattern );
					}
					break;
				}
			}
		}

		// Extra penalty for executable PHP files in uploads directory
		if ( stripos( $relative_path, 'wp-content/uploads/' ) !== false &&
			pathinfo( $filepath, PATHINFO_EXTENSION ) === 'php' ) {
			$risk_score += 20; // Additional penalty
			$reason      = 'CRITICAL: Executable PHP file in uploads directory';
		}

		return array(
			'modifier'   => $risk_score,
			'risk_score' => abs( $risk_score ),
			'reason'     => $reason,
		);
	}

	/**
	 * Check if file matches WordPress core file path pattern.
	 *
	 * @param string $filepath File path.
	 * @return bool
	 */
	public function is_wordpress_core_file( $filepath ) {
		$relative_path = str_replace( ABSPATH, '', $filepath );

		$core_patterns = array(
			'wp-includes/',
			'wp-admin/',
			'wp-content/themes/twenty', // Default themes
		);

		foreach ( $core_patterns as $pattern ) {
			if ( stripos( $relative_path, $pattern ) === 0 ) {
				return true;
			}
		}

		// Check root files
		$core_root_files = array(
			'index.php',
			'wp-activate.php',
			'wp-blog-header.php',
			'wp-comments-post.php',
			'wp-config-sample.php',
			'wp-cron.php',
			'wp-links-opml.php',
			'wp-load.php',
			'wp-login.php',
			'wp-mail.php',
			'wp-settings.php',
			'wp-signup.php',
			'wp-trackback.php',
			'xmlrpc.php',
		);

		$filename = basename( $filepath );
		return in_array( $filename, $core_root_files, true );
	}

	/**
	 * Get file age in days.
	 *
	 * @param string $filepath File path.
	 * @return int Age in days.
	 */
	public function get_file_age_days( $filepath ) {
		if ( ! file_exists( $filepath ) ) {
			return 0;
		}

		$mtime       = filemtime( $filepath );
		$age_seconds = time() - $mtime;
		return (int) floor( $age_seconds / 86400 );
	}

	/**
	 * Check if file was recently modified (< 7 days).
	 *
	 * @param string $filepath File path.
	 * @return array Result with modifier and reason.
	 */
	public function check_recent_modification( $filepath ) {
		$age_days = $this->get_file_age_days( $filepath );

		if ( $age_days <= 7 ) {
			return array(
				'is_recent' => true,
				'modifier'  => 10,
				'reason'    => sprintf( 'Recently modified (%d days ago)', $age_days ),
			);
		}

		return array(
			'is_recent' => false,
			'modifier'  => 0,
			'reason'    => '',
		);
	}
}
