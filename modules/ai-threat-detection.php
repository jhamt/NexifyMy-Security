<?php
/**
 * AI-Powered Threat Detection Module.
 * Uses behavioral analysis and statistical anomaly detection for zero-day threats.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_AI_Threat_Detection {

	/**
	 * Option key for learned behavior patterns.
	 */
	const PATTERNS_OPTION = 'nexifymy_ai_behavior_patterns';

	/**
	 * Option key for threat scores.
	 */
	const THREATS_OPTION = 'nexifymy_ai_detected_threats';

	/**
	 * Table name for behavior logs.
	 */
	private $behavior_table;

	/**
	 * Table name for user behavioral profiles (Zero-Trust).
	 */
	private $user_profiles_table;

	/**
	 * Session risk threshold for forced re-authentication.
	 */
	const SESSION_RISK_THRESHOLD = 60;

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'                => true,
		'learning_mode'          => true,
		'learning_period_days'   => 7,
		'anomaly_threshold'      => 75,      // Score above this = threat.
		'auto_block_threshold'   => 90,      // Score above this = auto-block.
		'track_login_behavior'   => true,
		'track_request_patterns' => true,
		'track_user_agents'      => true,
		'track_geo_patterns'     => true,
		'notify_on_anomaly'      => true,
		'session_risk_threshold' => 60,      // Force re-auth if risk > this.
	);

	/**
	 * Behavior weights for scoring.
	 */
	private $weights = array(
		'unusual_time'           => 15,
		'unusual_location'       => 20,
		'unusual_user_agent'     => 10,
		'rapid_requests'         => 25,
		'failed_logins'          => 20,
		'unusual_endpoint'       => 15,
		'payload_entropy'        => 20,
		'bot_signature'          => 25,
		'credential_stuffing'    => 30,
		'enumeration_attempt'    => 20,
		'unknown_ip_for_user'    => 25,
		'unusual_time_for_user'  => 15,
		'unknown_device'         => 20,
		'passkey_failure'        => 15,
		'passkey_success_bonus'  => -20,  // Reduces risk score.
	);

	/**
	 * Initialize the module.
	 */
	public function init() {
		global $wpdb;
		$this->behavior_table = $wpdb->prefix . 'nexifymy_behavior_log';
		$this->user_profiles_table = $wpdb->prefix . 'sentinel_user_profiles';

		$settings = $this->get_settings();

		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Create behavior table.
		add_action( 'init', array( $this, 'create_tables' ) );

		// Track behavior on every request.
		add_action( 'init', array( $this, 'analyze_request' ), 1 );

		// Track login attempts.
		if ( ! empty( $settings['track_login_behavior'] ) ) {
			add_action( 'wp_login', array( $this, 'record_successful_login' ), 10, 2 );
			add_action( 'wp_login_failed', array( $this, 'record_failed_login' ) );
		}

		// Schedule pattern learning.
		add_action( 'nexifymy_learn_patterns', array( $this, 'learn_patterns' ) );
		if ( ! wp_next_scheduled( 'nexifymy_learn_patterns' ) ) {
			wp_schedule_event( time(), 'hourly', 'nexifymy_learn_patterns' );
		}

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_get_ai_threats', array( $this, 'ajax_get_threats' ) );
		add_action( 'wp_ajax_nexifymy_get_ai_status', array( $this, 'ajax_get_status' ) );
		add_action( 'wp_ajax_nexifymy_reset_ai_learning', array( $this, 'ajax_reset_learning' ) );

		// Risk-based session control (Zero-Trust).
		add_action( 'admin_init', array( $this, 'monitor_session_risk' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			$settings = isset( $all_settings['ai_detection'] )
				? wp_parse_args( $all_settings['ai_detection'], self::$defaults )
				: self::$defaults;

			// Respect the global module toggle, if present.
			if ( isset( $all_settings['modules']['ai_detection_enabled'] ) && empty( $all_settings['modules']['ai_detection_enabled'] ) ) {
				$settings['enabled'] = false;
			}

			return $settings;
		}
		return self::$defaults;
	}

	/**
	 * Create database tables.
	 */
	public function create_tables() {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();

		// Behavior log table.
		$sql = "CREATE TABLE IF NOT EXISTS {$this->behavior_table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			ip_address VARCHAR(45) NOT NULL,
			user_id BIGINT(20) UNSIGNED DEFAULT 0,
			request_uri VARCHAR(500) NOT NULL,
			request_method VARCHAR(10) NOT NULL,
			user_agent VARCHAR(500) DEFAULT '',
			country_code VARCHAR(2) DEFAULT '',
			hour_of_day TINYINT(2) DEFAULT 0,
			day_of_week TINYINT(1) DEFAULT 0,
			payload_size INT(11) DEFAULT 0,
			response_code SMALLINT(3) DEFAULT 200,
			is_login_attempt TINYINT(1) DEFAULT 0,
			is_successful TINYINT(1) DEFAULT 1,
			threat_score TINYINT(3) DEFAULT 0,
			anomalies TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY ip_address (ip_address),
			KEY user_id (user_id),
			KEY created_at (created_at),
			KEY threat_score (threat_score)
		) $charset_collate;";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );

		// User behavioral profiles table (Zero-Trust).
		$sql_profiles = "CREATE TABLE IF NOT EXISTS {$this->user_profiles_table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id BIGINT(20) UNSIGNED NOT NULL,
			known_ips TEXT DEFAULT NULL,
			work_hours TEXT DEFAULT NULL,
			device_fingerprints TEXT DEFAULT NULL,
			typical_countries TEXT DEFAULT NULL,
			last_passkey_success DATETIME DEFAULT NULL,
			last_passkey_failure DATETIME DEFAULT NULL,
			passkey_failure_count INT(11) DEFAULT 0,
			avg_session_duration INT(11) DEFAULT 0,
			total_logins INT(11) DEFAULT 0,
			last_risk_score TINYINT(3) DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			UNIQUE KEY user_id (user_id),
			KEY last_risk_score (last_risk_score)
		) $charset_collate;";

		dbDelta( $sql_profiles );
	}

	/**
	 * Analyze incoming request for anomalies.
	 */
	public function analyze_request() {
		// Skip admin AJAX and cron.
		if ( wp_doing_ajax() || wp_doing_cron() ) {
			return;
		}

		$ip = $this->get_client_ip();
		$request_data = $this->collect_request_data( $ip );

		// Calculate threat score.
		$analysis = $this->analyze_behavior( $request_data );

		// Record behavior.
		$this->record_behavior( $request_data, $analysis );

		// Take action if threshold exceeded.
		$settings = $this->get_settings();

		if ( $analysis['score'] >= $settings['auto_block_threshold'] ) {
			$this->block_threat( $ip, $analysis );
		} elseif ( $analysis['score'] >= $settings['anomaly_threshold'] ) {
			$this->flag_anomaly( $ip, $analysis );
		}
	}

	/**
	 * Collect data about current request.
	 *
	 * @param string $ip Client IP.
	 * @return array Request data.
	 */
	private function collect_request_data( $ip ) {
		return array(
			'ip'             => $ip,
			'user_id'        => get_current_user_id(),
			'uri'            => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
			'method'         => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET',
			'user_agent'     => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
			'hour'           => (int) current_time( 'G' ),
			'day_of_week'    => (int) current_time( 'w' ),
			'payload_size'   => isset( $_SERVER['CONTENT_LENGTH'] ) ? (int) $_SERVER['CONTENT_LENGTH'] : 0,
			'country'        => $this->get_country_code( $ip ),
			'request_body'   => file_get_contents( 'php://input' ),
		);
	}

	/**
	 * Analyze behavior and calculate threat score.
	 *
	 * @param array $request_data Current request data.
	 * @return array Analysis results.
	 */
	private function analyze_behavior( $request_data ) {
		$score = 0;
		$anomalies = array();
		$patterns = $this->get_learned_patterns();

		// 1. Unusual time analysis.
		$time_score = $this->analyze_time_pattern( $request_data, $patterns );
		if ( $time_score > 0 ) {
			$score += $time_score;
			$anomalies[] = 'unusual_time';
		}

		// 2. Unusual location.
		$geo_score = $this->analyze_geo_pattern( $request_data, $patterns );
		if ( $geo_score > 0 ) {
			$score += $geo_score;
			$anomalies[] = 'unusual_location';
		}

		// 3. User agent analysis.
		$ua_score = $this->analyze_user_agent( $request_data );
		if ( $ua_score > 0 ) {
			$score += $ua_score;
			$anomalies[] = 'suspicious_user_agent';
		}

		// 4. Request rate analysis.
		$rate_score = $this->analyze_request_rate( $request_data['ip'] );
		if ( $rate_score > 0 ) {
			$score += $rate_score;
			$anomalies[] = 'rapid_requests';
		}

		// 5. Payload entropy (detect obfuscation).
		$entropy_score = $this->analyze_payload_entropy( $request_data['request_body'] );
		if ( $entropy_score > 0 ) {
			$score += $entropy_score;
			$anomalies[] = 'high_entropy_payload';
		}

		// 6. Enumeration detection.
		$enum_score = $this->detect_enumeration( $request_data );
		if ( $enum_score > 0 ) {
			$score += $enum_score;
			$anomalies[] = 'enumeration_attempt';
		}

		// 7. Bot signature detection.
		$bot_score = $this->detect_bot_behavior( $request_data );
		if ( $bot_score > 0 ) {
			$score += $bot_score;
			$anomalies[] = 'bot_behavior';
		}

		// 8. Failed login clustering.
		$login_score = $this->analyze_login_pattern( $request_data['ip'] );
		if ( $login_score > 0 ) {
			$score += $login_score;
			$anomalies[] = 'login_anomaly';
		}

		// Cap score at 100.
		$score = min( 100, $score );

		return array(
			'score'     => $score,
			'anomalies' => $anomalies,
			'risk_level'=> $this->score_to_risk_level( $score ),
		);
	}

	/**
	 * Analyze time-based patterns.
	 *
	 * @param array $request Request data.
	 * @param array $patterns Learned patterns.
	 * @return int Score contribution.
	 */
	private function analyze_time_pattern( $request, $patterns ) {
		if ( empty( $patterns['peak_hours'] ) ) {
			return 0;
		}

		$current_hour = $request['hour'];
		$peak_hours = $patterns['peak_hours'];

		// If request is at an unusual hour.
		if ( ! in_array( $current_hour, $peak_hours, true ) ) {
			// Night-time requests (1-5 AM) are more suspicious.
			if ( $current_hour >= 1 && $current_hour <= 5 ) {
				return $this->weights['unusual_time'];
			}
			return (int) ( $this->weights['unusual_time'] * 0.5 );
		}

		return 0;
	}

	/**
	 * Analyze geographic patterns.
	 *
	 * @param array $request Request data.
	 * @param array $patterns Learned patterns.
	 * @return int Score contribution.
	 */
	private function analyze_geo_pattern( $request, $patterns ) {
		if ( empty( $patterns['known_countries'] ) || empty( $request['country'] ) ) {
			return 0;
		}

		// Request from unknown country.
		if ( ! in_array( $request['country'], $patterns['known_countries'], true ) ) {
			return $this->weights['unusual_location'];
		}

		return 0;
	}

	/**
	 * Analyze user agent for suspicious patterns.
	 *
	 * @param array $request Request data.
	 * @return int Score contribution.
	 */
	private function analyze_user_agent( $request ) {
		$ua = strtolower( $request['user_agent'] );
		$score = 0;

		// Empty user agent.
		if ( empty( $ua ) ) {
			return $this->weights['bot_signature'];
		}

		// Known malicious patterns.
		$suspicious_patterns = array(
			'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab',
			'python-requests', 'go-http-client', 'curl/',
			'wget/', 'libwww-perl', 'httpclient',
		);

		foreach ( $suspicious_patterns as $pattern ) {
			if ( strpos( $ua, $pattern ) !== false ) {
				$score += $this->weights['bot_signature'];
				break;
			}
		}

		// Very short user agent.
		if ( strlen( $ua ) < 20 ) {
			$score += (int) ( $this->weights['unusual_user_agent'] * 0.5 );
		}

		return $score;
	}

	/**
	 * Analyze request rate for rapid fire attacks.
	 *
	 * @param string $ip Client IP.
	 * @return int Score contribution.
	 */
	private function analyze_request_rate( $ip ) {
		global $wpdb;

		$count = $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$this->behavior_table} 
			WHERE ip_address = %s AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)",
			$ip
		) );

		// More than 30 requests per minute is suspicious.
		if ( $count > 30 ) {
			return $this->weights['rapid_requests'];
		} elseif ( $count > 15 ) {
			return (int) ( $this->weights['rapid_requests'] * 0.5 );
		}

		return 0;
	}

	/**
	 * Analyze payload entropy to detect obfuscation.
	 *
	 * @param string $payload Request body.
	 * @return int Score contribution.
	 */
	private function analyze_payload_entropy( $payload ) {
		if ( empty( $payload ) || strlen( $payload ) < 50 ) {
			return 0;
		}

		$entropy = $this->calculate_entropy( $payload );

		// High entropy suggests encoding/obfuscation.
		if ( $entropy > 5.5 ) {
			return $this->weights['payload_entropy'];
		} elseif ( $entropy > 4.5 ) {
			return (int) ( $this->weights['payload_entropy'] * 0.5 );
		}

		return 0;
	}

	/**
	 * Calculate Shannon entropy of a string.
	 *
	 * @param string $data Input string.
	 * @return float Entropy value.
	 */
	private function calculate_entropy( $data ) {
		$frequencies = array();
		$length = strlen( $data );

		for ( $i = 0; $i < $length; $i++ ) {
			$char = $data[ $i ];
			if ( ! isset( $frequencies[ $char ] ) ) {
				$frequencies[ $char ] = 0;
			}
			$frequencies[ $char ]++;
		}

		$entropy = 0.0;
		foreach ( $frequencies as $count ) {
			$probability = $count / $length;
			$entropy -= $probability * log( $probability, 2 );
		}

		return $entropy;
	}

	/**
	 * Detect enumeration attempts.
	 *
	 * @param array $request Request data.
	 * @return int Score contribution.
	 */
	private function detect_enumeration( $request ) {
		$uri = $request['uri'];
		$score = 0;

		// User enumeration.
		if ( preg_match( '/\?author=\d+/', $uri ) ) {
			$score += $this->weights['enumeration_attempt'];
		}

		// REST API user enumeration.
		if ( strpos( $uri, '/wp-json/wp/v2/users' ) !== false ) {
			$score += $this->weights['enumeration_attempt'];
		}

		// Plugin/theme enumeration.
		if ( preg_match( '/wp-content\/(plugins|themes)\/[^\/]+\/(readme|changelog)/i', $uri ) ) {
			$score += (int) ( $this->weights['enumeration_attempt'] * 0.5 );
		}

		return $score;
	}

	/**
	 * Detect automated bot behavior.
	 *
	 * @param array $request Request data.
	 * @return int Score contribution.
	 */
	private function detect_bot_behavior( $request ) {
		$score = 0;

		// Check for missing common headers.
		$has_accept = ! empty( $_SERVER['HTTP_ACCEPT'] );
		$has_language = ! empty( $_SERVER['HTTP_ACCEPT_LANGUAGE'] );
		$has_encoding = ! empty( $_SERVER['HTTP_ACCEPT_ENCODING'] );

		// Real browsers send these headers.
		if ( ! $has_accept && ! $has_language ) {
			$score += (int) ( $this->weights['bot_signature'] * 0.5 );
		}

		// Check for sequential scanning patterns.
		global $wpdb;
		$recent_uris = $wpdb->get_col( $wpdb->prepare(
			"SELECT DISTINCT request_uri FROM {$this->behavior_table} 
			WHERE ip_address = %s AND created_at > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
			ORDER BY id DESC LIMIT 10",
			$request['ip']
		) );

		// Many unique URIs in short time = scanning.
		if ( count( $recent_uris ) >= 8 ) {
			$score += $this->weights['bot_signature'];
		}

		return $score;
	}

	/**
	 * Analyze login attempt patterns.
	 *
	 * @param string $ip Client IP.
	 * @return int Score contribution.
	 */
	private function analyze_login_pattern( $ip ) {
		global $wpdb;

		// Count failed logins in last 10 minutes.
		$failed = $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$this->behavior_table} 
			WHERE ip_address = %s 
			AND is_login_attempt = 1 
			AND is_successful = 0 
			AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)",
			$ip
		) );

		if ( $failed >= 5 ) {
			return $this->weights['credential_stuffing'];
		} elseif ( $failed >= 3 ) {
			return $this->weights['failed_logins'];
		}

		return 0;
	}

	/**
	 * Record behavior in database.
	 *
	 * @param array $request_data Request data.
	 * @param array $analysis Analysis results.
	 */
	private function record_behavior( $request_data, $analysis ) {
		global $wpdb;

		$wpdb->insert(
			$this->behavior_table,
			array(
				'ip_address'     => $request_data['ip'],
				'user_id'        => $request_data['user_id'],
				'request_uri'    => substr( $request_data['uri'], 0, 500 ),
				'request_method' => $request_data['method'],
				'user_agent'     => substr( $request_data['user_agent'], 0, 500 ),
				'country_code'   => $request_data['country'],
				'hour_of_day'    => $request_data['hour'],
				'day_of_week'    => $request_data['day_of_week'],
				'payload_size'   => $request_data['payload_size'],
				'threat_score'   => $analysis['score'],
				'anomalies'      => wp_json_encode( $analysis['anomalies'] ),
			),
			array( '%s', '%d', '%s', '%s', '%s', '%s', '%d', '%d', '%d', '%d', '%s' )
		);
	}

	/**
	 * Record successful login.
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user User object.
	 */
	public function record_successful_login( $user_login, $user ) {
		global $wpdb;

		$ip = $this->get_client_ip();
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$country = $this->get_country_code( $ip );

		// Calculate user-specific risk score BEFORE updating profile.
		$risk_analysis = $this->calculate_user_risk_score( $user->ID, $ip, $user_agent, $country );

		// Record in behavior log.
		$wpdb->insert(
			$this->behavior_table,
			array(
				'ip_address'      => $ip,
				'user_id'         => $user->ID,
				'request_uri'     => '/wp-login.php',
				'request_method'  => 'POST',
				'user_agent'      => $user_agent,
				'country_code'    => $country,
				'hour_of_day'     => (int) current_time( 'G' ),
				'day_of_week'     => (int) current_time( 'w' ),
				'is_login_attempt'=> 1,
				'is_successful'   => 1,
				'threat_score'    => $risk_analysis['score'],
				'anomalies'       => wp_json_encode( $risk_analysis['factors'] ),
			),
			array( '%s', '%d', '%s', '%s', '%s', '%s', '%d', '%d', '%d', '%d', '%d', '%s' )
		);

		// Update user profile with this login (learn from successful logins).
		$this->update_user_profile( $user->ID, $ip, $user_agent, $country );

		$settings = $this->get_settings();
		$threshold = isset( $settings['session_risk_threshold'] ) ? absint( $settings['session_risk_threshold'] ) : self::SESSION_RISK_THRESHOLD;
		$forced_reauth = isset( $_REQUEST['nexifymy_risk'] ) && '1' === sanitize_text_field( wp_unslash( $_REQUEST['nexifymy_risk'] ) );

		// Mark as verified after explicit re-auth flow to prevent redirect loops.
		if ( $forced_reauth ) {
			$this->mark_session_verified( $user->ID );
			return;
		}

		// Mark session as verified if risk is acceptable.
		if ( $risk_analysis['score'] < $threshold ) {
			$this->mark_session_verified( $user->ID );
		}
	}

	/**
	 * Record failed login.
	 *
	 * @param string $username Attempted username.
	 */
	public function record_failed_login( $username ) {
		global $wpdb;

		$wpdb->insert(
			$this->behavior_table,
			array(
				'ip_address'      => $this->get_client_ip(),
				'user_id'         => 0,
				'request_uri'     => '/wp-login.php',
				'request_method'  => 'POST',
				'user_agent'      => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
				'hour_of_day'     => (int) current_time( 'G' ),
				'day_of_week'     => (int) current_time( 'w' ),
				'is_login_attempt'=> 1,
				'is_successful'   => 0,
				'threat_score'    => 10,
			),
			array( '%s', '%d', '%s', '%s', '%s', '%d', '%d', '%d', '%d', '%d' )
		);
	}

	/**
	 * Learn normal behavior patterns.
	 */
	public function learn_patterns() {
		global $wpdb;

		$patterns = array();

		// Learn peak hours.
		$peak_hours = $wpdb->get_col(
			"SELECT hour_of_day FROM {$this->behavior_table} 
			WHERE threat_score < 30 AND created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
			GROUP BY hour_of_day
			HAVING COUNT(*) > 10
			ORDER BY COUNT(*) DESC
			LIMIT 12"
		);
		$patterns['peak_hours'] = array_map( 'intval', $peak_hours );

		// Learn known countries.
		$countries = $wpdb->get_col(
			"SELECT country_code FROM {$this->behavior_table} 
			WHERE threat_score < 30 AND country_code != '' 
			AND created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
			GROUP BY country_code
			HAVING COUNT(*) > 5"
		);
		$patterns['known_countries'] = $countries;

		// Learn common user agents.
		$user_agents = $wpdb->get_col(
			"SELECT SUBSTRING(user_agent, 1, 50) as ua_prefix FROM {$this->behavior_table} 
			WHERE threat_score < 30 AND user_agent != ''
			AND created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
			GROUP BY ua_prefix
			HAVING COUNT(*) > 5
			LIMIT 50"
		);
		$patterns['known_user_agents'] = $user_agents;

		// Store patterns.
		$patterns['last_learned'] = current_time( 'mysql' );
		update_option( self::PATTERNS_OPTION, $patterns, false );
	}

	/**
	 * Get learned patterns.
	 *
	 * @return array
	 */
	private function get_learned_patterns() {
		return get_option( self::PATTERNS_OPTION, array() );
	}

	/**
	 * Block detected threat.
	 *
	 * @param string $ip IP address.
	 * @param array  $analysis Analysis results.
	 */
	private function block_threat( $ip, $analysis ) {
		// Add to firewall blocklist.
		if ( isset( $GLOBALS['nexifymy_waf'] ) && method_exists( $GLOBALS['nexifymy_waf'], 'add_to_blocklist' ) ) {
			$GLOBALS['nexifymy_waf']->add_to_blocklist( $ip, 'AI Threat Detection: ' . implode( ', ', $analysis['anomalies'] ) );
		}

		// Log threat.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'ai_threat_blocked',
				sprintf( 'AI blocked threat from %s (Score: %d)', $ip, $analysis['score'] ),
				'critical',
				$analysis
			);
		}

		// Store threat record.
		$this->record_threat( $ip, $analysis );
	}

	/**
	 * Flag anomaly for review.
	 *
	 * @param string $ip IP address.
	 * @param array  $analysis Analysis results.
	 */
	private function flag_anomaly( $ip, $analysis ) {
		$threats = get_option( self::THREATS_OPTION, array() );

		$threats[] = array(
			'ip'        => $ip,
			'score'     => $analysis['score'],
			'anomalies' => $analysis['anomalies'],
			'flagged_at'=> current_time( 'mysql' ),
			'status'    => 'pending',
		);

		// Keep last 100 threats.
		$threats = array_slice( $threats, -100 );
		update_option( self::THREATS_OPTION, $threats, false );

		// Notify if enabled.
		$settings = $this->get_settings();
		if ( ! empty( $settings['notify_on_anomaly'] ) ) {
			$this->send_anomaly_notification( $ip, $analysis );
		}
	}

	/**
	 * Record threat in database.
	 *
	 * @param string $ip IP address.
	 * @param array  $analysis Analysis results.
	 */
	private function record_threat( $ip, $analysis ) {
		$threats = get_option( self::THREATS_OPTION, array() );

		$threats[] = array(
			'ip'         => $ip,
			'score'      => $analysis['score'],
			'anomalies'  => $analysis['anomalies'],
			'blocked_at' => current_time( 'mysql' ),
			'status'     => 'blocked',
		);

		$threats = array_slice( $threats, -100 );
		update_option( self::THREATS_OPTION, $threats, false );
	}

	/**
	 * Send anomaly notification.
	 *
	 * @param string $ip IP address.
	 * @param array  $analysis Analysis results.
	 */
	private function send_anomaly_notification( $ip, $analysis ) {
		$to = get_option( 'admin_email' );
		$subject = sprintf( '[%s] AI Threat Detection Alert', get_bloginfo( 'name' ) );

		$message = "AI-Powered Threat Detection Alert\n\n";
		$message .= sprintf( "Site: %s\n", home_url() );
		$message .= sprintf( "Time: %s\n\n", current_time( 'mysql' ) );
		$message .= sprintf( "Suspicious IP: %s\n", $ip );
		$message .= sprintf( "Threat Score: %d/100\n", $analysis['score'] );
		$message .= sprintf( "Risk Level: %s\n\n", $analysis['risk_level'] );
		$message .= "Detected Anomalies:\n";

		foreach ( $analysis['anomalies'] as $anomaly ) {
			$message .= "  - {$anomaly}\n";
		}

		$message .= "\nPlease review this activity in your security dashboard.";

		wp_mail( $to, $subject, $message );
	}

	/**
	 * Convert score to risk level.
	 *
	 * @param int $score Threat score.
	 * @return string Risk level.
	 */
	private function score_to_risk_level( $score ) {
		if ( $score >= 90 ) return 'critical';
		if ( $score >= 75 ) return 'high';
		if ( $score >= 50 ) return 'medium';
		if ( $score >= 25 ) return 'low';
		return 'minimal';
	}

	/**
	 * Get client IP address.
	 *
	 * @return string
	 */
	private function get_client_ip() {
		$ip_keys = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR' );

		foreach ( $ip_keys as $key ) {
			if ( ! empty( $_SERVER[ $key ] ) ) {
				$ip = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
				if ( strpos( $ip, ',' ) !== false ) {
					$ip = trim( explode( ',', $ip )[0] );
				}
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}

		return '0.0.0.0';
	}

	/**
	 * Get country code for IP.
	 *
	 * @param string $ip IP address.
	 * @return string Country code.
	 */
	private function get_country_code( $ip ) {
		// Use geo-blocking module if available.
		if ( isset( $GLOBALS['nexifymy_geo_blocking'] ) && method_exists( $GLOBALS['nexifymy_geo_blocking'], 'get_country' ) ) {
			return $GLOBALS['nexifymy_geo_blocking']->get_country( $ip );
		}
		return '';
	}

	/**
	 * Get AI detection status.
	 *
	 * @return array Status info.
	 */
	public function get_status() {
		global $wpdb;

		$patterns = $this->get_learned_patterns();
		$threats = get_option( self::THREATS_OPTION, array() );

		// Count behavior records.
		$total_records = $wpdb->get_var( "SELECT COUNT(*) FROM {$this->behavior_table}" );
		$threats_today = $wpdb->get_var(
			"SELECT COUNT(*) FROM {$this->behavior_table} 
			WHERE threat_score >= 75 AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)"
		);

		return array(
			'learning_status'  => empty( $patterns ) ? 'learning' : 'trained',
			'last_learned'     => $patterns['last_learned'] ?? null,
			'total_records'    => (int) $total_records,
			'known_countries'  => count( $patterns['known_countries'] ?? array() ),
			'peak_hours'       => $patterns['peak_hours'] ?? array(),
			'threats_today'    => (int) $threats_today,
			'recent_threats'   => array_slice( array_reverse( $threats ), 0, 10 ),
		);
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	public function ajax_get_threats() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}
		wp_send_json_success( get_option( self::THREATS_OPTION, array() ) );
	}

	public function ajax_get_status() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}
		wp_send_json_success( $this->get_status() );
	}

	public function ajax_reset_learning() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		delete_option( self::PATTERNS_OPTION );
		global $wpdb;
		$wpdb->query( "TRUNCATE TABLE {$this->behavior_table}" );

		wp_send_json_success( array( 'message' => 'AI learning reset successfully.' ) );
	}

	/*
	 * =========================================================================
	 * USER-SPECIFIC BEHAVIORAL PROFILING (ZERO-TRUST)
	 * =========================================================================
	 */

	/**
	 * Get user behavioral profile.
	 *
	 * @param int $user_id User ID.
	 * @return array|null Profile data or null if not found.
	 */
	public function get_user_profile( $user_id ) {
		global $wpdb;

		$profile = $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM {$this->user_profiles_table} WHERE user_id = %d",
			$user_id
		), ARRAY_A );

		if ( $profile ) {
			$profile['known_ips'] = json_decode( $profile['known_ips'], true ) ?: array();
			$profile['work_hours'] = json_decode( $profile['work_hours'], true ) ?: array();
			$profile['device_fingerprints'] = json_decode( $profile['device_fingerprints'], true ) ?: array();
			$profile['typical_countries'] = json_decode( $profile['typical_countries'], true ) ?: array();
		}

		return $profile;
	}

	/**
	 * Update user behavioral profile after successful login.
	 *
	 * @param int    $user_id User ID.
	 * @param string $ip IP address.
	 * @param string $user_agent User agent string.
	 * @param string $country Country code.
	 */
	public function update_user_profile( $user_id, $ip, $user_agent, $country = '' ) {
		global $wpdb;

		$profile = $this->get_user_profile( $user_id );
		$current_hour = (int) current_time( 'G' );
		$fingerprint = $this->generate_device_fingerprint( $user_agent );

		if ( ! $profile ) {
			// Create new profile.
			$wpdb->insert(
				$this->user_profiles_table,
				array(
					'user_id'             => $user_id,
					'known_ips'           => wp_json_encode( array( $ip => 1 ) ),
					'work_hours'          => wp_json_encode( array( $current_hour => 1 ) ),
					'device_fingerprints' => wp_json_encode( array( $fingerprint => 1 ) ),
					'typical_countries'   => $country ? wp_json_encode( array( $country => 1 ) ) : '[]',
					'total_logins'        => 1,
				),
				array( '%d', '%s', '%s', '%s', '%s', '%d' )
			);
		} else {
			// Update existing profile.
			$known_ips = $profile['known_ips'];
			$known_ips[ $ip ] = ( $known_ips[ $ip ] ?? 0 ) + 1;
			// Keep only top 20 IPs.
			arsort( $known_ips );
			$known_ips = array_slice( $known_ips, 0, 20, true );

			$work_hours = $profile['work_hours'];
			$work_hours[ $current_hour ] = ( $work_hours[ $current_hour ] ?? 0 ) + 1;

			$fingerprints = $profile['device_fingerprints'];
			$fingerprints[ $fingerprint ] = ( $fingerprints[ $fingerprint ] ?? 0 ) + 1;
			arsort( $fingerprints );
			$fingerprints = array_slice( $fingerprints, 0, 10, true );

			$countries = $profile['typical_countries'];
			if ( $country ) {
				$countries[ $country ] = ( $countries[ $country ] ?? 0 ) + 1;
			}

			$wpdb->update(
				$this->user_profiles_table,
				array(
					'known_ips'           => wp_json_encode( $known_ips ),
					'work_hours'          => wp_json_encode( $work_hours ),
					'device_fingerprints' => wp_json_encode( $fingerprints ),
					'typical_countries'   => wp_json_encode( $countries ),
					'total_logins'        => $profile['total_logins'] + 1,
				),
				array( 'user_id' => $user_id ),
				array( '%s', '%s', '%s', '%s', '%d' ),
				array( '%d' )
			);
		}
	}

	/**
	 * Calculate user-specific risk score for login.
	 *
	 * @param int    $user_id User ID.
	 * @param string $ip IP address.
	 * @param string $user_agent User agent string.
	 * @param string $country Country code.
	 * @return array Risk analysis with score and factors.
	 */
	public function calculate_user_risk_score( $user_id, $ip, $user_agent, $country = '' ) {
		$profile = $this->get_user_profile( $user_id );
		$score = 0;
		$factors = array();
		$current_hour = (int) current_time( 'G' );
		$fingerprint = $this->generate_device_fingerprint( $user_agent );

		// No profile = new user, minimal risk adjustment.
		if ( ! $profile || $profile['total_logins'] < 3 ) {
			return array(
				'score'   => 0,
				'factors' => array( 'new_user_profile' ),
				'risk_level' => 'minimal',
			);
		}

		// 1. Check if IP is known for this user.
		if ( ! isset( $profile['known_ips'][ $ip ] ) ) {
			$score += $this->weights['unknown_ip_for_user'];
			$factors[] = 'unknown_ip_for_user';
		}

		// 2. Check if current hour is typical for this user.
		$total_hour_logins = array_sum( $profile['work_hours'] );
		$hour_frequency = ( $profile['work_hours'][ $current_hour ] ?? 0 ) / max( 1, $total_hour_logins );
		if ( $hour_frequency < 0.05 ) { // Less than 5% of logins at this hour.
			$score += $this->weights['unusual_time_for_user'];
			$factors[] = 'unusual_time_for_user';
		}

		// 3. Check device fingerprint.
		if ( ! isset( $profile['device_fingerprints'][ $fingerprint ] ) ) {
			$score += $this->weights['unknown_device'];
			$factors[] = 'unknown_device';
		}

		// 4. Apply passkey bonus/penalty.
		if ( $profile['last_passkey_success'] && strtotime( $profile['last_passkey_success'] ) > strtotime( '-30 minutes' ) ) {
			$score += $this->weights['passkey_success_bonus']; // Negative = reduces score.
			$factors[] = 'recent_passkey_success';
		}
		if ( $profile['passkey_failure_count'] > 3 ) {
			$score += $this->weights['passkey_failure'] * min( 3, $profile['passkey_failure_count'] - 3 );
			$factors[] = 'multiple_passkey_failures';
		}

		// Cap score at 100, floor at 0.
		$score = max( 0, min( 100, $score ) );

		// Store last risk score.
		global $wpdb;
		$wpdb->update(
			$this->user_profiles_table,
			array( 'last_risk_score' => $score ),
			array( 'user_id' => $user_id ),
			array( '%d' ),
			array( '%d' )
		);

		return array(
			'score'      => $score,
			'factors'    => $factors,
			'risk_level' => $this->score_to_risk_level( $score ),
		);
	}

	/**
	 * Get user's last calculated risk score.
	 *
	 * @param int $user_id User ID.
	 * @return int Risk score (0-100).
	 */
	public function get_user_last_risk_score( $user_id ) {
		$profile = $this->get_user_profile( $user_id );
		return $profile ? (int) $profile['last_risk_score'] : 0;
	}

	/**
	 * Generate device fingerprint from user agent.
	 *
	 * @param string $user_agent User agent string.
	 * @return string Device fingerprint hash.
	 */
	private function generate_device_fingerprint( $user_agent ) {
		// Extract key identifiers from user agent.
		$ua = strtolower( $user_agent );
		$parts = array();

		// Browser family.
		if ( strpos( $ua, 'firefox' ) !== false ) {
			$parts[] = 'firefox';
		} elseif ( strpos( $ua, 'edg' ) !== false ) {
			$parts[] = 'edge';
		} elseif ( strpos( $ua, 'chrome' ) !== false ) {
			$parts[] = 'chrome';
		} elseif ( strpos( $ua, 'safari' ) !== false ) {
			$parts[] = 'safari';
		} else {
			$parts[] = 'other';
		}

		// OS family.
		if ( strpos( $ua, 'windows' ) !== false ) {
			$parts[] = 'windows';
		} elseif ( strpos( $ua, 'mac' ) !== false ) {
			$parts[] = 'mac';
		} elseif ( strpos( $ua, 'linux' ) !== false ) {
			$parts[] = 'linux';
		} elseif ( strpos( $ua, 'android' ) !== false ) {
			$parts[] = 'android';
		} elseif ( strpos( $ua, 'iphone' ) !== false || strpos( $ua, 'ipad' ) !== false ) {
			$parts[] = 'ios';
		} else {
			$parts[] = 'unknown';
		}

		return md5( implode( '|', $parts ) );
	}

	/*
	 * =========================================================================
	 * PASSKEY INTEGRATION
	 * =========================================================================
	 */

	/**
	 * Record passkey authentication event.
	 *
	 * @param string $event 'success' or 'failure'.
	 * @param int    $user_id User ID.
	 */
	public function record_passkey_event( $event, $user_id ) {
		global $wpdb;

		$profile = $this->get_user_profile( $user_id );

		if ( ! $profile ) {
			// Create minimal profile.
			$wpdb->insert(
				$this->user_profiles_table,
				array(
					'user_id'              => $user_id,
					'last_passkey_success' => $event === 'success' ? current_time( 'mysql' ) : null,
					'last_passkey_failure' => $event === 'failure' ? current_time( 'mysql' ) : null,
					'passkey_failure_count'=> $event === 'failure' ? 1 : 0,
				),
				array( '%d', '%s', '%s', '%d' )
			);
			return;
		}

		if ( $event === 'success' ) {
			$wpdb->update(
				$this->user_profiles_table,
				array(
					'last_passkey_success'  => current_time( 'mysql' ),
					'passkey_failure_count' => 0, // Reset failures on success.
				),
				array( 'user_id' => $user_id ),
				array( '%s', '%d' ),
				array( '%d' )
			);
		} else {
			$wpdb->update(
				$this->user_profiles_table,
				array(
					'last_passkey_failure'  => current_time( 'mysql' ),
					'passkey_failure_count' => $profile['passkey_failure_count'] + 1,
				),
				array( 'user_id' => $user_id ),
				array( '%s', '%d' ),
				array( '%d' )
			);
		}

		// Log the event.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'passkey_' . $event,
				sprintf( 'Passkey %s for user ID %d', $event, $user_id ),
				$event === 'failure' ? 'warning' : 'info'
			);
		}
	}

	/*
	 * =========================================================================
	 * RISK-BASED SESSION CONTROL
	 * =========================================================================
	 */

	/**
	 * Monitor session risk and force re-auth if needed.
	 */
	public function monitor_session_risk() {
		if ( ! is_user_logged_in() ) {
			return;
		}

		$user_id = get_current_user_id();
		$settings = $this->get_settings();
		$threshold = isset( $settings['session_risk_threshold'] ) ? absint( $settings['session_risk_threshold'] ) : self::SESSION_RISK_THRESHOLD;
		$threshold = max( 1, min( 100, $threshold ) );

		// Get last risk score.
		$risk_score = $this->get_user_last_risk_score( $user_id );

		// Check if user has already re-authenticated this session.
		$reauth_token = get_user_meta( $user_id, '_nexifymy_reauth_token', true );
		$session_token = wp_get_session_token();

		if ( $reauth_token === $session_token ) {
			return; // Already re-authenticated for this session.
		}

		// Force re-auth if risk is high.
		if ( $risk_score >= $threshold ) {
			$this->force_reauth( $user_id, $risk_score );
		}
	}

	/**
	 * Force user to re-authenticate.
	 *
	 * @param int $user_id User ID.
	 * @param int $risk_score Current risk score.
	 */
	private function force_reauth( $user_id, $risk_score ) {
		// Skip for AJAX requests.
		if ( wp_doing_ajax() ) {
			return;
		}

		// Log the forced re-auth.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'forced_reauth',
				sprintf( 'Forced re-authentication for user %d (risk score: %d)', $user_id, $risk_score ),
				'warning'
			);
		}

		// Redirect to login with reauth flag.
		$redirect_to = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : admin_url();

		wp_redirect( add_query_arg( array(
			'reauth'       => '1',
			'nexifymy_risk'=> '1',
			'redirect_to'  => urlencode( $redirect_to ),
		), wp_login_url() ) );
		exit;
	}

	/**
	 * Mark session as verified after successful re-auth.
	 *
	 * @param int $user_id User ID.
	 */
	public function mark_session_verified( $user_id ) {
		$session_token = wp_get_session_token();
		update_user_meta( $user_id, '_nexifymy_reauth_token', $session_token );
	}
}
