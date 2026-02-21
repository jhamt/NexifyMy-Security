<?php
/**
 * AI Threat Detection Module.
 *
 * Provides behavioral analysis with weighted risk factors, user profiling,
 * Zero-Trust continuous authentication, insider threat detection, and
 * data exfiltration monitoring.
 *
 * @package NexifyMy_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * AI Threat Detection class.
 *
 * Provides behavioral analysis, insider threat detection,
 * data exfiltration monitoring, and continuous authentication.
 */
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
	 * Option key that tracks AI schema version.
	 */
	const SCHEMA_OPTION = 'nexifymy_ai_schema_version';

	/**
	 * Current AI schema version.
	 */
	const SCHEMA_VERSION = '1.0.0';

	/**
	 * Table name for behavior logs.
	 *
	 * @var string
	 */
	private $behavior_table;

	/**
	 * Table name for user behavioral profiles (Zero-Trust).
	 *
	 * @var string
	 */
	private $user_profiles_table;

	/**
	 * Table name for insider threat events.
	 *
	 * @var string
	 */
	private $insider_events_table;

	/**
	 * Table name for data exfiltration log.
	 *
	 * @var string
	 */
	private $exfiltration_log_table;

	/**
	 * Session risk threshold for forced re-authentication.
	 *
	 * @var int
	 */
	const SESSION_RISK_THRESHOLD = 60;

	/**
	 * Default settings.
	 *
	 * @var array<string, mixed>
	 */
	private static $defaults = array(
		'enabled'                         => true,
		'learning_mode'                   => true,
		'learning_period_days'            => 7,
		'anomaly_threshold'               => 75,      // Score above this = threat.
		'auto_block_threshold'            => 90,      // Score above this = auto-block.
		'track_login_behavior'            => true,
		'track_request_patterns'          => true,
		'track_user_agents'               => true,
		'track_geo_patterns'              => true,
		'notify_on_anomaly'               => true,
		'session_risk_threshold'          => 60,      // Force re-auth if risk > this.
		'zero_trust_reauth_interval'      => 900,  // 15 minutes between risk re-checks.
		'zero_trust_risk_spike_threshold' => 20,  // Risk increase that triggers re-auth.
		'insider_threat_enabled'          => true,
		'insider_threat_threshold'        => 60,
		'data_exfiltration_enabled'       => true,
		'exfiltration_threshold'          => 60,
		'exfiltration_baseline_days'      => 30,
	);

	/**
	 * Behavior weights for scoring.
	 *
	 * @var array<string, int>
	 */
	private $weights = array(
		'unusual_time'                => 15,
		'unusual_location'            => 20,
		'unusual_user_agent'          => 10,
		'rapid_requests'              => 25,
		'failed_logins'               => 20,
		'unusual_endpoint'            => 15,
		'payload_entropy'             => 20,
		'bot_signature'               => 25,
		'credential_stuffing'         => 30,
		'enumeration_attempt'         => 20,
		'unknown_ip_for_user'         => 25,
		'unusual_time_for_user'       => 15,
		'unknown_device'              => 20,
		'passkey_failure'             => 15,
		'passkey_success_bonus'       => -20,  // Reduces risk score.
		'insider_bulk_delete'         => 30,
		'insider_db_export'           => 35,
		'insider_create_admin'        => 40,
		'insider_disable_security'    => 40,
		'insider_install_plugin'      => 25,
		'exfiltration_export'         => 30,
		'exfiltration_large_download' => 25,
		'exfiltration_api_bulk'       => 20,
	);

	/**
	 * Initialize the module.
	 */
	public function init() {
		global $wpdb;
		$this->behavior_table         = $wpdb->prefix . 'nexifymy_behavior_log';
		$this->user_profiles_table    = $wpdb->prefix . 'sentinel_user_profiles';
		$this->insider_events_table   = $wpdb->prefix . 'nexifymy_insider_events';
		$this->exfiltration_log_table = $wpdb->prefix . 'nexifymy_exfiltration_log';

		$settings = $this->get_settings();

		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Ensure schema is created once without running dbDelta on every request.
		$this->maybe_ensure_schema();

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

		// Continuous authentication via session validation.
		add_filter( 'determine_current_user', array( $this, 'continuous_auth_check' ), 99 );

		// Insider threat detection hooks.
		if ( ! empty( $settings['insider_threat_enabled'] ) ) {
			add_action( 'before_delete_post', array( $this, 'track_post_deletion' ) );
			add_action( 'user_register', array( $this, 'track_user_creation' ) );
			add_action( 'activated_plugin', array( $this, 'track_plugin_activation' ), 10, 2 );
			add_action( 'updated_option', array( $this, 'track_option_update' ), 10, 3 );
		}

		// Data exfiltration detection hooks.
		if ( ! empty( $settings['data_exfiltration_enabled'] ) ) {
			add_action( 'shutdown', array( $this, 'monitor_data_exfiltration' ) );
			add_action( 'export_wp', array( $this, 'track_wp_export' ) );
		}
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			$settings     = isset( $all_settings['ai_detection'] )
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
	 * Ensure database schema is created only when needed.
	 *
	 * @return void
	 */
	private function maybe_ensure_schema() {
		$installed_version = get_option( self::SCHEMA_OPTION, '' );
		if ( self::SCHEMA_VERSION === (string) $installed_version ) {
			return;
		}

		$this->create_tables();
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

		// Insider threat events table.
		$sql_insider = "CREATE TABLE IF NOT EXISTS {$this->insider_events_table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id BIGINT(20) UNSIGNED NOT NULL,
			action VARCHAR(60) NOT NULL,
			context LONGTEXT DEFAULT NULL,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			risk_contribution TINYINT(3) DEFAULT 0,
			PRIMARY KEY (id),
			KEY user_id (user_id),
			KEY action (action),
			KEY timestamp (timestamp)
		) $charset_collate;";

		dbDelta( $sql_insider );

		// Data exfiltration log table.
		$sql_exfil = "CREATE TABLE IF NOT EXISTS {$this->exfiltration_log_table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id BIGINT(20) UNSIGNED NOT NULL,
			export_type VARCHAR(60) NOT NULL,
			size_bytes BIGINT(20) DEFAULT 0,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			risk_score TINYINT(3) DEFAULT 0,
			PRIMARY KEY (id),
			KEY user_id (user_id),
			KEY export_type (export_type),
			KEY timestamp (timestamp)
		) $charset_collate;";

		dbDelta( $sql_exfil );

		update_option( self::SCHEMA_OPTION, self::SCHEMA_VERSION, false );
	}

	/**
	 * Analyze incoming request for anomalies.
	 */
	public function analyze_request() {
		// Skip admin AJAX and cron.
		if ( wp_doing_ajax() || wp_doing_cron() ) {
			return;
		}

		$ip           = $this->get_client_ip();
		$request_data = $this->collect_request_data( $ip );

		// Calculate threat score.
		$analysis = $this->analyze_behavior( $request_data );

		// Record behavior.
		$this->record_behavior( $request_data, $analysis );

		// Check for data exfiltration patterns.
		$settings = $this->get_settings();
		$user_id  = $request_data['user_id'];
		if ( $user_id > 0 && ! empty( $settings['data_exfiltration_enabled'] ) ) {
			$this->check_exfiltration_patterns( $user_id, $request_data );
		}

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
			'ip'           => $ip,
			'user_id'      => get_current_user_id(),
			'uri'          => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
			'method'       => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET',
			'user_agent'   => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
			'hour'         => (int) current_time( 'G' ),
			'day_of_week'  => (int) current_time( 'w' ),
			'payload_size' => isset( $_SERVER['CONTENT_LENGTH'] ) ? (int) $_SERVER['CONTENT_LENGTH'] : 0,
			'country'      => $this->get_country_code( $ip ),
			'request_body' => file_get_contents( 'php://input' ),
		);
	}

	/**
	 * Analyze behavior and calculate threat score.
	 *
	 * @param array $request_data Current request data.
	 * @return array Analysis results.
	 */
	private function analyze_behavior( $request_data ) {
		$score     = 0;
		$anomalies = array();
		$patterns  = $this->get_learned_patterns();

		// 1. Unusual time analysis.
		$time_score = $this->analyze_time_pattern( $request_data, $patterns );
		if ( $time_score > 0 ) {
			$score      += $time_score;
			$anomalies[] = 'unusual_time';
		}

		// 2. Unusual location.
		$geo_score = $this->analyze_geo_pattern( $request_data, $patterns );
		if ( $geo_score > 0 ) {
			$score      += $geo_score;
			$anomalies[] = 'unusual_location';
		}

		// 3. User agent analysis.
		$ua_score = $this->analyze_user_agent( $request_data );
		if ( $ua_score > 0 ) {
			$score      += $ua_score;
			$anomalies[] = 'suspicious_user_agent';
		}

		// 4. Request rate analysis.
		$rate_score = $this->analyze_request_rate( $request_data['ip'] );
		if ( $rate_score > 0 ) {
			$score      += $rate_score;
			$anomalies[] = 'rapid_requests';
		}

		// 5. Payload entropy (detect obfuscation).
		$entropy_score = $this->analyze_payload_entropy( $request_data['request_body'] );
		if ( $entropy_score > 0 ) {
			$score      += $entropy_score;
			$anomalies[] = 'high_entropy_payload';
		}

		// 6. Enumeration detection.
		$enum_score = $this->detect_enumeration( $request_data );
		if ( $enum_score > 0 ) {
			$score      += $enum_score;
			$anomalies[] = 'enumeration_attempt';
		}

		// 7. Bot signature detection.
		$bot_score = $this->detect_bot_behavior( $request_data );
		if ( $bot_score > 0 ) {
			$score      += $bot_score;
			$anomalies[] = 'bot_behavior';
		}

		// 8. Failed login clustering.
		$login_score = $this->analyze_login_pattern( $request_data['ip'] );
		if ( $login_score > 0 ) {
			$score      += $login_score;
			$anomalies[] = 'login_anomaly';
		}

		// Cap score at 100.
		$score = min( 100, $score );

		return array(
			'score'      => $score,
			'anomalies'  => $anomalies,
			'risk_level' => $this->score_to_risk_level( $score ),
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
		$peak_hours   = $patterns['peak_hours'];

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
		$ua    = strtolower( $request['user_agent'] );
		$score = 0;

		// Empty user agent.
		if ( empty( $ua ) ) {
			return $this->weights['bot_signature'];
		}

		// Known malicious patterns.
		$suspicious_patterns = array(
			'sqlmap',
			'nikto',
			'nmap',
			'masscan',
			'zgrab',
			'python-requests',
			'go-http-client',
			'curl/',
			'wget/',
			'libwww-perl',
			'httpclient',
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
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	private function analyze_request_rate( $ip ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name cannot be parameterized
		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$this->behavior_table}
			WHERE ip_address = %s AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)",
				$ip
			)
		);

		// More than 30 requests per minute is suspicious.
		if ( $count > 30 ) {
			return $this->weights['rapid_requests'];
		} elseif ( $count > 15 ) {
			return (int) ( $this->weights['rapid_requests'] * 0.5 );
		}

		return 0;
	}
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

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
		$length      = strlen( $data );

		for ( $i = 0; $i < $length; $i++ ) {
			$char = $data[ $i ];
			if ( ! isset( $frequencies[ $char ] ) ) {
				$frequencies[ $char ] = 0;
			}
			++$frequencies[ $char ];
		}

		$entropy = 0.0;
		foreach ( $frequencies as $count ) {
			$probability = $count / $length;
			$entropy    -= $probability * log( $probability, 2 );
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
		$uri   = $request['uri'];
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
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	private function detect_bot_behavior( $request ) {
		$score = 0;

		// Check for missing common headers.
		$has_accept   = ! empty( $_SERVER['HTTP_ACCEPT'] );
		$has_language = ! empty( $_SERVER['HTTP_ACCEPT_LANGUAGE'] );
		$has_encoding = ! empty( $_SERVER['HTTP_ACCEPT_ENCODING'] );

		// Real browsers send these headers.
		if ( ! $has_accept && ! $has_language ) {
			$score += (int) ( $this->weights['bot_signature'] * 0.5 );
		}

		// Check for sequential scanning patterns.
		global $wpdb;
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name cannot be parameterized
		$recent_uris = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT DISTINCT request_uri FROM {$this->behavior_table}
			WHERE ip_address = %s AND created_at > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
			ORDER BY id DESC LIMIT 10",
				$request['ip']
			)
		);

		// Many unique URIs in short time = scanning.
		if ( count( $recent_uris ) >= 8 ) {
			$score += $this->weights['bot_signature'];
		}

		return $score;
	}
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

	/**
	 * Analyze login attempt patterns.
	 *
	 * @param string $ip Client IP.
	 * @return int Score contribution.
	 */
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	private function analyze_login_pattern( $ip ) {
		global $wpdb;

		// Count failed logins in last 10 minutes.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name cannot be parameterized
		$failed = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$this->behavior_table}
			WHERE ip_address = %s
			AND is_login_attempt = 1
			AND is_successful = 0
			AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)",
				$ip
			)
		);

		if ( $failed >= 5 ) {
			return $this->weights['credential_stuffing'];
		} elseif ( $failed >= 3 ) {
			return $this->weights['failed_logins'];
		}

		return 0;
	}
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

	/**
	 * Record behavior in database.
	 *
	 * @param array $request_data Request data.
	 * @param array $analysis Analysis results.
	 */
	private function record_behavior( $request_data, $analysis ) {
		global $wpdb;

		$result = $wpdb->insert(
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

		if ( false === $result && class_exists( 'NexifyMy_Security_Logger' ) ) {
			$db_error = isset( $wpdb->last_error ) ? (string) $wpdb->last_error : '';
			$message  = 'Failed to record AI behavior.';
			if ( '' !== $db_error ) {
				$message .= ' Database error: ' . $db_error;
			}

			NexifyMy_Security_Logger::log(
				'ai_record_error',
				$message,
				'warning'
			);
		}
	}

	/**
	 * Record successful login and analyze risk.
	 *
	 * @param string  $user_login Username (WordPress provided, required for hook signature).
	 * @param WP_User $user User object.
	 * @return void
	 */
	// phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- WordPress hook signature requires $user_login
	public function record_successful_login( $user_login, $user ) {
		global $wpdb;

		$ip         = $this->get_client_ip();
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$country    = $this->get_country_code( $ip );

		// Calculate user-specific risk score BEFORE updating profile.
		$risk_analysis = $this->calculate_user_risk_score( $user->ID, $ip, $user_agent, $country );

		// Factor in recent insider threat activity.
		$settings = $this->get_settings();
		if ( ! empty( $settings['insider_threat_enabled'] ) ) {
			$insider_risk           = $this->get_recent_insider_risk( $user->ID );
			$risk_analysis['score'] = min( 100, $risk_analysis['score'] + $insider_risk );
			if ( $insider_risk > 0 ) {
				$risk_analysis['factors'][] = 'insider_threat_history';
			}
		}

		// Record in behavior log.
		$wpdb->insert(
			$this->behavior_table,
			array(
				'ip_address'       => $ip,
				'user_id'          => $user->ID,
				'request_uri'      => '/wp-login.php',
				'request_method'   => 'POST',
				'user_agent'       => $user_agent,
				'country_code'     => $country,
				'hour_of_day'      => (int) current_time( 'G' ),
				'day_of_week'      => (int) current_time( 'w' ),
				'is_login_attempt' => 1,
				'is_successful'    => 1,
				'threat_score'     => $risk_analysis['score'],
				'anomalies'        => wp_json_encode( $risk_analysis['factors'] ),
			),
			array( '%s', '%d', '%s', '%s', '%s', '%s', '%d', '%d', '%d', '%d', '%d', '%s' )
		);

		// Update user profile with this login (learn from successful logins).
		$this->update_user_profile( $user->ID, $ip, $user_agent, $country );

		// Store login-time risk score for continuous authentication spike detection.
		update_user_meta( $user->ID, '_nexifymy_login_risk_score', $risk_analysis['score'] );
		update_user_meta( $user->ID, '_last_risk_check', time() );

		$threshold     = isset( $settings['session_risk_threshold'] ) ? absint( $settings['session_risk_threshold'] ) : self::SESSION_RISK_THRESHOLD;
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
				'ip_address'       => $this->get_client_ip(),
				'user_id'          => 0,
				'request_uri'      => '/wp-login.php',
				'request_method'   => 'POST',
				'user_agent'       => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
				'hour_of_day'      => (int) current_time( 'G' ),
				'day_of_week'      => (int) current_time( 'w' ),
				'is_login_attempt' => 1,
				'is_successful'    => 0,
				'threat_score'     => 10,
			),
			array( '%s', '%d', '%s', '%s', '%s', '%d', '%d', '%d', '%d', '%d' )
		);
	}

	/**
	 * Learn normal behavior patterns.
	 *
	 * @return void
	 */
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	public function learn_patterns() {
		global $wpdb;

		$settings      = $this->get_settings();
		$learning_days = max( 1, absint( $settings['learning_period_days'] ?? 7 ) );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$total_records = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$this->behavior_table}
			WHERE created_at > DATE_SUB(NOW(), INTERVAL %d DAY)",
				$learning_days
			)
		);

		$minimum_samples = 1;
		if ( $total_records >= 30 ) {
			$minimum_samples = 3;
		} elseif ( $total_records >= 10 ) {
			$minimum_samples = 2;
		}

		$patterns = array(
			'sample_size'    => $total_records,
			'learning_days'  => $learning_days,
		);

		// Learn peak hours.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$peak_hours             = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT hour_of_day FROM {$this->behavior_table}
			WHERE threat_score < %d AND created_at > DATE_SUB(NOW(), INTERVAL %d DAY)
			GROUP BY hour_of_day
			HAVING COUNT(*) >= %d
			ORDER BY COUNT(*) DESC
			LIMIT %d",
				30,
				$learning_days,
				$minimum_samples,
				12
			)
		);

		if ( empty( $peak_hours ) && $total_records > 0 ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$peak_hours = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT hour_of_day FROM {$this->behavior_table}
				WHERE threat_score < %d AND created_at > DATE_SUB(NOW(), INTERVAL %d DAY)
				GROUP BY hour_of_day
				ORDER BY COUNT(*) DESC
				LIMIT %d",
					30,
					$learning_days,
					6
				)
			);
		}
		$patterns['peak_hours'] = array_map( 'intval', $peak_hours );

		// Learn known countries.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$countries                   = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT country_code FROM {$this->behavior_table}
			WHERE threat_score < %d AND country_code != ''
			AND created_at > DATE_SUB(NOW(), INTERVAL %d DAY)
			GROUP BY country_code
			HAVING COUNT(*) >= %d",
				30,
				$learning_days,
				$minimum_samples
			)
		);

		if ( empty( $countries ) && $total_records > 0 ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$countries = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT country_code FROM {$this->behavior_table}
				WHERE threat_score < %d AND country_code != ''
				AND created_at > DATE_SUB(NOW(), INTERVAL %d DAY)
				GROUP BY country_code
				ORDER BY COUNT(*) DESC
				LIMIT %d",
					30,
					$learning_days,
					10
				)
			);
		}
		$patterns['known_countries'] = $countries;

		// Learn common user agents.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$user_agents                   = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT SUBSTRING(user_agent, 1, 50) as ua_prefix FROM {$this->behavior_table}
			WHERE threat_score < %d AND user_agent != ''
			AND created_at > DATE_SUB(NOW(), INTERVAL %d DAY)
			GROUP BY ua_prefix
			HAVING COUNT(*) >= %d
			LIMIT %d",
				30,
				$learning_days,
				max( 1, $minimum_samples - 1 ),
				50
			)
		);

		if ( empty( $user_agents ) && $total_records > 0 ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$user_agents = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT SUBSTRING(user_agent, 1, 50) as ua_prefix FROM {$this->behavior_table}
				WHERE threat_score < %d AND user_agent != ''
				AND created_at > DATE_SUB(NOW(), INTERVAL %d DAY)
				GROUP BY ua_prefix
				ORDER BY COUNT(*) DESC
				LIMIT %d",
					30,
					$learning_days,
					20
				)
			);
		}
		$patterns['known_user_agents'] = $user_agents;

		// Store patterns.
		$patterns['last_learned'] = current_time( 'mysql' );
		update_option( self::PATTERNS_OPTION, $patterns, false );
	}
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

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
		if ( class_exists( 'NexifyMy_Security_Firewall' ) && method_exists( 'NexifyMy_Security_Firewall', 'block_ip' ) ) {
			NexifyMy_Security_Firewall::block_ip( $ip, 'AI Threat Detection: ' . implode( ', ', $analysis['anomalies'] ) );
		} elseif ( isset( $GLOBALS['nexifymy_waf'] ) && method_exists( $GLOBALS['nexifymy_waf'], 'add_to_blocklist' ) ) {
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
			'ip'         => $ip,
			'score'      => $analysis['score'],
			'anomalies'  => $analysis['anomalies'],
			'flagged_at' => current_time( 'mysql' ),
			'status'     => 'pending',
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
		$to      = get_option( 'admin_email' );
		$subject = sprintf( '[%s] AI Threat Detection Alert', get_bloginfo( 'name' ) );

		$message  = "AI-Powered Threat Detection Alert\n\n";
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
		if ( $score >= 90 ) {
			return 'critical';
		}
		if ( $score >= 75 ) {
			return 'high';
		}
		if ( $score >= 50 ) {
			return 'medium';
		}
		if ( $score >= 25 ) {
			return 'low';
		}
		return 'minimal';
	}

	/**
	 * Get client IP address.
	 *
	 * @return string
	 */
	private function get_client_ip() {
		$remote_addr     = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$trusted_proxies = get_option( 'nexifymy_security_trusted_proxies', array() );

		if ( $remote_addr && in_array( $remote_addr, (array) $trusted_proxies, true ) ) {
			$ip_keys = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP' );
			foreach ( $ip_keys as $key ) {
				if ( empty( $_SERVER[ $key ] ) ) {
					continue;
				}

				$ip = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
				if ( strpos( $ip, ',' ) !== false ) {
					$ip = trim( explode( ',', $ip )[0] );
				}
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}

		if ( $remote_addr && filter_var( $remote_addr, FILTER_VALIDATE_IP ) ) {
			return $remote_addr;
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
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	public function get_status() {
		global $wpdb;

		// Count behavior records.
		$total_records = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$this->behavior_table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$patterns      = $this->get_learned_patterns();

		$last_learned_timestamp = ! empty( $patterns['last_learned'] ) ? strtotime( (string) $patterns['last_learned'] ) : false;
		$pattern_is_stale       = ! $last_learned_timestamp || $last_learned_timestamp < ( time() - 3600 );
		$has_core_patterns      = ! empty( $patterns['peak_hours'] ) || ! empty( $patterns['known_countries'] ) || ! empty( $patterns['known_user_agents'] );

		// Re-learn patterns on demand so status is not blocked on WP-Cron timing.
		if ( $total_records > 0 && ( $pattern_is_stale || ! $has_core_patterns ) ) {
			$this->learn_patterns();
			$patterns          = $this->get_learned_patterns();
			$has_core_patterns = ! empty( $patterns['peak_hours'] ) || ! empty( $patterns['known_countries'] ) || ! empty( $patterns['known_user_agents'] );
		}

		$settings          = $this->get_settings();
		$anomaly_threshold = max( 0, min( 100, absint( $settings['anomaly_threshold'] ?? 75 ) ) );
		$threats_today_db = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$this->behavior_table}
			WHERE threat_score >= %d AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)",
				$anomaly_threshold
			)
		);
		$threats          = get_option( self::THREATS_OPTION, array() );
		$threats          = is_array( $threats ) ? $threats : array();
		$threats_today_ui = 0;
		$cutoff_timestamp = time() - 86400;
		foreach ( $threats as $threat ) {
			$raw_time = $threat['blocked_at'] ?? ( $threat['flagged_at'] ?? '' );
			if ( empty( $raw_time ) ) {
				continue;
			}

			$threat_timestamp = strtotime( (string) $raw_time );
			if ( false !== $threat_timestamp && $threat_timestamp >= $cutoff_timestamp ) {
				++$threats_today_ui;
			}
		}

		$threats_today = max( $threats_today_db, $threats_today_ui );

		return array(
			'learning_status' => ( $has_core_patterns || ( ! empty( $patterns['last_learned'] ) && $total_records >= 10 ) ) ? 'trained' : 'learning',
			'last_learned'    => $patterns['last_learned'] ?? null,
			'total_records'   => $total_records,
			'known_countries' => count( $patterns['known_countries'] ?? array() ),
			'peak_hours'      => $patterns['peak_hours'] ?? array(),
			'threats_today'   => $threats_today,
			'recent_threats'  => array_slice( array_reverse( $threats ), 0, 10 ),
		);
	}
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

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

	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	public function ajax_reset_learning() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		delete_option( self::PATTERNS_OPTION );
		global $wpdb;
		$wpdb->query( "TRUNCATE TABLE {$this->behavior_table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		wp_send_json_success( array( 'message' => 'AI learning reset successfully.' ) );
	}
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

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
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	public function get_user_profile( $user_id ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name cannot be parameterized
		$profile = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$this->user_profiles_table} WHERE user_id = %d",
				$user_id
			),
			ARRAY_A
		);

		if ( $profile ) {
			$profile['known_ips']           = json_decode( $profile['known_ips'], true ) ?: array();
			$profile['work_hours']          = json_decode( $profile['work_hours'], true ) ?: array();
			$profile['device_fingerprints'] = json_decode( $profile['device_fingerprints'], true ) ?: array();
			$profile['typical_countries']   = json_decode( $profile['typical_countries'], true ) ?: array();
		}

		return $profile;
	}
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

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

		$profile      = $this->get_user_profile( $user_id );
		$current_hour = (int) current_time( 'G' );
		$fingerprint  = $this->generate_device_fingerprint( $user_agent );

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
			$known_ips        = $profile['known_ips'];
			$known_ips[ $ip ] = ( $known_ips[ $ip ] ?? 0 ) + 1;
			// Keep only top 20 IPs.
			arsort( $known_ips );
			$known_ips = array_slice( $known_ips, 0, 20, true );

			$work_hours                  = $profile['work_hours'];
			$work_hours[ $current_hour ] = ( $work_hours[ $current_hour ] ?? 0 ) + 1;

			$fingerprints                 = $profile['device_fingerprints'];
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
		$profile      = $this->get_user_profile( $user_id );
		$score        = 0;
		$factors      = array();
		$current_hour = (int) current_time( 'G' );
		$fingerprint  = $this->generate_device_fingerprint( $user_agent );

		// No profile = new user, minimal risk adjustment.
		if ( ! $profile || $profile['total_logins'] < 3 ) {
			return array(
				'score'      => 0,
				'factors'    => array( 'new_user_profile' ),
				'risk_level' => 'minimal',
			);
		}

		// 1. Check if IP is known for this user.
		if ( ! isset( $profile['known_ips'][ $ip ] ) ) {
			$score    += $this->weights['unknown_ip_for_user'];
			$factors[] = 'unknown_ip_for_user';
		}

		// 2. Check if current hour is typical for this user.
		$total_hour_logins = array_sum( $profile['work_hours'] );
		$hour_frequency    = ( $profile['work_hours'][ $current_hour ] ?? 0 ) / max( 1, $total_hour_logins );
		if ( $hour_frequency < 0.05 ) { // Less than 5% of logins at this hour.
			$score    += $this->weights['unusual_time_for_user'];
			$factors[] = 'unusual_time_for_user';
		}

		// 3. Check device fingerprint.
		if ( ! isset( $profile['device_fingerprints'][ $fingerprint ] ) ) {
			$score    += $this->weights['unknown_device'];
			$factors[] = 'unknown_device';
		}

		// 4. Apply passkey bonus/penalty.
		if ( $profile['last_passkey_success'] && strtotime( $profile['last_passkey_success'] ) > strtotime( '-30 minutes' ) ) {
			$score    += $this->weights['passkey_success_bonus']; // Negative = reduces score.
			$factors[] = 'recent_passkey_success';
		}
		if ( $profile['passkey_failure_count'] > 3 ) {
			$score    += $this->weights['passkey_failure'] * min( 3, $profile['passkey_failure_count'] - 3 );
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
		$ua    = strtolower( $user_agent );
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
					'user_id'               => $user_id,
					'last_passkey_success'  => $event === 'success' ? current_time( 'mysql' ) : null,
					'last_passkey_failure'  => $event === 'failure' ? current_time( 'mysql' ) : null,
					'passkey_failure_count' => $event === 'failure' ? 1 : 0,
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

		$user_id   = get_current_user_id();
		$settings  = $this->get_settings();
		$threshold = isset( $settings['session_risk_threshold'] ) ? absint( $settings['session_risk_threshold'] ) : self::SESSION_RISK_THRESHOLD;
		$threshold = max( 1, min( 100, $threshold ) );

		// Get last risk score.
		$risk_score = $this->get_user_last_risk_score( $user_id );

		// Check if user has already re-authenticated this session.
		$reauth_token  = get_user_meta( $user_id, '_nexifymy_reauth_token', true );
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

		wp_redirect(
			add_query_arg(
				array(
					'reauth'        => '1',
					'nexifymy_risk' => '1',
					'redirect_to'   => urlencode( $redirect_to ),
				),
				wp_login_url()
			)
		);
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

	/*
	 * =========================================================================
	 * CONTINUOUS AUTHENTICATION
	 * =========================================================================
	 */

	/**
	 * Filter callback for 'determine_current_user' (priority 99).
	 *
	 * Validates the session continuously and forces re-auth on risk spikes.
	 *
	 * @param int $user_id Current user ID resolved by WordPress.
	 * @return int The user ID, or 0 if session was invalidated.
	 */
	public function continuous_auth_check( $user_id ) {
		// Skip guests and AJAX/cron requests.
		if ( $user_id <= 0 || wp_doing_ajax() || wp_doing_cron() ) {
			return $user_id;
		}

		$session_token = wp_get_session_token();

		if ( empty( $session_token ) ) {
			return $user_id;
		}

		$needs_reauth = $this->check_session_validity( $user_id, $session_token );

		if ( $needs_reauth ) {
			// Log the forced re-auth.
			if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
				NexifyMy_Security_Logger::log(
					'continuous_auth_reauth',
					sprintf( 'Continuous auth forced re-authentication for user %d', $user_id ),
					'warning'
				);
			}

			// Destroy session and redirect.
			wp_logout();

			if ( ! headers_sent() ) {
				$redirect_to = isset( $_SERVER['REQUEST_URI'] )
					? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) )
					: admin_url();

				wp_redirect(
					add_query_arg(
						array(
							'reauth'        => '1',
							'nexifymy_risk' => '1',
							'redirect_to'   => urlencode( $redirect_to ),
						),
						wp_login_url()
					)
				);
				exit;
			}

			return 0;
		}

		return $user_id;
	}

	/**
	 * Check if a session is still valid by recalculating risk at intervals.
	 *
	 * @param int    $user_id       User ID.
	 * @param string $session_token Session token.
	 * @return bool True if re-authentication is required.
	 */
	public function check_session_validity( $user_id, $session_token ) {
		$settings = $this->get_settings();

		$interval = isset( $settings['zero_trust_reauth_interval'] )
			? absint( $settings['zero_trust_reauth_interval'] )
			: 900;
		$interval = max( 60, $interval ); // Minimum 60 seconds.

		// Retrieve last risk check timestamp.
		$last_check = (int) get_user_meta( $user_id, '_last_risk_check', true );

		// If within the interval, no re-check needed.
		if ( $last_check > 0 && ( time() - $last_check ) < $interval ) {
			return false;
		}

		// Recalculate risk score.
		$ip         = $this->get_client_ip();
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] )
			? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) )
			: '';
		$country    = $this->get_country_code( $ip );

		$risk_analysis = $this->calculate_user_risk_score( $user_id, $ip, $user_agent, $country );

		// Update last check timestamp.
		update_user_meta( $user_id, '_last_risk_check', time() );

		// Check for risk spike.
		$spike_detected = $this->detect_risk_spike( $user_id, $risk_analysis['score'] );

		if ( $spike_detected ) {
			return true;
		}

		// Also check absolute threshold.
		$threshold = isset( $settings['session_risk_threshold'] )
			? absint( $settings['session_risk_threshold'] )
			: self::SESSION_RISK_THRESHOLD;

		// Skip if already re-authed for this session.
		$reauth_token = get_user_meta( $user_id, '_nexifymy_reauth_token', true );
		if ( $reauth_token === $session_token ) {
			return false;
		}

		return $risk_analysis['score'] >= $threshold;
	}

	/**
	 * Detect a risk spike by comparing current score with login-time score.
	 *
	 * @param int $user_id       User ID.
	 * @param int $current_score Current risk score.
	 * @return bool True if spike exceeds threshold.
	 */
	public function detect_risk_spike( $user_id, $current_score ) {
		$settings  = $this->get_settings();
		$threshold = isset( $settings['zero_trust_risk_spike_threshold'] )
			? absint( $settings['zero_trust_risk_spike_threshold'] )
			: 20;

		$login_score = (int) get_user_meta( $user_id, '_nexifymy_login_risk_score', true );

		$spike = $current_score - $login_score;

		if ( $spike > $threshold ) {
			// Log spike event.
			if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
				NexifyMy_Security_Logger::log(
					'risk_spike_detected',
					sprintf(
						'Risk spike detected for user %d: login score %d → current score %d (spike: +%d)',
						$user_id,
						$login_score,
						$current_score,
						$spike
					),
					'critical'
				);
			}

			// Send alert email.
			$this->send_risk_spike_alert( $user_id, $login_score, $current_score );

			// Request passkey/2FA challenge via passkey module if available.
			$passkey_module = isset( $GLOBALS['nexifymy_passkey'] ) ? $GLOBALS['nexifymy_passkey'] : null;
			if ( $passkey_module && method_exists( $passkey_module, 'user_has_credentials' ) ) {
				if ( $passkey_module->user_has_credentials( $user_id ) ) {
					// User has passkeys registered — force re-auth will present passkey challenge.
					update_user_meta( $user_id, '_nexifymy_require_passkey_challenge', 1 );
				}
			}

			return true;
		}

		return false;
	}

	/**
	 * Send risk spike alert email to site admin.
	 *
	 * @param int $user_id       User ID.
	 * @param int $login_score   Risk score at login time.
	 * @param int $current_score Current risk score.
	 */
	private function send_risk_spike_alert( $user_id, $login_score, $current_score ) {
		$user        = get_userdata( $user_id );
		$username    = $user ? $user->user_login : sprintf( 'User #%d', $user_id );
		$admin_email = function_exists( 'get_option' ) ? get_option( 'admin_email', '' ) : '';

		if ( empty( $admin_email ) ) {
			return;
		}

		$subject = sprintf(
			'[%s] Security Alert: Risk Spike Detected for %s',
			function_exists( 'get_bloginfo' ) ? get_bloginfo( 'name' ) : 'WordPress',
			$username
		);

		$message = sprintf(
			"A significant risk spike has been detected for user \"%s\" (ID: %d).\n\n" .
			"Risk at login: %d\n" .
			"Current risk:  %d\n" .
			"Spike:         +%d points\n\n" .
			"Action taken: Forced re-authentication.\n" .
			"Time: %s\n" .
			"IP: %s\n\n" .
			'— SentinelWP Security',
			$username,
			$user_id,
			$login_score,
			$current_score,
			$current_score - $login_score,
			current_time( 'mysql' ),
			$this->get_client_ip()
		);

		wp_mail( $admin_email, $subject, $message );
	}

	/*
	 * =========================================================================
	 * INSIDER THREAT DETECTION
	 * =========================================================================
	 */

	/**
	 * Detect insider threat activity and calculate risk.
	 *
	 * @param int    $user_id User ID performing the action.
	 * @param string $action  Action type (bulk_delete, db_export, create_admin_user, disable_security, install_plugin).
	 * @param array  $context Additional context about the action.
	 * @return int Risk score (0-40).
	 */
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	public function detect_insider_threat( $user_id, $action, $context = array() ) {
		if ( $user_id <= 0 ) {
			return 0;
		}

		$settings = $this->get_settings();
		if ( empty( $settings['insider_threat_enabled'] ) ) {
			return 0;
		}

		$allowed_actions = array( 'bulk_delete', 'db_export', 'create_admin_user', 'disable_security', 'install_plugin' );
		if ( ! in_array( $action, $allowed_actions, true ) ) {
			return 0;
		}

		global $wpdb;

		$weight_key = 'insider_' . $action;
		if ( $action === 'create_admin_user' ) {
			$weight_key = 'insider_create_admin';
		}
		$max_weight = isset( $this->weights[ $weight_key ] ) ? $this->weights[ $weight_key ] : 30;

		// Query 30-day baseline: average daily count.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name cannot be parameterized
		$baseline = (float) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) / 30 FROM {$this->insider_events_table}
			WHERE user_id = %d AND action = %s AND timestamp > DATE_SUB(NOW(), INTERVAL 30 DAY)",
				$user_id,
				$action
			)
		);

		// Query today's count.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name cannot be parameterized
		$today_count = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$this->insider_events_table}
			WHERE user_id = %d AND action = %s AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)",
				$user_id,
				$action
			)
		);

		// Calculate risk contribution.
		$risk = 0;
		if ( $baseline > 0 ) {
			if ( $today_count > $baseline * 3 ) {
				$risk = $max_weight;
			} elseif ( $today_count > $baseline * 2 ) {
				$risk = (int) ( $max_weight * 0.5 );
			}
		} else {
			// No baseline established.
			if ( $today_count >= 2 ) {
				$risk = $max_weight;
			} elseif ( $today_count >= 1 ) {
				$risk = (int) ( $max_weight * 0.3 );
			}
		}

		// Insert event record.
		$wpdb->insert(
			$this->insider_events_table,
			array(
				'user_id'           => $user_id,
				'action'            => $action,
				'context'           => wp_json_encode( $context ),
				'risk_contribution' => $risk,
			),
			array( '%d', '%s', '%s', '%d' )
		);

		// Check cumulative 24h risk.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name cannot be parameterized
		$cumulative_risk = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT SUM(risk_contribution) FROM {$this->insider_events_table}
			WHERE user_id = %d AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)",
				$user_id
			)
		);

		$threshold = isset( $settings['insider_threat_threshold'] ) ? absint( $settings['insider_threat_threshold'] ) : 60;
		if ( $cumulative_risk >= $threshold ) {
			$this->send_insider_threat_alert( $user_id, $action, $cumulative_risk, $baseline, $today_count + 1, $context );
		}

		return $risk;
	}
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

	/**
	 * Get recent insider risk score for a user (last 24 hours).
	 *
	 * @param int $user_id User ID.
	 * @return int Cumulative insider risk score.
	 */
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	public function get_recent_insider_risk( $user_id ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name cannot be parameterized
		$risk = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT SUM(risk_contribution) FROM {$this->insider_events_table}
			WHERE user_id = %d AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)",
				$user_id
			)
		);

		return $risk;
	}
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

	/**
	 * Track post deletion for bulk delete detection.
	 *
	 * @param int $post_id Post ID being deleted.
	 */
	public function track_post_deletion( $post_id ) {
		if ( function_exists( 'wp_is_post_revision' ) && wp_is_post_revision( $post_id ) ) {
			return;
		}

		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			return;
		}

		// Use a static counter to track rapid deletions within this request.
		static $deletion_count      = 0;
		static $first_deletion_time = 0;

		$now = time();
		if ( 0 === $first_deletion_time ) {
			$first_deletion_time = $now;
		}

		++$deletion_count;

		// Trigger insider threat detection on 5+ deletions within 60 seconds.
		if ( $deletion_count >= 5 && ( $now - $first_deletion_time ) <= 60 ) {
			$post    = function_exists( 'get_post' ) ? get_post( $post_id ) : null;
			$context = array(
				'post_id'        => $post_id,
				'post_type'      => $post ? $post->post_type : 'unknown',
				'deletion_count' => $deletion_count,
			);
			$this->detect_insider_threat( $user_id, 'bulk_delete', $context );
		}
	}

	/**
	 * Track new user creation for admin role detection.
	 *
	 * @param int $user_id Newly created user ID.
	 */
	public function track_user_creation( $user_id ) {
		$current_user_id = get_current_user_id();
		if ( $current_user_id <= 0 ) {
			return;
		}

		$new_user = get_userdata( $user_id );
		if ( ! $new_user ) {
			return;
		}

		// Check if the new user has administrator role.
		$roles = isset( $new_user->roles ) ? (array) $new_user->roles : array();
		if ( in_array( 'administrator', $roles, true ) ) {
			$context = array(
				'new_user_id'    => $user_id,
				'new_user_login' => $new_user->user_login,
				'role'           => 'administrator',
			);
			$this->detect_insider_threat( $current_user_id, 'create_admin_user', $context );
		}
	}

	/**
	 * Track plugin activation.
	 *
	 * @param string $plugin       Plugin basename.
	 * @param bool   $network_wide Whether network-wide activation.
	 */
	public function track_plugin_activation( $plugin, $network_wide = false ) {
		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			return;
		}

		$plugin_data = array( 'plugin' => $plugin );
		if ( function_exists( 'get_plugin_data' ) ) {
			$plugin_file = WP_PLUGIN_DIR . '/' . $plugin;
			if ( file_exists( $plugin_file ) ) {
				$data                = get_plugin_data( $plugin_file );
				$plugin_data['name'] = isset( $data['Name'] ) ? $data['Name'] : $plugin;
			}
		}
		$plugin_data['network_wide'] = $network_wide;

		$this->detect_insider_threat( $user_id, 'install_plugin', $plugin_data );
	}

	/**
	 * Track option updates for security-sensitive changes.
	 *
	 * @param string $option    Option name.
	 * @param mixed  $old_value Old value.
	 * @param mixed  $value     New value.
	 */
	public function track_option_update( $option, $old_value, $value ) {
		$watched_options = array(
			'nexifymy_security_settings',
			'active_plugins',
			'users_can_register',
			'default_role',
		);

		if ( ! in_array( $option, $watched_options, true ) ) {
			return;
		}

		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			return;
		}

		// Detect security module being disabled.
		if ( 'nexifymy_security_settings' === $option ) {
			$old_modules = isset( $old_value['modules'] ) ? (array) $old_value['modules'] : array();
			$new_modules = isset( $value['modules'] ) ? (array) $value['modules'] : array();

			foreach ( $old_modules as $key => $was_enabled ) {
				$is_enabled = isset( $new_modules[ $key ] ) ? $new_modules[ $key ] : $was_enabled;
				if ( ! empty( $was_enabled ) && empty( $is_enabled ) ) {
					$context = array(
						'option'          => $option,
						'disabled_module' => $key,
					);
					$this->detect_insider_threat( $user_id, 'disable_security', $context );
					return; // One event per update is sufficient.
				}
			}
			return;
		}

		$context = array( 'option' => $option );
		$this->detect_insider_threat( $user_id, 'disable_security', $context );
	}

	/**
	 * Send insider threat alert email.
	 *
	 * @param int    $user_id  User ID.
	 * @param string $action   Action type.
	 * @param int    $risk     Cumulative risk score.
	 * @param float  $baseline 30-day daily average.
	 * @param int    $count    Today's count.
	 * @param array  $context  Additional context.
	 */
	private function send_insider_threat_alert( $user_id, $action, $risk, $baseline, $count, $context ) {
		$user        = get_userdata( $user_id );
		$username    = $user ? $user->user_login : sprintf( 'User #%d', $user_id );
		$admin_email = get_option( 'admin_email', '' );

		if ( empty( $admin_email ) ) {
			return;
		}

		$deviation = $baseline > 0 ? round( ( $count / $baseline ) * 100 ) : 0;

		$subject = sprintf(
			'[%s] Insider Threat Alert: %s',
			get_bloginfo( 'name' ),
			ucwords( str_replace( '_', ' ', $action ) )
		);

		$message  = "Insider Threat Detection Alert\n\n";
		$message .= sprintf( "Site: %s\n", home_url() );
		$message .= sprintf( "Time: %s\n\n", current_time( 'mysql' ) );
		$message .= sprintf( "User: %s (ID: %d)\n", $username, $user_id );
		$message .= sprintf( "IP: %s\n", $this->get_client_ip() );
		$message .= sprintf( "Action: %s\n", ucwords( str_replace( '_', ' ', $action ) ) );
		$message .= sprintf( "Cumulative Risk Score: %d\n", $risk );
		$message .= sprintf( "Today's Count: %d\n", $count );
		$message .= sprintf( "30-Day Baseline: %.1f/day\n", $baseline );
		if ( $deviation > 0 ) {
			$message .= sprintf( "Deviation: %d%% of baseline\n", $deviation );
		}
		$message .= "\nPlease review this activity in your security dashboard.";

		wp_mail( $admin_email, $subject, $message );

		// Log the event.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'insider_threat_detected',
				sprintf( 'Insider threat detected: %s by user %s (ID: %d), risk: %d', $action, $username, $user_id, $risk ),
				'critical',
				$context
			);
		}
	}

	/*
	 * =========================================================================
	 * DATA EXFILTRATION DETECTION
	 * =========================================================================
	 */

	/**
	 * Monitor for data exfiltration patterns on shutdown.
	 * Runs after request is fully processed.
	 *
	 * @return void
	 */
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Hook callback, not processing form data
	public function monitor_data_exfiltration() {
		if ( wp_doing_ajax() || wp_doing_cron() ) {
			return;
		}

		if ( ! is_user_logged_in() ) {
			return;
		}

		$settings = $this->get_settings();
		if ( empty( $settings['data_exfiltration_enabled'] ) ) {
			return;
		}

		$user_id = get_current_user_id();
		$uri     = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$body    = file_get_contents( 'php://input' );

		$keywords    = array( 'export', 'download', 'backup' );
		$has_keyword = false;
		foreach ( $keywords as $keyword ) {
			if ( stripos( $uri, $keyword ) !== false || stripos( $body, $keyword ) !== false ) {
				$has_keyword = true;
				break;
			}
		}

		if ( ! $has_keyword ) {
			return;
		}

		// Check for large downloads.
		$content_length = isset( $_SERVER['CONTENT_LENGTH'] ) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
		if ( $content_length > 10485760 ) { // 10MB.
			$this->track_exfiltration_event( $user_id, 'large_download', $content_length );
			return;
		}

		// Check for REST API bulk requests.
		if ( strpos( $uri, '/wp-json/' ) !== false ) {
			$per_page = 0;
			if ( preg_match( '/per_page=(\d+)/', $uri, $matches ) ) {
				$per_page = (int) $matches[1];
			}
			if ( $per_page > 100 ) {
				$this->track_exfiltration_event( $user_id, 'api_bulk_request', 0 );
				return;
			}
		}

		// General export/download/backup keyword match.
		$this->track_exfiltration_event( $user_id, 'db_export', 0 );
	}

	/**
	 * Track WordPress export event.
	 *
	 * @param array $args Export arguments.
	 * @return void
	 */
	// phpcs:ignore WordPress.Security.NonceVerification.Missing -- WordPress core export hook, nonce verified by core
	public function track_wp_export( $args = array() ) {
		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			return;
		}

		$risk_bonus = 0;

		// Check for sensitive data export (users/usermeta).
		$content = isset( $_POST['content'] ) ? sanitize_text_field( wp_unslash( $_POST['content'] ) ) : '';
		if ( in_array( $content, array( 'users', 'usermeta' ), true ) ) {
			$risk_bonus = 20;
		}

		$this->track_exfiltration_event( $user_id, 'db_export', 0, $risk_bonus );
	}

	/**
	 * Track an exfiltration event and calculate risk.
	 *
	 * @param int    $user_id     User ID.
	 * @param string $export_type Type of export (db_export, large_download, api_bulk_request).
	 * @param int    $size_bytes  Size of the export in bytes.
	 * @param int    $risk_bonus  Additional risk points.
	 * @return int Risk score.
	 */
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	public function track_exfiltration_event( $user_id, $export_type, $size_bytes = 0, $risk_bonus = 0 ) {
		if ( $user_id <= 0 ) {
			return 0;
		}

		$settings      = $this->get_settings();
		$baseline_days = isset( $settings['exfiltration_baseline_days'] ) ? absint( $settings['exfiltration_baseline_days'] ) : 30;
		$baseline_days = max( 1, $baseline_days );

		global $wpdb;

		// Query baseline: average daily count.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name cannot be parameterized
		$baseline = (float) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) / %d FROM {$this->exfiltration_log_table}
			WHERE user_id = %d AND export_type = %s AND timestamp > DATE_SUB(NOW(), INTERVAL %d DAY)",
				$baseline_days,
				$user_id,
				$export_type,
				$baseline_days
			)
		);

		// Query today's count.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name cannot be parameterized
		$today_count = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$this->exfiltration_log_table}
			WHERE user_id = %d AND export_type = %s AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)",
				$user_id,
				$export_type
			)
		);

		// Calculate risk based on type and deviation.
		$risk       = 0;
		$weight_map = array(
			'db_export'        => array(
				'key'        => 'exfiltration_export',
				'multiplier' => 3,
			),
			'large_download'   => array(
				'key'        => 'exfiltration_large_download',
				'multiplier' => 5,
			),
			'api_bulk_request' => array(
				'key'        => 'exfiltration_api_bulk',
				'multiplier' => 3,
			),
		);

		$type_config = isset( $weight_map[ $export_type ] ) ? $weight_map[ $export_type ] : $weight_map['db_export'];
		$max_weight  = isset( $this->weights[ $type_config['key'] ] ) ? $this->weights[ $type_config['key'] ] : 20;

		if ( $baseline > 0 ) {
			if ( $today_count > $baseline * $type_config['multiplier'] ) {
				$risk = $max_weight;
			}
		} else {
			// No baseline.
			if ( $today_count >= 3 ) {
				$risk = $max_weight;
			} elseif ( $today_count >= 2 ) {
				$risk = (int) ( $max_weight * 0.5 );
			}
		}

		$risk += $risk_bonus;

		// Insert event record.
		$wpdb->insert(
			$this->exfiltration_log_table,
			array(
				'user_id'     => $user_id,
				'export_type' => $export_type,
				'size_bytes'  => $size_bytes,
				'risk_score'  => $risk,
			),
			array( '%d', '%s', '%d', '%d' )
		);

		// Check if threshold exceeded.
		$threshold = isset( $settings['exfiltration_threshold'] ) ? absint( $settings['exfiltration_threshold'] ) : 60;
		if ( $risk >= $threshold ) {
			$this->send_exfiltration_alert( $user_id, $export_type, $risk, $baseline, $today_count + 1, $size_bytes );
		}

		// Log the event.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'data_exfiltration_detected',
				sprintf( 'Data exfiltration event: %s by user ID %d, risk: %d', $export_type, $user_id, $risk ),
				$risk >= $threshold ? 'critical' : 'warning'
			);
		}

		return $risk;
	}
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

	/**
	 * Check request data for exfiltration patterns (lightweight inline check).
	 *
	 * @param int   $user_id      User ID.
	 * @param array $request_data Request data from collect_request_data().
	 */
	private function check_exfiltration_patterns( $user_id, $request_data ) {
		$uri = $request_data['uri'];

		// Check for REST API bulk requests.
		if ( strpos( $uri, '/wp-json/' ) !== false ) {
			if ( preg_match( '/per_page=(\d+)/', $uri, $matches ) ) {
				$per_page = (int) $matches[1];
				if ( $per_page > 100 ) {
					$this->track_exfiltration_event( $user_id, 'api_bulk_request', 0 );
				}
			}
		}

		// Check for export-related URIs.
		$export_patterns = array( 'export.php', 'admin-ajax.php?action=export', 'tools.php?page=export' );
		foreach ( $export_patterns as $pattern ) {
			if ( strpos( $uri, $pattern ) !== false ) {
				$this->track_exfiltration_event( $user_id, 'db_export', 0 );
				break;
			}
		}
	}

	/**
	 * Send exfiltration alert email.
	 *
	 * @param int    $user_id     User ID.
	 * @param string $export_type Export type.
	 * @param int    $risk        Risk score.
	 * @param float  $baseline    Daily baseline average.
	 * @param int    $count       Today's count.
	 * @param int    $size_bytes  Export size in bytes.
	 */
	private function send_exfiltration_alert( $user_id, $export_type, $risk, $baseline, $count, $size_bytes ) {
		$user        = get_userdata( $user_id );
		$username    = $user ? $user->user_login : sprintf( 'User #%d', $user_id );
		$admin_email = get_option( 'admin_email', '' );

		if ( empty( $admin_email ) ) {
			return;
		}

		$subject = sprintf(
			'[%s] Data Exfiltration Alert: %s',
			get_bloginfo( 'name' ),
			ucwords( str_replace( '_', ' ', $export_type ) )
		);

		$size_mb = $size_bytes > 0 ? round( $size_bytes / 1048576, 2 ) : 0;

		$message  = "Data Exfiltration Detection Alert\n\n";
		$message .= sprintf( "Site: %s\n", home_url() );
		$message .= sprintf( "Time: %s\n\n", current_time( 'mysql' ) );
		$message .= sprintf( "User: %s (ID: %d)\n", $username, $user_id );
		$message .= sprintf( "IP: %s\n", $this->get_client_ip() );
		$message .= sprintf( "Export Type: %s\n", ucwords( str_replace( '_', ' ', $export_type ) ) );
		if ( $size_mb > 0 ) {
			$message .= sprintf( "Size: %.2f MB\n", $size_mb );
		}
		$message .= sprintf( "Risk Score: %d\n", $risk );
		$message .= sprintf( "Today's Count: %d\n", $count );
		$message .= sprintf( "Baseline: %.1f/day\n", $baseline );
		$message .= "\nPlease review this activity in your security dashboard.";

		wp_mail( $admin_email, $subject, $message );
	}
}
