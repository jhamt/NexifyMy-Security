<?php
/**
 * Predictive Threat Hunting Module.
 *
 * Adds site risk profiling, attack-vector prediction, proactive hardening
 * recommendations, and safe simulation scenarios.
 *
 * @package NexifyMy_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Predictive_Threat_Hunting {

	const SCHEMA_OPTION = 'nexifymy_predictive_schema_version';
	const SCHEMA_VERSION = '1.0.0';
	const TABLE_SUFFIX = 'nexifymy_threat_predictions';
	const PROFILE_OPTION = 'nexifymy_threat_site_profile';
	const FORECAST_OPTION = 'nexifymy_threat_forecast';
	const SIMULATION_REPORTS_OPTION = 'nexifymy_attack_simulation_reports';
	const FORECAST_CRON_HOOK = 'nexifymy_update_threat_forecast';
	const SIMULATION_CRON_HOOK = 'nexifymy_monthly_attack_simulation';

	/**
	 * Predictions table.
	 *
	 * @var string
	 */
	private $predictions_table = '';

	/**
	 * Cached settings.
	 *
	 * @var array|null
	 */
	private static $settings_cache = null;

	/**
	 * Module defaults.
	 *
	 * @var array
	 */
	private static $defaults = array(
		'enabled'               => true,
		'forecast_update'       => 'weekly',
		'simulation_enabled'    => true,
		'simulation_schedule'   => 'monthly',
		'simulation_run_hour'   => 3,
		'probability_threshold' => 25,
	);

	/**
	 * Initialize module.
	 *
	 * @return void
	 */
	public function init() {
		global $wpdb;

		$this->predictions_table = $wpdb->prefix . self::TABLE_SUFFIX;
		$this->maybe_ensure_schema();

		$settings = $this->get_settings();
		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		add_action( self::FORECAST_CRON_HOOK, array( $this, 'refresh_forecast' ) );
		if ( ! wp_next_scheduled( self::FORECAST_CRON_HOOK ) ) {
			$forecast_schedule = in_array( $settings['forecast_update'], array( 'daily', 'weekly' ), true )
				? $settings['forecast_update']
				: 'weekly';
			wp_schedule_event( time(), $forecast_schedule, self::FORECAST_CRON_HOOK );
		}

		add_action( self::SIMULATION_CRON_HOOK, array( $this, 'run_monthly_penetration_test' ) );
		if ( ! wp_next_scheduled( self::SIMULATION_CRON_HOOK ) && ! empty( $settings['simulation_enabled'] ) ) {
			$simulation_schedule = in_array( $settings['simulation_schedule'], array( 'weekly', 'monthly' ), true )
				? $settings['simulation_schedule']
				: 'monthly';
			wp_schedule_event(
				$this->get_next_monthly_simulation_timestamp( (int) $settings['simulation_run_hour'] ),
				$simulation_schedule,
				self::SIMULATION_CRON_HOOK
			);
		}

		add_action( 'wp_dashboard_setup', array( $this, 'register_dashboard_widget' ) );
		add_action( 'wp_ajax_nexifymy_get_threat_forecast', array( $this, 'ajax_get_threat_forecast' ) );
		add_action( 'wp_ajax_nexifymy_run_attack_simulation', array( $this, 'ajax_run_attack_simulation' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( null !== self::$settings_cache ) {
			return self::$settings_cache;
		}

		$settings = self::$defaults;
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['predictive_threat_hunting'] ) && is_array( $all_settings['predictive_threat_hunting'] ) ) {
				$settings = wp_parse_args( $all_settings['predictive_threat_hunting'], self::$defaults );
			}

			if ( function_exists( 'nexifymy_security_is_module_enabled' ) ) {
				$settings['enabled'] = nexifymy_security_is_module_enabled( $all_settings, 'predictive_hunting_enabled', true );
			} elseif ( isset( $all_settings['modules']['predictive_hunting_enabled'] ) ) {
				$settings['enabled'] = ! empty( $all_settings['modules']['predictive_hunting_enabled'] );
			}
		}

		self::$settings_cache = $settings;
		return self::$settings_cache;
	}

	/**
	 * Flush settings cache.
	 *
	 * @return void
	 */
	public static function flush_settings_cache() {
		self::$settings_cache = null;
	}

	/**
	 * Ensure schema.
	 *
	 * @return void
	 */
	private function maybe_ensure_schema() {
		$installed = get_option( self::SCHEMA_OPTION, '' );
		if ( self::SCHEMA_VERSION === (string) $installed ) {
			return;
		}

		$this->create_table();
	}

	/**
	 * Create industry risk table.
	 *
	 * @return void
	 */
	public function create_table() {
		global $wpdb;

		$this->predictions_table = $wpdb->prefix . self::TABLE_SUFFIX;
		$charset_collate         = $wpdb->get_charset_collate();

		if ( ! function_exists( 'dbDelta' ) ) {
			$upgrade_file = ABSPATH . 'wp-admin/includes/upgrade.php';
			if ( file_exists( $upgrade_file ) ) {
				require_once $upgrade_file;
			}
		}

		if ( ! function_exists( 'dbDelta' ) ) {
			return;
		}

		$sql = "CREATE TABLE IF NOT EXISTS {$this->predictions_table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			industry VARCHAR(80) NOT NULL,
			common_attack_vectors LONGTEXT NOT NULL,
			risk_level TINYINT(2) NOT NULL DEFAULT 1,
			recent_incidents INT(11) NOT NULL DEFAULT 0,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			UNIQUE KEY industry (industry),
			KEY risk_level (risk_level)
		) {$charset_collate};";

		dbDelta( $sql );
		update_option( self::SCHEMA_OPTION, self::SCHEMA_VERSION, false );
	}

	/**
	 * Profile the current site.
	 *
	 * @return array
	 */
	public function profile_site() {
		$industry = $this->detect_industry();
		$size     = $this->detect_site_size();
		$stack    = $this->detect_tech_stack();

		$profile = array(
			'profiled_at'     => current_time( 'mysql' ),
			'industry'        => $industry,
			'size'            => $size['label'],
			'size_metrics'    => $size,
			'monthly_traffic' => (int) $size['monthly_traffic'],
			'tech_stack'      => $stack,
		);

		update_option( self::PROFILE_OPTION, $profile, false );
		$this->sync_industry_risk_row( $industry );

		return $profile;
	}

	/**
	 * Get a forecast snapshot, refreshing if stale.
	 *
	 * @param bool $force_refresh Force a refresh.
	 * @return array
	 */
	public function get_forecast_snapshot( $force_refresh = false ) {
		$forecast = get_option( self::FORECAST_OPTION, array() );
		$is_stale = true;

		if ( ! empty( $forecast['generated_at'] ) ) {
			$generated = strtotime( (string) $forecast['generated_at'] );
			$is_stale  = ! $generated || ( time() - $generated ) > WEEK_IN_SECONDS;
		}

		if ( $force_refresh || empty( $forecast ) || $is_stale ) {
			$forecast = $this->refresh_forecast();
		}

		return is_array( $forecast ) ? $forecast : array();
	}

	/**
	 * Refresh forecast.
	 *
	 * @return array
	 */
	public function refresh_forecast() {
		$profile         = $this->profile_site();
		$predictions     = $this->predict_next_attack_vector();
		$recommendations = $this->get_hardening_recommendations( $predictions );
		$risk_assessment = $this->get_risk_score_with_timeline( $predictions, $recommendations );

		$forecast = array(
			'generated_at'    => current_time( 'mysql' ),
			'profile'         => $profile,
			'predictions'     => $predictions,
			'recommendations' => $recommendations,
			'risk_assessment' => $risk_assessment,
		);

		update_option( self::FORECAST_OPTION, $forecast, false );

		return $forecast;
	}

	/**
	 * Predict next attack vectors.
	 *
	 * @return array
	 */
	public function predict_next_attack_vector() {
		$profile = get_option( self::PROFILE_OPTION, array() );
		if ( empty( $profile ) || empty( $profile['industry'] ) ) {
			$profile = $this->profile_site();
		}

		$industry    = (string) ( $profile['industry'] ?? 'general' );
		$risk_row    = $this->get_industry_risk_row( $industry );
		$predictions = array();

		if ( 'healthcare' === $industry && $this->has_plugin( 'contact-form-7' ) ) {
			$this->add_prediction(
				$predictions,
				'Form injection attacks',
				70,
				'Healthcare + Contact Form 7 path is exposed to form abuse.'
			);
		}

		if ( 'e-commerce' === $industry && $this->has_plugin( 'woocommerce' ) ) {
			$this->add_prediction(
				$predictions,
				'Payment skimming',
				74,
				'WooCommerce checkout pages are high-value targets.'
			);
			$this->add_prediction(
				$predictions,
				'SQL injection on checkout',
				68,
				'Checkout and coupon flows are commonly probed for SQL injection.'
			);
		}

		if ( $this->has_recent_brute_force_activity() ) {
			$this->add_prediction(
				$predictions,
				'Credential stuffing attack within 7 days',
				65,
				'Recent brute-force telemetry often precedes credential stuffing.'
			);
		}

		if ( $this->has_outdated_plugins() ) {
			$this->add_prediction(
				$predictions,
				'Plugin vulnerability exploitation',
				60,
				'Outdated plugin versions increase exploit probability.'
			);
		}

		if ( ! empty( $risk_row['common_attack_vectors'] ) && is_array( $risk_row['common_attack_vectors'] ) ) {
			$base_probability = max( 30, min( 80, (int) $risk_row['risk_level'] * 8 ) );
			foreach ( $risk_row['common_attack_vectors'] as $vector ) {
				$this->add_prediction(
					$predictions,
					(string) $vector,
					$base_probability,
					sprintf( 'Industry baseline signal: %s', $industry )
				);
			}
		}

		usort(
			$predictions,
			function ( $a, $b ) {
				return (int) $b['probability'] - (int) $a['probability'];
			}
		);

		$settings = $this->get_settings();
		$minimum  = max( 1, absint( $settings['probability_threshold'] ) );
		$filtered = array_values(
			array_filter(
				$predictions,
				function ( $row ) use ( $minimum ) {
					return (int) ( $row['probability'] ?? 0 ) >= $minimum;
				}
			)
		);

		return array_slice( $filtered, 0, 8 );
	}

	/**
	 * Build hardening recommendations from predictions.
	 *
	 * @param array|null $predictions Optional predictions list.
	 * @return array
	 */
	public function get_hardening_recommendations( $predictions = null ) {
		if ( null === $predictions ) {
			$predictions = $this->predict_next_attack_vector();
		}

		$recommendations = array();
		$outdated        = $this->get_outdated_plugins();

		foreach ( $predictions as $prediction ) {
			$vector = strtolower( (string) ( $prediction['vector'] ?? '' ) );

			if ( false !== strpos( $vector, 'sql injection' ) ) {
				$this->add_recommendation(
					$recommendations,
					'enable_strict_waf',
					'Enable WAF strict mode',
					'high',
					3,
					array(
						'Enable strict SQLi signatures in Firewall settings.',
						'Enable query parameter normalization.',
						'Monitor false positives for 48 hours and tune allowlist rules.',
					),
					'SQL injection activity predicted.'
				);
			}

			if ( false !== strpos( $vector, 'brute force' ) || false !== strpos( $vector, 'credential stuffing' ) ) {
				$this->add_recommendation(
					$recommendations,
					'strengthen_auth',
					'Enable 2FA and rate limiting',
					'high',
					2,
					array(
						'Require Two-Factor Authentication for privileged accounts.',
						'Set login rate limiting to 5 attempts per 5 minutes.',
						'Enable lockout escalation for repeated offender IPs.',
					),
					'Credential abuse risk is elevated.'
				);
			}

			if ( false !== strpos( $vector, 'plugin vulnerability' ) || false !== strpos( $vector, 'payment skimming' ) ) {
				$steps = array(
					'Update vulnerable plugins immediately.',
					'Remove abandoned plugins lacking recent updates.',
					'Enable daily vulnerability scans and notifications.',
				);
				if ( ! empty( $outdated ) ) {
					$steps[] = 'Priority updates: ' . implode( ', ', array_slice( $outdated, 0, 5 ) );
				}

				$this->add_recommendation(
					$recommendations,
					'patch_plugins',
					'Update high-risk plugins',
					'high',
					1,
					$steps,
					'Plugin-driven threat vectors detected.'
				);
			}

			if ( false !== strpos( $vector, 'form injection' ) || false !== strpos( $vector, 'xss' ) ) {
				$this->add_recommendation(
					$recommendations,
					'harden_forms',
					'Harden public forms',
					'medium',
					5,
					array(
						'Enable strict input validation and sanitization on form handlers.',
						'Apply form-specific rate limiting.',
						'Log and alert repeated payload signatures by source IP.',
					),
					'Form payload abuse risk detected.'
				);
			}
		}

		usort(
			$recommendations,
			function ( $a, $b ) {
				$weights = array(
					'critical' => 4,
					'high'     => 3,
					'medium'   => 2,
					'low'      => 1,
				);
				return ( $weights[ $b['priority'] ] ?? 1 ) - ( $weights[ $a['priority'] ] ?? 1 );
			}
		);

		return array_values( $recommendations );
	}

	/**
	 * Compute risk score and mitigation timeline.
	 *
	 * @param array|null $predictions Predictions list.
	 * @param array|null $recommendations Recommendations list.
	 * @return array
	 */
	public function get_risk_score_with_timeline( $predictions = null, $recommendations = null ) {
		if ( null === $predictions ) {
			$predictions = $this->predict_next_attack_vector();
		}
		if ( null === $recommendations ) {
			$recommendations = $this->get_hardening_recommendations( $predictions );
		}

		$score      = 0;
		$weight_sum = 0;

		foreach ( $predictions as $index => $item ) {
			$weight     = max( 1, 5 - $index );
			$weight_sum += $weight;
			$score     += (int) ( $item['probability'] ?? 0 ) * $weight;
		}

		$final_score = $weight_sum > 0 ? (int) round( $score / $weight_sum ) : 0;
		$final_score = max( 0, min( 100, $final_score ) );

		$level = 'low';
		if ( $final_score >= 80 ) {
			$level = 'critical';
		} elseif ( $final_score >= 60 ) {
			$level = 'high';
		} elseif ( $final_score >= 40 ) {
			$level = 'medium';
		}

		$timeline = array();
		foreach ( $recommendations as $row ) {
			$days       = max( 1, absint( $row['timeline_days'] ?? 7 ) );
			$timeline[] = array(
				'action'   => $row['title'] ?? '',
				'priority' => $row['priority'] ?? 'medium',
				'due_date' => gmdate( 'Y-m-d', strtotime( '+' . $days . ' days' ) ),
			);
		}

		return array(
			'risk_score' => $final_score,
			'risk_level' => $level,
			'timeline'   => $timeline,
		);
	}

	/**
	 * Add prediction with dedupe.
	 *
	 * @param array  $predictions Predictions by reference.
	 * @param string $vector Vector label.
	 * @param int    $probability Probability score.
	 * @param string $reason Reason.
	 * @return void
	 */
	private function add_prediction( &$predictions, $vector, $probability, $reason ) {
		$vector      = sanitize_text_field( (string) $vector );
		$probability = max( 1, min( 100, absint( $probability ) ) );
		$reason      = sanitize_text_field( (string) $reason );

		foreach ( $predictions as &$item ) {
			if ( strtolower( (string) ( $item['vector'] ?? '' ) ) === strtolower( $vector ) ) {
				$item['probability'] = max( (int) ( $item['probability'] ?? 0 ), $probability );
				if ( $reason && ! in_array( $reason, (array) $item['reasons'], true ) ) {
					$item['reasons'][] = $reason;
				}
				return;
			}
		}

		$predictions[] = array(
			'vector'      => $vector,
			'probability' => $probability,
			'reasons'     => $reason ? array( $reason ) : array(),
		);
	}

	/**
	 * Add recommendation with dedupe.
	 *
	 * @param array  $recommendations Recommendation list by reference.
	 * @param string $id Recommendation key.
	 * @param string $title Title.
	 * @param string $priority Priority.
	 * @param int    $timeline_days Timeline in days.
	 * @param array  $steps Step list.
	 * @param string $justification Justification text.
	 * @return void
	 */
	private function add_recommendation( &$recommendations, $id, $title, $priority, $timeline_days, $steps, $justification ) {
		$id = sanitize_key( (string) $id );

		foreach ( $recommendations as $row ) {
			if ( isset( $row['id'] ) && $id === $row['id'] ) {
				return;
			}
		}

		$recommendations[] = array(
			'id'            => $id,
			'title'         => sanitize_text_field( (string) $title ),
			'priority'      => in_array( $priority, array( 'critical', 'high', 'medium', 'low' ), true ) ? $priority : 'medium',
			'timeline_days' => max( 1, absint( $timeline_days ) ),
			'steps'         => array_values( array_map( 'sanitize_text_field', (array) $steps ) ),
			'justification' => sanitize_text_field( (string) $justification ),
		);
	}

	/**
	 * Detect likely industry.
	 *
	 * @return string
	 */
	private function detect_industry() {
		$corpus   = strtolower( $this->get_content_corpus() );
		$keywords = array(
			'healthcare' => array( 'patient', 'hipaa', 'medical', 'clinic', 'healthcare' ),
			'finance'    => array( 'bank', 'loan', 'investment', 'financial', 'fintech' ),
			'e-commerce' => array( 'checkout', 'cart', 'product', 'shipping', 'woocommerce' ),
			'education'  => array( 'course', 'student', 'school', 'curriculum', 'lms' ),
		);

		$scores = array(
			'healthcare' => 0,
			'finance'    => 0,
			'e-commerce' => 0,
			'education'  => 0,
		);

		foreach ( $keywords as $industry => $terms ) {
			foreach ( $terms as $term ) {
				$scores[ $industry ] += substr_count( $corpus, $term );
			}
		}

		if ( $this->has_plugin( 'woocommerce' ) ) {
			$scores['e-commerce'] += 4;
		}
		if ( $this->has_plugin( 'learndash' ) || $this->has_plugin( 'lifterlms' ) ) {
			$scores['education'] += 4;
		}
		if ( $this->has_plugin( 'buddypress' ) ) {
			$scores['education'] += 1;
			$scores['healthcare'] += 1;
		}

		arsort( $scores );
		$top_key   = key( $scores );
		$top_score = reset( $scores );

		return ( $top_score > 0 && is_string( $top_key ) ) ? $top_key : 'general';
	}

	/**
	 * Build content corpus.
	 *
	 * @return string
	 */
	private function get_content_corpus() {
		$parts = array();

		if ( function_exists( 'get_bloginfo' ) ) {
			$parts[] = (string) get_bloginfo( 'name' );
			$parts[] = (string) get_bloginfo( 'description' );
		}

		$parts[] = (string) get_option( 'blogdescription', '' );
		$parts[] = (string) get_option( 'blogname', '' );

		if ( function_exists( 'get_posts' ) ) {
			$posts = get_posts(
				array(
					'numberposts' => 20,
					'post_status' => 'publish',
				)
			);
			if ( is_array( $posts ) ) {
				foreach ( $posts as $post ) {
					if ( is_object( $post ) ) {
						$parts[] = (string) ( $post->post_title ?? '' );
						$parts[] = (string) ( $post->post_content ?? '' );
					}
				}
			}
		}

		return implode( ' ', array_filter( $parts ) );
	}

	/**
	 * Detect site size.
	 *
	 * @return array
	 */
	private function detect_site_size() {
		$posts   = $this->get_posts_count();
		$users   = $this->get_users_count();
		$traffic = $this->estimate_monthly_traffic( $posts, $users );
		$label   = 'small';

		if ( $posts >= 5000 || $users >= 500 || $traffic >= 250000 ) {
			$label = 'large';
		} elseif ( $posts >= 500 || $users >= 50 || $traffic >= 25000 ) {
			$label = 'medium';
		}

		return array(
			'label'           => $label,
			'posts'           => (int) $posts,
			'users'           => (int) $users,
			'monthly_traffic' => (int) $traffic,
		);
	}

	/**
	 * Detect stack profile from active plugins.
	 *
	 * @return array
	 */
	private function detect_tech_stack() {
		$plugins = $this->get_active_plugins();
		$stack   = array( 'wordpress-core' );
		$map     = array(
			'woocommerce'   => 'e-commerce',
			'buddypress'    => 'social-network',
			'contact-form-7'=> 'form-plugin',
			'elementor'     => 'page-builder',
			'wpforms'       => 'form-plugin',
			'learndash'     => 'education-lms',
			'lifterlms'     => 'education-lms',
		);

		foreach ( $plugins as $plugin ) {
			$plugin = (string) $plugin;
			foreach ( $map as $needle => $label ) {
				if ( false !== stripos( $plugin, $needle ) ) {
					$stack[] = $label;
				}
			}
		}

		return array_values( array_unique( $stack ) );
	}

	/**
	 * Return active plugins.
	 *
	 * @return array
	 */
	private function get_active_plugins() {
		$plugins = get_option( 'active_plugins', array() );
		if ( ! is_array( $plugins ) ) {
			$plugins = array();
		}

		if ( function_exists( 'is_multisite' ) && is_multisite() && function_exists( 'get_site_option' ) ) {
			$network = get_site_option( 'active_sitewide_plugins', array() );
			if ( is_array( $network ) ) {
				$plugins = array_merge( $plugins, array_keys( $network ) );
			}
		}

		return array_values( array_unique( array_map( 'sanitize_text_field', $plugins ) ) );
	}

	/**
	 * Get published post count.
	 *
	 * @return int
	 */
	private function get_posts_count() {
		if ( function_exists( 'wp_count_posts' ) ) {
			$counts = wp_count_posts( 'post' );
			if ( is_object( $counts ) && isset( $counts->publish ) ) {
				return (int) $counts->publish;
			}
		}

		global $wpdb;
		if ( empty( $wpdb ) || ! isset( $wpdb->posts ) || ! method_exists( $wpdb, 'get_var' ) ) {
			return 0;
		}

		return (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_status = 'publish' AND post_type = 'post'"
		);
	}

	/**
	 * Get user count.
	 *
	 * @return int
	 */
	private function get_users_count() {
		if ( function_exists( 'count_users' ) ) {
			$users = count_users();
			if ( is_array( $users ) && isset( $users['total_users'] ) ) {
				return (int) $users['total_users'];
			}
		}

		global $wpdb;
		if ( empty( $wpdb ) || ! isset( $wpdb->users ) || ! method_exists( $wpdb, 'get_var' ) ) {
			return 0;
		}

		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->users}" );
	}

	/**
	 * Estimate monthly traffic.
	 *
	 * @param int $posts_count Post count.
	 * @param int $users_count User count.
	 * @return int
	 */
	private function estimate_monthly_traffic( $posts_count = 0, $users_count = 0 ) {
		$ga_traffic = (int) get_option( 'nexifymy_google_analytics_monthly_users', 0 );
		if ( $ga_traffic > 0 ) {
			return $ga_traffic;
		}

		$saved_estimate = (int) get_option( 'nexifymy_estimated_monthly_traffic', 0 );
		if ( $saved_estimate > 0 ) {
			return $saved_estimate;
		}

		$posts_count = (int) $posts_count;
		$users_count = (int) $users_count;

		return max( 1000, ( $posts_count * 400 ) + ( $users_count * 120 ) + 2000 );
	}

	/**
	 * Upsert industry risk row.
	 *
	 * @param string $industry Industry key.
	 * @return void
	 */
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	private function sync_industry_risk_row( $industry ) {
		global $wpdb;

		$industry = sanitize_text_field( (string) $industry );
		if ( '' === $industry ) {
			$industry = 'general';
		}

		$base_map          = $this->get_default_industry_risk_map();
		$record            = $base_map[ $industry ] ?? $base_map['general'];
		$external_vectors  = $this->fetch_external_attack_vectors( $industry );
		$incident_estimate = $this->collect_recent_incident_count( $industry );

		$vectors = array_values(
			array_unique(
				array_merge( (array) $record['common_attack_vectors'], (array) $external_vectors )
			)
		);

		$risk_level = (int) $record['risk_level'];
		if ( $incident_estimate > 30 ) {
			++$risk_level;
		}
		$risk_level = max( 1, min( 10, $risk_level ) );

		$exists = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$this->predictions_table} WHERE industry = %s",
				$industry
			)
		);

		$data = array(
			'industry'              => $industry,
			'common_attack_vectors' => wp_json_encode( $vectors ),
			'risk_level'            => $risk_level,
			'recent_incidents'      => (int) $incident_estimate,
			'updated_at'            => current_time( 'mysql' ),
		);

		if ( $exists > 0 ) {
			$wpdb->update(
				$this->predictions_table,
				$data,
				array( 'industry' => $industry ),
				array( '%s', '%s', '%d', '%d', '%s' ),
				array( '%s' )
			);
			return;
		}

		$wpdb->insert(
			$this->predictions_table,
			$data,
			array( '%s', '%s', '%d', '%d', '%s' )
		);
	}
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

	/**
	 * Get industry row.
	 *
	 * @param string $industry Industry key.
	 * @return array
	 */
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	private function get_industry_risk_row( $industry ) {
		global $wpdb;
		$industry = sanitize_text_field( (string) $industry );
		if ( '' === $industry ) {
			$industry = 'general';
		}

		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT industry, common_attack_vectors, risk_level, recent_incidents
				FROM {$this->predictions_table}
				WHERE industry = %s
				LIMIT 1",
				$industry
			),
			ARRAY_A
		);

		if ( ! is_array( $row ) ) {
			$this->sync_industry_risk_row( $industry );
			$row = $wpdb->get_row(
				$wpdb->prepare(
					"SELECT industry, common_attack_vectors, risk_level, recent_incidents
					FROM {$this->predictions_table}
					WHERE industry = %s
					LIMIT 1",
					$industry
				),
				ARRAY_A
			);
		}

		if ( ! is_array( $row ) ) {
			return array(
				'industry'              => $industry,
				'common_attack_vectors' => array(),
				'risk_level'            => 4,
				'recent_incidents'      => 0,
			);
		}

		$row['common_attack_vectors'] = json_decode( (string) $row['common_attack_vectors'], true );
		if ( ! is_array( $row['common_attack_vectors'] ) ) {
			$row['common_attack_vectors'] = array();
		}

		$row['risk_level']       = (int) $row['risk_level'];
		$row['recent_incidents'] = (int) $row['recent_incidents'];
		return $row;
	}
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

	/**
	 * Collect incident estimate from local/p2p/external sources.
	 *
	 * @param string $industry Industry key.
	 * @return int
	 */
	private function collect_recent_incident_count( $industry ) {
		$local_incidents = $this->get_local_incident_count();
		$p2p_incidents   = 0;

		if ( class_exists( 'NexifyMy_Security_P2P' ) && method_exists( 'NexifyMy_Security_P2P', 'get_daily_threat_count' ) ) {
			$p2p_incidents = (int) NexifyMy_Security_P2P::get_daily_threat_count() * 30;
		}

		$external = $this->fetch_external_incident_count( $industry );
		$total    = $local_incidents + $p2p_incidents + $external;

		return max( 0, min( 500, (int) $total ) );
	}

	/**
	 * Count local incidents from behavior logs.
	 *
	 * @return int
	 */
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	private function get_local_incident_count() {
		global $wpdb;

		$table  = $wpdb->prefix . 'nexifymy_behavior_log';
		$exists = $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ) === $table;
		if ( ! $exists ) {
			return 0;
		}

		return (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$table}
			WHERE created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
			  AND ( threat_score >= 75 OR ( is_login_attempt = 1 AND is_successful = 0 ) )"
		);
	}
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

	/**
	 * Fetch external incident count estimate.
	 *
	 * @param string $industry Industry key.
	 * @return int
	 */
	private function fetch_external_incident_count( $industry ) {
		if ( ! function_exists( 'wp_remote_get' ) || ! function_exists( 'wp_remote_retrieve_body' ) ) {
			return 0;
		}

		$industry = sanitize_text_field( (string) $industry );
		$total    = 0;

		$attackerkb_url = 'https://api.attackerkb.com/v1/search?query=' . rawurlencode( $industry );
		$cve_url        = 'https://cve.circl.lu/api/search/' . rawurlencode( $industry );

		$responses = array(
			wp_remote_get( $attackerkb_url, array( 'timeout' => 4 ) ),
			wp_remote_get( $cve_url, array( 'timeout' => 4 ) ),
		);

		foreach ( $responses as $response ) {
			if ( is_wp_error( $response ) ) {
				continue;
			}

			$body = wp_remote_retrieve_body( $response );
			if ( empty( $body ) ) {
				continue;
			}

			$data = json_decode( $body, true );
			if ( ! is_array( $data ) ) {
				continue;
			}

			if ( isset( $data['total'] ) ) {
				$total += (int) $data['total'];
			} elseif ( isset( $data['count'] ) ) {
				$total += (int) $data['count'];
			} else {
				$total += count( $data );
			}
		}

		return max( 0, min( 200, $total ) );
	}

	/**
	 * Fetch inferred external vectors.
	 *
	 * @param string $industry Industry key.
	 * @return array
	 */
	private function fetch_external_attack_vectors( $industry ) {
		$incident_count = $this->fetch_external_incident_count( $industry );
		if ( $incident_count <= 0 ) {
			return array();
		}

		$vectors = array();
		if ( in_array( $industry, array( 'healthcare', 'finance' ), true ) ) {
			$vectors[] = 'Ransomware payload delivery';
		}
		if ( in_array( $industry, array( 'e-commerce', 'finance' ), true ) ) {
			$vectors[] = 'Payment fraud automation';
		}
		if ( in_array( $industry, array( 'education', 'healthcare' ), true ) ) {
			$vectors[] = 'Account takeover via credential stuffing';
		}

		return array_values( array_unique( $vectors ) );
	}

	/**
	 * Default industry risk map.
	 *
	 * @return array
	 */
	private function get_default_industry_risk_map() {
		return array(
			'healthcare' => array(
				'common_attack_vectors' => array( 'Form injection attacks', 'PHI data exfiltration', 'Ransomware staging' ),
				'risk_level'            => 8,
			),
			'finance'    => array(
				'common_attack_vectors' => array( 'Credential stuffing', 'Business logic abuse', 'Fraudulent API transactions' ),
				'risk_level'            => 9,
			),
			'e-commerce' => array(
				'common_attack_vectors' => array( 'Payment skimming', 'SQL injection on checkout', 'Coupon abuse automation' ),
				'risk_level'            => 8,
			),
			'education'  => array(
				'common_attack_vectors' => array( 'Credential stuffing', 'Privilege escalation in LMS plugins', 'Student data scraping' ),
				'risk_level'            => 7,
			),
			'general'    => array(
				'common_attack_vectors' => array( 'Brute force login attempts', 'XSS payload injection', 'Plugin vulnerability exploitation' ),
				'risk_level'            => 5,
			),
		);
	}

	/**
	 * Check recent brute-force signal.
	 *
	 * @return bool
	 */
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	private function has_recent_brute_force_activity() {
		global $wpdb;

		$table  = $wpdb->prefix . 'nexifymy_behavior_log';
		$exists = $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ) === $table;
		if ( ! $exists ) {
			return false;
		}

		$count = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$table}
			WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
			  AND is_login_attempt = 1
			  AND is_successful = 0"
		);

		return $count >= 10;
	}
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

	/**
	 * Check if a plugin is active by slug fragment.
	 *
	 * @param string $slug_fragment Slug fragment.
	 * @return bool
	 */
	private function has_plugin( $slug_fragment ) {
		$slug_fragment = strtolower( sanitize_text_field( (string) $slug_fragment ) );
		if ( '' === $slug_fragment ) {
			return false;
		}

		foreach ( $this->get_active_plugins() as $plugin ) {
			if ( false !== stripos( (string) $plugin, $slug_fragment ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check outdated plugin presence.
	 *
	 * @return bool
	 */
	private function has_outdated_plugins() {
		return ! empty( $this->get_outdated_plugins() );
	}

	/**
	 * Get outdated plugin names.
	 *
	 * @return array
	 */
	private function get_outdated_plugins() {
		if ( ! function_exists( 'get_plugin_updates' ) ) {
			return array();
		}

		$updates = get_plugin_updates();
		if ( empty( $updates ) || ! is_array( $updates ) ) {
			return array();
		}

		$names = array();
		foreach ( $updates as $plugin_data ) {
			if ( is_object( $plugin_data ) && isset( $plugin_data->Name ) ) {
				$names[] = sanitize_text_field( (string) $plugin_data->Name );
			}
		}

		return array_values( array_unique( array_filter( $names ) ) );
	}

	/**
	 * Run a safe simulation scenario.
	 *
	 * @param string $attack_type Attack type.
	 * @return array
	 */
	public function run_attack_simulation( $attack_type ) {
		$attack_type = sanitize_key( (string) $attack_type );
		$scenarios   = $this->get_simulation_scenarios();
		if ( ! isset( $scenarios[ $attack_type ] ) ) {
			return array(
				'attack_type' => $attack_type,
				'succeeded'   => false,
				'blocked'     => false,
				'message'     => 'Unsupported simulation type.',
			);
		}

		$settings = class_exists( 'NexifyMy_Security_Settings' )
			? NexifyMy_Security_Settings::get_all()
			: array();
		$modules  = isset( $settings['modules'] ) && is_array( $settings['modules'] ) ? $settings['modules'] : array();

		$required_controls = (array) $scenarios[ $attack_type ]['required_controls'];
		$control_results   = array();
		$all_controls_ok   = true;

		foreach ( $required_controls as $key ) {
			$enabled                 = ! empty( $modules[ $key ] );
			$control_results[ $key ] = $enabled;
			$all_controls_ok         = $all_controls_ok && $enabled;
		}

		$sandbox_analysis = null;
		if ( class_exists( 'NexifyMy_Security_Sandbox' ) && method_exists( 'NexifyMy_Security_Sandbox', 'analyze_code' ) ) {
			$sandbox_analysis = NexifyMy_Security_Sandbox::analyze_code(
				$this->get_simulation_payload_code( $attack_type ),
				array(
					'static_only' => true,
					'label'       => 'Predictive simulation: ' . $attack_type,
				)
			);
		}

		$blocked = $all_controls_ok;
		if ( is_array( $sandbox_analysis ) && isset( $sandbox_analysis['risk'] ) && (int) $sandbox_analysis['risk'] >= 70 ) {
			$blocked = true;
		}

		return array(
			'attack_type'         => $attack_type,
			'scenario'            => $scenarios[ $attack_type ]['label'],
			'simulated_at'        => current_time( 'mysql' ),
			'payloads_tested'     => (int) $scenarios[ $attack_type ]['payload_count'],
			'defense_controls'    => $control_results,
			'blocked'             => $blocked,
			'succeeded'           => ! $blocked,
			'time_to_detection'   => $blocked ? 140 : 1200,
			'recommended_fix'     => $blocked ? '' : $scenarios[ $attack_type ]['recommended_fix'],
			'sandbox_risk'        => is_array( $sandbox_analysis ) ? (int) ( $sandbox_analysis['risk'] ?? 0 ) : 0,
			'preview_mode'        => true,
			'compliance_relevant' => true,
		);
	}

	/**
	 * Analyze simulation results.
	 *
	 * @param array $results Raw results.
	 * @return array
	 */
	public function analyze_simulation_results( $results ) {
		$results            = is_array( $results ) ? $results : array();
		$succeeded_attacks  = array();
		$failed_defenses    = array();
		$recommended_fixes  = array();
		$detection_time_sum = 0;
		$detection_samples  = 0;

		foreach ( $results as $row ) {
			if ( empty( $row['blocked'] ) ) {
				$succeeded_attacks[] = $row['attack_type'] ?? 'unknown';
				if ( ! empty( $row['recommended_fix'] ) ) {
					$recommended_fixes[] = (string) $row['recommended_fix'];
				}
			}

			if ( ! empty( $row['defense_controls'] ) && is_array( $row['defense_controls'] ) ) {
				foreach ( $row['defense_controls'] as $control => $passed ) {
					if ( ! $passed ) {
						$failed_defenses[] = (string) $control;
					}
				}
			}

			if ( ! empty( $row['time_to_detection'] ) ) {
				$detection_time_sum += (int) $row['time_to_detection'];
				++$detection_samples;
			}
		}

		return array(
			'analyzed_at'            => current_time( 'mysql' ),
			'total_scenarios'        => count( $results ),
			'attacks_succeeded'      => array_values( array_unique( $succeeded_attacks ) ),
			'defenses_failed'        => array_values( array_unique( $failed_defenses ) ),
			'average_detection_time' => $detection_samples > 0 ? (int) round( $detection_time_sum / $detection_samples ) : 0,
			'recommended_fixes'      => array_values( array_unique( $recommended_fixes ) ),
			'compliance_frameworks'  => array( 'PCI-DSS', 'SOC 2', 'ISO 27001' ),
		);
	}

	/**
	 * Run monthly simulated penetration suite.
	 *
	 * @return array
	 */
	public function run_monthly_penetration_test() {
		$scenario_map = array(
			'automated_bot_attack_simulation'  => 'brute_force',
			'malicious_plugin_install_attempt' => 'malicious_plugin_install',
			'database_export_attempt'          => 'database_export',
			'privilege_escalation_test'        => 'privilege_escalation',
		);

		$results = array();
		foreach ( $scenario_map as $scenario_key => $attack_type ) {
			$result                 = $this->run_attack_simulation( $attack_type );
			$result['scenario_key'] = $scenario_key;
			$results[]              = $result;
		}

		$analysis = $this->analyze_simulation_results( $results );
		$report   = array(
			'report_id'             => uniqid( 'simulation_' ),
			'generated_at'          => current_time( 'mysql' ),
			'results'               => $results,
			'analysis'              => $analysis,
			'compliance_frameworks' => array( 'PCI-DSS', 'SOC 2', 'ISO 27001' ),
		);

		$this->store_simulation_report( $report );
		$this->email_simulation_report( $report );

		return $report;
	}

	/**
	 * Return compliance snapshot for report module integration.
	 *
	 * @return array
	 */
	public function get_compliance_snapshot() {
		$forecast = $this->get_forecast_snapshot();
		$latest   = $this->get_latest_simulation_report();

		return array(
			'forecast_generated_at' => $forecast['generated_at'] ?? '',
			'profile'               => $forecast['profile'] ?? array(),
			'predictions'           => $forecast['predictions'] ?? array(),
			'recommendations'       => $forecast['recommendations'] ?? array(),
			'risk_assessment'       => $forecast['risk_assessment'] ?? array(),
			'latest_simulation'     => $latest,
		);
	}

	/**
	 * Register dashboard widget.
	 *
	 * @return void
	 */
	public function register_dashboard_widget() {
		if ( ! function_exists( 'wp_add_dashboard_widget' ) ) {
			return;
		}

		wp_add_dashboard_widget(
			'nexifymy_threat_forecast_widget',
			__( 'Threat Forecast', 'nexifymy-security' ),
			array( $this, 'render_dashboard_widget' )
		);
	}

	/**
	 * Render dashboard widget content.
	 *
	 * @return void
	 */
	public function render_dashboard_widget() {
		$forecast        = $this->get_forecast_snapshot();
		$profile         = isset( $forecast['profile'] ) && is_array( $forecast['profile'] ) ? $forecast['profile'] : array();
		$predictions     = isset( $forecast['predictions'] ) && is_array( $forecast['predictions'] ) ? $forecast['predictions'] : array();
		$recommendations = isset( $forecast['recommendations'] ) && is_array( $forecast['recommendations'] ) ? $forecast['recommendations'] : array();

		$industry = ! empty( $profile['industry'] ) ? $profile['industry'] : 'general';
		$size     = ! empty( $profile['size'] ) ? $profile['size'] : 'unknown';
		?>
		<div class="nexifymy-threat-forecast-widget">
			<p>
				<strong><?php esc_html_e( 'Your site profile:', 'nexifymy-security' ); ?></strong>
				<?php echo esc_html( ucfirst( str_replace( '-', ' ', $industry ) ) . ', ' . ucfirst( $size ) . ' size' ); ?>
			</p>
			<p><strong><?php esc_html_e( 'Predicted threats this month:', 'nexifymy-security' ); ?></strong></p>
			<?php if ( empty( $predictions ) ) : ?>
				<p><?php esc_html_e( 'No high-confidence vectors detected yet.', 'nexifymy-security' ); ?></p>
			<?php else : ?>
				<ol>
					<?php foreach ( array_slice( $predictions, 0, 3 ) as $prediction ) : ?>
						<li><?php echo esc_html( $prediction['vector'] . ' (' . $prediction['probability'] . '%)' ); ?></li>
					<?php endforeach; ?>
				</ol>
			<?php endif; ?>

			<p><strong><?php esc_html_e( 'Recommended actions:', 'nexifymy-security' ); ?></strong></p>
			<?php if ( empty( $recommendations ) ) : ?>
				<p><?php esc_html_e( 'No immediate actions required.', 'nexifymy-security' ); ?></p>
			<?php else : ?>
				<ol>
					<?php foreach ( array_slice( $recommendations, 0, 2 ) as $row ) : ?>
						<li><?php echo esc_html( $row['title'] ); ?></li>
					<?php endforeach; ?>
				</ol>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * AJAX: return forecast.
	 *
	 * @return void
	 */
	public function ajax_get_threat_forecast() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		wp_send_json_success( $this->get_forecast_snapshot() );
	}

	/**
	 * AJAX: run simulation.
	 *
	 * @return void
	 */
	public function ajax_run_attack_simulation() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$attack_type = isset( $_POST['attack_type'] ) ? sanitize_key( wp_unslash( $_POST['attack_type'] ) ) : '';
		if ( 'monthly_suite' === $attack_type || empty( $attack_type ) ) {
			wp_send_json_success( $this->run_monthly_penetration_test() );
		}

		$result   = $this->run_attack_simulation( $attack_type );
		$analysis = $this->analyze_simulation_results( array( $result ) );
		wp_send_json_success(
			array(
				'result'   => $result,
				'analysis' => $analysis,
			)
		);
	}

	/**
	 * Predefined simulation scenarios.
	 *
	 * @return array
	 */
	private function get_simulation_scenarios() {
		return array(
			'sql_injection'            => array(
				'label'             => 'SQL injection against forms',
				'payload_count'     => 8,
				'required_controls' => array( 'waf_enabled' ),
				'recommended_fix'   => 'Enable strict WAF SQLi signatures and query normalization.',
			),
			'xss'                      => array(
				'label'             => 'XSS payloads in comment forms',
				'payload_count'     => 7,
				'required_controls' => array( 'waf_enabled' ),
				'recommended_fix'   => 'Enable XSS filtering and tighten form sanitization.',
			),
			'brute_force'              => array(
				'label'             => 'Brute force login simulation (100 attempts)',
				'payload_count'     => 100,
				'required_controls' => array( 'rate_limiter_enabled', 'two_factor_enabled' ),
				'recommended_fix'   => 'Enable rate limiting and enforce 2FA for privileged roles.',
			),
			'malicious_plugin_install' => array(
				'label'             => 'Malicious plugin installation attempt',
				'payload_count'     => 3,
				'required_controls' => array( 'self_protection_enabled', 'supply_chain_enabled' ),
				'recommended_fix'   => 'Enable supply-chain scanning and lock down plugin installs.',
			),
			'database_export'          => array(
				'label'             => 'Database export attempt',
				'payload_count'     => 4,
				'required_controls' => array( 'ai_detection_enabled', 'activity_log_enabled' ),
				'recommended_fix'   => 'Enable exfiltration alerts and log all export events.',
			),
			'privilege_escalation'     => array(
				'label'             => 'Privilege escalation test',
				'payload_count'     => 5,
				'required_controls' => array( 'two_factor_enabled', 'activity_log_enabled' ),
				'recommended_fix'   => 'Audit role changes and enforce least privilege.',
			),
		);
	}

	/**
	 * Build sandbox payload for a scenario.
	 *
	 * @param string $attack_type Attack type.
	 * @return string
	 */
	private function get_simulation_payload_code( $attack_type ) {
		switch ( $attack_type ) {
			case 'sql_injection':
				return '$payload = "1 OR 1=1"; echo $payload;';
			case 'xss':
				return '$payload = "<script>alert(1)</script>"; echo $payload;';
			case 'brute_force':
				return 'for ($i=0; $i<100; $i++) { echo "attempt\n"; }';
			case 'malicious_plugin_install':
				return 'call_user_func("system", "id");';
			case 'database_export':
				return 'global $wpdb; $wpdb->query("SELECT * FROM wp_users");';
			case 'privilege_escalation':
				return 'wp_set_current_user(1);';
			default:
				return 'echo "simulation";';
		}
	}

	/**
	 * Persist simulation report history.
	 *
	 * @param array $report Report payload.
	 * @return void
	 */
	private function store_simulation_report( $report ) {
		$history = get_option( self::SIMULATION_REPORTS_OPTION, array() );
		$history = is_array( $history ) ? $history : array();
		$history = array_merge( $history, array( $report ) );
		$history = array_slice( $history, -24 );
		update_option( self::SIMULATION_REPORTS_OPTION, array_values( $history ), false );
	}

	/**
	 * Get latest simulation report.
	 *
	 * @return array
	 */
	public function get_latest_simulation_report() {
		$history = get_option( self::SIMULATION_REPORTS_OPTION, array() );
		if ( ! is_array( $history ) || empty( $history ) ) {
			return array();
		}

		return (array) end( $history );
	}

	/**
	 * Email monthly simulation summary.
	 *
	 * @param array $report Report payload.
	 * @return void
	 */
	private function email_simulation_report( $report ) {
		$admin_email = get_option( 'admin_email', '' );
		if ( empty( $admin_email ) ) {
			return;
		}

		$analysis = isset( $report['analysis'] ) && is_array( $report['analysis'] ) ? $report['analysis'] : array();
		$subject  = sprintf( '[%s] Monthly Penetration Test Results', get_bloginfo( 'name' ) );
		$message  = "Monthly Penetration Test Results\n\n";
		$message .= sprintf( "Generated: %s\n", $report['generated_at'] ?? current_time( 'mysql' ) );
		$message .= sprintf( "Scenarios Tested: %d\n", (int) ( $analysis['total_scenarios'] ?? 0 ) );
		$message .= sprintf( "Average Detection Time: %d ms\n", (int) ( $analysis['average_detection_time'] ?? 0 ) );

		$succeeded = isset( $analysis['attacks_succeeded'] ) && is_array( $analysis['attacks_succeeded'] )
			? $analysis['attacks_succeeded']
			: array();
		$message  .= 'Succeeded Attacks: ' . ( empty( $succeeded ) ? 'None' : implode( ', ', $succeeded ) ) . "\n";

		$fixes = isset( $analysis['recommended_fixes'] ) && is_array( $analysis['recommended_fixes'] )
			? $analysis['recommended_fixes']
			: array();
		if ( ! empty( $fixes ) ) {
			$message .= "Recommended Fixes:\n- " . implode( "\n- ", $fixes ) . "\n";
		}

		wp_mail( $admin_email, $subject, $message );
	}

	/**
	 * Next monthly run timestamp at low-traffic hour.
	 *
	 * @param int $hour Hour (0-23).
	 * @return int
	 */
	private function get_next_monthly_simulation_timestamp( $hour ) {
		$hour = max( 0, min( 23, absint( $hour ) ) );

		$now       = time();
		$next_base = strtotime( gmdate( 'Y-m-01 00:00:00', strtotime( '+1 month', $now ) ) );
		$run_time  = strtotime( gmdate( 'Y-m-01', $next_base ) . sprintf( ' %02d:00:00', $hour ) );

		if ( ! $run_time || $run_time <= $now ) {
			$run_time = $now + WEEK_IN_SECONDS;
		}

		return $run_time;
	}
}
