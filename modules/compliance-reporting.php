<?php
/**
 * Compliance & Reporting Module.
 * Generates automated security audit reports with PDF export.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Compliance {

	/**
	 * Option key for report history.
	 */
	const REPORTS_OPTION = 'nexifymy_compliance_reports';

	/**
	 * Reports directory.
	 */
	const REPORTS_DIR = 'nexifymy-reports';

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'              => true,
		'auto_generate'        => true,
		'schedule'             => 'weekly',  // daily, weekly, monthly.
		'email_reports'        => true,
		'include_gdpr'         => true,
		'include_security'     => true,
		'include_performance'  => true,
		'include_threats'      => true,
		'report_format'        => 'html',    // html, pdf.
		'retention_days'       => 90,
	);

	/**
	 * Compliance checks.
	 */
	private $compliance_checks = array();

	/**
	 * Initialize the module.
	 */
	public function init() {
		$this->define_compliance_checks();

		$settings = $this->get_settings();

		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Schedule automatic reports.
		if ( ! empty( $settings['auto_generate'] ) ) {
			add_action( 'nexifymy_generate_report', array( $this, 'generate_scheduled_report' ) );

			if ( ! wp_next_scheduled( 'nexifymy_generate_report' ) ) {
				$schedule = $settings['schedule'];
				wp_schedule_event( time(), $schedule, 'nexifymy_generate_report' );
			}
		}

		// Cleanup old reports.
		add_action( 'nexifymy_cleanup_reports', array( $this, 'cleanup_old_reports' ) );
		if ( ! wp_next_scheduled( 'nexifymy_cleanup_reports' ) ) {
			wp_schedule_event( time(), 'daily', 'nexifymy_cleanup_reports' );
		}

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_generate_report', array( $this, 'ajax_generate_report' ) );
		add_action( 'wp_ajax_nexifymy_get_reports', array( $this, 'ajax_get_reports' ) );
		add_action( 'wp_ajax_nexifymy_download_report', array( $this, 'ajax_download_report' ) );
		add_action( 'wp_ajax_nexifymy_run_compliance_check', array( $this, 'ajax_run_compliance_check' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['compliance'] ) ) {
				return wp_parse_args( $all_settings['compliance'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Define compliance checks.
	 */
	private function define_compliance_checks() {
		$this->compliance_checks = array(
			// GDPR Compliance.
			'gdpr' => array(
				'name'   => 'GDPR Compliance',
				'checks' => array(
					'ssl_enabled' => array(
						'name'        => 'SSL/HTTPS Encryption',
						'description' => 'Data must be encrypted in transit.',
						'check'       => array( $this, 'check_ssl_enabled' ),
						'weight'      => 'critical',
					),
					'privacy_policy' => array(
						'name'        => 'Privacy Policy Page',
						'description' => 'Site must have a privacy policy.',
						'check'       => array( $this, 'check_privacy_policy' ),
						'weight'      => 'critical',
					),
					'data_retention' => array(
						'name'        => 'Log Retention Policy',
						'description' => 'Logs should be automatically purged.',
						'check'       => array( $this, 'check_log_retention' ),
						'weight'      => 'high',
					),
					'user_data_export' => array(
						'name'        => 'User Data Export',
						'description' => 'WordPress data export tools are available.',
						'check'       => array( $this, 'check_data_export' ),
						'weight'      => 'high',
					),
					'cookie_consent' => array(
						'name'        => 'Cookie Consent',
						'description' => 'Cookie consent mechanism is recommended.',
						'check'       => array( $this, 'check_cookie_consent' ),
						'weight'      => 'medium',
					),
				),
			),

			// Security Posture.
			'security' => array(
				'name'   => 'Security Posture',
				'checks' => array(
					'firewall_enabled' => array(
						'name'        => 'Web Application Firewall',
						'description' => 'WAF should be active.',
						'check'       => array( $this, 'check_firewall_enabled' ),
						'weight'      => 'critical',
					),
					'2fa_available' => array(
						'name'        => 'Two-Factor Authentication',
						'description' => '2FA should be available for users.',
						'check'       => array( $this, 'check_2fa_available' ),
						'weight'      => 'high',
					),
					'strong_passwords' => array(
						'name'        => 'Password Policy',
						'description' => 'Strong password requirements enforced.',
						'check'       => array( $this, 'check_password_policy' ),
						'weight'      => 'high',
					),
					'login_protection' => array(
						'name'        => 'Brute Force Protection',
						'description' => 'Rate limiting on login attempts.',
						'check'       => array( $this, 'check_login_protection' ),
						'weight'      => 'critical',
					),
					'file_integrity' => array(
						'name'        => 'File Integrity Monitoring',
						'description' => 'Scanner checks for file changes.',
						'check'       => array( $this, 'check_file_integrity' ),
						'weight'      => 'high',
					),
					'updates_current' => array(
						'name'        => 'Software Updates',
						'description' => 'WordPress core and plugins are up to date.',
						'check'       => array( $this, 'check_updates_current' ),
						'weight'      => 'critical',
					),
				),
			),

			// Access Control.
			'access' => array(
				'name'   => 'Access Control',
				'checks' => array(
					'admin_users' => array(
						'name'        => 'Administrator Accounts',
						'description' => 'Number of admin users should be minimal.',
						'check'       => array( $this, 'check_admin_users' ),
						'weight'      => 'medium',
					),
					'no_admin_username' => array(
						'name'        => 'Default Username',
						'description' => 'No user with "admin" username.',
						'check'       => array( $this, 'check_no_admin_username' ),
						'weight'      => 'high',
					),
					'file_editor_disabled' => array(
						'name'        => 'File Editor Disabled',
						'description' => 'WordPress file editor is disabled.',
						'check'       => array( $this, 'check_file_editor_disabled' ),
						'weight'      => 'high',
					),
				),
			),

			// Data Protection.
			'data' => array(
				'name'   => 'Data Protection',
				'checks' => array(
					'database_backups' => array(
						'name'        => 'Database Backups',
						'description' => 'Regular database backups are scheduled.',
						'check'       => array( $this, 'check_database_backups' ),
						'weight'      => 'critical',
					),
					'db_prefix_changed' => array(
						'name'        => 'Database Prefix',
						'description' => 'Not using default wp_ prefix.',
						'check'       => array( $this, 'check_db_prefix' ),
						'weight'      => 'medium',
					),
				),
			),
		);
	}

	/*
	 * =========================================================================
	 * COMPLIANCE CHECKS
	 * =========================================================================
	 */

	private function check_ssl_enabled() {
		return is_ssl();
	}

	private function check_privacy_policy() {
		return (bool) get_option( 'wp_page_for_privacy_policy' );
	}

	private function check_log_retention() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$settings = NexifyMy_Security_Settings::get_all();
			return ! empty( $settings['logging']['retention_days'] );
		}
		return false;
	}

	private function check_data_export() {
		// WordPress 4.9.6+ has data export tools.
		global $wp_version;
		return version_compare( $wp_version, '4.9.6', '>=' );
	}

	private function check_cookie_consent() {
		// Check for common cookie consent plugins.
		$cookie_plugins = array(
			'cookie-notice/cookie-notice.php',
			'cookie-law-info/cookie-law-info.php',
			'gdpr-cookie-consent/gdpr-cookie-consent.php',
		);

		foreach ( $cookie_plugins as $plugin ) {
			if ( is_plugin_active( $plugin ) ) {
				return true;
			}
		}

		return false;
	}

	private function check_firewall_enabled() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$settings = NexifyMy_Security_Settings::get_all();
			return ! empty( $settings['waf']['enabled'] );
		}
		return false;
	}

	private function check_2fa_available() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$settings = NexifyMy_Security_Settings::get_all();
			return ! empty( $settings['2fa']['enabled'] );
		}
		return false;
	}

	private function check_password_policy() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$settings = NexifyMy_Security_Settings::get_all();
			return ! empty( $settings['password']['enabled'] );
		}
		return false;
	}

	private function check_login_protection() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$settings = NexifyMy_Security_Settings::get_all();
			return ! empty( $settings['rate_limiter']['enabled'] );
		}
		return false;
	}

	private function check_file_integrity() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$settings = NexifyMy_Security_Settings::get_all();
			return ! empty( $settings['scanner']['enabled'] );
		}
		return false;
	}

	private function check_updates_current() {
		if ( ! function_exists( 'get_plugin_updates' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}

		$plugin_updates = get_plugin_updates();
		$core = get_preferred_from_update_core();
		$core_needs_update = $core && $core->response === 'upgrade';

		return empty( $plugin_updates ) && ! $core_needs_update;
	}

	private function check_admin_users() {
		$admins = get_users( array( 'role' => 'administrator' ) );
		return count( $admins ) <= 3;
	}

	private function check_no_admin_username() {
		return ! username_exists( 'admin' );
	}

	private function check_file_editor_disabled() {
		return defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
	}

	private function check_database_backups() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$settings = NexifyMy_Security_Settings::get_all();
			return ! empty( $settings['database']['backup_enabled'] );
		}
		return false;
	}

	private function check_db_prefix() {
		global $wpdb;
		return $wpdb->prefix !== 'wp_';
	}

	/*
	 * =========================================================================
	 * REPORT GENERATION
	 * =========================================================================
	 */

	/**
	 * Generate a comprehensive security audit report.
	 *
	 * @return array Report data.
	 */
	public function generate_report() {
		$settings = $this->get_settings();
		$report = array(
			'id'           => uniqid( 'report_' ),
			'generated_at' => current_time( 'mysql' ),
			'site_url'     => home_url(),
			'site_name'    => get_bloginfo( 'name' ),
			'wp_version'   => get_bloginfo( 'version' ),
			'php_version'  => PHP_VERSION,
			'sections'     => array(),
			'summary'      => array(
				'total_checks'  => 0,
				'passed'        => 0,
				'failed'        => 0,
				'warnings'      => 0,
				'score'         => 0,
				'grade'         => 'F',
			),
		);

		// Run compliance checks.
		$total_weight = 0;
		$earned_weight = 0;

		foreach ( $this->compliance_checks as $category_key => $category ) {
			$section = array(
				'name'   => $category['name'],
				'checks' => array(),
				'passed' => 0,
				'failed' => 0,
			);

			foreach ( $category['checks'] as $check_key => $check ) {
				$passed = call_user_func( $check['check'] );
				$weight = $this->get_weight_value( $check['weight'] );

				$total_weight += $weight;
				if ( $passed ) {
					$earned_weight += $weight;
					$section['passed']++;
					$report['summary']['passed']++;
				} else {
					$section['failed']++;
					if ( $check['weight'] === 'critical' ) {
						$report['summary']['failed']++;
					} else {
						$report['summary']['warnings']++;
					}
				}

				$section['checks'][] = array(
					'name'        => $check['name'],
					'description' => $check['description'],
					'passed'      => $passed,
					'weight'      => $check['weight'],
				);

				$report['summary']['total_checks']++;
			}

			$report['sections'][ $category_key ] = $section;
		}

		// Calculate score.
		if ( $total_weight > 0 ) {
			$report['summary']['score'] = round( ( $earned_weight / $total_weight ) * 100 );
		}
		$report['summary']['grade'] = $this->score_to_grade( $report['summary']['score'] );

		// Add threat summary if enabled.
		if ( ! empty( $settings['include_threats'] ) ) {
			$report['threats'] = $this->get_threat_summary();
		}

		// Add performance metrics if enabled.
		if ( ! empty( $settings['include_performance'] ) ) {
			$report['performance'] = $this->get_performance_metrics();
		}

		// Save report.
		$this->save_report( $report );

		return $report;
	}

	/**
	 * Get weight value for scoring.
	 *
	 * @param string $weight Weight level.
	 * @return int
	 */
	private function get_weight_value( $weight ) {
		switch ( $weight ) {
			case 'critical':
				return 15;
			case 'high':
				return 10;
			case 'medium':
				return 5;
			default:
				return 3;
		}
	}

	/**
	 * Convert score to grade.
	 *
	 * @param int $score Score.
	 * @return string Grade.
	 */
	private function score_to_grade( $score ) {
		if ( $score >= 90 ) return 'A';
		if ( $score >= 80 ) return 'B';
		if ( $score >= 70 ) return 'C';
		if ( $score >= 60 ) return 'D';
		return 'F';
	}

	/**
	 * Get threat summary from AI detection.
	 *
	 * @return array
	 */
	private function get_threat_summary() {
		global $wpdb;

		$table = $wpdb->prefix . 'nexifymy_behavior_log';
		$table_exists = $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ) === $table;

		if ( ! $table_exists ) {
			return array( 'available' => false );
		}

		$last_30_days = $wpdb->get_row(
			"SELECT 
				COUNT(*) as total_requests,
				SUM(CASE WHEN threat_score >= 75 THEN 1 ELSE 0 END) as high_threats,
				SUM(CASE WHEN threat_score >= 50 AND threat_score < 75 THEN 1 ELSE 0 END) as medium_threats,
				SUM(CASE WHEN is_login_attempt = 1 AND is_successful = 0 THEN 1 ELSE 0 END) as failed_logins
			FROM {$table}
			WHERE created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)",
			ARRAY_A
		);

		return array(
			'available'     => true,
			'period'        => '30 days',
			'total_requests'=> (int) ( $last_30_days['total_requests'] ?? 0 ),
			'high_threats'  => (int) ( $last_30_days['high_threats'] ?? 0 ),
			'medium_threats'=> (int) ( $last_30_days['medium_threats'] ?? 0 ),
			'failed_logins' => (int) ( $last_30_days['failed_logins'] ?? 0 ),
		);
	}

	/**
	 * Get performance metrics.
	 *
	 * @return array
	 */
	private function get_performance_metrics() {
		$stats = get_option( 'nexifymy_performance_stats', array() );

		return array(
			'avg_response_time' => round( $stats['avg_time_ms'] ?? 0, 2 ) . 'ms',
			'avg_memory_usage'  => round( ( $stats['avg_memory_kb'] ?? 0 ) / 1024, 2 ) . 'MB',
			'requests_tracked'  => $stats['requests_tracked'] ?? 0,
		);
	}

	/**
	 * Save report to file and database.
	 *
	 * @param array $report Report data.
	 */
	private function save_report( $report ) {
		// Save to uploads directory.
		$upload_dir = wp_upload_dir();
		$reports_dir = $upload_dir['basedir'] . '/' . self::REPORTS_DIR;

		if ( ! is_dir( $reports_dir ) ) {
			wp_mkdir_p( $reports_dir );
			file_put_contents( $reports_dir . '/.htaccess', 'Deny from all' );
			file_put_contents( $reports_dir . '/index.php', '<?php // Silence is golden' );
		}

		$filename = 'security-audit-' . date( 'Y-m-d-His' ) . '.html';
		$filepath = $reports_dir . '/' . $filename;

		// Generate HTML report.
		$html = $this->generate_html_report( $report );
		file_put_contents( $filepath, $html );

		// Store report metadata.
		$reports = get_option( self::REPORTS_OPTION, array() );
		$reports[ $report['id'] ] = array(
			'id'           => $report['id'],
			'filename'     => $filename,
			'generated_at' => $report['generated_at'],
			'score'        => $report['summary']['score'],
			'grade'        => $report['summary']['grade'],
		);

		// Keep last 50 reports.
		if ( count( $reports ) > 50 ) {
			$reports = array_slice( $reports, -50, 50, true );
		}

		update_option( self::REPORTS_OPTION, $reports, false );

		// Email if enabled.
		$settings = $this->get_settings();
		if ( ! empty( $settings['email_reports'] ) ) {
			$this->email_report( $report, $filepath );
		}
	}

	/**
	 * Generate HTML report.
	 *
	 * @param array $report Report data.
	 * @return string HTML content.
	 */
	private function generate_html_report( $report ) {
		$grade_colors = array(
			'A' => '#22c55e',
			'B' => '#84cc16',
			'C' => '#eab308',
			'D' => '#f97316',
			'F' => '#ef4444',
		);

		$grade_color = $grade_colors[ $report['summary']['grade'] ] ?? '#666';

		ob_start();
		?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Security Audit Report - <?php echo esc_html( $report['site_name'] ); ?></title>
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1a1a1a; background: #f5f5f5; }
		.container { max-width: 900px; margin: 0 auto; padding: 40px 20px; }
		.header { background: linear-gradient(135deg, #1e3a5f 0%, #2c5282 100%); color: white; padding: 40px; border-radius: 12px 12px 0 0; }
		.header h1 { font-size: 28px; margin-bottom: 8px; }
		.header p { opacity: 0.9; }
		.content { background: white; padding: 40px; border-radius: 0 0 12px 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
		.score-card { display: flex; align-items: center; justify-content: space-between; background: #f8fafc; padding: 30px; border-radius: 12px; margin-bottom: 40px; }
		.grade { width: 100px; height: 100px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 48px; font-weight: bold; color: white; background: <?php echo $grade_color; ?>; }
		.score-details { flex: 1; margin-left: 30px; }
		.score-details h2 { font-size: 24px; margin-bottom: 10px; }
		.stats { display: flex; gap: 20px; margin-top: 15px; }
		.stat { text-align: center; padding: 10px 20px; background: white; border-radius: 8px; }
		.stat-value { font-size: 24px; font-weight: bold; }
		.stat-label { font-size: 12px; color: #666; text-transform: uppercase; }
		.section { margin-bottom: 30px; }
		.section h3 { font-size: 18px; color: #1e3a5f; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #e5e7eb; }
		.check-list { list-style: none; }
		.check-item { display: flex; align-items: flex-start; padding: 12px 0; border-bottom: 1px solid #f3f4f6; }
		.check-item:last-child { border-bottom: none; }
		.check-status { width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 15px; font-size: 14px; flex-shrink: 0; }
		.check-status.pass { background: #dcfce7; color: #16a34a; }
		.check-status.fail { background: #fee2e2; color: #dc2626; }
		.check-info h4 { font-size: 14px; font-weight: 600; margin-bottom: 4px; }
		.check-info p { font-size: 13px; color: #666; }
		.weight-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; text-transform: uppercase; margin-left: 10px; }
		.weight-critical { background: #fee2e2; color: #dc2626; }
		.weight-high { background: #ffedd5; color: #ea580c; }
		.weight-medium { background: #fef9c3; color: #ca8a04; }
		.metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-top: 20px; }
		.metric { background: #f8fafc; padding: 20px; border-radius: 8px; text-align: center; }
		.metric-value { font-size: 24px; font-weight: bold; color: #1e3a5f; }
		.metric-label { font-size: 12px; color: #666; margin-top: 5px; }
		.footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb; color: #666; font-size: 13px; }
		@media print { body { background: white; } .container { padding: 0; } .content { box-shadow: none; } }
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>🛡️ Security Audit Report</h1>
			<p><?php echo esc_html( $report['site_name'] ); ?> — <?php echo esc_html( $report['site_url'] ); ?></p>
			<p style="margin-top: 10px; font-size: 14px; opacity: 0.8;">Generated: <?php echo esc_html( $report['generated_at'] ); ?></p>
		</div>
		
		<div class="content">
			<div class="score-card">
				<div class="grade"><?php echo esc_html( $report['summary']['grade'] ); ?></div>
				<div class="score-details">
					<h2>Security Score: <?php echo esc_html( $report['summary']['score'] ); ?>%</h2>
					<p>Based on <?php echo esc_html( $report['summary']['total_checks'] ); ?> compliance and security checks.</p>
					<div class="stats">
						<div class="stat">
							<div class="stat-value" style="color: #16a34a;"><?php echo esc_html( $report['summary']['passed'] ); ?></div>
							<div class="stat-label">Passed</div>
						</div>
						<div class="stat">
							<div class="stat-value" style="color: #dc2626;"><?php echo esc_html( $report['summary']['failed'] ); ?></div>
							<div class="stat-label">Critical</div>
						</div>
						<div class="stat">
							<div class="stat-value" style="color: #ca8a04;"><?php echo esc_html( $report['summary']['warnings'] ); ?></div>
							<div class="stat-label">Warnings</div>
						</div>
					</div>
				</div>
			</div>

			<?php foreach ( $report['sections'] as $section ) : ?>
			<div class="section">
				<h3><?php echo esc_html( $section['name'] ); ?> (<?php echo esc_html( $section['passed'] ); ?>/<?php echo esc_html( $section['passed'] + $section['failed'] ); ?>)</h3>
				<ul class="check-list">
					<?php foreach ( $section['checks'] as $check ) : ?>
					<li class="check-item">
						<div class="check-status <?php echo $check['passed'] ? 'pass' : 'fail'; ?>">
							<?php echo $check['passed'] ? '✓' : '✗'; ?>
						</div>
						<div class="check-info">
							<h4>
								<?php echo esc_html( $check['name'] ); ?>
								<span class="weight-badge weight-<?php echo esc_attr( $check['weight'] ); ?>"><?php echo esc_html( $check['weight'] ); ?></span>
							</h4>
							<p><?php echo esc_html( $check['description'] ); ?></p>
						</div>
					</li>
					<?php endforeach; ?>
				</ul>
			</div>
			<?php endforeach; ?>

			<?php if ( ! empty( $report['threats']['available'] ) ) : ?>
			<div class="section">
				<h3>Threat Summary (Last 30 Days)</h3>
				<div class="metrics">
					<div class="metric">
						<div class="metric-value"><?php echo esc_html( number_format( $report['threats']['total_requests'] ) ); ?></div>
						<div class="metric-label">Total Requests</div>
					</div>
					<div class="metric">
						<div class="metric-value" style="color: #dc2626;"><?php echo esc_html( $report['threats']['high_threats'] ); ?></div>
						<div class="metric-label">High Threats</div>
					</div>
					<div class="metric">
						<div class="metric-value" style="color: #ca8a04;"><?php echo esc_html( $report['threats']['failed_logins'] ); ?></div>
						<div class="metric-label">Failed Logins</div>
					</div>
				</div>
			</div>
			<?php endif; ?>

			<?php if ( ! empty( $report['performance'] ) ) : ?>
			<div class="section">
				<h3>Performance Metrics</h3>
				<div class="metrics">
					<div class="metric">
						<div class="metric-value"><?php echo esc_html( $report['performance']['avg_response_time'] ); ?></div>
						<div class="metric-label">Avg Response Time</div>
					</div>
					<div class="metric">
						<div class="metric-value"><?php echo esc_html( $report['performance']['avg_memory_usage'] ); ?></div>
						<div class="metric-label">Avg Memory Usage</div>
					</div>
					<div class="metric">
						<div class="metric-value"><?php echo esc_html( number_format( $report['performance']['requests_tracked'] ) ); ?></div>
						<div class="metric-label">Requests Tracked</div>
					</div>
				</div>
			</div>
			<?php endif; ?>

			<div class="section">
				<h3>System Information</h3>
				<table style="width: 100%; font-size: 14px;">
					<tr><td style="padding: 8px 0; border-bottom: 1px solid #f3f4f6;"><strong>WordPress Version</strong></td><td><?php echo esc_html( $report['wp_version'] ); ?></td></tr>
					<tr><td style="padding: 8px 0; border-bottom: 1px solid #f3f4f6;"><strong>PHP Version</strong></td><td><?php echo esc_html( $report['php_version'] ); ?></td></tr>
					<tr><td style="padding: 8px 0;"><strong>Report ID</strong></td><td><?php echo esc_html( $report['id'] ); ?></td></tr>
				</table>
			</div>

			<div class="footer">
				<p>Generated by NexifyMy Security</p>
				<p style="margin-top: 5px;">This report is confidential and intended for security assessment purposes only.</p>
			</div>
		</div>
	</div>
</body>
</html>
		<?php
		return ob_get_clean();
	}

	/**
	 * Email report to admin.
	 *
	 * @param array  $report Report data.
	 * @param string $filepath Path to report file.
	 */
	private function email_report( $report, $filepath ) {
		$to = get_option( 'admin_email' );
		$subject = sprintf( '[%s] Security Audit Report - Grade: %s', get_bloginfo( 'name' ), $report['summary']['grade'] );

		$message = "Security Audit Report\n\n";
		$message .= sprintf( "Site: %s\n", $report['site_url'] );
		$message .= sprintf( "Generated: %s\n\n", $report['generated_at'] );
		$message .= sprintf( "Security Grade: %s\n", $report['summary']['grade'] );
		$message .= sprintf( "Security Score: %d%%\n\n", $report['summary']['score'] );
		$message .= sprintf( "Passed: %d | Critical: %d | Warnings: %d\n\n", 
			$report['summary']['passed'],
			$report['summary']['failed'],
			$report['summary']['warnings']
		);
		$message .= "The full HTML report is attached to this email.\n";
		$message .= "You can open it in any web browser or print it to PDF.";

		$headers = array( 'Content-Type: text/plain; charset=UTF-8' );
		$attachments = array( $filepath );

		wp_mail( $to, $subject, $message, $headers, $attachments );
	}

	/**
	 * Generate scheduled report.
	 */
	public function generate_scheduled_report() {
		$this->generate_report();
	}

	/**
	 * Cleanup old reports.
	 */
	public function cleanup_old_reports() {
		$settings = $this->get_settings();
		$retention_days = $settings['retention_days'];

		$upload_dir = wp_upload_dir();
		$reports_dir = $upload_dir['basedir'] . '/' . self::REPORTS_DIR;

		if ( ! is_dir( $reports_dir ) ) {
			return;
		}

		$cutoff = time() - ( $retention_days * DAY_IN_SECONDS );

		foreach ( glob( $reports_dir . '/*.html' ) as $file ) {
			if ( filemtime( $file ) < $cutoff ) {
				unlink( $file );
			}
		}
	}

	/**
	 * Get all reports.
	 *
	 * @return array
	 */
	public function get_reports() {
		return get_option( self::REPORTS_OPTION, array() );
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	public function ajax_generate_report() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$report = $this->generate_report();
		wp_send_json_success( $report );
	}

	public function ajax_get_reports() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		wp_send_json_success( $this->get_reports() );
	}

	public function ajax_download_report() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$report_id = isset( $_POST['report_id'] ) ? sanitize_text_field( wp_unslash( $_POST['report_id'] ) ) : '';
		$reports = $this->get_reports();

		if ( ! isset( $reports[ $report_id ] ) ) {
			wp_send_json_error( 'Report not found.' );
		}

		$upload_dir = wp_upload_dir();
		$filepath = $upload_dir['basedir'] . '/' . self::REPORTS_DIR . '/' . $reports[ $report_id ]['filename'];

		if ( ! file_exists( $filepath ) ) {
			wp_send_json_error( 'Report file not found.' );
		}

		wp_send_json_success( array(
			'url' => $upload_dir['baseurl'] . '/' . self::REPORTS_DIR . '/' . $reports[ $report_id ]['filename'],
		) );
	}

	public function ajax_run_compliance_check() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$results = array();

		foreach ( $this->compliance_checks as $category_key => $category ) {
			$results[ $category_key ] = array(
				'name'   => $category['name'],
				'checks' => array(),
			);

			foreach ( $category['checks'] as $check_key => $check ) {
				$passed = call_user_func( $check['check'] );
				$results[ $category_key ]['checks'][ $check_key ] = array(
					'name'   => $check['name'],
					'passed' => $passed,
					'weight' => $check['weight'],
				);
			}
		}

		wp_send_json_success( $results );
	}
}
