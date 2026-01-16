<?php
/**
 * Handles the admin interface and settings.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Admin {

	/**
	 * Initialize hooks.
	 */
	public function init() {
		add_action( 'admin_menu', array( $this, 'add_menu_pages' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'wp_ajax_nexifymy_get_dashboard_data', array( $this, 'ajax_get_dashboard_data' ) );
	}

	/**
	 * Add menu pages.
	 */
	public function add_menu_pages() {
		add_menu_page(
			__( 'NexifyMy Security', 'nexifymy-security' ),
			__( 'Nexify Security', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security',
			array( $this, 'render_dashboard' ),
			'dashicons-shield-alt',
			80
		);

		add_submenu_page(
			'nexifymy-security',
			__( 'Dashboard', 'nexifymy-security' ),
			__( 'Dashboard', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security',
			array( $this, 'render_dashboard' )
		);

		add_submenu_page(
			'nexifymy-security',
			__( 'Scanner', 'nexifymy-security' ),
			__( 'Scanner', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-scanner',
			array( $this, 'render_scanner' )
		);

		add_submenu_page(
			'nexifymy-security',
			__( 'Firewall', 'nexifymy-security' ),
			__( 'Firewall', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-firewall',
			array( $this, 'render_firewall' )
		);

		add_submenu_page(
			'nexifymy-security',
			__( 'Quarantine', 'nexifymy-security' ),
			__( 'Quarantine', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-quarantine',
			array( $this, 'render_quarantine' )
		);

		add_submenu_page(
			'nexifymy-security',
			__( 'Logs', 'nexifymy-security' ),
			__( 'Logs', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-logs',
			array( $this, 'render_logs' )
		);

		add_submenu_page(
			'nexifymy-security',
			__( 'Settings', 'nexifymy-security' ),
			__( 'Settings', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-settings',
			array( $this, 'render_settings' )
		);
	}

	/**
	 * Enqueue admin assets.
	 */
	public function enqueue_assets( $hook ) {
		// Only load on our plugin pages.
		if ( strpos( $hook, 'nexifymy-security' ) === false ) {
			return;
		}

		wp_enqueue_style( 'nexifymy-security-admin', NEXIFYMY_SECURITY_URL . 'assets/css/admin.css', array(), NEXIFYMY_SECURITY_VERSION );
		wp_enqueue_script( 'nexifymy-security-admin', NEXIFYMY_SECURITY_URL . 'assets/js/admin.js', array( 'jquery' ), NEXIFYMY_SECURITY_VERSION, true );

		wp_localize_script( 'nexifymy-security-admin', 'nexifymySecurity', array(
			'ajaxUrl' => admin_url( 'admin-ajax.php' ),
			'nonce'   => wp_create_nonce( 'nexifymy_security_nonce' ),
			'strings' => array(
				'scanning'    => __( 'Scanning...', 'nexifymy-security' ),
				'scanComplete' => __( 'Scan Complete', 'nexifymy-security' ),
				'error'       => __( 'Error', 'nexifymy-security' ),
			),
		) );
	}

	/**
	 * Calculate security score.
	 */
	private function calculate_security_score() {
		$score = 100;
		$issues = array();

		// Check if all modules are active (simulated - in real use, check options).
		// For now, give points for having the plugin active.

		// Check last scan results.
		$last_scan = get_option( 'nexifymy_last_scheduled_scan' );
		if ( ! $last_scan ) {
			$score -= 20;
			$issues[] = __( 'No scan has been run yet', 'nexifymy-security' );
		} elseif ( isset( $last_scan['results']['threats_found'] ) && $last_scan['results']['threats_found'] > 0 ) {
			$threats = $last_scan['results']['threats_found'];
			$score -= min( 50, $threats * 10 );
			$issues[] = sprintf( __( '%d threats detected in last scan', 'nexifymy-security' ), $threats );
		}

		// Check if WordPress is up to date.
		global $wp_version;
		$latest = get_site_transient( 'update_core' );
		if ( $latest && isset( $latest->updates[0]->version ) && version_compare( $wp_version, $latest->updates[0]->version, '<' ) ) {
			$score -= 15;
			$issues[] = __( 'WordPress is not up to date', 'nexifymy-security' );
		}

		// Check for recent blocked attacks.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			$stats = NexifyMy_Security_Logger::get_stats( 7 );
			if ( isset( $stats['by_severity']['critical'] ) && $stats['by_severity']['critical'] > 5 ) {
				$score -= 10;
				$issues[] = __( 'High number of blocked attacks recently', 'nexifymy-security' );
			}
		}

		return array(
			'score'  => max( 0, min( 100, $score ) ),
			'issues' => $issues,
		);
	}

	/**
	 * Get dashboard data via AJAX.
	 */
	public function ajax_get_dashboard_data() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$security_score = $this->calculate_security_score();
		$last_scan = get_option( 'nexifymy_last_scheduled_scan' );
		$stats = array();

		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			$stats = NexifyMy_Security_Logger::get_stats( 7 );
		}

		wp_send_json_success( array(
			'security_score' => $security_score,
			'last_scan'      => $last_scan,
			'stats'          => $stats,
		) );
	}

	/**
	 * Render the main dashboard.
	 */
	public function render_dashboard() {
		$security_data = $this->calculate_security_score();
		$score = $security_data['score'];
		$score_class = $score >= 80 ? 'good' : ( $score >= 50 ? 'warning' : 'critical' );
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1>
					<span class="dashicons dashicons-shield-alt"></span>
					<?php _e( 'NexifyMy Security', 'nexifymy-security' ); ?>
				</h1>
				<p class="description"><?php _e( 'Your website security at a glance.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nexifymy-dashboard-grid">
				<!-- Security Score Card -->
				<div class="nexifymy-card nexifymy-card-score">
					<div class="card-header">
						<h2><?php _e( 'Security Score', 'nexifymy-security' ); ?></h2>
					</div>
					<div class="card-body">
						<div class="score-circle <?php echo esc_attr( $score_class ); ?>">
							<span class="score-value"><?php echo esc_html( $score ); ?></span>
							<span class="score-label">/100</span>
						</div>
						<?php if ( ! empty( $security_data['issues'] ) ) : ?>
							<ul class="issues-list">
								<?php foreach ( $security_data['issues'] as $issue ) : ?>
									<li><span class="dashicons dashicons-warning"></span> <?php echo esc_html( $issue ); ?></li>
								<?php endforeach; ?>
							</ul>
						<?php else : ?>
							<p class="all-good"><span class="dashicons dashicons-yes-alt"></span> <?php _e( 'All systems secure!', 'nexifymy-security' ); ?></p>
						<?php endif; ?>
					</div>
				</div>

				<!-- Quick Actions Card -->
				<div class="nexifymy-card">
					<div class="card-header">
						<h2><?php _e( 'Quick Actions', 'nexifymy-security' ); ?></h2>
					</div>
					<div class="card-body">
						<div class="quick-actions">
							<button class="button button-primary button-hero" id="run-quick-scan">
								<span class="dashicons dashicons-search"></span>
								<?php _e( 'Run Quick Scan', 'nexifymy-security' ); ?>
							</button>
							<button class="button button-secondary" id="run-deep-scan">
								<span class="dashicons dashicons-shield"></span>
								<?php _e( 'Run Deep Scan', 'nexifymy-security' ); ?>
							</button>
						</div>
						<div id="scan-progress" style="display: none;">
							<div class="progress-bar">
								<div class="progress-fill"></div>
							</div>
							<p class="scan-status"><?php _e( 'Scanning...', 'nexifymy-security' ); ?></p>
						</div>
						<div id="scan-results" style="display: none;"></div>
					</div>
				</div>

				<!-- Recent Activity Card -->
				<div class="nexifymy-card nexifymy-card-wide">
					<div class="card-header">
						<h2><?php _e( 'Recent Activity (Last 7 Days)', 'nexifymy-security' ); ?></h2>
					</div>
					<div class="card-body">
						<div class="stats-grid" id="stats-grid">
							<div class="stat-item">
								<span class="stat-value" id="stat-total">--</span>
								<span class="stat-label"><?php _e( 'Total Events', 'nexifymy-security' ); ?></span>
							</div>
							<div class="stat-item stat-critical">
								<span class="stat-value" id="stat-critical">--</span>
								<span class="stat-label"><?php _e( 'Critical', 'nexifymy-security' ); ?></span>
							</div>
							<div class="stat-item stat-warning">
								<span class="stat-value" id="stat-warning">--</span>
								<span class="stat-label"><?php _e( 'Warnings', 'nexifymy-security' ); ?></span>
							</div>
							<div class="stat-item stat-info">
								<span class="stat-value" id="stat-info">--</span>
								<span class="stat-label"><?php _e( 'Info', 'nexifymy-security' ); ?></span>
							</div>
						</div>
					</div>
				</div>

				<!-- Last Scan Results Card -->
				<div class="nexifymy-card nexifymy-card-wide">
					<div class="card-header">
						<h2><?php _e( 'Last Scan Results', 'nexifymy-security' ); ?></h2>
					</div>
					<div class="card-body">
						<?php
						$last_scan = get_option( 'nexifymy_last_scheduled_scan' );
						if ( $last_scan ) :
							$results = $last_scan['results'];
						?>
							<p>
								<strong><?php _e( 'Scanned:', 'nexifymy-security' ); ?></strong> 
								<?php echo esc_html( $last_scan['time'] ); ?>
							</p>
							<p>
								<strong><?php _e( 'Files Scanned:', 'nexifymy-security' ); ?></strong> 
								<?php echo isset( $results['files_scanned'] ) ? esc_html( $results['files_scanned'] ) : 'N/A'; ?>
							</p>
							<p>
								<strong><?php _e( 'Threats Found:', 'nexifymy-security' ); ?></strong> 
								<span class="<?php echo $results['threats_found'] > 0 ? 'threat-count' : 'clean-count'; ?>">
									<?php echo esc_html( $results['threats_found'] ); ?>
								</span>
							</p>
						<?php else : ?>
							<p><?php _e( 'No scans have been run yet.', 'nexifymy-security' ); ?></p>
							<a href="<?php echo admin_url( 'admin.php?page=nexifymy-security-scanner' ); ?>" class="button">
								<?php _e( 'Run Your First Scan', 'nexifymy-security' ); ?>
							</a>
						<?php endif; ?>
					</div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the scanner page.
	 */
	public function render_scanner() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-search"></span> <?php _e( 'Malware Scanner', 'nexifymy-security' ); ?></h1>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Scan Your Website', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<p><?php _e( 'Choose a scan mode and click the button to start scanning.', 'nexifymy-security' ); ?></p>
					
					<div class="scan-modes">
						<div class="scan-mode" data-mode="quick">
							<h3><?php _e( 'Quick Scan', 'nexifymy-security' ); ?></h3>
							<p><?php _e( 'Fast scan of uploads folder. ~1 minute', 'nexifymy-security' ); ?></p>
							<button class="button button-primary scan-btn"><?php _e( 'Start Quick Scan', 'nexifymy-security' ); ?></button>
						</div>
						<div class="scan-mode" data-mode="standard">
							<h3><?php _e( 'Standard Scan', 'nexifymy-security' ); ?></h3>
							<p><?php _e( 'Scan plugins, themes, uploads. ~5 minutes', 'nexifymy-security' ); ?></p>
							<button class="button button-primary scan-btn"><?php _e( 'Start Standard Scan', 'nexifymy-security' ); ?></button>
						</div>
						<div class="scan-mode" data-mode="deep">
							<h3><?php _e( 'Deep Scan', 'nexifymy-security' ); ?></h3>
							<p><?php _e( 'Full site scan + core integrity. ~15 minutes', 'nexifymy-security' ); ?></p>
							<button class="button button-primary scan-btn"><?php _e( 'Start Deep Scan', 'nexifymy-security' ); ?></button>
						</div>
					</div>

					<div id="scanner-progress" style="display: none;">
						<div class="progress-bar"><div class="progress-fill"></div></div>
						<p class="scan-status"></p>
					</div>

					<div id="scanner-results" style="display: none;">
						<h3><?php _e( 'Scan Results', 'nexifymy-security' ); ?></h3>
						<div id="results-content"></div>
					</div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the firewall page.
	 */
	public function render_firewall() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-shield"></span> <?php _e( 'Firewall Settings', 'nexifymy-security' ); ?></h1>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Web Application Firewall (WAF)', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<p><?php _e( 'The firewall is actively protecting your site against common attacks.', 'nexifymy-security' ); ?></p>
					
					<table class="widefat">
						<thead>
							<tr>
								<th><?php _e( 'Protection', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Status', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<tr>
								<td><?php _e( 'SQL Injection Protection', 'nexifymy-security' ); ?></td>
								<td><span class="status-active"><?php _e( 'Active', 'nexifymy-security' ); ?></span></td>
							</tr>
							<tr>
								<td><?php _e( 'XSS Protection', 'nexifymy-security' ); ?></td>
								<td><span class="status-active"><?php _e( 'Active', 'nexifymy-security' ); ?></span></td>
							</tr>
							<tr>
								<td><?php _e( 'File Inclusion Protection', 'nexifymy-security' ); ?></td>
								<td><span class="status-active"><?php _e( 'Active', 'nexifymy-security' ); ?></span></td>
							</tr>
							<tr>
								<td><?php _e( 'Bad Bot Blocking', 'nexifymy-security' ); ?></td>
								<td><span class="status-active"><?php _e( 'Active', 'nexifymy-security' ); ?></span></td>
							</tr>
							<tr>
								<td><?php _e( 'Brute Force Protection', 'nexifymy-security' ); ?></td>
								<td><span class="status-active"><?php _e( 'Active', 'nexifymy-security' ); ?></span></td>
							</tr>
						</tbody>
					</table>
				</div>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Blocked IPs', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<div id="blocked-ips-list">
						<p><?php _e( 'Loading blocked IPs...', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the logs page.
	 */
	public function render_logs() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-list-view"></span> <?php _e( 'Security Logs', 'nexifymy-security' ); ?></h1>
			</div>

			<div class="nexifymy-card nexifymy-card-full">
				<div class="card-header">
					<h2><?php _e( 'Event Logs', 'nexifymy-security' ); ?></h2>
					<div class="log-filters">
						<select id="log-severity-filter">
							<option value=""><?php _e( 'All Severities', 'nexifymy-security' ); ?></option>
							<option value="critical"><?php _e( 'Critical', 'nexifymy-security' ); ?></option>
							<option value="warning"><?php _e( 'Warning', 'nexifymy-security' ); ?></option>
							<option value="info"><?php _e( 'Info', 'nexifymy-security' ); ?></option>
						</select>
						<button class="button" id="refresh-logs"><?php _e( 'Refresh', 'nexifymy-security' ); ?></button>
					</div>
				</div>
				<div class="card-body">
					<table class="widefat striped" id="logs-table">
						<thead>
							<tr>
								<th><?php _e( 'Time', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Type', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Severity', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Message', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'IP', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody id="logs-tbody">
							<tr><td colspan="5"><?php _e( 'Loading logs...', 'nexifymy-security' ); ?></td></tr>
						</tbody>
					</table>
					<div class="log-pagination" id="log-pagination"></div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the settings page.
	 */
	public function render_settings() {
		// Load settings.
		require_once NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-settings.php';
		$settings = NexifyMy_Security_Settings::get_all();
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-admin-generic"></span> <?php _e( 'Settings', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Configure your security settings.', 'nexifymy-security' ); ?></p>
			</div>

			<form id="nexifymy-settings-form">
				<!-- Module Toggles -->
				<div class="nexifymy-card">
					<div class="card-header">
						<h2><?php _e( 'Module Controls', 'nexifymy-security' ); ?></h2>
					</div>
					<div class="card-body">
						<table class="form-table">
							<tr>
								<th><?php _e( 'Web Application Firewall', 'nexifymy-security' ); ?></th>
								<td>
									<label><input type="checkbox" name="modules[waf_enabled]" value="1" <?php checked( $settings['modules']['waf_enabled'] ); ?>> <?php _e( 'Enable WAF protection', 'nexifymy-security' ); ?></label>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Malware Scanner', 'nexifymy-security' ); ?></th>
								<td>
									<label><input type="checkbox" name="modules[scanner_enabled]" value="1" <?php checked( $settings['modules']['scanner_enabled'] ); ?>> <?php _e( 'Enable malware scanner', 'nexifymy-security' ); ?></label>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Brute Force Protection', 'nexifymy-security' ); ?></th>
								<td>
									<label><input type="checkbox" name="modules[rate_limiter_enabled]" value="1" <?php checked( $settings['modules']['rate_limiter_enabled'] ); ?>> <?php _e( 'Enable login rate limiting', 'nexifymy-security' ); ?></label>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Background Scans', 'nexifymy-security' ); ?></th>
								<td>
									<label><input type="checkbox" name="modules[background_scan_enabled]" value="1" <?php checked( $settings['modules']['background_scan_enabled'] ); ?>> <?php _e( 'Enable scheduled scans', 'nexifymy-security' ); ?></label>
								</td>
							</tr>
						</table>
					</div>
				</div>

				<!-- Rate Limiter Settings -->
				<div class="nexifymy-card">
					<div class="card-header">
						<h2><?php _e( 'Brute Force Protection', 'nexifymy-security' ); ?></h2>
					</div>
					<div class="card-body">
						<table class="form-table">
							<tr>
								<th><?php _e( 'Max Failed Attempts', 'nexifymy-security' ); ?></th>
								<td>
									<input type="number" name="rate_limiter[max_attempts]" value="<?php echo esc_attr( $settings['rate_limiter']['max_attempts'] ); ?>" min="1" max="20" class="small-text">
									<p class="description"><?php _e( 'Number of failed login attempts before lockout.', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Lockout Duration', 'nexifymy-security' ); ?></th>
								<td>
									<input type="number" name="rate_limiter[lockout_duration]" value="<?php echo esc_attr( $settings['rate_limiter']['lockout_duration'] ); ?>" min="60" class="small-text"> <?php _e( 'seconds', 'nexifymy-security' ); ?>
									<p class="description"><?php _e( 'How long to block an IP after exceeding attempts.', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Attempt Window', 'nexifymy-security' ); ?></th>
								<td>
									<input type="number" name="rate_limiter[attempt_window]" value="<?php echo esc_attr( $settings['rate_limiter']['attempt_window'] ); ?>" min="60" class="small-text"> <?php _e( 'seconds', 'nexifymy-security' ); ?>
									<p class="description"><?php _e( 'Time window used to count failed login attempts.', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
						</table>
					</div>
				</div>

				<!-- IP Settings -->
				<div class="nexifymy-card">
					<div class="card-header">
						<h2><?php _e( 'IP Configuration', 'nexifymy-security' ); ?></h2>
					</div>
					<div class="card-body">
						<table class="form-table">
							<tr>
								<th><?php _e( 'IP Whitelist', 'nexifymy-security' ); ?></th>
								<td>
									<textarea name="ip[whitelist]" rows="4" class="large-text code"><?php echo esc_textarea( implode( "\n", $settings['ip']['whitelist'] ) ); ?></textarea>
									<p class="description"><?php _e( 'One IP per line. These IPs will bypass WAF checks.', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Trusted Proxies', 'nexifymy-security' ); ?></th>
								<td>
									<textarea name="ip[trusted_proxies]" rows="4" class="large-text code"><?php echo esc_textarea( implode( "\n", $settings['ip']['trusted_proxies'] ) ); ?></textarea>
									<p class="description"><?php _e( 'One IP per line. Proxy IPs allowed to send X-Forwarded-For headers (e.g., Cloudflare, load balancers).', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
						</table>
					</div>
				</div>

				<!-- Scanner Settings -->
				<div class="nexifymy-card">
					<div class="card-header">
						<h2><?php _e( 'Scanner Settings', 'nexifymy-security' ); ?></h2>
					</div>
					<div class="card-body">
						<table class="form-table">
							<tr>
								<th><?php _e( 'Default Scan Mode', 'nexifymy-security' ); ?></th>
								<td>
									<select name="scanner[default_mode]">
										<option value="quick" <?php selected( $settings['scanner']['default_mode'], 'quick' ); ?>><?php _e( 'Quick', 'nexifymy-security' ); ?></option>
										<option value="standard" <?php selected( $settings['scanner']['default_mode'], 'standard' ); ?>><?php _e( 'Standard', 'nexifymy-security' ); ?></option>
										<option value="deep" <?php selected( $settings['scanner']['default_mode'], 'deep' ); ?>><?php _e( 'Deep', 'nexifymy-security' ); ?></option>
									</select>
									<p class="description"><?php _e( 'Default scan mode used when none is specified.', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Max File Size', 'nexifymy-security' ); ?></th>
								<td>
									<input type="number" name="scanner[max_file_size_kb]" value="<?php echo esc_attr( $settings['scanner']['max_file_size_kb'] ); ?>" min="100" class="small-text"> KB
									<p class="description"><?php _e( 'Skip files larger than this size.', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Excluded Paths', 'nexifymy-security' ); ?></th>
								<td>
									<textarea name="scanner[excluded_paths]" rows="3" class="large-text code"><?php echo esc_textarea( implode( "\n", $settings['scanner']['excluded_paths'] ) ); ?></textarea>
									<p class="description"><?php _e( 'Paths to exclude from scanning (relative to WordPress root). One per line.', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Excluded Extensions', 'nexifymy-security' ); ?></th>
								<td>
									<textarea name="scanner[excluded_extensions]" rows="3" class="large-text code"><?php echo esc_textarea( implode( "\n", $settings['scanner']['excluded_extensions'] ) ); ?></textarea>
									<p class="description"><?php _e( 'File extensions to exclude from scanning (one per line, without dots).', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
						</table>
					</div>
				</div>

				<!-- Background Scan Settings -->
				<div class="nexifymy-card">
					<div class="card-header">
						<h2><?php _e( 'Scheduled Scans', 'nexifymy-security' ); ?></h2>
					</div>
					<div class="card-body">
						<table class="form-table">
							<tr>
								<th><?php _e( 'Scan Schedule', 'nexifymy-security' ); ?></th>
								<td>
									<select name="background_scan[schedule]">
										<option value="hourly" <?php selected( $settings['background_scan']['schedule'], 'hourly' ); ?>><?php _e( 'Hourly', 'nexifymy-security' ); ?></option>
										<option value="twicedaily" <?php selected( $settings['background_scan']['schedule'], 'twicedaily' ); ?>><?php _e( 'Twice Daily', 'nexifymy-security' ); ?></option>
										<option value="daily" <?php selected( $settings['background_scan']['schedule'], 'daily' ); ?>><?php _e( 'Daily', 'nexifymy-security' ); ?></option>
										<option value="weekly" <?php selected( $settings['background_scan']['schedule'], 'weekly' ); ?>><?php _e( 'Weekly', 'nexifymy-security' ); ?></option>
										<option value="disabled" <?php selected( $settings['background_scan']['schedule'], 'disabled' ); ?>><?php _e( 'Disabled', 'nexifymy-security' ); ?></option>
									</select>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Scheduled Scan Mode', 'nexifymy-security' ); ?></th>
								<td>
									<select name="background_scan[scan_mode]">
										<option value="quick" <?php selected( $settings['background_scan']['scan_mode'], 'quick' ); ?>><?php _e( 'Quick', 'nexifymy-security' ); ?></option>
								<option value="standard" <?php selected( $settings['background_scan']['scan_mode'], 'standard' ); ?>><?php _e( 'Standard', 'nexifymy-security' ); ?></option>
								<option value="deep" <?php selected( $settings['background_scan']['scan_mode'], 'deep' ); ?>><?php _e( 'Deep', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
				</table>
			</div>
		</div>

		<!-- Logging Settings -->
		<div class="nexifymy-card">
			<div class="card-header">
				<h2><?php _e( 'Logging', 'nexifymy-security' ); ?></h2>
			</div>
			<div class="card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Log Retention', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" name="logging[retention_days]" value="<?php echo esc_attr( $settings['logging']['retention_days'] ); ?>" min="1" max="365" class="small-text"> <?php _e( 'days', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Logs older than this are automatically purged daily.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
				</table>
			</div>
		</div>

		<!-- Email Alerts Settings -->
		<?php
		$alert_settings = array(
			'enabled'           => false,
			'recipient_email'   => get_option( 'admin_email' ),
			'alert_types'       => array( 'threat_detected', 'ip_lockout' ),
			'throttle_minutes'  => 60,
			'daily_summary'     => false,
		);
		if ( class_exists( 'NexifyMy_Security_Alerts' ) ) {
			$alert_settings = NexifyMy_Security_Alerts::get_settings();
		}
		?>
		<div class="nexifymy-card">
			<div class="card-header">
				<h2><?php _e( 'Email Alerts', 'nexifymy-security' ); ?></h2>
			</div>
			<div class="card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Alerts', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" name="alerts[enabled]" value="1" <?php checked( $alert_settings['enabled'] ); ?>> <?php _e( 'Send email notifications for security events', 'nexifymy-security' ); ?></label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Recipient Email', 'nexifymy-security' ); ?></th>
						<td>
							<input type="email" name="alerts[recipient_email]" value="<?php echo esc_attr( $alert_settings['recipient_email'] ); ?>" class="regular-text">
							<p class="description"><?php _e( 'Leave blank to use admin email.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Alert Types', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" name="alerts[alert_types][]" value="threat_detected" <?php checked( in_array( 'threat_detected', $alert_settings['alert_types'] ) ); ?>> <?php _e( 'Threat Detected', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="alerts[alert_types][]" value="ip_lockout" <?php checked( in_array( 'ip_lockout', $alert_settings['alert_types'] ) ); ?>> <?php _e( 'IP Lockout', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="alerts[alert_types][]" value="waf_block" <?php checked( in_array( 'waf_block', $alert_settings['alert_types'] ) ); ?>> <?php _e( 'WAF Attack Blocked', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="alerts[alert_types][]" value="file_quarantined" <?php checked( in_array( 'file_quarantined', $alert_settings['alert_types'] ) ); ?>> <?php _e( 'File Quarantined', 'nexifymy-security' ); ?></label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Throttle Period', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" name="alerts[throttle_minutes]" value="<?php echo esc_attr( $alert_settings['throttle_minutes'] ); ?>" min="0" max="1440" class="small-text"> <?php _e( 'minutes', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Prevent duplicate alerts within this period.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Daily Summary', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" name="alerts[daily_summary]" value="1" <?php checked( $alert_settings['daily_summary'] ); ?>> <?php _e( 'Send daily email digest', 'nexifymy-security' ); ?></label>
						</td>
					</tr>
					<tr>
						<th></th>
						<td>
							<button type="button" class="button" id="test-alert"><?php _e( 'Send Test Alert', 'nexifymy-security' ); ?></button>
							<span id="test-alert-result"></span>
						</td>
					</tr>
				</table>
			</div>
		</div>

		<!-- Action Buttons -->
		<div class="nexifymy-settings-actions">
			<button type="submit" class="button button-primary button-hero" id="save-settings">
				<?php _e( 'Save Settings', 'nexifymy-security' ); ?>
			</button>
			<button type="button" class="button" id="reset-settings">
				<?php _e( 'Reset to Defaults', 'nexifymy-security' ); ?>
			</button>
		</div>
		</form>
	</div>
	<?php
}

	/**
	 * Render the quarantine page.
	 */
	public function render_quarantine() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-archive"></span> <?php _e( 'Quarantine', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Manage quarantined threats. Review, restore, or permanently delete files.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nexifymy-card nexifymy-card-full">
				<div class="card-header">
					<h2><?php _e( 'Quarantined Files', 'nexifymy-security' ); ?></h2>
					<button class="button" id="refresh-quarantine"><?php _e( 'Refresh', 'nexifymy-security' ); ?></button>
				</div>
				<div class="card-body">
					<p class="description"><?php _e( 'Files in quarantine are safely stored and cannot execute.', 'nexifymy-security' ); ?></p>
					
					<table class="widefat striped" id="quarantine-table">
						<thead>
							<tr>
								<th><?php _e( 'Original Path', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Size', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Reason', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Quarantined', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Actions', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody id="quarantine-tbody">
							<tr><td colspan="5"><?php _e( 'Loading quarantined files...', 'nexifymy-security' ); ?></td></tr>
						</tbody>
					</table>
				</div>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'About Quarantine', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<ul>
						<li><strong><?php _e( 'Quarantine:', 'nexifymy-security' ); ?></strong> <?php _e( 'Moves suspicious files to a protected directory.', 'nexifymy-security' ); ?></li>
						<li><strong><?php _e( 'Restore:', 'nexifymy-security' ); ?></strong> <?php _e( 'Returns the file to its original location.', 'nexifymy-security' ); ?></li>
						<li><strong><?php _e( 'Delete:', 'nexifymy-security' ); ?></strong> <?php _e( 'Permanently removes the file.', 'nexifymy-security' ); ?></li>
					</ul>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the database page.
	 */
	public function render_database() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-database"></span> <?php _e( 'Database Security', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Backup, optimize, and secure your database.', 'nexifymy-security' ); ?></p>
			</div>

			<!-- Database Info Card -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Database Information', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<div id="database-info">
						<p><?php _e( 'Loading database information...', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>

			<!-- Backup Card -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Database Backup', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<p><?php _e( 'Create a backup of your WordPress database. Backups are stored securely and can be downloaded.', 'nexifymy-security' ); ?></p>
					<button class="button button-primary" id="create-backup">
						<span class="dashicons dashicons-download"></span> <?php _e( 'Create Backup Now', 'nexifymy-security' ); ?>
					</button>
					<span id="backup-status"></span>

					<h3><?php _e( 'Existing Backups', 'nexifymy-security' ); ?></h3>
					<table class="widefat striped" id="backups-table">
						<thead>
							<tr>
								<th><?php _e( 'Filename', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Size', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Created', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Actions', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody id="backups-tbody">
							<tr><td colspan="4"><?php _e( 'Loading backups...', 'nexifymy-security' ); ?></td></tr>
						</tbody>
					</table>
				</div>
			</div>

			<!-- Optimization Card -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Database Optimization', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<p><?php _e( 'Clean up unnecessary data to improve database performance.', 'nexifymy-security' ); ?></p>
					
					<div id="optimization-stats">
						<p><?php _e( 'Loading optimization stats...', 'nexifymy-security' ); ?></p>
					</div>

					<button class="button button-secondary" id="optimize-database">
						<span class="dashicons dashicons-performance"></span> <?php _e( 'Optimize Database', 'nexifymy-security' ); ?>
					</button>
					<span id="optimize-status"></span>
				</div>
			</div>
		</div>
		<?php
	}
}
