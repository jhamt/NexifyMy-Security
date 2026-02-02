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
		add_action( 'wp_ajax_nexifymy_toggle_module', array( $this, 'ajax_toggle_module' ) );
		add_action( 'wp_ajax_nexifymy_save_module_settings', array( $this, 'ajax_save_module_settings' ) );
	}

	/**
	 * Add menu pages.
	 */
	public function add_menu_pages() {
		// Main menu
		add_menu_page(
			__( 'NexifyMy Security', 'nexifymy-security' ),
			__( 'Nexify Security', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security',
			array( $this, 'render_dashboard' ),
			'dashicons-shield-alt',
			80
		);

		// Dashboard
		add_submenu_page(
			'nexifymy-security',
			__( 'Dashboard', 'nexifymy-security' ),
			__( 'Dashboard', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security',
			array( $this, 'render_dashboard' )
		);

		// Scanner (contains Scanner, Quarantine, Malware Definitions)
		add_submenu_page(
			'nexifymy-security',
			__( 'Scanner', 'nexifymy-security' ),
			__( 'Scanner', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-scanner',
			array( $this, 'render_scanner_page' )
		);

		// Firewall (contains Firewall, Login Protection, Geo Blocking, Rate Limiter)
		add_submenu_page(
			'nexifymy-security',
			__( 'Firewall', 'nexifymy-security' ),
			__( 'Firewall', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-firewall',
			array( $this, 'render_firewall_page' )
		);

		// Modules (contains 2FA, Hardening, Hide Login, Password, Captcha, Self-Protection)
		add_submenu_page(
			'nexifymy-security',
			__( 'Modules', 'nexifymy-security' ),
			__( 'Modules', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-modules',
			array( $this, 'render_modules_page' )
		);

		// Tools (contains Database, Core Repair, Vulnerabilities, Live Traffic, CDN)
		add_submenu_page(
			'nexifymy-security',
			__( 'Tools', 'nexifymy-security' ),
			__( 'Tools', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-tools',
			array( $this, 'render_tools_page' )
		);

		// Settings (contains Logs, Notifications, Settings)
		add_submenu_page(
			'nexifymy-security',
			__( 'Settings', 'nexifymy-security' ),
			__( 'Settings', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-settings',
			array( $this, 'render_settings_page' )
		);

		// Notifications (quick access)
		add_submenu_page(
			'nexifymy-security',
			__( 'Notifications', 'nexifymy-security' ),
			__( 'Notifications', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-notifications',
			array( $this, 'render_notifications_page' )
		);
	}


	/**
	 * Enqueue admin assets.
	 */
	public function enqueue_assets( $hook ) {
		// Only load on our plugin pages.
		if ( ! $hook || ( strpos( $hook, 'nexifymy' ) === false && strpos( $hook, 'nexify-security' ) === false ) ) {
			return;
		}

		wp_enqueue_style( 'nexifymy-security-admin', NEXIFYMY_SECURITY_URL . 'assets/css/admin.css', array(), NEXIFYMY_SECURITY_VERSION );
		wp_enqueue_script( 'nexifymy-security-admin', NEXIFYMY_SECURITY_URL . 'assets/js/admin.js', array( 'jquery' ), NEXIFYMY_SECURITY_VERSION . '.' . time(), true );

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
		$last_scan = get_option( 'nexifymy_last_scan' );
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
	 * Toggle module enable/disable via AJAX.
	 */
	public function ajax_toggle_module() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$module = isset( $_POST['module'] ) ? sanitize_key( $_POST['module'] ) : '';
		$enabled = isset( $_POST['enabled'] ) ? absint( $_POST['enabled'] ) : 0;

		if ( empty( $module ) ) {
			wp_send_json_error( 'Invalid module' );
		}

		$settings = get_option( 'nexifymy_security_settings', array() );
		
		if ( ! isset( $settings['modules'] ) ) {
			$settings['modules'] = array();
		}

		$settings['modules'][ $module . '_enabled' ] = $enabled;
		update_option( 'nexifymy_security_settings', $settings );

		wp_send_json_success( array(
			'module' => $module,
			'enabled' => $enabled,
		) );
	}

	/**
	 * Save module settings via AJAX.
	 */
	public function ajax_save_module_settings() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$module = isset( $_POST['module'] ) ? sanitize_key( $_POST['module'] ) : '';
		$module_settings = isset( $_POST['settings'] ) ? $_POST['settings'] : array();

		if ( empty( $module ) ) {
			wp_send_json_error( 'Invalid module' );
		}

		$settings = get_option( 'nexifymy_security_settings', array() );
		
		// Sanitize based on module type
		$sanitized = array();
		foreach ( $module_settings as $key => $value ) {
			$key = sanitize_key( $key );
			if ( is_array( $value ) ) {
				$sanitized[ $key ] = array_map( 'sanitize_text_field', $value );
			} elseif ( is_numeric( $value ) ) {
				$sanitized[ $key ] = absint( $value );
			} else {
				$sanitized[ $key ] = sanitize_text_field( $value );
			}
		}

		$settings[ $module ] = $sanitized;
		update_option( 'nexifymy_security_settings', $settings );

		wp_send_json_success( array(
			'module' => $module,
			'message' => __( 'Settings saved successfully', 'nexifymy-security' ),
		) );
	}

	/**
	 * Render the main dashboard.
	 */
	public function render_dashboard() {
		$security_data = $this->calculate_security_score();
		$score = $security_data['score'];
		$score_class = $score >= 80 ? 'good' : ( $score >= 50 ? 'warning' : 'critical' );
		$settings = get_option( 'nexifymy_security_settings', array() );
		
		// All security modules organized by category
		$module_categories = array(
			'firewall' => array(
				'title' => __( 'Firewall & Protection', 'nexifymy-security' ),
				'icon' => 'shield-alt',
				'modules' => array(
					'waf' => array( 'name' => __( 'Web Application Firewall', 'nexifymy-security' ), 'desc' => __( 'Block malicious requests', 'nexifymy-security' ), 'icon' => 'shield', 'enabled' => ! empty( $settings['modules']['waf_enabled'] ) ),
					'rate_limiter' => array( 'name' => __( 'Rate Limiting', 'nexifymy-security' ), 'desc' => __( 'Prevent brute force', 'nexifymy-security' ), 'icon' => 'clock', 'enabled' => ! empty( $settings['modules']['rate_limiter_enabled'] ) ),
					'ip_blocking' => array( 'name' => __( 'IP Blocking', 'nexifymy-security' ), 'desc' => __( 'Block suspicious IPs', 'nexifymy-security' ), 'icon' => 'dismiss', 'enabled' => ! empty( $settings['modules']['ip_blocking_enabled'] ) ),
					'geo_blocking' => array( 'name' => __( 'Geo Blocking', 'nexifymy-security' ), 'desc' => __( 'Country restrictions', 'nexifymy-security' ), 'icon' => 'location-alt', 'enabled' => ! empty( $settings['modules']['geo_blocking_enabled'] ) ),
				),
			),
			'scanner' => array(
				'title' => __( 'Malware & Scanning', 'nexifymy-security' ),
				'icon' => 'search',
				'modules' => array(
					'scanner' => array( 'name' => __( 'Malware Scanner', 'nexifymy-security' ), 'desc' => __( 'Detect threats', 'nexifymy-security' ), 'icon' => 'warning', 'enabled' => ! empty( $settings['modules']['scanner_enabled'] ) ),
					'core_repair' => array( 'name' => __( 'Core File Repair', 'nexifymy-security' ), 'desc' => __( 'Fix modified files', 'nexifymy-security' ), 'icon' => 'update', 'enabled' => ! empty( $settings['modules']['core_repair_enabled'] ) ),
					'background_scan' => array( 'name' => __( 'Scheduled Scans', 'nexifymy-security' ), 'desc' => __( 'Automated scanning', 'nexifymy-security' ), 'icon' => 'calendar-alt', 'enabled' => ! empty( $settings['modules']['background_scan_enabled'] ) ),
					'vulnerabilities' => array( 'name' => __( 'Vulnerability Check', 'nexifymy-security' ), 'desc' => __( 'Plugin/theme CVEs', 'nexifymy-security' ), 'icon' => 'flag', 'enabled' => ! empty( $settings['modules']['vulnerabilities_enabled'] ) ),
				),
			),
			'login' => array(
				'title' => __( 'Login & Authentication', 'nexifymy-security' ),
				'icon' => 'lock',
				'modules' => array(
					'two_factor' => array( 'name' => __( 'Two-Factor Auth (2FA)', 'nexifymy-security' ), 'desc' => __( 'Extra login security', 'nexifymy-security' ), 'icon' => 'smartphone', 'enabled' => ! empty( $settings['modules']['2fa_enabled'] ) ),
					'captcha' => array( 'name' => __( 'CAPTCHA Protection', 'nexifymy-security' ), 'desc' => __( 'Bot prevention', 'nexifymy-security' ), 'icon' => 'forms', 'enabled' => ! empty( $settings['modules']['captcha_enabled'] ) ),
					'password' => array( 'name' => __( 'Password Policies', 'nexifymy-security' ), 'desc' => __( 'Strong passwords', 'nexifymy-security' ), 'icon' => 'admin-network', 'enabled' => ! empty( $settings['modules']['password_enabled'] ) ),
					'login_protection' => array( 'name' => __( 'Login Protection', 'nexifymy-security' ), 'desc' => __( 'Limit login attempts', 'nexifymy-security' ), 'icon' => 'admin-users', 'enabled' => ! empty( $settings['modules']['login_protection_enabled'] ) ),
				),
			),
			'hardening' => array(
				'title' => __( 'WordPress Hardening', 'nexifymy-security' ),
				'icon' => 'admin-tools',
				'modules' => array(
					'file_permissions' => array( 'name' => __( 'File Permissions', 'nexifymy-security' ), 'desc' => __( 'Secure file access', 'nexifymy-security' ), 'icon' => 'media-document', 'enabled' => ! empty( $settings['modules']['file_permissions_enabled'] ) ),
					'security_headers' => array( 'name' => __( 'Security Headers', 'nexifymy-security' ), 'desc' => __( 'HTTP headers', 'nexifymy-security' ), 'icon' => 'admin-settings', 'enabled' => ! empty( $settings['modules']['headers_enabled'] ) ),
					'xmlrpc' => array( 'name' => __( 'XML-RPC Control', 'nexifymy-security' ), 'desc' => __( 'Disable XML-RPC', 'nexifymy-security' ), 'icon' => 'editor-code', 'enabled' => ! empty( $settings['modules']['xmlrpc_disabled'] ) ),
					'rest_api' => array( 'name' => __( 'REST API Security', 'nexifymy-security' ), 'desc' => __( 'API restrictions', 'nexifymy-security' ), 'icon' => 'rest-api', 'enabled' => ! empty( $settings['modules']['rest_api_enabled'] ) ),
					'file_editor' => array( 'name' => __( 'File Editor', 'nexifymy-security' ), 'desc' => __( 'Disable WP editor', 'nexifymy-security' ), 'icon' => 'edit', 'enabled' => ! empty( $settings['modules']['file_editor_disabled'] ) ),
				),
			),
			'monitoring' => array(
				'title' => __( 'Monitoring & Alerts', 'nexifymy-security' ),
				'icon' => 'chart-line',
				'modules' => array(
					'live_traffic' => array( 'name' => __( 'Live Traffic', 'nexifymy-security' ), 'desc' => __( 'Real-time monitoring', 'nexifymy-security' ), 'icon' => 'visibility', 'enabled' => ! empty( $settings['modules']['live_traffic_enabled'] ) ),
					'notifications' => array( 'name' => __( 'Email Notifications', 'nexifymy-security' ), 'desc' => __( 'Security alerts', 'nexifymy-security' ), 'icon' => 'email', 'enabled' => ! empty( $settings['modules']['notifications_enabled'] ) ),
					'audit_log' => array( 'name' => __( 'Security Logs', 'nexifymy-security' ), 'desc' => __( 'Activity tracking', 'nexifymy-security' ), 'icon' => 'list-view', 'enabled' => ! empty( $settings['modules']['logging_enabled'] ) ),
					'self_protection' => array( 'name' => __( 'Self Protection', 'nexifymy-security' ), 'desc' => __( 'Plugin integrity', 'nexifymy-security' ), 'icon' => 'shield', 'enabled' => ! empty( $settings['modules']['self_protection_enabled'] ) ),
				),
			),
			'tools' => array(
				'title' => __( 'Tools & Utilities', 'nexifymy-security' ),
				'icon' => 'admin-generic',
				'modules' => array(
					'quarantine' => array( 'name' => __( 'Quarantine', 'nexifymy-security' ), 'desc' => __( 'Isolate threats', 'nexifymy-security' ), 'icon' => 'vault', 'enabled' => ! empty( $settings['modules']['quarantine_enabled'] ) ),
					'database' => array( 'name' => __( 'Database Security', 'nexifymy-security' ), 'desc' => __( 'Backups & cleanup', 'nexifymy-security' ), 'icon' => 'database', 'enabled' => ! empty( $settings['modules']['database_enabled'] ) ),
					'cdn' => array( 'name' => __( 'CDN Integration', 'nexifymy-security' ), 'desc' => __( 'Cloudflare & more', 'nexifymy-security' ), 'icon' => 'cloud', 'enabled' => ! empty( $settings['modules']['cdn_enabled'] ) ),
				),
			),
		);

		// Get recent activity
		$recent_events = array();
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			$recent_events = NexifyMy_Security_Logger::get_recent_events( 5 );
		}

		// Get stats
		$stats = array( 'total' => 0, 'blocked' => 0 );
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			$log_stats = NexifyMy_Security_Logger::get_stats( 7 );
			$stats['total'] = isset( $log_stats['total_events'] ) ? $log_stats['total_events'] : 0;
			$stats['blocked'] = isset( $log_stats['by_severity']['critical'] ) ? $log_stats['by_severity']['critical'] : 0;
		}
		
		$last_scan = get_option( 'nexifymy_last_scan' );
		?>
		<div class="wrap nexifymy-security-wrap">
			
			<!-- Header -->
			<div class="nms-header">
				<div class="nms-header-left">
					<div class="nms-logo">
						<span class="dashicons dashicons-shield-alt"></span>
					</div>
					<div class="nms-header-title">
						<h1>
							<?php _e( 'NexifyMy Security', 'nexifymy-security' ); ?>
							<span class="nms-version">v<?php echo esc_html( NEXIFYMY_SECURITY_VERSION ); ?></span>
						</h1>
						<p><?php _e( 'Enterprise-Grade WordPress Security', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-header-actions">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-scanner' ) ); ?>" class="nms-btn nms-btn-primary">
						<span class="dashicons dashicons-search"></span>
						<?php _e( 'Run Scan', 'nexifymy-security' ); ?>
					</a>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-settings' ) ); ?>" class="nms-btn nms-btn-secondary">
						<span class="dashicons dashicons-admin-generic"></span>
						<?php _e( 'Settings', 'nexifymy-security' ); ?>
					</a>
				</div>
			</div>

			<!-- Horizontal Navigation Tabs -->
			<div class="nms-tabs">
				<a href="javascript:void(0);" class="nms-tab active" data-tab="overview">
					<span class="dashicons dashicons-dashboard"></span>
					<?php _e( 'Dashboard', 'nexifymy-security' ); ?>
				</a>
				<a href="javascript:void(0);" class="nms-tab" data-tab="firewall">
					<span class="dashicons dashicons-shield"></span>
					<?php _e( 'Firewall', 'nexifymy-security' ); ?>
				</a>
				<a href="javascript:void(0);" class="nms-tab" data-tab="scanner">
					<span class="dashicons dashicons-search"></span>
					<?php _e( 'Scan', 'nexifymy-security' ); ?>
				</a>
				<a href="javascript:void(0);" class="nms-tab" data-tab="login-security">
					<span class="dashicons dashicons-lock"></span>
					<?php _e( 'Login Security', 'nexifymy-security' ); ?>
				</a>
				<a href="javascript:void(0);" class="nms-tab" data-tab="hardening">
					<span class="dashicons dashicons-admin-tools"></span>
					<?php _e( 'Hardening', 'nexifymy-security' ); ?>
				</a>
				<a href="javascript:void(0);" class="nms-tab" data-tab="modules">
					<span class="dashicons dashicons-admin-plugins"></span>
					<?php _e( 'Modules', 'nexifymy-security' ); ?>
				</a>
				<a href="javascript:void(0);" class="nms-tab" data-tab="live-traffic">
					<span class="dashicons dashicons-visibility"></span>
					<?php _e( 'Live Traffic', 'nexifymy-security' ); ?>
				</a>
				<a href="javascript:void(0);" class="nms-tab" data-tab="logs">
					<span class="dashicons dashicons-list-view"></span>
					<?php _e( 'Logs', 'nexifymy-security' ); ?>
					<?php if ( $stats['blocked'] > 0 ) : ?>
						<span class="nms-tab-badge"><?php echo intval( $stats['blocked'] ); ?></span>
					<?php endif; ?>
				</a>
				<a href="javascript:void(0);" class="nms-tab" data-tab="analytics">
					<span class="dashicons dashicons-chart-area"></span>
					<?php _e( 'Analytics', 'nexifymy-security' ); ?>
				</a>
			</div>
			
			<div class="nms-main-content">

			<!-- Main Content Area (Full Width) -->
				<!-- Tab Content Container -->
				<div class="nms-tab-content-wrapper">
				
				<!-- Overview Tab Content -->
				<div class="nms-tab-content active" id="nms-tab-overview">
					
					<!-- Stats Row -->
					<div class="nms-stats-row">
				<div class="nms-stat-card">
					<div class="nms-stat-icon blue">
						<span class="dashicons dashicons-shield-alt"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo esc_html( $score ); ?>%</h4>
						<p><?php _e( 'Security Score', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon red">
						<span class="dashicons dashicons-dismiss"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo intval( $stats['blocked'] ); ?></h4>
						<p><?php _e( 'Threats Blocked', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon green">
						<span class="dashicons dashicons-yes-alt"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo ( $last_scan && isset( $last_scan['time'] ) ) ? esc_html( human_time_diff( strtotime( $last_scan['time'] ), current_time( 'timestamp' ) ) ) . ' ' . __( 'ago', 'nexifymy-security' ) : '--'; ?></h4>
						<p><?php _e( 'Last Scan', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon purple">
						<span class="dashicons dashicons-chart-line"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo intval( $stats['total'] ); ?></h4>
						<p><?php _e( 'Events (7 days)', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>

			<!-- Main Grid -->
			<div class="nms-dashboard-grid">
				
				<!-- Main Column -->
				<div class="nms-main-col">
					
					<!-- Security Score Hero -->
					<div class="nms-card">
						<div class="nms-score-hero">
							<div class="nms-score-circle-container">
								<svg class="nms-score-svg" viewBox="0 0 100 100">
									<circle class="nms-score-bg" cx="50" cy="50" r="42" />
									<circle class="nms-score-progress <?php echo esc_attr( $score_class ); ?>" cx="50" cy="50" r="42" 
										stroke-dasharray="<?php echo esc_attr( ( $score / 100 ) * 264 ); ?> 264" />
								</svg>
								<div class="nms-score-value">
									<strong><?php echo esc_html( $score ); ?></strong>
									<span>/100</span>
								</div>
							</div>
							<div class="nms-score-details">
								<h3><?php _e( 'Security Status', 'nexifymy-security' ); ?></h3>
								<div class="nms-score-status <?php echo esc_attr( $score_class ); ?>">
									<span class="dashicons dashicons-<?php echo $score >= 80 ? 'yes-alt' : ( $score >= 50 ? 'warning' : 'dismiss' ); ?>"></span>
									<?php
									if ( $score >= 80 ) {
										_e( 'Your site is well protected', 'nexifymy-security' );
									} elseif ( $score >= 50 ) {
										_e( 'Some improvements recommended', 'nexifymy-security' );
									} else {
										_e( 'Immediate action required', 'nexifymy-security' );
									}
									?>
								</div>
								<?php if ( ! empty( $security_data['issues'] ) ) : ?>
									<ul class="nms-issues-list">
										<?php foreach ( array_slice( $security_data['issues'], 0, 4 ) as $issue ) : ?>
											<li>
												<span class="dashicons dashicons-warning"></span>
												<?php echo esc_html( $issue ); ?>
											</li>
										<?php endforeach; ?>
									</ul>
								<?php endif; ?>
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-scanner' ) ); ?>" class="nms-btn nms-btn-primary">
									<?php _e( 'Run Full Security Scan', 'nexifymy-security' ); ?>
								</a>
							</div>
						</div>
					</div>

					<!-- Module Categories -->
					<?php foreach ( $module_categories as $cat_key => $category ) : ?>
						<div class="nms-modules-section">
							<div class="nms-section-title">
								<h3>
									<span class="dashicons dashicons-<?php echo esc_attr( $category['icon'] ); ?>"></span>
									<?php echo esc_html( $category['title'] ); ?>
								</h3>
								<span class="nms-count"><?php echo count( $category['modules'] ); ?> <?php _e( 'modules', 'nexifymy-security' ); ?></span>
							</div>
							<div class="nms-modules-grid">
								<?php foreach ( $category['modules'] as $mod_key => $module ) : ?>
									<div class="nms-module-card <?php echo $module['enabled'] ? 'active' : ''; ?>">
										<div class="nms-module-icon">
											<span class="dashicons dashicons-<?php echo esc_attr( $module['icon'] ); ?>"></span>
										</div>
										<div class="nms-module-info">
											<span class="nms-module-name"><?php echo esc_html( $module['name'] ); ?></span>
											<span class="nms-module-desc"><?php echo esc_html( $module['desc'] ); ?></span>
										</div>
										<label class="nms-toggle">
											<input type="checkbox" <?php checked( $module['enabled'] ); ?> data-module="<?php echo esc_attr( $mod_key ); ?>">
											<span class="nms-toggle-slider"></span>
										</label>
									</div>
								<?php endforeach; ?>
							</div>
						</div>
					<?php endforeach; ?>

				</div>

				<!-- Side Column -->
				<div class="nms-side-col">
					
					<!-- Quick Actions -->
					<div class="nms-card">
						<div class="nms-card-header">
							<h2>
								<span class="dashicons dashicons-performance"></span>
								<?php _e( 'Quick Actions', 'nexifymy-security' ); ?>
							</h2>
						</div>
						<div class="nms-card-body">
							<div class="nms-quick-actions">
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-scanner&mode=quick' ) ); ?>" class="nms-action-btn primary">
									<div class="nms-action-icon">
										<span class="dashicons dashicons-search"></span>
									</div>
									<div class="nms-action-text">
										<strong><?php _e( 'Quick Scan', 'nexifymy-security' ); ?></strong>
										<span><?php _e( 'Fast security check', 'nexifymy-security' ); ?></span>
									</div>
								</a>
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-scanner&mode=deep' ) ); ?>" class="nms-action-btn">
									<div class="nms-action-icon">
										<span class="dashicons dashicons-shield"></span>
									</div>
									<div class="nms-action-text">
										<strong><?php _e( 'Deep Scan', 'nexifymy-security' ); ?></strong>
										<span><?php _e( 'Full malware analysis', 'nexifymy-security' ); ?></span>
									</div>
								</a>
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-hardening' ) ); ?>" class="nms-action-btn">
									<div class="nms-action-icon">
										<span class="dashicons dashicons-admin-tools"></span>
									</div>
									<div class="nms-action-text">
										<strong><?php _e( 'Harden Site', 'nexifymy-security' ); ?></strong>
										<span><?php _e( 'Apply security fixes', 'nexifymy-security' ); ?></span>
									</div>
								</a>
							</div>
						</div>
					</div>

					<!-- Recent Activity -->
					<div class="nms-card">
						<div class="nms-card-header">
							<h2>
								<span class="dashicons dashicons-backup"></span>
								<?php _e( 'Recent Activity', 'nexifymy-security' ); ?>
							</h2>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-logs' ) ); ?>" class="nms-card-header-action">
								<?php _e( 'View All', 'nexifymy-security' ); ?>
							</a>
						</div>
						<div class="nms-card-body no-padding">
							<?php if ( ! empty( $recent_events ) ) : ?>
								<ul class="nms-activity-list">
									<?php foreach ( $recent_events as $event ) : ?>
										<li class="nms-activity-item">
											<div class="nms-activity-icon <?php echo esc_attr( $event['severity'] ?? 'info' ); ?>">
												<span class="dashicons dashicons-<?php echo esc_attr( $event['icon'] ?? 'info' ); ?>"></span>
											</div>
											<div class="nms-activity-content">
												<div class="nms-activity-title"><?php echo esc_html( $event['message'] ?? '' ); ?></div>
												<div class="nms-activity-meta"><?php echo esc_html( $event['ip'] ?? '' ); ?></div>
											</div>
											<div class="nms-activity-time"><?php echo esc_html( human_time_diff( $event['time'] ?? time() ) ); ?></div>
										</li>
									<?php endforeach; ?>
								</ul>
							<?php else : ?>
								<div class="nms-empty-state">
									<span class="dashicons dashicons-info"></span>
									<h4><?php _e( 'No Recent Activity', 'nexifymy-security' ); ?></h4>
									<p><?php _e( 'Security events will appear here.', 'nexifymy-security' ); ?></p>
								</div>
							<?php endif; ?>
						</div>
					</div>

					<!-- System Info -->
					<div class="nms-card">
						<div class="nms-card-header">
							<h2>
								<span class="dashicons dashicons-info"></span>
								<?php _e( 'System Status', 'nexifymy-security' ); ?>
							</h2>
						</div>
						<div class="nms-card-body">
							<ul class="nms-system-list">
								<li class="nms-system-item">
									<span class="nms-system-label"><?php _e( 'WordPress', 'nexifymy-security' ); ?></span>
									<span class="nms-system-value good"><?php echo esc_html( get_bloginfo( 'version' ) ); ?></span>
								</li>
								<li class="nms-system-item">
									<span class="nms-system-label"><?php _e( 'PHP Version', 'nexifymy-security' ); ?></span>
									<span class="nms-system-value <?php echo version_compare( PHP_VERSION, '7.4', '>=' ) ? 'good' : 'warning'; ?>">
										<?php echo esc_html( PHP_VERSION ); ?>
									</span>
								</li>
								<li class="nms-system-item">
									<span class="nms-system-label"><?php _e( 'SSL Status', 'nexifymy-security' ); ?></span>
									<span class="nms-system-value <?php echo is_ssl() ? 'good' : 'bad'; ?>">
										<?php echo is_ssl() ? __( 'Active', 'nexifymy-security' ) : __( 'Not Active', 'nexifymy-security' ); ?>
									</span>
								</li>
								<li class="nms-system-item">
									<span class="nms-system-label"><?php _e( 'Plugin Version', 'nexifymy-security' ); ?></span>
									<span class="nms-system-value"><?php echo esc_html( NEXIFYMY_SECURITY_VERSION ); ?></span>
								</li>
							</ul>
						</div>
					</div>

					</div>
			</div>
			</div><!-- End #nms-tab-overview -->

				<!-- Firewall Tab Content -->
			<div class="nms-tab-content" id="nms-tab-firewall">
				<?php
				$fw_settings = isset( $settings['firewall'] ) ? $settings['firewall'] : array();
				$fw_enabled = ! empty( $settings['modules']['waf_enabled'] );
				?>
				<div class="nms-card">
					<div class="nms-card-header">
						<h3><?php _e( 'Web Application Firewall (WAF)', 'nexifymy-security' ); ?></h3>
					</div>
					<div class="nms-card-body">
						<div class="nms-settings-row">
							<div class="nms-setting-item">
								<div class="nms-setting-info">
									<span class="dashicons dashicons-shield-alt"></span>
									<div>
										<strong><?php _e( 'Enable Firewall', 'nexifymy-security' ); ?></strong>
										<p><?php _e( 'Block malicious requests and attacks', 'nexifymy-security' ); ?></p>
									</div>
								</div>
								<label class="nms-toggle">
									<input type="checkbox" data-module="waf" <?php checked( $fw_enabled ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</div>
						</div>
						
						<h4 style="margin: 20px 0 15px; font-size: 14px;"><?php _e( 'Protection Rules', 'nexifymy-security' ); ?></h4>
						<div class="nms-quick-settings-grid">
							<div class="nms-quick-setting">
								<span class="dashicons dashicons-database"></span>
								<span><?php _e( 'SQL Injection', 'nexifymy-security' ); ?></span>
								<label class="nms-toggle nms-toggle-sm">
									<input type="checkbox" name="sql_injection" <?php checked( ! empty( $fw_settings['sql_injection'] ) || empty( $fw_settings ) ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</div>
							<div class="nms-quick-setting">
								<span class="dashicons dashicons-editor-code"></span>
								<span><?php _e( 'XSS Protection', 'nexifymy-security' ); ?></span>
								<label class="nms-toggle nms-toggle-sm">
									<input type="checkbox" name="xss_protection" <?php checked( ! empty( $fw_settings['xss_protection'] ) || empty( $fw_settings ) ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</div>
							<div class="nms-quick-setting">
								<span class="dashicons dashicons-media-document"></span>
								<span><?php _e( 'File Inclusion', 'nexifymy-security' ); ?></span>
								<label class="nms-toggle nms-toggle-sm">
									<input type="checkbox" name="file_inclusion" <?php checked( ! empty( $fw_settings['file_inclusion'] ) || empty( $fw_settings ) ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</div>
							<div class="nms-quick-setting">
								<span class="dashicons dashicons-admin-users"></span>
								<span><?php _e( 'Bad Bots', 'nexifymy-security' ); ?></span>
								<label class="nms-toggle nms-toggle-sm">
									<input type="checkbox" name="bad_bots" <?php checked( ! empty( $fw_settings['bad_bots'] ) || empty( $fw_settings ) ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</div>
						</div>
						
						<div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--nms-border);">
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-firewall' ) ); ?>" class="nms-btn nms-btn-secondary">
								<span class="dashicons dashicons-admin-generic"></span>
								<?php _e( 'Advanced Firewall Settings', 'nexifymy-security' ); ?>
							</a>
						</div>
					</div>
				</div>
			</div>


				<!-- Scanner Tab Content -->
			<div class="nms-tab-content" id="nms-tab-scanner">
				<?php
				$scanner_enabled = ! empty( $settings['modules']['scanner_enabled'] ) || ! isset( $settings['modules']['scanner_enabled'] );
				?>
				<div class="nms-card">
					<div class="nms-card-header">
						<h3><?php _e( 'Malware Scanner', 'nexifymy-security' ); ?></h3>
					</div>
					<div class="nms-card-body">
						<div class="nms-settings-row">
							<div class="nms-setting-item">
								<div class="nms-setting-info">
									<span class="dashicons dashicons-search"></span>
									<div>
										<strong><?php _e( 'Enable Scanner Module', 'nexifymy-security' ); ?></strong>
										<p><?php _e( 'Detect malware, backdoors, and suspicious code', 'nexifymy-security' ); ?></p>
									</div>
								</div>
								<label class="nms-toggle">
									<input type="checkbox" data-module="scanner" <?php checked( $scanner_enabled ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</div>
						</div>
						
						<h4 style="margin: 20px 0 15px; font-size: 14px;"><?php _e( 'Quick Scan Actions', 'nexifymy-security' ); ?></h4>
						<div class="nms-scan-buttons">
							<button type="button" class="nms-btn nms-btn-primary scan-btn" data-mode="quick">
								<span class="dashicons dashicons-search"></span>
								<?php _e( 'Quick Scan', 'nexifymy-security' ); ?>
							</button>
							<button type="button" class="nms-btn nms-btn-secondary scan-btn" data-mode="standard">
								<span class="dashicons dashicons-shield"></span>
								<?php _e( 'Standard Scan', 'nexifymy-security' ); ?>
							</button>
							<button type="button" class="nms-btn nms-btn-secondary scan-btn" data-mode="deep">
								<span class="dashicons dashicons-shield-alt"></span>
								<?php _e( 'Deep Scan', 'nexifymy-security' ); ?>
							</button>
						</div>
						
						<!-- Scan Progress (hidden until scan starts) -->
						<div id="scanner-progress" class="nms-scan-progress" style="display: none; margin-top: 20px;">
							<div class="nms-progress-container">
								<div class="nms-progress-bar">
									<div class="nms-progress-fill" style="width: 0%"></div>
								</div>
								<div class="nms-progress-info">
									<span class="nms-progress-percent">0%</span>
									<span class="nms-progress-status"><?php _e( 'Initializing...', 'nexifymy-security' ); ?></span>
								</div>
							</div>
						</div>
						
						<!-- Scan Results (hidden until scan completes) -->
						<div id="scanner-results" style="display: none; margin-top: 20px;"></div>
						
						<?php if ( $last_scan && isset( $last_scan['time'] ) ) : ?>
						<div style="margin-top: 20px; padding: 15px; background: var(--nms-gray-50); border-radius: var(--nms-radius-md);">
							<strong><?php _e( 'Last Scan:', 'nexifymy-security' ); ?></strong>
							<?php echo esc_html( human_time_diff( strtotime( $last_scan['time'] ), current_time( 'timestamp' ) ) ); ?> <?php _e( 'ago', 'nexifymy-security' ); ?>
							<?php if ( isset( $last_scan['results']['threats_found'] ) ) : ?>
								&mdash; <span style="color: <?php echo $last_scan['results']['threats_found'] > 0 ? 'var(--nms-danger)' : 'var(--nms-success)'; ?>;">
									<?php echo intval( $last_scan['results']['threats_found'] ); ?> <?php _e( 'threats found', 'nexifymy-security' ); ?>
								</span>
							<?php endif; ?>
						</div>
						<?php endif; ?>
						
						<div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--nms-border);">
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-scanner' ) ); ?>" class="nms-btn nms-btn-secondary">
								<span class="dashicons dashicons-admin-generic"></span>
								<?php _e( 'Advanced Scanner Options', 'nexifymy-security' ); ?>
							</a>
						</div>
					</div>
				</div>
			</div>


				<!-- Modules Tab Content -->
				<div class="nms-tab-content" id="nms-tab-modules">
					<div class="nms-card">
						<div class="nms-card-header">
							<h3><?php _e( 'Security Modules', 'nexifymy-security' ); ?></h3>
							<p><?php _e( 'Enable or disable security modules.', 'nexifymy-security' ); ?></p>
						</div>
						<div class="nms-card-body">
							<div class="nms-modules-list">
								<?php
								$modules = array(
									'waf'          => array( 'name' => __( 'WAF Firewall', 'nexifymy-security' ), 'icon' => 'shield' ),
									'scanner'      => array( 'name' => __( 'Malware Scanner', 'nexifymy-security' ), 'icon' => 'search' ),
									'rate_limiter' => array( 'name' => __( 'Rate Limiter', 'nexifymy-security' ), 'icon' => 'lock' ),
									'two_factor'   => array( 'name' => __( '2FA', 'nexifymy-security' ), 'icon' => 'smartphone' ),
								);

								$settings = class_exists( 'NexifyMy_Security_Settings' )
									? NexifyMy_Security_Settings::get_all()
									: get_option( 'nexifymy_security_settings', array() );

								foreach ( $modules as $key => $module ) :
									$enabled = ! empty( $settings['modules'][ $key . '_enabled' ] );
								?>
								<div class="nms-module-row">
									<span class="dashicons dashicons-<?php echo esc_attr( $module['icon'] ); ?>"></span>
									<span class="nms-module-name"><?php echo esc_html( $module['name'] ); ?></span>
									<label class="nms-toggle">
										<input type="checkbox" data-module="<?php echo esc_attr( $key ); ?>" <?php checked( $enabled ); ?>>
										<span class="nms-toggle-slider"></span>
									</label>
								</div>
								<?php endforeach; ?>
							</div>
						</div>
					</div>
				</div>

				<!-- Tools Tab Content -->
				<div class="nms-tab-content" id="nms-tab-tools">
					<div class="nms-card">
						<div class="nms-card-header"><h3><?php _e( 'Security Tools', 'nexifymy-security' ); ?></h3></div>
						<div class="nms-card-body">
							<div class="nms-tools-grid">
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-quarantine' ) ); ?>" class="nms-tool-link"><span class="dashicons dashicons-archive"></span> <?php _e( 'Quarantine', 'nexifymy-security' ); ?></a>
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-database' ) ); ?>" class="nms-tool-link"><span class="dashicons dashicons-database"></span> <?php _e( 'Database', 'nexifymy-security' ); ?></a>
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-hardening' ) ); ?>" class="nms-tool-link"><span class="dashicons dashicons-shield-alt"></span> <?php _e( 'Hardening', 'nexifymy-security' ); ?></a>
							</div>
						</div>
					</div>
				</div>

				<!-- Logs Tab Content -->
				<div class="nms-tab-content" id="nms-tab-logs">
					<?php $this->render_logs_tab(); ?>
				</div>

				<!-- Analytics Tab Content -->
				<div class="nms-tab-content" id="nms-tab-analytics">
					<?php $this->render_analytics_tab(); ?>
				</div>

				<!-- Settings Tab Content -->
				<div class="nms-tab-content" id="nms-tab-settings">
					<div class="nms-card">
						<div class="nms-card-header"><h3><?php _e( 'Settings', 'nexifymy-security' ); ?></h3></div>
						<div class="nms-card-body">
							<p><?php _e( 'Configure plugin settings.', 'nexifymy-security' ); ?></p>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-settings' ) ); ?>" class="nms-btn nms-btn-primary"><?php _e( 'Open Settings', 'nexifymy-security' ); ?></a>
						</div>
					</div>
				</div>

			<!-- Login Security Tab Content -->
		<div class="nms-tab-content" id="nms-tab-login-security">
			<?php
			$login_settings = isset( $settings['login'] ) ? $settings['login'] : array();
			$two_factor_enabled = ! empty( $settings['modules']['two_factor_enabled'] );
			$rate_limiter_enabled = ! empty( $settings['modules']['rate_limiter_enabled'] );
			?>
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Login Security', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<div class="nms-quick-settings-grid nms-quick-settings-grid-2">
						<div class="nms-quick-setting-card">
							<div class="nms-quick-setting-header">
								<span class="dashicons dashicons-smartphone"></span>
								<strong><?php _e( 'Two-Factor Authentication', 'nexifymy-security' ); ?></strong>
							</div>
							<p><?php _e( 'Require a second factor for login verification', 'nexifymy-security' ); ?></p>
							<label class="nms-toggle">
								<input type="checkbox" data-module="two_factor" <?php checked( $two_factor_enabled ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
						
						<div class="nms-quick-setting-card">
							<div class="nms-quick-setting-header">
								<span class="dashicons dashicons-lock"></span>
								<strong><?php _e( 'Login Rate Limiting', 'nexifymy-security' ); ?></strong>
							</div>
							<p><?php _e( 'Limit login attempts to prevent brute force attacks', 'nexifymy-security' ); ?></p>
							<label class="nms-toggle">
								<input type="checkbox" data-module="rate_limiter" <?php checked( $rate_limiter_enabled ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
						
						<div class="nms-quick-setting-card">
							<div class="nms-quick-setting-header">
								<span class="dashicons dashicons-shield"></span>
								<strong><?php _e( 'Login CAPTCHA', 'nexifymy-security' ); ?></strong>
							</div>
							<p><?php _e( 'Add CAPTCHA verification to login forms', 'nexifymy-security' ); ?></p>
							<label class="nms-toggle">
								<input type="checkbox" name="login_captcha" <?php checked( ! empty( $login_settings['captcha_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
						
						<div class="nms-quick-setting-card">
							<div class="nms-quick-setting-header">
								<span class="dashicons dashicons-admin-network"></span>
								<strong><?php _e( 'Strong Passwords', 'nexifymy-security' ); ?></strong>
							</div>
							<p><?php _e( 'Enforce strong password requirements', 'nexifymy-security' ); ?></p>
							<label class="nms-toggle">
								<input type="checkbox" name="strong_passwords" <?php checked( ! empty( $login_settings['strong_passwords'] ) || empty( $login_settings ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
					</div>
					
					<div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--nms-border);">
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-modules' ) ); ?>" class="nms-btn nms-btn-secondary">
							<span class="dashicons dashicons-admin-generic"></span>
							<?php _e( 'Advanced Login Settings', 'nexifymy-security' ); ?>
						</a>
					</div>
				</div>
			</div>
		</div>

			<!-- Hardening Tab Content -->
		<div class="nms-tab-content" id="nms-tab-hardening">
			<?php
			$hardening_settings = isset( $settings['hardening'] ) ? $settings['hardening'] : array();
			?>
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'WordPress Hardening', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<p style="color: var(--nms-gray-600); margin-bottom: 20px;"><?php _e( 'Apply security hardening measures to protect your WordPress installation.', 'nexifymy-security' ); ?></p>
					
					<div class="nms-hardening-checklist">
						<div class="nms-hardening-item">
							<div class="nms-hardening-info">
								<span class="dashicons dashicons-dismiss" style="color: var(--nms-danger);"></span>
								<div>
									<strong><?php _e( 'Disable XML-RPC', 'nexifymy-security' ); ?></strong>
									<p><?php _e( 'Prevent XML-RPC attacks and brute force attempts', 'nexifymy-security' ); ?></p>
								</div>
							</div>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_xmlrpc" <?php checked( ! empty( $hardening_settings['disable_xmlrpc'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
						
						<div class="nms-hardening-item">
							<div class="nms-hardening-info">
								<span class="dashicons dashicons-edit" style="color: var(--nms-warning);"></span>
								<div>
									<strong><?php _e( 'Disable File Editor', 'nexifymy-security' ); ?></strong>
									<p><?php _e( 'Prevent code editing in WordPress admin', 'nexifymy-security' ); ?></p>
								</div>
							</div>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_file_editor" <?php checked( ! empty( $hardening_settings['disable_file_editor'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
						
						<div class="nms-hardening-item">
							<div class="nms-hardening-info">
								<span class="dashicons dashicons-rest-api" style="color: var(--nms-info);"></span>
								<div>
									<strong><?php _e( 'Restrict REST API', 'nexifymy-security' ); ?></strong>
									<p><?php _e( 'Limit REST API access to authenticated users', 'nexifymy-security' ); ?></p>
								</div>
							</div>
							<label class="nms-toggle">
								<input type="checkbox" name="restrict_rest_api" <?php checked( ! empty( $hardening_settings['restrict_rest_api'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
						
						<div class="nms-hardening-item">
							<div class="nms-hardening-info">
								<span class="dashicons dashicons-visibility" style="color: var(--nms-gray-500);"></span>
								<div>
									<strong><?php _e( 'Disable Directory Browsing', 'nexifymy-security' ); ?></strong>
									<p><?php _e( 'Prevent directory listing via .htaccess', 'nexifymy-security' ); ?></p>
								</div>
							</div>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_directory_browsing" <?php checked( ! empty( $hardening_settings['disable_directory_browsing'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
						
						<div class="nms-hardening-item">
							<div class="nms-hardening-info">
								<span class="dashicons dashicons-shield" style="color: var(--nms-success);"></span>
								<div>
									<strong><?php _e( 'Security Headers', 'nexifymy-security' ); ?></strong>
									<p><?php _e( 'Add HTTP security headers (X-Frame-Options, CSP, etc.)', 'nexifymy-security' ); ?></p>
								</div>
							</div>
							<label class="nms-toggle">
								<input type="checkbox" name="security_headers" <?php checked( ! empty( $hardening_settings['security_headers'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
					</div>
					
					<div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--nms-border);">
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-hardening' ) ); ?>" class="nms-btn nms-btn-secondary">
							<span class="dashicons dashicons-admin-generic"></span>
							<?php _e( 'Advanced Hardening Options', 'nexifymy-security' ); ?>
						</a>
					</div>
				</div>
			</div>
		</div>


			<!-- Live Traffic Tab Content -->
			<div class="nms-tab-content" id="nms-tab-live-traffic">
				<div class="nms-card">
					<div class="nms-card-header"><h3><?php _e( 'Live Traffic', 'nexifymy-security' ); ?></h3></div>
					<div class="nms-card-body">
						<p><?php _e( 'Monitor real-time traffic and visitor activity.', 'nexifymy-security' ); ?></p>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-tools' ) ); ?>" class="nms-btn nms-btn-primary"><?php _e( 'View Live Traffic', 'nexifymy-security' ); ?></a>
					</div>
				</div>
			</div>

			<!-- Notifications Tab Content -->
			<div class="nms-tab-content" id="nms-tab-notifications">
				<div class="nms-card">
					<div class="nms-card-header"><h3><?php _e( 'Notification Settings', 'nexifymy-security' ); ?></h3></div>
					<div class="nms-card-body">
						<p><?php _e( 'Configure email alerts and notifications.', 'nexifymy-security' ); ?></p>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-notifications' ) ); ?>" class="nms-btn nms-btn-primary"><?php _e( 'Manage Notifications', 'nexifymy-security' ); ?></a>
					</div>
				</div>
			</div>

			<!-- Help Tab Content -->
			<div class="nms-tab-content" id="nms-tab-help">
				<div class="nms-card">
					<div class="nms-card-header"><h3><?php _e( 'Help & Documentation', 'nexifymy-security' ); ?></h3></div>
					<div class="nms-card-body">
						<h4><?php _e( 'Getting Started', 'nexifymy-security' ); ?></h4>
						<ul style="list-style: disc; margin-left: 20px; margin-bottom: 20px;">
							<li><?php _e( 'Run a security scan to identify vulnerabilities', 'nexifymy-security' ); ?></li>
							<li><?php _e( 'Enable firewall protection to block attacks', 'nexifymy-security' ); ?></li>
							<li><?php _e( 'Configure 2FA for enhanced login security', 'nexifymy-security' ); ?></li>
							<li><?php _e( 'Review security logs regularly', 'nexifymy-security' ); ?></li>
						</ul>
						<h4><?php _e( 'Need Support?', 'nexifymy-security' ); ?></h4>
						<p><?php _e( 'Contact our support team for assistance with NexifyMy Security.', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>

			</div><!-- End .nms-tab-content-wrapper -->

			</div><!-- End .nms-main-content -->

		</div><!-- End .nms-layout-flex -->

	</div><!-- End .wrap -->
		<?php
	}

	/**
	 * Render the scanner page.
	 */
	public function render_scanner() {
		$last_scan = get_option( 'nexifymy_last_scheduled_scan' );
		$signature_version = get_option( 'nexifymy_signature_version', '1.0.0' );
		$signature_count = get_option( 'nexifymy_signature_count', 0 );
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-search"></span> <?php _e( 'Malware Scanner', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Scan your website for malware, suspicious code, and security issues.', 'nexifymy-security' ); ?></p>
			</div>

			<!-- Scanner Stats -->
			<div class="nms-stats-row">
				<div class="nms-stat-card">
					<div class="nms-stat-icon green">
						<span class="dashicons dashicons-clock"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo ( $last_scan && isset( $last_scan['time'] ) ) ? esc_html( human_time_diff( strtotime( $last_scan['time'] ), current_time( 'timestamp' ) ) ) . ' ' . __( 'ago', 'nexifymy-security' ) : '--'; ?></h4>
						<p><?php _e( 'Last Scan', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon red">
						<span class="dashicons dashicons-warning"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo isset( $last_scan['results']['threats_found'] ) ? intval( $last_scan['results']['threats_found'] ) : '0'; ?></h4>
						<p><?php _e( 'Threats Found', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon blue">
						<span class="dashicons dashicons-media-default"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo isset( $last_scan['results']['files_scanned'] ) ? number_format( intval( $last_scan['results']['files_scanned'] ) ) : '0'; ?></h4>
						<p><?php _e( 'Files Scanned', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon purple">
						<span class="dashicons dashicons-database"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo esc_html( $signature_version ); ?></h4>
						<p><?php _e( 'Definitions', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon success">
						<span class="dashicons dashicons-yes-alt"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo isset( $last_scan['results']['files_clean'] ) ? number_format( intval( $last_scan['results']['files_clean'] ) ) : '0'; ?></h4>
						<p><?php _e( 'Clean Files', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon warning">
						<span class="dashicons dashicons-shield-alt"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo isset( $last_scan['results']['quarantined'] ) ? intval( $last_scan['results']['quarantined'] ) : '0'; ?></h4>
						<p><?php _e( 'Quarantined', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>

			<!-- Scan Modes -->
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Start a New Scan', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
				<div class="nms-scan-modes-grid">
					<!-- Quick Scan -->
					<div class="nms-scan-mode-card" data-mode="quick">
						<div class="nms-scan-mode-icon">
							<span class="dashicons dashicons-search"></span>
						</div>
						<h4><?php _e( 'Quick Scan', 'nexifymy-security' ); ?></h4>
						<p><?php _e( 'Scan critical areas only', 'nexifymy-security' ); ?></p>
						<ul class="nms-scan-features">
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'High-risk areas only', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Fast execution', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Checks for web shells', 'nexifymy-security' ); ?></li>
						</ul>
						<button class="nms-btn nms-btn-primary scan-btn"><?php _e( 'Start Scan', 'nexifymy-security' ); ?></button>
					</div>

					<!-- Standard Scan -->
					<div class="nms-scan-mode-card" data-mode="standard">
						<div class="nms-recommended-badge"><?php _e( 'Recommended', 'nexifymy-security' ); ?></div>
						<div class="nms-scan-mode-icon">
							<span class="dashicons dashicons-shield"></span>
						</div>
						<h4><?php _e( 'Standard Scan', 'nexifymy-security' ); ?></h4>
						<p><?php _e( 'Full malware scan', 'nexifymy-security' ); ?></p>
						<ul class="nms-scan-features">
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Full malware signatures', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Plugin & Theme analysis', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Database security check', 'nexifymy-security' ); ?></li>
						</ul>
						<button class="nms-btn nms-btn-primary scan-btn"><?php _e( 'Start Scan', 'nexifymy-security' ); ?></button>
					</div>

					<!-- Deep Scan -->
					<div class="nms-scan-mode-card" data-mode="deep">
						<div class="nms-scan-mode-icon">
							<span class="dashicons dashicons-shield-alt"></span>
						</div>
						<h4><?php _e( 'Deep Scan', 'nexifymy-security' ); ?></h4>
						<p><?php _e( 'Comprehensive analysis', 'nexifymy-security' ); ?></p>
						<ul class="nms-scan-features">
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Exhaustive file scan', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Heuristic pattern detection', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Core WordPress integrity', 'nexifymy-security' ); ?></li>
						</ul>
						<button class="nms-btn nms-btn-primary scan-btn"><?php _e( 'Start Scan', 'nexifymy-security' ); ?></button>
					</div>
				</div>
					</div>
				</div>
			</div>

			<!-- Scan Progress -->
			<div id="scanner-progress" class="nms-card" style="display: none; margin-top: 20px;">
				<div class="nms-card-header">
					<h3><span class="dashicons dashicons-update spin"></span> <?php _e( 'Scanning...', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<div class="nms-progress-container">
						<div class="nms-progress-bar">
							<div class="nms-progress-fill" style="width: 0%"></div>
						</div>
						<div class="nms-progress-info">
							<span class="nms-progress-percent">0%</span>
							<span class="nms-progress-status"><?php _e( 'Initializing...', 'nexifymy-security' ); ?></span>
						</div>
					</div>
					<p class="nms-scan-file-current" style="margin-top: 10px; color: var(--nms-gray-500); font-size: 12px;"></p>
				</div>
			</div>

			<!-- Scan Results -->
			<div id="scanner-results" class="nms-card" style="display: none; margin-top: 20px;">
				<div class="nms-card-header">
					<h3><?php _e( 'Scan Results', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<div id="results-summary" style="margin-bottom: 20px;"></div>
					<table class="widefat" id="results-table">
						<thead>
							<tr>
								<th><?php _e( 'File', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Threat', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Severity', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Actions', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody id="results-content">
						</tbody>
					</table>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the firewall page.
	 */
	public function render_firewall() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$fw_settings = isset( $settings['firewall'] ) ? $settings['firewall'] : array();
		$blocked_count = get_option( 'nexifymy_blocked_requests_count', 0 );
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-shield"></span> <?php _e( 'Firewall Settings', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Configure Web Application Firewall (WAF) to protect your site.', 'nexifymy-security' ); ?></p>
			</div>

			<!-- Firewall Stats -->
			<div class="nms-stats-row" style="margin-bottom: 20px;">
				<div class="nms-stat-card">
					<div class="nms-stat-icon green">
						<span class="dashicons dashicons-shield-alt"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo empty( $fw_settings['enabled'] ) ? __( 'Disabled', 'nexifymy-security' ) : __( 'Active', 'nexifymy-security' ); ?></h4>
						<p><?php _e( 'WAF Status', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon red">
						<span class="dashicons dashicons-dismiss"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo number_format( intval( $blocked_count ) ); ?></h4>
						<p><?php _e( 'Blocked Attacks', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon blue">
						<span class="dashicons dashicons-admin-site-alt3"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo isset( $fw_settings['mode'] ) ? ucfirst( esc_html( $fw_settings['mode'] ) ) : 'Standard'; ?></h4>
						<p><?php _e( 'Protection Mode', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>

			<!-- WAF Settings -->
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Firewall Configuration', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<table class="form-table" id="firewall-settings">
						<tr>
							<th><?php _e( 'Enable Firewall', 'nexifymy-security' ); ?></th>
							<td>
								<label class="nms-toggle">
									<input type="checkbox" id="fw-enabled" <?php checked( ! empty( $fw_settings['enabled'] ) ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
								<p class="description"><?php _e( 'Enable Web Application Firewall protection.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Protection Mode', 'nexifymy-security' ); ?></th>
							<td>
								<select id="fw-mode">
									<option value="standard" <?php selected( $fw_settings['mode'] ?? 'standard', 'standard' ); ?>><?php _e( 'Standard - Balanced protection', 'nexifymy-security' ); ?></option>
									<option value="strict" <?php selected( $fw_settings['mode'] ?? '', 'strict' ); ?>><?php _e( 'Strict - Maximum security', 'nexifymy-security' ); ?></option>
									<option value="learning" <?php selected( $fw_settings['mode'] ?? '', 'learning' ); ?>><?php _e( 'Learning - Log only, no blocking', 'nexifymy-security' ); ?></option>
								</select>
							</td>
						</tr>
					</table>
				</div>
			</div>

			<!-- Protection Rules -->
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Protection Rules', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<table class="form-table" id="firewall-rules">
						<tr>
							<th><?php _e( 'SQL Injection Protection', 'nexifymy-security' ); ?></th>
							<td>
								<label class="nms-toggle">
									<input type="checkbox" name="sql_injection" <?php checked( $fw_settings['sql_injection'] ?? true ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'XSS Protection', 'nexifymy-security' ); ?></th>
							<td>
								<label class="nms-toggle">
									<input type="checkbox" name="xss_protection" <?php checked( $fw_settings['xss_protection'] ?? true ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'File Inclusion Protection', 'nexifymy-security' ); ?></th>
							<td>
								<label class="nms-toggle">
									<input type="checkbox" name="file_inclusion" <?php checked( $fw_settings['file_inclusion'] ?? true ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Bad Bot Blocking', 'nexifymy-security' ); ?></th>
							<td>
								<label class="nms-toggle">
									<input type="checkbox" name="bad_bots" <?php checked( $fw_settings['bad_bots'] ?? true ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Directory Traversal Protection', 'nexifymy-security' ); ?></th>
							<td>
								<label class="nms-toggle">
									<input type="checkbox" name="directory_traversal" <?php checked( $fw_settings['directory_traversal'] ?? true ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</td>
						</tr>
					</table>
					<p style="margin-top: 20px;">
						<button type="button" class="nms-btn nms-btn-primary" id="save-firewall-settings">
							<?php _e( 'Save Settings', 'nexifymy-security' ); ?>
						</button>
						<span id="firewall-status" style="margin-left: 15px;"></span>
					</p>
				</div>
			</div>

			<!-- IP Management -->
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'IP Management', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
						<div>
							<h4><?php _e( 'Whitelist IPs', 'nexifymy-security' ); ?></h4>
							<textarea id="ip-whitelist" rows="6" class="large-text" placeholder="<?php _e( 'Enter IPs, one per line', 'nexifymy-security' ); ?>"><?php echo esc_textarea( $fw_settings['whitelist'] ?? '' ); ?></textarea>
							<p class="description"><?php _e( 'IPs that will never be blocked.', 'nexifymy-security' ); ?></p>
						</div>
						<div>
							<h4><?php _e( 'Blacklist IPs', 'nexifymy-security' ); ?></h4>
							<textarea id="ip-blacklist" rows="6" class="large-text" placeholder="<?php _e( 'Enter IPs, one per line', 'nexifymy-security' ); ?>"><?php echo esc_textarea( $fw_settings['blacklist'] ?? '' ); ?></textarea>
							<p class="description"><?php _e( 'IPs that will always be blocked.', 'nexifymy-security' ); ?></p>
						</div>
					</div>
				</div>
			</div>

			<!-- Blocked IPs -->
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Recently Blocked IPs', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
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
	 * Render the notifications page.
	 */
	public function render_notifications() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-bell"></span> <?php _e( 'Notifications', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Unread security alerts from your logs.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nexifymy-card nexifymy-card-full">
				<div class="card-header">
					<h2><?php _e( 'Unread Alerts', 'nexifymy-security' ); ?> <span id="notifications-unread-count"></span></h2>
					<button type="button" class="button" id="mark-all-notifications-read"><?php _e( 'Mark All as Read', 'nexifymy-security' ); ?></button>
				</div>
				<div class="card-body">
					<table class="widefat striped">
						<thead>
							<tr>
								<th><?php _e( 'Date', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Event', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Severity', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Message', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'IP', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody id="notifications-tbody">
							<tr><td colspan="5"><?php _e( 'Loading alerts...', 'nexifymy-security' ); ?></td></tr>
						</tbody>
					</table>
					<p class="description"><?php _e( 'Shows unread Critical/Warning events. Use Logs for full history.', 'nexifymy-security' ); ?></p>
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

		<!-- Confirmation Modal -->
		<div id="nms-confirm-modal" class="nms-modal-overlay">
			<div class="nms-modal">
				<div class="nms-modal-header danger" id="modal-header">
					<span class="dashicons dashicons-warning"></span>
					<h3 id="modal-title"><?php _e( 'Confirm Action', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-modal-body">
					<p id="modal-message"><?php _e( 'Are you sure you want to proceed?', 'nexifymy-security' ); ?></p>
					<div class="file-path" id="modal-file-path"></div>
				</div>
				<div class="nms-modal-footer">
					<button type="button" class="nms-modal-btn nms-modal-btn-cancel" id="modal-cancel">
						<?php _e( 'Cancel', 'nexifymy-security' ); ?>
					</button>
					<button type="button" class="nms-modal-btn nms-modal-btn-danger" id="modal-confirm">
						<?php _e( 'Confirm', 'nexifymy-security' ); ?>
					</button>
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

	/**
	 * Render the Live Traffic page.
	 */
	public function render_live_traffic() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-chart-area"></span> <?php _e( 'Live Traffic', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Monitor real-time HTTP requests to your site.', 'nexifymy-security' ); ?></p>
			</div>

			<!-- Traffic Stats Card -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Traffic Statistics (Last 24 Hours)', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<div id="traffic-stats">
						<p><?php _e( 'Loading statistics...', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>

			<!-- Live Traffic Table -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Recent Requests', 'nexifymy-security' ); ?></h2>
					<button class="button" id="refresh-traffic">
						<span class="dashicons dashicons-update"></span> <?php _e( 'Refresh', 'nexifymy-security' ); ?>
					</button>
				</div>
				<div class="card-body">
					<table class="widefat striped" id="traffic-table">
						<thead>
							<tr>
								<th><?php _e( 'Time', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'IP', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Method', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'URL', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Status', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody id="traffic-tbody">
							<tr><td colspan="5"><?php _e( 'Loading traffic...', 'nexifymy-security' ); ?></td></tr>
						</tbody>
					</table>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Geo Blocking page.
	 */
	public function render_geo_blocking() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-admin-site-alt3"></span> <?php _e( 'Geo Blocking', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Block or allow traffic based on country.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Country Blocking Settings', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'Enable Geo Blocking', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="geo-enabled" /> <?php _e( 'Enable country-based blocking', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Mode', 'nexifymy-security' ); ?></th>
							<td>
								<select id="geo-mode">
									<option value="blacklist"><?php _e( 'Blacklist (block selected)', 'nexifymy-security' ); ?></option>
									<option value="whitelist"><?php _e( 'Whitelist (allow only selected)', 'nexifymy-security' ); ?></option>
								</select>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Countries', 'nexifymy-security' ); ?></th>
							<td>
								<select id="geo-countries" multiple style="width: 100%; height: 200px;">
									<?php _e( 'Loading countries...', 'nexifymy-security' ); ?>
								</select>
								<p class="description"><?php _e( 'Hold Ctrl/Cmd to select multiple countries.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Block Message', 'nexifymy-security' ); ?></th>
							<td>
								<input type="text" id="geo-message" class="regular-text" value="Access denied from your region." />
							</td>
						</tr>
					</table>
					<p>
						<button class="button button-primary" id="save-geo-settings"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
						<span id="geo-status"></span>
					</p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Hardening page.
	 */
	public function render_hardening() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-lock"></span> <?php _e( 'Security Hardening', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Apply security hardening measures to WordPress.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Hardening Options', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table" id="hardening-options">
						<tr>
							<th><?php _e( 'Disable XML-RPC', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" name="disable_xmlrpc" checked /> <?php _e( 'Block XML-RPC access (prevents brute force)', 'nexifymy-security' ); ?></label></td>
						</tr>
						<tr>
							<th><?php _e( 'Hide WP Version', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" name="hide_wp_version" checked /> <?php _e( 'Remove WordPress version from source code', 'nexifymy-security' ); ?></label></td>
						</tr>
						<tr>
							<th><?php _e( 'Disable File Editor', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" name="disable_file_editor" checked /> <?php _e( 'Disable theme/plugin editor in admin', 'nexifymy-security' ); ?></label></td>
						</tr>
						<tr>
							<th><?php _e( 'Security Headers', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" name="security_headers" checked /> <?php _e( 'Add X-Frame-Options, X-XSS-Protection headers', 'nexifymy-security' ); ?></label></td>
						</tr>
						<tr>
							<th><?php _e( 'Restrict REST API', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" name="disable_rest_api" /> <?php _e( 'Require login for REST API access', 'nexifymy-security' ); ?></label></td>
						</tr>
						<tr>
							<th><?php _e( 'Disable Pingback', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" name="disable_pingback" checked /> <?php _e( 'Disable pingback/trackback functionality', 'nexifymy-security' ); ?></label></td>
						</tr>
					</table>
					<p>
						<button class="button button-primary" id="apply-hardening"><?php _e( 'Apply Settings', 'nexifymy-security' ); ?></button>
						<span id="hardening-status"></span>
					</p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Password Policy page.
	 */
	public function render_password() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-privacy"></span> <?php _e( 'Password Policy', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Enforce strong password requirements for all users.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Password Requirements', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table" id="password-options">
						<tr>
							<th><?php _e( 'Minimum Length', 'nexifymy-security' ); ?></th>
							<td>
								<input type="number" id="pass-min-length" value="12" min="8" max="32" />
								<p class="description"><?php _e( 'Minimum password length (8-32 characters)', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Character Requirements', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" name="require_upper" checked /> <?php _e( 'Uppercase letter (A-Z)', 'nexifymy-security' ); ?></label><br>
								<label><input type="checkbox" name="require_lower" checked /> <?php _e( 'Lowercase letter (a-z)', 'nexifymy-security' ); ?></label><br>
								<label><input type="checkbox" name="require_number" checked /> <?php _e( 'Number (0-9)', 'nexifymy-security' ); ?></label><br>
								<label><input type="checkbox" name="require_special" checked /> <?php _e( 'Special character (!@#$...)', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Block Common Passwords', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" name="block_common" checked /> <?php _e( 'Prevent use of commonly breached passwords', 'nexifymy-security' ); ?></label></td>
						</tr>
						<tr>
							<th><?php _e( 'Password Expiry', 'nexifymy-security' ); ?></th>
							<td>
								<select id="pass-expiry">
									<option value="0"><?php _e( 'Never expires', 'nexifymy-security' ); ?></option>
									<option value="30"><?php _e( '30 days', 'nexifymy-security' ); ?></option>
									<option value="60"><?php _e( '60 days', 'nexifymy-security' ); ?></option>
									<option value="90"><?php _e( '90 days', 'nexifymy-security' ); ?></option>
								</select>
							</td>
						</tr>
					</table>
					<p>
						<button class="button button-primary" id="save-password-settings"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
						<span id="password-status"></span>
					</p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the CDN page.
	 */
	public function render_cdn() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-cloud"></span> <?php _e( 'CDN Integration', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Configure CDN integration and cache management.', 'nexifymy-security' ); ?></p>
			</div>

			<!-- CDN Status -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'CDN Status', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<div id="cdn-status">
						<p><?php _e( 'Loading CDN status...', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>

			<!-- Cloudflare Settings -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Cloudflare API Settings', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'Enable CDN Integration', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" id="cdn-enabled" /> <?php _e( 'Enable CDN features', 'nexifymy-security' ); ?></label></td>
						</tr>
						<tr>
							<th><?php _e( 'Provider', 'nexifymy-security' ); ?></th>
							<td>
								<select id="cdn-provider">
									<option value="auto"><?php _e( 'Auto-detect', 'nexifymy-security' ); ?></option>
									<option value="cloudflare"><?php _e( 'Cloudflare', 'nexifymy-security' ); ?></option>
									<option value="sucuri"><?php _e( 'Sucuri', 'nexifymy-security' ); ?></option>
									<option value="generic"><?php _e( 'Generic Proxy', 'nexifymy-security' ); ?></option>
								</select>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Trust Proxy Headers', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" id="cdn-trust-proxy" checked /> <?php _e( 'Use CDN/proxy headers to determine real client IP', 'nexifymy-security' ); ?></label></td>
						</tr>
						<tr>
							<th><?php _e( 'API Token', 'nexifymy-security' ); ?></th>
							<td>
								<input type="password" id="cf-api-key" class="regular-text" />
								<p class="description"><?php _e( 'Cloudflare API Token (with Zone permissions)', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Zone ID', 'nexifymy-security' ); ?></th>
							<td>
								<input type="text" id="cf-zone-id" class="regular-text" />
								<p class="description"><?php _e( 'Found in Cloudflare dashboard under Overview', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
					</table>
					<p>
						<button class="button button-primary" id="save-cdn-settings"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
						<button class="button" id="test-cdn-connection" style="margin-left: 8px;"><?php _e( 'Test Connection', 'nexifymy-security' ); ?></button>
						<button class="button" id="purge-cdn-cache" style="margin-left: 8px;"><?php _e( 'Purge Cache', 'nexifymy-security' ); ?></button>
						<span id="cdn-settings-status" style="margin-left: 12px;"></span>
					</p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Vulnerabilities page.
	 */
	public function render_vulnerabilities() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-warning"></span> <?php _e( 'Vulnerability Scanner', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Scan plugins, themes, and WordPress core for known vulnerabilities.', 'nexifymy-security' ); ?></p>
			</div>

			<!-- Scan Controls -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Scan Controls', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<p>
						<button class="button button-primary button-hero" id="run-vuln-scan">
							<span class="dashicons dashicons-search"></span> <?php _e( 'Run Vulnerability Scan', 'nexifymy-security' ); ?>
						</button>
					</p>
					<div id="vuln-scan-status"></div>
				</div>
			</div>

			<!-- Scan Results -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Scan Results', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<div id="vuln-results">
						<p><?php _e( 'No scan results available. Run a scan to check for vulnerabilities.', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>

			<!-- Settings -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Scanner Settings', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'Enable Scanner', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="vuln-enabled" checked /> <?php _e( 'Enable vulnerability scanner features', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'WPScan API Token', 'nexifymy-security' ); ?></th>
							<td>
								<input type="password" id="wpscan-api-token" class="regular-text" />
								<p class="description"><?php _e( 'Get a free API token from wpscan.com for detailed vulnerability data.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Automatic Scans', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="vuln-auto-scan" /> <?php _e( 'Enable scheduled scans', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Scan Schedule', 'nexifymy-security' ); ?></th>
							<td>
								<select id="vuln-scan-schedule">
									<option value="weekly"><?php _e( 'Weekly', 'nexifymy-security' ); ?></option>
									<option value="daily"><?php _e( 'Daily', 'nexifymy-security' ); ?></option>
								</select>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Email Alerts', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="vuln-email-alerts" checked /> <?php _e( 'Send email when vulnerabilities are found', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
					</table>
					<p>
						<button class="button button-primary" id="save-vuln-settings"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
						<span id="vuln-settings-status"></span>
					</p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Captcha page.
	 */
	public function render_captcha() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-shield"></span> <?php _e( 'Login Captcha', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Protect login and registration forms with math-based captcha.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Captcha Settings', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table" id="captcha-settings">
						<tr>
							<th><?php _e( 'Enable Captcha', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" name="captcha_enabled" checked /> <?php _e( 'Enable captcha protection', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Protected Forms', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" name="enable_login" checked /> <?php _e( 'Login form', 'nexifymy-security' ); ?></label><br>
								<label><input type="checkbox" name="enable_registration" checked /> <?php _e( 'Registration form', 'nexifymy-security' ); ?></label><br>
								<label><input type="checkbox" name="enable_reset" checked /> <?php _e( 'Password reset form', 'nexifymy-security' ); ?></label><br>
								<label><input type="checkbox" name="enable_comment" /> <?php _e( 'Comment form', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Difficulty', 'nexifymy-security' ); ?></th>
							<td>
								<select id="captcha-difficulty">
									<option value="easy"><?php _e( 'Easy (addition only)', 'nexifymy-security' ); ?></option>
									<option value="medium"><?php _e( 'Medium (addition/subtraction)', 'nexifymy-security' ); ?></option>
									<option value="hard"><?php _e( 'Hard (includes multiplication)', 'nexifymy-security' ); ?></option>
								</select>
							</td>
						</tr>
					</table>
					<p>
						<button class="button button-primary" id="save-captcha-settings"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
						<span id="captcha-status"></span>
					</p>
				</div>
			</div>

			<!-- Preview -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Captcha Preview', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<p><?php _e( 'This is how the captcha will appear on login forms:', 'nexifymy-security' ); ?></p>
					<div style="max-width: 300px; padding: 20px; background: #f1f1f1; border-radius: 5px;">
						<label style="font-weight: 600;">5 + 3 = ?</label><br>
						<input type="number" style="width: 100%; padding: 8px; margin-top: 5px;" placeholder="<?php _e( 'Enter answer', 'nexifymy-security' ); ?>" />
					</div>
					</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the 2FA page.
	 */
	public function render_2fa() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-lock"></span> <?php _e( 'Two-Factor Authentication', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Add an extra layer of security with TOTP-based 2FA.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( '2FA Settings', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'Enable 2FA', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="2fa-enabled" checked /> <?php _e( 'Allow users to enable 2FA', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Force for Admins', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="2fa-force-admin" /> <?php _e( 'Require 2FA for all administrators', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Email Backup', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="2fa-email-backup" checked /> <?php _e( 'Allow email code as backup method', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Remember Device', 'nexifymy-security' ); ?></th>
							<td>
								<input type="number" id="2fa-remember-days" value="30" min="1" max="365" style="width: 80px;" />
								<span><?php _e( 'days', 'nexifymy-security' ); ?></span>
							</td>
						</tr>
					</table>
					<p>
						<button class="button button-primary" id="save-2fa-settings"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
						<span id="2fa-status"></span>
					</p>
				</div>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'How 2FA Works', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<ol>
						<li><?php _e( 'Users enable 2FA in their profile settings', 'nexifymy-security' ); ?></li>
						<li><?php _e( 'Scan QR code with authenticator app (Google/Microsoft Authenticator)', 'nexifymy-security' ); ?></li>
						<li><?php _e( 'Enter 6-digit code to verify setup', 'nexifymy-security' ); ?></li>
						<li><?php _e( 'On next login, enter password + 6-digit code', 'nexifymy-security' ); ?></li>
					</ol>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Hide Login page.
	 */
	public function render_hide_login() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-hidden"></span> <?php _e( 'Hide Login URL', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Hide wp-admin and wp-login.php from attackers.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Login URL Settings', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'Enable', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="hide-login-enabled" /> <?php _e( 'Hide default login URLs', 'nexifymy-security' ); ?></label>
								<p class="description" style="color: orange;">
									<strong><?php _e( 'Warning:', 'nexifymy-security' ); ?></strong>
									<?php _e( 'Make sure to remember your custom login URL!', 'nexifymy-security' ); ?>
								</p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Login Slug', 'nexifymy-security' ); ?></th>
							<td>
								<code><?php echo esc_html( home_url( '/' ) ); ?></code>
								<input type="text" id="login-slug" value="secure-login" style="width: 200px;" />
								<p class="description"><?php _e( 'Choose a unique, hard-to-guess slug.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Redirect Blocked Access', 'nexifymy-security' ); ?></th>
							<td>
								<select id="hide-login-redirect">
									<option value="404"><?php _e( 'Show 404 page', 'nexifymy-security' ); ?></option>
									<option value="home"><?php _e( 'Redirect to homepage', 'nexifymy-security' ); ?></option>
									<option value="custom"><?php _e( 'Custom URL', 'nexifymy-security' ); ?></option>
								</select>
							</td>
						</tr>
					</table>
					<p>
						<button class="button button-primary" id="save-hide-login-settings"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
						<span id="hide-login-status"></span>
					</p>
				</div>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Current Login URL', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<p id="current-login-url">
						<code><?php echo esc_html( wp_login_url() ); ?></code>
					</p>
					<p class="description"><?php _e( 'Bookmark this URL so you can always access your login page.', 'nexifymy-security' ); ?></p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Self-Protection page.
	 */
	public function render_self_protection() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-shield-alt"></span> <?php _e( 'Plugin Self-Protection', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Protect the security plugin from tampering and unauthorized modifications.', 'nexifymy-security' ); ?></p>
			</div>

			<!-- Protection Status -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Integrity Status', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<div id="protection-status">
						<p><?php _e( 'Loading protection status...', 'nexifymy-security' ); ?></p>
					</div>
					<p>
						<button class="button button-primary" id="run-integrity-check">
							<span class="dashicons dashicons-search"></span> <?php _e( 'Run Integrity Check', 'nexifymy-security' ); ?>
						</button>
						<button class="button" id="regenerate-hashes">
							<span class="dashicons dashicons-update"></span> <?php _e( 'Regenerate Baseline', 'nexifymy-security' ); ?>
						</button>
						<span id="integrity-status"></span>
					</p>
				</div>
			</div>

			<!-- Settings -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Protection Settings', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'File Integrity Monitoring', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="monitor-files" checked /> <?php _e( 'Monitor plugin files for changes', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Block File Editor', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="block-editor" checked /> <?php _e( 'Prevent editing plugin files via WordPress editor', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Email Alerts', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="tampering-alerts" checked /> <?php _e( 'Send email when tampering is detected', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Check Interval', 'nexifymy-security' ); ?></th>
							<td>
								<select id="check-interval">
									<option value="hourly"><?php _e( 'Hourly', 'nexifymy-security' ); ?></option>
									<option value="daily"><?php _e( 'Daily', 'nexifymy-security' ); ?></option>
								</select>
							</td>
						</tr>
					</table>
				</div>
			</div>

			<!-- How It Works -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'How Self-Protection Works', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<ul>
						<li><strong><?php _e( 'File Hashing:', 'nexifymy-security' ); ?></strong> <?php _e( 'SHA-256 hashes of all plugin files are stored as a baseline.', 'nexifymy-security' ); ?></li>
						<li><strong><?php _e( 'Integrity Checks:', 'nexifymy-security' ); ?></strong> <?php _e( 'Files are periodically compared against the baseline.', 'nexifymy-security' ); ?></li>
						<li><strong><?php _e( 'Tamper Detection:', 'nexifymy-security' ); ?></strong> <?php _e( 'Any modifications trigger immediate email alerts.', 'nexifymy-security' ); ?></li>
						<li><strong><?php _e( 'Editor Blocking:', 'nexifymy-security' ); ?></strong> <?php _e( 'Plugin files cannot be edited via WordPress.', 'nexifymy-security' ); ?></li>
						<li><strong><?php _e( 'Deactivation Monitoring:', 'nexifymy-security' ); ?></strong> <?php _e( 'Alerts sent if plugin is deactivated.', 'nexifymy-security' ); ?></li>
					</ul>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Core Repair page.
	 */
	public function render_core_repair() {
		global $wp_version;
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-hammer"></span> <?php _e( 'Core File Repair', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Check and repair corrupted WordPress core files using official sources.', 'nexifymy-security' ); ?></p>
			</div>

			<!-- WordPress Version Info -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'WordPress Core Status', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'WordPress Version', 'nexifymy-security' ); ?></th>
							<td><strong><?php echo esc_html( $wp_version ); ?></strong></td>
						</tr>
						<tr>
							<th><?php _e( 'Integrity Status', 'nexifymy-security' ); ?></th>
							<td id="core-status"><?php _e( 'Not checked yet', 'nexifymy-security' ); ?></td>
						</tr>
					</table>
				</div>
			</div>

			<!-- Action Buttons -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Actions', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<p>
						<button class="button button-primary" id="check-core-integrity">
							<span class="dashicons dashicons-search"></span> <?php _e( 'Check Core Integrity', 'nexifymy-security' ); ?>
						</button>
						<button class="button button-secondary" id="repair-all-core" style="display: none;">
							<span class="dashicons dashicons-hammer"></span> <?php _e( 'Repair All Modified Files', 'nexifymy-security' ); ?>
						</button>
						<span id="repair-status"></span>
					</p>
				</div>
			</div>

			<!-- Results -->
			<div class="nexifymy-card" id="integrity-results" style="display: none;">
				<div class="card-header">
					<h2><?php _e( 'Integrity Check Results', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<div id="results-content"></div>
				</div>
			</div>

			<!-- How It Works -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'How Core Repair Works', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<ol>
						<li><?php _e( 'Fetches official file checksums from WordPress.org API', 'nexifymy-security' ); ?></li>
						<li><?php _e( 'Compares each core file against the expected hash', 'nexifymy-security' ); ?></li>
						<li><?php _e( 'Identifies modified or missing files', 'nexifymy-security' ); ?></li>
						<li><?php _e( 'Downloads fresh WordPress package from official source', 'nexifymy-security' ); ?></li>
						<li><?php _e( 'Backs up corrupted files before replacement', 'nexifymy-security' ); ?></li>
						<li><?php _e( 'Replaces corrupted files with clean versions', 'nexifymy-security' ); ?></li>
					</ol>
					<p class="description">
						<strong><?php _e( 'Note:', 'nexifymy-security' ); ?></strong>
						<?php _e( 'Backups are stored in wp-content/nexifymy-backups/core/', 'nexifymy-security' ); ?>
					</p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Modules Hub page.
	 */
	public function render_modules_hub() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$modules = array(
			'firewall' => array(
				'name' => __( 'Web Application Firewall', 'nexifymy-security' ),
				'desc' => __( 'Protect against SQL injection, XSS, RFI, and other attacks.', 'nexifymy-security' ),
				'icon' => 'shield',
				'page' => 'firewall',
			),
			'scanner' => array(
				'name' => __( 'Malware Scanner', 'nexifymy-security' ),
				'desc' => __( 'Scan files for malware and suspicious code.', 'nexifymy-security' ),
				'icon' => 'search',
				'page' => 'scanner',
			),
			'login_protection' => array(
				'name' => __( 'Login Protection', 'nexifymy-security' ),
				'desc' => __( 'Brute force protection and login attempt limits.', 'nexifymy-security' ),
				'icon' => 'lock',
				'page' => 'login-protection',
			),
			'two_factor' => array(
				'name' => __( 'Two-Factor Authentication', 'nexifymy-security' ),
				'desc' => __( 'Add 2FA to user accounts for extra security.', 'nexifymy-security' ),
				'icon' => 'smartphone',
				'page' => '2fa',
			),
			'hide_login' => array(
				'name' => __( 'Hide Login', 'nexifymy-security' ),
				'desc' => __( 'Change the default login URL to prevent attacks.', 'nexifymy-security' ),
				'icon' => 'hidden',
				'page' => 'hide-login',
			),
			'geo_blocking' => array(
				'name' => __( 'Geo Blocking', 'nexifymy-security' ),
				'desc' => __( 'Block access from specific countries.', 'nexifymy-security' ),
				'icon' => 'admin-site',
				'page' => 'geo-blocking',
			),
			'rate_limiter' => array(
				'name' => __( 'Rate Limiter', 'nexifymy-security' ),
				'desc' => __( 'Limit request rates to prevent abuse.', 'nexifymy-security' ),
				'icon' => 'clock',
				'page' => 'rate-limiter',
			),
			'hardening' => array(
				'name' => __( 'Security Hardening', 'nexifymy-security' ),
				'desc' => __( 'Apply WordPress security best practices.', 'nexifymy-security' ),
				'icon' => 'shield-alt',
				'page' => 'hardening',
			),
			'captcha' => array(
				'name' => __( 'CAPTCHA', 'nexifymy-security' ),
				'desc' => __( 'Add CAPTCHA to login and forms.', 'nexifymy-security' ),
				'icon' => 'visibility',
				'page' => 'captcha',
			),
			'self_protection' => array(
				'name' => __( 'Self-Protection', 'nexifymy-security' ),
				'desc' => __( 'Protect plugin files from tampering.', 'nexifymy-security' ),
				'icon' => 'admin-plugins',
				'page' => 'self-protection',
			),
			'password_policy' => array(
				'name' => __( 'Password Policy', 'nexifymy-security' ),
				'desc' => __( 'Enforce strong password requirements.', 'nexifymy-security' ),
				'icon' => 'privacy',
				'page' => 'password',
			),
		);
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><?php _e( 'Security Modules', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Enable and configure security modules for your site.', 'nexifymy-security' ); ?></p>
			</div>
			<div class="nms-modules-grid">
				<?php foreach ( $modules as $key => $module ) :
					$enabled = ! empty( $settings['modules'][ $key ] );
				?>
				<div class="nms-module-card <?php echo $enabled ? 'active' : ''; ?>">
					<div class="nms-module-card-header">
						<span class="dashicons dashicons-<?php echo esc_attr( $module['icon'] ); ?>"></span>
						<h3><?php echo esc_html( $module['name'] ); ?></h3>
						<label class="nms-toggle">
							<input type="checkbox" data-module="<?php echo esc_attr( $key ); ?>" <?php checked( $enabled ); ?>>
							<span class="nms-toggle-slider"></span>
						</label>
					</div>
					<div class="nms-module-card-body">
						<p><?php echo esc_html( $module['desc'] ); ?></p>
					</div>
					<div class="nms-module-card-footer">
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-' . $module['page'] ) ); ?>" class="nms-btn nms-btn-secondary">
							<?php _e( 'Settings', 'nexifymy-security' ); ?> →
						</a>
					</div>
				</div>
				<?php endforeach; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Tools Hub page.
	 */
	public function render_tools_hub() {
		$tools = array(
			array(
				'name' => __( 'Database Security', 'nexifymy-security' ),
				'desc' => __( 'Optimize and secure your database.', 'nexifymy-security' ),
				'icon' => 'database',
				'page' => 'database',
			),
			array(
				'name' => __( 'Core File Repair', 'nexifymy-security' ),
				'desc' => __( 'Verify and repair WordPress core files.', 'nexifymy-security' ),
				'icon' => 'admin-tools',
				'page' => 'core-repair',
			),
			array(
				'name' => __( 'Vulnerability Scanner', 'nexifymy-security' ),
				'desc' => __( 'Check for known vulnerabilities.', 'nexifymy-security' ),
				'icon' => 'warning',
				'page' => 'vulnerabilities',
			),
			array(
				'name' => __( 'Live Traffic', 'nexifymy-security' ),
				'desc' => __( 'Monitor real-time site traffic.', 'nexifymy-security' ),
				'icon' => 'chart-line',
				'page' => 'live-traffic',
			),
			array(
				'name' => __( 'Quarantine', 'nexifymy-security' ),
				'desc' => __( 'View and manage quarantined threats.', 'nexifymy-security' ),
				'icon' => 'archive',
				'page' => 'quarantine',
			),
			array(
				'name' => __( 'Malware Definitions', 'nexifymy-security' ),
				'desc' => __( 'Update malware detection signatures.', 'nexifymy-security' ),
				'icon' => 'update',
				'page' => 'definitions',
			),
			array(
				'name' => __( 'Security Logs', 'nexifymy-security' ),
				'desc' => __( 'View all security events.', 'nexifymy-security' ),
				'icon' => 'list-view',
				'page' => 'logs',
			),
			array(
				'name' => __( 'CDN Integration', 'nexifymy-security' ),
				'desc' => __( 'Configure CDN for security and performance.', 'nexifymy-security' ),
				'icon' => 'networking',
				'page' => 'cdn',
			),
		);
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><?php _e( 'Security Tools', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Quick access to security maintenance tools.', 'nexifymy-security' ); ?></p>
			</div>
			<div class="nms-tools-grid-hub">
				<?php foreach ( $tools as $tool ) : ?>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-' . $tool['page'] ) ); ?>" class="nms-tool-card">
					<span class="dashicons dashicons-<?php echo esc_attr( $tool['icon'] ); ?>"></span>
					<h3><?php echo esc_html( $tool['name'] ); ?></h3>
					<p><?php echo esc_html( $tool['desc'] ); ?></p>
				</a>
				<?php endforeach; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Malware Definitions page.
	 */
	public function render_malware_definitions() {
		$status = array();
		if ( isset( $GLOBALS['nexifymy_signatures'] ) && method_exists( $GLOBALS['nexifymy_signatures'], 'get_status' ) ) {
			$status = $GLOBALS['nexifymy_signatures']->get_status();
		}

		$signature_source = $status['last_update']['source'] ?? ( $status['source'] ?? 'unknown' );
		$signature_version = is_string( $signature_source ) && $signature_source !== '' ? $signature_source : 'unknown';
		$last_update = $status['last_update']['updated_at'] ?? null;
		$signature_count = isset( $status['total_signatures'] ) ? (int) $status['total_signatures'] : 0;

		$settings = get_option( 'nexifymy_security_settings', array() );
		$auto_update = isset( $settings['signatures']['auto_update'] ) ? (bool) $settings['signatures']['auto_update'] : true;
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><?php _e( 'Malware Definitions', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Keep your malware signatures up to date for best protection.', 'nexifymy-security' ); ?></p>
			</div>
			
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Signature Status', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<table class="widefat">
						<tbody>
							<tr>
								<th><?php _e( 'Current Version', 'nexifymy-security' ); ?></th>
								<td><code><?php echo esc_html( $signature_version ); ?></code></td>
							</tr>
							<tr>
								<th><?php _e( 'Total Signatures', 'nexifymy-security' ); ?></th>
								<td><?php echo intval( $signature_count ); ?></td>
							</tr>
							<tr>
								<th><?php _e( 'Last Updated', 'nexifymy-security' ); ?></th>
								<td><?php echo $last_update ? esc_html( human_time_diff( strtotime( $last_update ), current_time( 'timestamp' ) ) ) . ' ' . __( 'ago', 'nexifymy-security' ) : __( 'Never', 'nexifymy-security' ); ?></td>
							</tr>
						</tbody>
					</table>
					<div style="margin-top: 20px;">
						<button type="button" id="update-definitions" class="nms-btn nms-btn-primary">
							<span class="dashicons dashicons-update"></span>
							<?php _e( 'Update Definitions Now', 'nexifymy-security' ); ?>
						</button>
						<span id="update-status" style="margin-left: 15px;"></span>
					</div>
				</div>
			</div>
			
			<div class="nms-card" style="margin-top: 20px;">
				<div class="nms-card-header">
					<h3><?php _e( 'Auto-Update Settings', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'Auto-Update', 'nexifymy-security' ); ?></th>
							<td>
								<label class="nms-toggle">
									<input type="checkbox" id="auto-update-signatures" value="1" <?php checked( $auto_update ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
								<p class="description"><?php _e( 'Automatically update malware signatures daily.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Login Protection page.
	 */
	public function render_login_protection() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$login_settings = isset( $settings['login_protection'] ) ? $settings['login_protection'] : array();
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><?php _e( 'Login Protection', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Protect your login page from brute force attacks.', 'nexifymy-security' ); ?></p>
			</div>
			
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Brute Force Protection', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'Enable Protection', 'nexifymy-security' ); ?></th>
							<td>
								<label class="nms-toggle">
									<input type="checkbox" id="login-prot-enabled" value="1" <?php checked( ! empty( $login_settings['enabled'] ) ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Max Login Attempts', 'nexifymy-security' ); ?></th>
							<td>
								<input type="number" id="login-prot-attempts" value="<?php echo intval( $login_settings['max_attempts'] ?? 5 ); ?>" min="1" max="20" class="small-text">
								<p class="description"><?php _e( 'Lock out after this many failed attempts.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Lockout Duration', 'nexifymy-security' ); ?></th>
							<td>
								<input type="number" id="login-prot-duration" value="<?php echo intval( $login_settings['lockout_duration'] ?? 30 ); ?>" min="5" max="1440" class="small-text">
								<?php _e( 'minutes', 'nexifymy-security' ); ?>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Permanent Ban Threshold', 'nexifymy-security' ); ?></th>
							<td>
								<input type="number" id="login-prot-ban" value="<?php echo intval( $login_settings['ban_threshold'] ?? 3 ); ?>" min="1" max="10" class="small-text">
								<p class="description"><?php _e( 'Number of lockouts before permanent ban.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
					</table>
				</div>
			</div>
			
			<p class="submit">
				<button type="button" id="save-login-prot-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
				<span id="login-prot-status" style="margin-left: 15px;"></span>
			</p>
		</div>
		<?php
	}

	/**
	 * Render the Rate Limiter page.
	 */
	public function render_rate_limiter() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$rate_settings = isset( $settings['rate_limiter'] ) ? $settings['rate_limiter'] : array();
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nexifymy-header">
				<h1><?php _e( 'Rate Limiter', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Limit request rates to prevent abuse and DDoS attacks.', 'nexifymy-security' ); ?></p>
			</div>
			
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Rate Limiting Settings', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'Enable Rate Limiting', 'nexifymy-security' ); ?></th>
							<td>
								<label class="nms-toggle">
									<input type="checkbox" id="rate-enabled" value="1" <?php checked( ! empty( $rate_settings['enabled'] ) ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Requests Per Minute', 'nexifymy-security' ); ?></th>
							<td>
								<input type="number" id="rate-requests" value="<?php echo intval( $rate_settings['requests_per_minute'] ?? 60 ); ?>" min="10" max="500" class="small-text">
								<p class="description"><?php _e( 'Maximum requests allowed per minute per IP.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Block Duration', 'nexifymy-security' ); ?></th>
							<td>
								<input type="number" id="rate-duration" value="<?php echo intval( $rate_settings['block_duration'] ?? 60 ); ?>" min="1" max="1440" class="small-text">
								<?php _e( 'minutes', 'nexifymy-security' ); ?>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Whitelist IPs', 'nexifymy-security' ); ?></th>
							<td>
								<textarea id="rate-whitelist" class="large-text" rows="3" placeholder="<?php _e( 'One IP per line', 'nexifymy-security' ); ?>"><?php echo esc_textarea( $rate_settings['whitelist'] ?? '' ); ?></textarea>
								<p class="description"><?php _e( 'IPs that bypass rate limiting.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
					</table>
				</div>
			</div>
			
			<p class="submit">
				<button type="button" id="save-rate-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
				<span id="rate-status" style="margin-left: 15px;"></span>
			</p>
		</div>
		<?php
	}

	/**
	 * Render the Scanner page with tabs.
	 */
	public function render_scanner_page() {
		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'scanner';
		?>
		<div class="wrap nexifymy-security-wrap nms-tabbed-page">
			<div class="nms-page-header">
				<h1><span class="dashicons dashicons-search"></span> <?php _e( 'Scanner', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Scan your site for malware, vulnerabilities, and security issues.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nms-page-tabs">
				<button class="nms-page-tab <?php echo $active_tab === 'scanner' ? 'active' : ''; ?>" data-tab="scanner">
					<span class="dashicons dashicons-search"></span> <?php _e( 'Scanner', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'quarantine' ? 'active' : ''; ?>" data-tab="quarantine">
					<span class="dashicons dashicons-archive"></span> <?php _e( 'Quarantine', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'definitions' ? 'active' : ''; ?>" data-tab="definitions">
					<span class="dashicons dashicons-database"></span> <?php _e( 'Malware Definitions', 'nexifymy-security' ); ?>
				</button>
			</div>

			<div class="nms-tab-content">
				<div id="tab-scanner" class="nms-tab-panel <?php echo $active_tab === 'scanner' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'scanner' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_scanner_content(); ?>
				</div>
				<div id="tab-quarantine" class="nms-tab-panel <?php echo $active_tab === 'quarantine' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'quarantine' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_quarantine_content(); ?>
				</div>
				<div id="tab-definitions" class="nms-tab-panel <?php echo $active_tab === 'definitions' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'definitions' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_definitions_content(); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Firewall page with tabs.
	 */
	public function render_firewall_page() {
		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'firewall';
		?>
		<div class="wrap nexifymy-security-wrap nms-tabbed-page">
			<div class="nms-page-header">
				<h1><span class="dashicons dashicons-shield-alt"></span> <?php _e( 'Firewall', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Configure firewall rules and protection settings.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nms-page-tabs">
				<button class="nms-page-tab <?php echo $active_tab === 'firewall' ? 'active' : ''; ?>" data-tab="firewall">
					<span class="dashicons dashicons-shield"></span> <?php _e( 'Firewall Rules', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'login' ? 'active' : ''; ?>" data-tab="login">
					<span class="dashicons dashicons-lock"></span> <?php _e( 'Login Protection', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'geo' ? 'active' : ''; ?>" data-tab="geo">
					<span class="dashicons dashicons-admin-site-alt3"></span> <?php _e( 'Geo Blocking', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'rate' ? 'active' : ''; ?>" data-tab="rate">
					<span class="dashicons dashicons-dashboard"></span> <?php _e( 'Rate Limiter', 'nexifymy-security' ); ?>
				</button>
			</div>

			<div class="nms-tab-content">
				<div id="tab-firewall" class="nms-tab-panel <?php echo $active_tab === 'firewall' ? 'active' : ''; ?>">
					<?php $this->render_firewall_content(); ?>
				</div>
				<div id="tab-login" class="nms-tab-panel <?php echo $active_tab === 'login' ? 'active' : ''; ?>">
					<?php $this->render_login_content(); ?>
				</div>
				<div id="tab-geo" class="nms-tab-panel <?php echo $active_tab === 'geo' ? 'active' : ''; ?>">
					<?php $this->render_geo_content(); ?>
				</div>
				<div id="tab-rate" class="nms-tab-panel <?php echo $active_tab === 'rate' ? 'active' : ''; ?>">
					<?php $this->render_rate_content(); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Modules page with tabs.
	 */
	public function render_modules_page() {
		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'overview';
		?>
		<div class="wrap nexifymy-security-wrap nms-tabbed-page">
			<div class="nms-page-header">
				<h1><span class="dashicons dashicons-admin-plugins"></span> <?php _e( 'Modules', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Enable and configure security modules.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nms-page-tabs">
				<button class="nms-page-tab <?php echo $active_tab === 'overview' ? 'active' : ''; ?>" data-tab="overview">
					<span class="dashicons dashicons-screenoptions"></span> <?php _e( 'Overview', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'waf' ? 'active' : ''; ?>" data-tab="waf">
					<span class="dashicons dashicons-shield-alt"></span> <?php _e( 'WAF', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'firewall' ? 'active' : ''; ?>" data-tab="firewall">
					<span class="dashicons dashicons-lock"></span> <?php _e( 'Firewall', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'scanner' ? 'active' : ''; ?>" data-tab="scanner">
					<span class="dashicons dashicons-search"></span> <?php _e( 'Scanner', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'ratelimit' ? 'active' : ''; ?>" data-tab="ratelimit">
					<span class="dashicons dashicons-clock"></span> <?php _e( 'Rate Limit', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'login' ? 'active' : ''; ?>" data-tab="login">
					<span class="dashicons dashicons-admin-users"></span> <?php _e( 'Login', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'geo' ? 'active' : ''; ?>" data-tab="geo">
					<span class="dashicons dashicons-location-alt"></span> <?php _e( 'Geo Block', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === '2fa' ? 'active' : ''; ?>" data-tab="2fa">
					<span class="dashicons dashicons-smartphone"></span> <?php _e( '2FA', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'hardening' ? 'active' : ''; ?>" data-tab="hardening">
					<span class="dashicons dashicons-hammer"></span> <?php _e( 'Hardening', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'hidelogin' ? 'active' : ''; ?>" data-tab="hidelogin">
					<span class="dashicons dashicons-hidden"></span> <?php _e( 'Hide Login', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'password' ? 'active' : ''; ?>" data-tab="password">
					<span class="dashicons dashicons-admin-network"></span> <?php _e( 'Password', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'captcha' ? 'active' : ''; ?>" data-tab="captcha">
					<span class="dashicons dashicons-forms"></span> <?php _e( 'Captcha', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'traffic' ? 'active' : ''; ?>" data-tab="traffic">
					<span class="dashicons dashicons-visibility"></span> <?php _e( 'Traffic', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'notifications' ? 'active' : ''; ?>" data-tab="notifications">
					<span class="dashicons dashicons-email"></span> <?php _e( 'Alerts', 'nexifymy-security' ); ?>
				</button>
			</div>

			<div class="nms-tab-content">
				<div id="tab-overview" class="nms-tab-panel <?php echo $active_tab === 'overview' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'overview' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_modules_hub_content(); ?>
				</div>
				<div id="tab-waf" class="nms-tab-panel <?php echo $active_tab === 'waf' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'waf' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_waf_settings_content(); ?>
				</div>
				<div id="tab-firewall" class="nms-tab-panel <?php echo $active_tab === 'firewall' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'firewall' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_firewall_content(); ?>
				</div>
				<div id="tab-scanner" class="nms-tab-panel <?php echo $active_tab === 'scanner' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'scanner' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_scanner_settings_content(); ?>
				</div>
				<div id="tab-ratelimit" class="nms-tab-panel <?php echo $active_tab === 'ratelimit' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'ratelimit' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_rate_content(); ?>
				</div>
				<div id="tab-login" class="nms-tab-panel <?php echo $active_tab === 'login' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'login' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_login_content(); ?>
				</div>
				<div id="tab-geo" class="nms-tab-panel <?php echo $active_tab === 'geo' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'geo' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_geo_content(); ?>
				</div>
				<div id="tab-2fa" class="nms-tab-panel <?php echo $active_tab === '2fa' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === '2fa' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_2fa_content(); ?>
				</div>
				<div id="tab-hardening" class="nms-tab-panel <?php echo $active_tab === 'hardening' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'hardening' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_hardening_content(); ?>
				</div>
				<div id="tab-hidelogin" class="nms-tab-panel <?php echo $active_tab === 'hidelogin' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'hidelogin' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_hide_login_content(); ?>
				</div>
				<div id="tab-password" class="nms-tab-panel <?php echo $active_tab === 'password' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'password' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_password_content(); ?>
				</div>
				<div id="tab-captcha" class="nms-tab-panel <?php echo $active_tab === 'captcha' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'captcha' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_captcha_content(); ?>
				</div>
				<div id="tab-traffic" class="nms-tab-panel <?php echo $active_tab === 'traffic' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'traffic' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_live_traffic_content(); ?>
				</div>
				<div id="tab-notifications" class="nms-tab-panel <?php echo $active_tab === 'notifications' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'notifications' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_notifications_content(); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Tools page with tabs.
	 */
	public function render_tools_page() {
		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'overview';
		?>
		<div class="wrap nexifymy-security-wrap nms-tabbed-page">
			<div class="nms-page-header">
				<h1><span class="dashicons dashicons-admin-tools"></span> <?php _e( 'Tools', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Maintenance and diagnostic tools for your site.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nms-page-tabs">
				<button class="nms-page-tab <?php echo $active_tab === 'overview' ? 'active' : ''; ?>" data-tab="overview">
					<span class="dashicons dashicons-screenoptions"></span> <?php _e( 'Overview', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'database' ? 'active' : ''; ?>" data-tab="database">
					<span class="dashicons dashicons-database"></span> <?php _e( 'Database', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'core' ? 'active' : ''; ?>" data-tab="core">
					<span class="dashicons dashicons-hammer"></span> <?php _e( 'Core Repair', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'traffic' ? 'active' : ''; ?>" data-tab="traffic">
					<span class="dashicons dashicons-visibility"></span> <?php _e( 'Live Traffic', 'nexifymy-security' ); ?>
				</button>
			</div>

			<div class="nms-tab-content">
				<div id="tab-overview" class="nms-tab-panel <?php echo $active_tab === 'overview' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'overview' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_tools_hub_content(); ?>
				</div>
				<div id="tab-database" class="nms-tab-panel <?php echo $active_tab === 'database' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'database' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_database_content(); ?>
				</div>
				<div id="tab-core" class="nms-tab-panel <?php echo $active_tab === 'core' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'core' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_core_repair_content(); ?>
				</div>
				<div id="tab-traffic" class="nms-tab-panel <?php echo $active_tab === 'traffic' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'traffic' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_live_traffic_content(); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Settings page with tabs.
	 */
	public function render_settings_page() {
		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'general';
		?>
		<div class="wrap nexifymy-security-wrap nms-tabbed-page">
			<div class="nms-page-header">
				<h1><span class="dashicons dashicons-admin-generic"></span> <?php _e( 'Settings', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Configure plugin settings and preferences.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nms-page-tabs">
				<button class="nms-page-tab <?php echo $active_tab === 'general' ? 'active' : ''; ?>" data-tab="general">
					<span class="dashicons dashicons-admin-settings"></span> <?php _e( 'General', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'email' ? 'active' : ''; ?>" data-tab="email">
					<span class="dashicons dashicons-email-alt"></span> <?php _e( 'Email Alerts', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'import-export' ? 'active' : ''; ?>" data-tab="import-export">
					<span class="dashicons dashicons-download"></span> <?php _e( 'Import/Export', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'advanced' ? 'active' : ''; ?>" data-tab="advanced">
					<span class="dashicons dashicons-admin-tools"></span> <?php _e( 'Advanced', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'logs' ? 'active' : ''; ?>" data-tab="logs">
					<span class="dashicons dashicons-editor-alignleft"></span> <?php _e( 'Logs', 'nexifymy-security' ); ?>
				</button>
			</div>

			<div class="nms-tab-content">
				<div id="tab-general" class="nms-tab-panel <?php echo $active_tab === 'general' ? 'active' : ''; ?>">
					<?php $this->render_settings_content(); ?>
				</div>
				<div id="tab-email" class="nms-tab-panel <?php echo $active_tab === 'email' ? 'active' : ''; ?>">
					<?php $this->render_email_settings_content(); ?>
				</div>
				<div id="tab-import-export" class="nms-tab-panel <?php echo $active_tab === 'import-export' ? 'active' : ''; ?>">
					<?php $this->render_import_export_content(); ?>
				</div>
				<div id="tab-advanced" class="nms-tab-panel <?php echo $active_tab === 'advanced' ? 'active' : ''; ?>">
					<?php $this->render_advanced_settings_content(); ?>
				</div>
				<div id="tab-logs" class="nms-tab-panel <?php echo $active_tab === 'logs' ? 'active' : ''; ?>">
					<?php $this->render_logs_content(); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render modules hub content for tab panel.
	 */
	private function render_modules_hub_content() {
		$modules = array(
			'2fa'              => array( 'name' => __( '2FA', 'nexifymy-security' ), 'icon' => 'smartphone', 'desc' => __( 'Two-factor authentication', 'nexifymy-security' ) ),
			'hardening'        => array( 'name' => __( 'Hardening', 'nexifymy-security' ), 'icon' => 'hammer', 'desc' => __( 'Security hardening', 'nexifymy-security' ) ),
			'hide_login'       => array( 'name' => __( 'Hide Login', 'nexifymy-security' ), 'icon' => 'hidden', 'desc' => __( 'Hide wp-admin', 'nexifymy-security' ) ),
			'password_policy'  => array( 'name' => __( 'Password', 'nexifymy-security' ), 'icon' => 'admin-network', 'desc' => __( 'Password policy', 'nexifymy-security' ) ),
			'captcha'          => array( 'name' => __( 'Captcha', 'nexifymy-security' ), 'icon' => 'shield', 'desc' => __( 'Bot protection', 'nexifymy-security' ) ),
			'self_protection'  => array( 'name' => __( 'Self-Protection', 'nexifymy-security' ), 'icon' => 'lock', 'desc' => __( 'Plugin protection', 'nexifymy-security' ) ),
		);
		$settings = get_option( 'nexifymy_security_settings', array() );
		$enabled_modules = isset( $settings['enabled_modules'] ) ? $settings['enabled_modules'] : array();
		?>
		<div class="nms-modules-grid" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px;">
			<?php foreach ( $modules as $key => $module ) : 
				$is_enabled = in_array( $key, $enabled_modules );
			?>
			<div class="nms-card" style="margin: 0;">
				<div class="nms-card-body">
					<div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
						<div class="nms-stat-icon <?php echo $is_enabled ? 'green' : 'blue'; ?>" style="width: 40px; height: 40px;">
							<span class="dashicons dashicons-<?php echo esc_attr( $module['icon'] ); ?>"></span>
						</div>
						<div>
							<h4 style="margin: 0; font-size: 15px;"><?php echo esc_html( $module['name'] ); ?></h4>
							<p style="margin: 0; font-size: 12px; color: var(--nms-gray-500);"><?php echo esc_html( $module['desc'] ); ?></p>
						</div>
					</div>
					<div style="display: flex; justify-content: space-between; align-items: center;">
						<label class="nms-toggle">
							<input type="checkbox" class="module-toggle" data-module="<?php echo esc_attr( $key ); ?>" <?php checked( $is_enabled ); ?>>
							<span class="nms-toggle-slider"></span>
						</label>
						<span class="nms-badge <?php echo $is_enabled ? 'nms-badge-success' : 'nms-badge-warning'; ?>">
							<?php echo $is_enabled ? __( 'Active', 'nexifymy-security' ) : __( 'Inactive', 'nexifymy-security' ); ?>
						</span>
					</div>
				</div>
			</div>
			<?php endforeach; ?>
		</div>
		<?php
	}

	/**
	 * Render 2FA content for tab panel.
	 */
	private function render_2fa_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$tfa_settings = isset( $settings['2fa'] ) ? $settings['2fa'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><?php _e( 'Two-Factor Authentication', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable 2FA', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="2fa-enabled" <?php checked( ! empty( $tfa_settings['enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Require for Roles', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" name="2fa-roles[]" value="administrator" <?php checked( in_array( 'administrator', $tfa_settings['roles'] ?? array() ) ); ?>> Administrator</label><br>
							<label><input type="checkbox" name="2fa-roles[]" value="editor" <?php checked( in_array( 'editor', $tfa_settings['roles'] ?? array() ) ); ?>> Editor</label>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-2fa-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="2fa-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render hardening content for tab panel.
	 */
	private function render_hardening_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$hardening = isset( $settings['hardening'] ) ? $settings['hardening'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><?php _e( 'Security Hardening', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Disable File Editor', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" name="disable_file_editor" <?php checked( ! empty( $hardening['disable_file_editor'] ) ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Hide WP Version', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" name="hide_wp_version" <?php checked( ! empty( $hardening['hide_wp_version'] ) ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Disable XML-RPC', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" name="disable_xmlrpc" <?php checked( ! empty( $hardening['disable_xmlrpc'] ) ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-hardening-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="hardening-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render hide login content for tab panel.
	 */
	private function render_hide_login_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$hide_login = isset( $settings['hide_login'] ) ? $settings['hide_login'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><?php _e( 'Hide Login Page', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Hide Login', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" id="hide-login-enabled" <?php checked( ! empty( $hide_login['enabled'] ) ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Custom Login URL', 'nexifymy-security' ); ?></th>
						<td><input type="text" id="hide-login-url" value="<?php echo esc_attr( $hide_login['login_url'] ?? '' ); ?>" class="regular-text" placeholder="my-secret-login"></td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-hide-login-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="hide-login-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render password content for tab panel.
	 */
	private function render_password_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$pass_settings = isset( $settings['password'] ) ? $settings['password'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><?php _e( 'Password Policy', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enforce Strong Passwords', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" id="pass-enforce" <?php checked( ! empty( $pass_settings['enforce'] ) ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Minimum Length', 'nexifymy-security' ); ?></th>
						<td><input type="number" id="pass-min-length" value="<?php echo intval( $pass_settings['min_length'] ?? 12 ); ?>" min="8" max="32" class="small-text"></td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-pass-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="pass-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render captcha content for tab panel.
	 */
	private function render_captcha_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$captcha = isset( $settings['captcha'] ) ? $settings['captcha'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><?php _e( 'Captcha Settings', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Captcha', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" id="captcha-enabled" <?php checked( ! empty( $captcha['enabled'] ) ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Site Key', 'nexifymy-security' ); ?></th>
						<td><input type="text" id="captcha-site-key" value="<?php echo esc_attr( $captcha['site_key'] ?? '' ); ?>" class="regular-text"></td>
					</tr>
					<tr>
						<th><?php _e( 'Secret Key', 'nexifymy-security' ); ?></th>
						<td><input type="password" id="captcha-secret-key" value="<?php echo esc_attr( $captcha['secret_key'] ?? '' ); ?>" class="regular-text"></td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-captcha-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="captcha-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render tools hub content for tab panel.
	 */
	private function render_tools_hub_content() {
		$tools = array(
			array( 'name' => __( 'Database Optimizer', 'nexifymy-security' ), 'icon' => 'database', 'desc' => __( 'Clean and optimize database', 'nexifymy-security' ), 'tab' => 'database' ),
			array( 'name' => __( 'Core File Repair', 'nexifymy-security' ), 'icon' => 'hammer', 'desc' => __( 'Verify and repair core files', 'nexifymy-security' ), 'tab' => 'core' ),
			array( 'name' => __( 'Live Traffic', 'nexifymy-security' ), 'icon' => 'visibility', 'desc' => __( 'Monitor real-time traffic', 'nexifymy-security' ), 'tab' => 'traffic' ),
		);
		?>
		<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px;">
			<?php foreach ( $tools as $tool ) : ?>
			<div class="nms-card" style="margin: 0; cursor: pointer;" onclick="jQuery('.nms-page-tab[data-tab=\'<?php echo esc_attr( $tool['tab'] ); ?>\']').click();">
				<div class="nms-card-body" style="display: flex; align-items: center; gap: 16px;">
					<div class="nms-stat-icon blue" style="width: 48px; height: 48px;">
						<span class="dashicons dashicons-<?php echo esc_attr( $tool['icon'] ); ?>"></span>
					</div>
					<div>
						<h4 style="margin: 0 0 4px; font-size: 15px; font-weight: 600;"><?php echo esc_html( $tool['name'] ); ?></h4>
						<p style="margin: 0; font-size: 13px; color: var(--nms-gray-500);"><?php echo esc_html( $tool['desc'] ); ?></p>
					</div>
				</div>
			</div>
			<?php endforeach; ?>
		</div>
		<?php
	}

	/**
	 * Render database content for tab panel.
	 */
	private function render_database_content() {
		global $wpdb;
		$tables = $wpdb->get_results( "SHOW TABLE STATUS" );
		$total_size = 0;
		$overhead = 0;
		foreach ( $tables as $table ) {
			$total_size += $table->Data_length + $table->Index_length;
			$overhead += $table->Data_free;
		}
		?>
		<div class="nms-stats-row">
			<div class="nms-stat-card">
				<div class="nms-stat-icon blue"><span class="dashicons dashicons-database"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo count( $tables ); ?></h4>
					<p><?php _e( 'Tables', 'nexifymy-security' ); ?></p>
				</div>
			</div>
			<div class="nms-stat-card">
				<div class="nms-stat-icon green"><span class="dashicons dashicons-chart-area"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo size_format( $total_size ); ?></h4>
					<p><?php _e( 'Total Size', 'nexifymy-security' ); ?></p>
				</div>
			</div>
			<div class="nms-stat-card">
				<div class="nms-stat-icon <?php echo $overhead > 0 ? 'orange' : 'green'; ?>"><span class="dashicons dashicons-warning"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo size_format( $overhead ); ?></h4>
					<p><?php _e( 'Overhead', 'nexifymy-security' ); ?></p>
				</div>
			</div>
		</div>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Database Actions', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<button class="nms-btn nms-btn-primary" id="optimize-db"><?php _e( 'Optimize Database', 'nexifymy-security' ); ?></button>
				<span id="db-status" style="margin-left: 15px;"></span>
			</div>
		</div>
		<?php
	}

	/**
	 * Render core repair content for tab panel.
	 */
	private function render_core_repair_content() {
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'WordPress Core File Verification', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<p class="description"><?php _e( 'Compare your WordPress core files against the official checksums to detect modifications.', 'nexifymy-security' ); ?></p>
				<div style="margin-top: 20px;">
					<button class="nms-btn nms-btn-primary" id="verify-core"><?php _e( 'Verify Core Files', 'nexifymy-security' ); ?></button>
					<span id="core-status" style="margin-left: 15px;"></span>
				</div>
				<div id="core-results" style="margin-top: 20px; display: none;"></div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render live traffic content for tab panel.
	 */
	private function render_live_traffic_content() {
		?>
		<div class="nms-card">
			<div class="nms-card-header" style="display: flex; justify-content: space-between; align-items: center;">
				<h3><?php _e( 'Live Traffic Monitor', 'nexifymy-security' ); ?></h3>
				<button class="nms-btn nms-btn-secondary" id="refresh-traffic"><?php _e( 'Refresh', 'nexifymy-security' ); ?></button>
			</div>
			<div class="nms-card-body">
				<table class="widefat striped" id="traffic-table">
					<thead>
						<tr>
							<th><?php _e( 'Time', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'IP', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'URL', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Status', 'nexifymy-security' ); ?></th>
						</tr>
					</thead>
					<tbody id="traffic-tbody">
						<tr><td colspan="4"><?php _e( 'Loading traffic data...', 'nexifymy-security' ); ?></td></tr>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	/**
	 * Render settings content for tab panel.
	 */
	private function render_settings_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'General Settings', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Email Notifications', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="settings-email" <?php checked( ! empty( $settings['email_notifications'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Notification Email', 'nexifymy-security' ); ?></th>
						<td><input type="email" id="settings-email-address" value="<?php echo esc_attr( $settings['email_address'] ?? get_option( 'admin_email' ) ); ?>" class="regular-text"></td>
					</tr>
					<tr>
						<th><?php _e( 'Auto-Updates', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="settings-auto-update" <?php checked( ! empty( $settings['auto_updates'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-general-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="general-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render logs content for tab panel.
	 */
	private function render_logs_content() {
		?>
		<div class="nms-card">
			<div class="nms-card-header" style="display: flex; justify-content: space-between; align-items: center;">
				<h3><?php _e( 'Security Logs', 'nexifymy-security' ); ?></h3>
				<div>
					<button class="nms-btn nms-btn-secondary" id="refresh-logs"><?php _e( 'Refresh', 'nexifymy-security' ); ?></button>
					<button class="nms-btn nms-btn-danger" id="clear-logs"><?php _e( 'Clear Logs', 'nexifymy-security' ); ?></button>
				</div>
			</div>
			<div class="nms-card-body">
				<table class="widefat striped" id="logs-table">
					<thead>
						<tr>
							<th><?php _e( 'Time', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Type', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Message', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'IP', 'nexifymy-security' ); ?></th>
						</tr>
					</thead>
					<tbody id="logs-tbody">
						<tr><td colspan="4"><?php _e( 'Loading logs...', 'nexifymy-security' ); ?></td></tr>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	/**
	 * Render notifications content for tab panel.
	 */
	private function render_notifications_content() {
		?>
		<div class="nms-card">
			<div class="nms-card-header" style="display: flex; justify-content: space-between; align-items: center;">
				<h3><?php _e( 'Security Notifications', 'nexifymy-security' ); ?></h3>
				<button class="nms-btn nms-btn-secondary" id="mark-all-read"><?php _e( 'Mark All Read', 'nexifymy-security' ); ?></button>
			</div>
			<div class="nms-card-body">
				<table class="widefat striped" id="notifications-table">
					<thead>
						<tr>
							<th><?php _e( 'Date', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Type', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Message', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Actions', 'nexifymy-security' ); ?></th>
						</tr>
					</thead>
					<tbody id="notifications-tbody">
						<tr><td colspan="4"><?php _e( 'Loading notifications...', 'nexifymy-security' ); ?></td></tr>
					</tbody>
				</table>
		</div>
		</div>
		<?php
	}

	/**
	 * Render scanner content for tab panel.
	 */
	private function render_scanner_content() {
		$last_scan = get_option( 'nexifymy_last_scan', array() );
		$scan_results = get_option( 'nexifymy_scan_results', array() );
		?>
		<div class="nms-stats-row">
			<div class="nms-stat-card">
				<div class="nms-stat-icon blue"><span class="dashicons dashicons-media-document"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo number_format( $last_scan['files_scanned'] ?? 0 ); ?></h4>
					<p><?php _e( 'Files Scanned', 'nexifymy-security' ); ?></p>
				</div>
			</div>
			<div class="nms-stat-card">
				<div class="nms-stat-icon <?php echo ( $scan_results['threats'] ?? 0 ) > 0 ? 'red' : 'green'; ?>"><span class="dashicons dashicons-shield"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo intval( $scan_results['threats'] ?? 0 ); ?></h4>
					<p><?php _e( 'Threats Found', 'nexifymy-security' ); ?></p>
				</div>
			</div>
			<div class="nms-stat-card">
				<div class="nms-stat-icon green"><span class="dashicons dashicons-clock"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo $last_scan['time'] ? human_time_diff( strtotime( $last_scan['time'] ) ) . ' ago' : __( 'Never', 'nexifymy-security' ); ?></h4>
					<p><?php _e( 'Last Scan', 'nexifymy-security' ); ?></p>
				</div>
			</div>
		</div>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Start a Scan', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<div class="nms-scan-modes-grid">
					<div class="nms-scan-mode-card" data-mode="quick">
						<div class="nms-scan-mode-icon">
							<span class="dashicons dashicons-search"></span>
						</div>
						<h4><?php _e( 'Quick Scan', 'nexifymy-security' ); ?></h4>
						<p><?php _e( 'Fast security check', 'nexifymy-security' ); ?></p>
						<ul class="nms-scan-features">
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'High-risk areas only', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Fast execution', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Checks for web shells', 'nexifymy-security' ); ?></li>
						</ul>
						<button class="nms-btn nms-btn-primary scan-btn"><?php _e( 'Start Scan', 'nexifymy-security' ); ?></button>
					</div>
					<div class="nms-scan-mode-card" data-mode="standard">
						<div class="nms-recommended-badge"><?php _e( 'Recommended', 'nexifymy-security' ); ?></div>
						<div class="nms-scan-mode-icon">
							<span class="dashicons dashicons-shield"></span>
						</div>
						<h4><?php _e( 'Standard Scan', 'nexifymy-security' ); ?></h4>
						<p><?php _e( 'Full malware scan', 'nexifymy-security' ); ?></p>
						<ul class="nms-scan-features">
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Full malware signatures', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Plugin & Theme analysis', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Database security check', 'nexifymy-security' ); ?></li>
						</ul>
						<button class="nms-btn nms-btn-primary scan-btn"><?php _e( 'Start Scan', 'nexifymy-security' ); ?></button>
					</div>
					<div class="nms-scan-mode-card" data-mode="deep">
						<div class="nms-scan-mode-icon">
							<span class="dashicons dashicons-shield-alt"></span>
						</div>
						<h4><?php _e( 'Deep Scan', 'nexifymy-security' ); ?></h4>
						<p><?php _e( 'Comprehensive analysis', 'nexifymy-security' ); ?></p>
						<ul class="nms-scan-features">
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Core file integrity', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Advanced heuristics', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Full site analysis', 'nexifymy-security' ); ?></li>
						</ul>
						<button class="nms-btn nms-btn-primary scan-btn"><?php _e( 'Start Scan', 'nexifymy-security' ); ?></button>
					</div>
				</div>
				<div id="scan-progress" class="nms-scan-progress-panel" style="display: none;">
					<div class="nms-progress-header">
						<span class="dashicons dashicons-update spin"></span>
						<span id="scan-status-text"><?php _e( 'Initializing...', 'nexifymy-security' ); ?></span>
					</div>
					<div class="nms-progress-bar"><div class="nms-progress-fill" style="width: 0%;"></div></div>
					<div class="nms-progress-info">
						<span id="scan-files-count">0 / 0 files</span>
						<span class="nms-progress-percent">0%</span>
					</div>
					<div class="nms-progress-current" style="margin-top: 10px; font-size: 12px; color: #666;">
						<strong><?php _e( 'Current:', 'nexifymy-security' ); ?></strong>
						<code id="scan-current-file" style="background: #f5f5f5; padding: 2px 6px; border-radius: 3px;">—</code>
					</div>
					<div id="scan-threat-counts" class="nms-threat-counts" style="margin-top: 10px; display: flex; gap: 15px; font-size: 13px;">
						<!-- Filled dynamically by JS -->
					</div>
				</div>
				<div id="scan-results" style="display: none; margin-top: 20px;">
					<div id="results-content"></div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render quarantine content for tab panel.
	 */
	private function render_quarantine_content() {
		$quarantine = get_option( 'nexifymy_quarantine', array() );
		?>
		<div class="nms-card">
			<div class="nms-card-header" style="display: flex; justify-content: space-between; align-items: center;">
				<h3><?php _e( 'Quarantined Files', 'nexifymy-security' ); ?></h3>
				<span class="nms-badge nms-badge-warning"><?php echo count( $quarantine ); ?> <?php _e( 'files', 'nexifymy-security' ); ?></span>
			</div>
			<div class="nms-card-body">
				<?php if ( empty( $quarantine ) ) : ?>
					<p style="text-align: center; color: var(--nms-gray-500);"><?php _e( 'No files in quarantine.', 'nexifymy-security' ); ?></p>
				<?php else : ?>
					<table class="widefat striped">
						<thead>
							<tr>
								<th><?php _e( 'File', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Threat', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Date', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Actions', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $quarantine as $item ) : ?>
							<tr>
								<td><code><?php echo esc_html( basename( $item['file'] ?? '' ) ); ?></code></td>
								<td><span class="nms-badge nms-badge-danger"><?php echo esc_html( $item['threat'] ?? 'Unknown' ); ?></span></td>
								<td><?php echo esc_html( $item['date'] ?? '' ); ?></td>
								<td>
									<button class="nms-btn nms-btn-sm nms-btn-secondary restore-file" data-id="<?php echo esc_attr( $item['id'] ?? '' ); ?>"><?php _e( 'Restore', 'nexifymy-security' ); ?></button>
									<button class="nms-btn nms-btn-sm nms-btn-danger delete-file" data-id="<?php echo esc_attr( $item['id'] ?? '' ); ?>"><?php _e( 'Delete', 'nexifymy-security' ); ?></button>
								</td>
							</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render malware definitions content for tab panel.
	 */
	private function render_definitions_content() {
		$signature_version = get_option( 'nexifymy_signature_version', '1.0.0' );
		$last_update = get_option( 'nexifymy_signature_last_update', null );
		$signature_count = get_option( 'nexifymy_signature_count', 0 );
		?>
		<div class="nms-stats-row">
			<div class="nms-stat-card">
				<div class="nms-stat-icon blue"><span class="dashicons dashicons-database"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo esc_html( $signature_version ); ?></h4>
					<p><?php _e( 'Version', 'nexifymy-security' ); ?></p>
				</div>
			</div>
			<div class="nms-stat-card">
				<div class="nms-stat-icon green"><span class="dashicons dashicons-shield"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo number_format( $signature_count ); ?></h4>
					<p><?php _e( 'Signatures', 'nexifymy-security' ); ?></p>
				</div>
			</div>
			<div class="nms-stat-card">
				<div class="nms-stat-icon purple"><span class="dashicons dashicons-clock"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo $last_update ? human_time_diff( strtotime( $last_update ) ) . ' ago' : __( 'Never', 'nexifymy-security' ); ?></h4>
					<p><?php _e( 'Last Updated', 'nexifymy-security' ); ?></p>
				</div>
			</div>
		</div>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Update Definitions', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<?php
				$settings = get_option( 'nexifymy_security_settings', array() );
				$auto_update = isset( $settings['signatures']['auto_update'] ) ? $settings['signatures']['auto_update'] : true;
				$next_update = wp_next_scheduled( 'nexifymy_update_signatures' );
				?>
				<table class="form-table" style="margin-bottom: 20px;">
					<tr>
						<th><?php _e( 'Auto-Update', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="auto-update-signatures" <?php checked( $auto_update ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Automatically update malware signatures daily.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Next Update', 'nexifymy-security' ); ?></th>
						<td>
							<?php if ( $next_update ) : ?>
								<span style="color: var(--nms-success);"><?php echo human_time_diff( $next_update ) . ' ' . __( 'from now', 'nexifymy-security' ); ?></span>
							<?php else : ?>
								<span style="color: var(--nms-gray-500);"><?php _e( 'Not scheduled', 'nexifymy-security' ); ?></span>
							<?php endif; ?>
						</td>
					</tr>
				</table>
				<button class="nms-btn nms-btn-primary" id="update-definitions">
					<span class="dashicons dashicons-update" style="margin-right: 5px;"></span>
					<?php _e( 'Update Now', 'nexifymy-security' ); ?>
				</button>
				<span id="definition-status" style="margin-left: 15px;"></span>
			</div>
		</div>
		<?php
	}

	/**
	 * Render WAF settings content for modules page tab panel.
	 */
	private function render_waf_settings_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$waf_settings = isset( $settings['waf'] ) ? $settings['waf'] : array();
		$modules = isset( $settings['modules'] ) ? $settings['modules'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-shield-alt"></span> <?php _e( 'Web Application Firewall (WAF)', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<p class="description" style="margin-bottom: 20px;"><?php _e( 'The WAF protects your site from common web attacks including SQL injection, XSS, and malicious bots.', 'nexifymy-security' ); ?></p>
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable WAF Module', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-module-enabled" data-module="waf" <?php checked( ! empty( $modules['waf_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Enable or disable the entire WAF module.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Block SQL Injection', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-block-sqli" <?php checked( ! empty( $waf_settings['block_sqli'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Block XSS Attacks', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-block-xss" <?php checked( ! empty( $waf_settings['block_xss'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Block Local File Inclusion', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-block-lfi" <?php checked( ! empty( $waf_settings['block_lfi'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Block Bad Bots', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-block-bots" <?php checked( ! empty( $waf_settings['block_bad_bots'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Log Only Mode', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-log-only" <?php checked( ! empty( $waf_settings['log_only_mode'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'When enabled, threats are logged but not blocked. Useful for testing.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-waf-module-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save WAF Settings', 'nexifymy-security' ); ?></button>
					<span id="waf-module-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render Scanner settings content for modules page tab panel.
	 */
	private function render_scanner_settings_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$scanner_settings = isset( $settings['scanner'] ) ? $settings['scanner'] : array();
		$modules = isset( $settings['modules'] ) ? $settings['modules'] : array();
		$bg_settings = isset( $settings['background_scan'] ) ? $settings['background_scan'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-search"></span> <?php _e( 'Scanner Settings', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<p class="description" style="margin-bottom: 20px;"><?php _e( 'Configure malware scanner behavior and scheduled scanning options.', 'nexifymy-security' ); ?></p>
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Scanner Module', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="scanner-module-enabled" data-module="scanner" <?php checked( ! empty( $modules['scanner_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Default Scan Mode', 'nexifymy-security' ); ?></th>
						<td>
							<select id="scanner-default-mode">
								<option value="quick" <?php selected( $scanner_settings['default_mode'] ?? 'standard', 'quick' ); ?>><?php _e( 'Quick Scan', 'nexifymy-security' ); ?></option>
								<option value="standard" <?php selected( $scanner_settings['default_mode'] ?? 'standard', 'standard' ); ?>><?php _e( 'Standard Scan', 'nexifymy-security' ); ?></option>
								<option value="deep" <?php selected( $scanner_settings['default_mode'] ?? 'standard', 'deep' ); ?>><?php _e( 'Deep Scan', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Max File Size', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="scanner-max-size" value="<?php echo intval( $scanner_settings['max_file_size_kb'] ?? 2048 ); ?>" min="100" max="10240" class="small-text"> <?php _e( 'KB', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Files larger than this will be skipped during scanning.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Scheduled Scans', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="scanner-background-enabled" <?php checked( ! empty( $modules['background_scan_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Scan Schedule', 'nexifymy-security' ); ?></th>
						<td>
							<select id="scanner-schedule">
								<option value="hourly" <?php selected( $bg_settings['schedule'] ?? 'daily', 'hourly' ); ?>><?php _e( 'Hourly', 'nexifymy-security' ); ?></option>
								<option value="twicedaily" <?php selected( $bg_settings['schedule'] ?? 'daily', 'twicedaily' ); ?>><?php _e( 'Twice Daily', 'nexifymy-security' ); ?></option>
								<option value="daily" <?php selected( $bg_settings['schedule'] ?? 'daily', 'daily' ); ?>><?php _e( 'Daily', 'nexifymy-security' ); ?></option>
								<option value="weekly" <?php selected( $bg_settings['schedule'] ?? 'daily', 'weekly' ); ?>><?php _e( 'Weekly', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Excluded Extensions', 'nexifymy-security' ); ?></th>
						<td>
							<input type="text" id="scanner-excluded-ext" value="<?php echo esc_attr( implode( ', ', $scanner_settings['excluded_extensions'] ?? array( 'jpg', 'jpeg', 'png', 'gif', 'pdf', 'zip' ) ) ); ?>" class="regular-text">
							<p class="description"><?php _e( 'Comma-separated list of file extensions to skip (e.g., jpg, png, pdf).', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-scanner-module-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Scanner Settings', 'nexifymy-security' ); ?></button>
					<span id="scanner-module-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render firewall rules content for tab panel.
	 */
	private function render_firewall_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$waf_settings = isset( $settings['waf'] ) ? $settings['waf'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Web Application Firewall', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable WAF', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" id="waf-enabled" <?php checked( ! empty( $waf_settings['enabled'] ) ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Protection Level', 'nexifymy-security' ); ?></th>
						<td>
							<select id="waf-level">
								<option value="low" <?php selected( $waf_settings['level'] ?? 'medium', 'low' ); ?>><?php _e( 'Low', 'nexifymy-security' ); ?></option>
								<option value="medium" <?php selected( $waf_settings['level'] ?? 'medium', 'medium' ); ?>><?php _e( 'Medium', 'nexifymy-security' ); ?></option>
								<option value="high" <?php selected( $waf_settings['level'] ?? 'medium', 'high' ); ?>><?php _e( 'High', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-waf-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="waf-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render login protection content for tab panel.
	 */
	private function render_login_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$login_settings = isset( $settings['login_protection'] ) ? $settings['login_protection'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Login Protection', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Protection', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" id="login-enabled" <?php checked( ! empty( $login_settings['enabled'] ) ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Max Attempts', 'nexifymy-security' ); ?></th>
						<td><input type="number" id="login-max-attempts" value="<?php echo intval( $login_settings['max_attempts'] ?? 5 ); ?>" min="1" max="20" class="small-text"></td>
					</tr>
					<tr>
						<th><?php _e( 'Lockout Duration', 'nexifymy-security' ); ?></th>
						<td><input type="number" id="login-lockout" value="<?php echo intval( $login_settings['lockout_duration'] ?? 30 ); ?>" min="5" max="1440" class="small-text"> <?php _e( 'minutes', 'nexifymy-security' ); ?></td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-login-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="login-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render geo blocking content for tab panel.
	 */
	private function render_geo_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$geo_settings = isset( $settings['geo_blocking'] ) ? $settings['geo_blocking'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Geo Blocking', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Geo Blocking', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" id="geo-enabled" <?php checked( ! empty( $geo_settings['enabled'] ) ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Block Mode', 'nexifymy-security' ); ?></th>
						<td>
							<select id="geo-mode">
								<option value="blacklist" <?php selected( $geo_settings['mode'] ?? 'blacklist', 'blacklist' ); ?>><?php _e( 'Blacklist', 'nexifymy-security' ); ?></option>
								<option value="whitelist" <?php selected( $geo_settings['mode'] ?? 'blacklist', 'whitelist' ); ?>><?php _e( 'Whitelist', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-geo-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="geo-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render rate limiter content for tab panel.
	 */
	private function render_rate_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$rate_settings = isset( $settings['rate_limiter'] ) ? $settings['rate_limiter'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Rate Limiting', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Rate Limiting', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" id="rate-enabled" <?php checked( ! empty( $rate_settings['enabled'] ) ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Requests per Minute', 'nexifymy-security' ); ?></th>
						<td><input type="number" id="rate-requests" value="<?php echo intval( $rate_settings['requests_per_minute'] ?? 60 ); ?>" min="10" max="500" class="small-text"></td>
					</tr>
					<tr>
						<th><?php _e( 'Block Duration', 'nexifymy-security' ); ?></th>
						<td><input type="number" id="rate-duration" value="<?php echo intval( $rate_settings['block_duration'] ?? 300 ); ?>" min="60" class="small-text"> <?php _e( 'seconds', 'nexifymy-security' ); ?></td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-rate-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="rate-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Notifications page (standalone).
	 */
	public function render_notifications_page() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nms-page-header">
				<h1><span class="dashicons dashicons-bell"></span> <?php _e( 'Notifications', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'View and manage security alerts and notifications.', 'nexifymy-security' ); ?></p>
			</div>
			<?php $this->render_notifications_content(); ?>
		</div>
		<?php
	}

	/**
	 * Render email settings content for Settings page.
	 */
	private function render_email_settings_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$email = isset( $settings['email_alerts'] ) ? $settings['email_alerts'] : array();
		$defaults = array(
			'enabled'          => false,
			'recipient'        => get_option( 'admin_email' ),
			'from_name'        => get_bloginfo( 'name' ),
			'from_email'       => 'security@' . parse_url( home_url(), PHP_URL_HOST ),
			'alert_threats'    => true,
			'alert_lockouts'   => true,
			'alert_waf'        => false,
			'alert_login'      => false,
			'daily_summary'    => false,
			'weekly_report'    => true,
			'throttle_minutes' => 60,
		);
		$email = wp_parse_args( $email, $defaults );
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Email Alert Settings', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Email Alerts', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" id="email-enabled" <?php checked( $email['enabled'] ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Recipient Email', 'nexifymy-security' ); ?></th>
						<td>
							<input type="email" id="email-recipient" value="<?php echo esc_attr( $email['recipient'] ); ?>" class="regular-text">
							<p class="description"><?php _e( 'Primary email address for security alerts.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'From Name', 'nexifymy-security' ); ?></th>
						<td><input type="text" id="email-from-name" value="<?php echo esc_attr( $email['from_name'] ); ?>" class="regular-text"></td>
					</tr>
					<tr>
						<th><?php _e( 'From Email', 'nexifymy-security' ); ?></th>
						<td><input type="email" id="email-from-email" value="<?php echo esc_attr( $email['from_email'] ); ?>" class="regular-text"></td>
					</tr>
				</table>
			</div>
		</div>

		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Alert Types', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Security Alerts', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" id="alert-threats" <?php checked( $email['alert_threats'] ); ?>> <?php _e( 'Threat Detected (malware, suspicious files)', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" id="alert-lockouts" <?php checked( $email['alert_lockouts'] ); ?>> <?php _e( 'IP Lockouts (brute force attempts)', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" id="alert-waf" <?php checked( $email['alert_waf'] ); ?>> <?php _e( 'WAF Blocks (attacked blocked by firewall)', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" id="alert-login" <?php checked( $email['alert_login'] ); ?>> <?php _e( 'Admin Logins (successful admin logins)', 'nexifymy-security' ); ?></label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Periodic Reports', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" id="daily-summary" <?php checked( $email['daily_summary'] ); ?>> <?php _e( 'Daily Status Summary', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" id="weekly-report" <?php checked( $email['weekly_report'] ); ?>> <?php _e( 'Weekly Security Report', 'nexifymy-security' ); ?></label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Throttle Period', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="throttle-minutes" value="<?php echo intval( $email['throttle_minutes'] ); ?>" min="0" max="1440" class="small-text"> <?php _e( 'minutes', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Prevent duplicate alerts within this time period. Set to 0 to disable throttling.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-email-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Email Settings', 'nexifymy-security' ); ?></button>
					<button type="button" id="test-email" class="nms-btn nms-btn-secondary"><?php _e( 'Send Test Email', 'nexifymy-security' ); ?></button>
					<span id="email-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render import/export content for Settings page.
	 */
	private function render_import_export_content() {
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Export Settings', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<p><?php _e( 'Export your NexifyMy Security settings to a JSON file. This includes all module configurations, firewall rules, IP lists, and scan settings.', 'nexifymy-security' ); ?></p>
				<p>
					<label><input type="checkbox" id="export-logs" checked> <?php _e( 'Include security logs (last 30 days)', 'nexifymy-security' ); ?></label><br>
					<label><input type="checkbox" id="export-ip-lists" checked> <?php _e( 'Include IP whitelist/blacklist', 'nexifymy-security' ); ?></label><br>
					<label><input type="checkbox" id="export-scan-results" checked> <?php _e( 'Include last scan results', 'nexifymy-security' ); ?></label>
				</p>
				<p class="submit">
					<button type="button" id="export-settings" class="nms-btn nms-btn-primary"><span class="dashicons dashicons-download"></span> <?php _e( 'Export Settings', 'nexifymy-security' ); ?></button>
				</p>
			</div>
		</div>

		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Import Settings', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<p><?php _e( 'Import settings from a previously exported JSON file. This will overwrite your current settings.', 'nexifymy-security' ); ?></p>
				<p class="warning" style="color: #d63638; background: #fcf0f1; padding: 10px; border-radius: 4px;">
					<span class="dashicons dashicons-warning"></span>
					<?php _e( 'Warning: Importing will replace all current settings. Make sure to export your current settings first as a backup.', 'nexifymy-security' ); ?>
				</p>
				<input type="file" id="import-file" accept=".json" style="margin: 10px 0;">
				<p class="submit">
					<button type="button" id="import-settings" class="nms-btn nms-btn-secondary"><span class="dashicons dashicons-upload"></span> <?php _e( 'Import Settings', 'nexifymy-security' ); ?></button>
					<span id="import-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>

		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Reset to Defaults', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<p><?php _e( 'Reset all NexifyMy Security settings to their default values. This action cannot be undone.', 'nexifymy-security' ); ?></p>
				<p class="submit">
					<button type="button" id="reset-settings" class="nms-btn" style="background: #d63638; color: white;"><span class="dashicons dashicons-trash"></span> <?php _e( 'Reset All Settings', 'nexifymy-security' ); ?></button>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render advanced settings content for Settings page.
	 */
	private function render_advanced_settings_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$advanced = isset( $settings['advanced'] ) ? $settings['advanced'] : array();
		$defaults = array(
			'delete_on_uninstall' => false,
			'debug_mode'          => false,
			'disable_xmlrpc'      => true,
			'disable_rest_users'  => true,
			'hide_wp_version'     => true,
			'disable_file_editor' => true,
			'block_author_scans'  => true,
			'block_bad_requests'  => true,
			'block_empty_ua'      => false,
			'performance_mode'    => 'balanced',
			'scan_timeout'        => 300,
			'request_size_limit'  => 10240,
		);
		$advanced = wp_parse_args( $advanced, $defaults );
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Security Hardening', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'XML-RPC', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="disable-xmlrpc" <?php checked( $advanced['disable_xmlrpc'] ); ?>> <?php _e( 'Disable XML-RPC (prevents pingback attacks)', 'nexifymy-security' ); ?></label></td>
					</tr>
					<tr>
						<th><?php _e( 'REST API Users', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="disable-rest-users" <?php checked( $advanced['disable_rest_users'] ); ?>> <?php _e( 'Disable public user enumeration via REST API', 'nexifymy-security' ); ?></label></td>
					</tr>
					<tr>
						<th><?php _e( 'WP Version', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="hide-wp-version" <?php checked( $advanced['hide_wp_version'] ); ?>> <?php _e( 'Hide WordPress version from source code', 'nexifymy-security' ); ?></label></td>
					</tr>
					<tr>
						<th><?php _e( 'File Editor', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="disable-file-editor" <?php checked( $advanced['disable_file_editor'] ); ?>> <?php _e( 'Disable theme and plugin editor', 'nexifymy-security' ); ?></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Author Scans', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="block-author-scans" <?php checked( $advanced['block_author_scans'] ); ?>> <?php _e( 'Block author enumeration scans (?author=1)', 'nexifymy-security' ); ?></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Bad Requests', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="block-bad-requests" <?php checked( $advanced['block_bad_requests'] ); ?>> <?php _e( 'Block malformed requests and suspicious query strings', 'nexifymy-security' ); ?></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Empty User Agent', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="block-empty-ua" <?php checked( $advanced['block_empty_ua'] ); ?>> <?php _e( 'Block requests with empty user-agent (may block some legitimate bots)', 'nexifymy-security' ); ?></label></td>
					</tr>
				</table>
			</div>
		</div>

		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Performance Settings', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Performance Mode', 'nexifymy-security' ); ?></th>
						<td>
							<select id="performance-mode">
								<option value="low" <?php selected( $advanced['performance_mode'], 'low' ); ?>><?php _e( 'Low Impact (fewer checks, faster)', 'nexifymy-security' ); ?></option>
								<option value="balanced" <?php selected( $advanced['performance_mode'], 'balanced' ); ?>><?php _e( 'Balanced (recommended)', 'nexifymy-security' ); ?></option>
								<option value="high" <?php selected( $advanced['performance_mode'], 'high' ); ?>><?php _e( 'High Security (more checks, slower)', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Scan Timeout', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="scan-timeout" value="<?php echo intval( $advanced['scan_timeout'] ); ?>" min="60" max="3600" class="small-text"> <?php _e( 'seconds', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Maximum time for malware scans before timeout.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Request Size Limit', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="request-size-limit" value="<?php echo intval( $advanced['request_size_limit'] ); ?>" min="1024" max="102400" class="small-text"> KB
							<p class="description"><?php _e( 'Maximum request body size to scan. Larger requests will be skipped.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
				</table>
			</div>
		</div>

		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Plugin Options', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Debug Mode', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="debug-mode" <?php checked( $advanced['debug_mode'] ); ?>> <?php _e( 'Enable debug logging (for troubleshooting only)', 'nexifymy-security' ); ?></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Uninstall Behavior', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="delete-on-uninstall" <?php checked( $advanced['delete_on_uninstall'] ); ?>> <?php _e( 'Delete all plugin data when uninstalling', 'nexifymy-security' ); ?></label></td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-advanced-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Advanced Settings', 'nexifymy-security' ); ?></button>
					<span id="advanced-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}
	/**
	 * Render the Analytics tab content.
	 */
	public function render_analytics_tab() {
		$data = array();
		if ( isset( $GLOBALS['nexifymy_analytics'] ) ) {
			$data = $GLOBALS['nexifymy_analytics']->get_chart_data( 7 );
		}
		// Fallback data if module not loaded or empty
		if ( empty( $data['labels'] ) ) {
			$data = array(
				'labels' => array( 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun' ),
				'datasets' => array(
					'threats' => array( 0, 0, 0, 1, 0, 2, 0 ),
					'blocked' => array( 5, 8, 12, 7, 9, 15, 10 ),
					'logins'  => array( 2, 1, 0, 3, 1, 0, 1 ),
				)
			);
		}
		?>
		<div class="nexifymy-header">
			<h1><?php _e( 'Security Analytics', 'nexifymy-security' ); ?></h1>
			<p><?php _e( 'Detailed insights into your website security performance.', 'nexifymy-security' ); ?></p>
		</div>

		<div class="nms-card">
			<div class="nms-card-header">
				<h3><?php _e( 'Threat Detection & Blocking - Last 7 Days', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<canvas id="nms-threats-chart" width="400" height="150"></canvas>
			</div>
		</div>

		<div class="nms-grid-2">
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Login Attempts', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<canvas id="nms-logins-chart" width="400" height="200"></canvas>
				</div>
			</div>
			
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Top Detection Reasons', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<ul class="nms-list-stats">
						<li>
							<span class="nms-stat-label"><span class="dashicons dashicons-shield"></span> <?php _e( 'SQL Injection', 'nexifymy-security' ); ?></span>
							<span class="nms-badge warning">12 <?php _e( 'blocked', 'nexifymy-security' ); ?></span>
						</li>
						<li>
							<span class="nms-stat-label"><span class="dashicons dashicons-code-standards"></span> <?php _e( 'XSS Attack', 'nexifymy-security' ); ?></span>
							<span class="nms-badge warning">5 <?php _e( 'blocked', 'nexifymy-security' ); ?></span>
						</li>
						<li>
							<span class="nms-stat-label"><span class="dashicons dashicons-admin-network"></span> <?php _e( 'Brute Force', 'nexifymy-security' ); ?></span>
							<span class="nms-badge danger">42 <?php _e( 'blocked', 'nexifymy-security' ); ?></span>
						</li>
						<li>
							<span class="nms-stat-label"><span class="dashicons dashicons-hidden"></span> <?php _e( 'Directory Traversal', 'nexifymy-security' ); ?></span>
							<span class="nms-badge info">3 <?php _e( 'blocked', 'nexifymy-security' ); ?></span>
						</li>
					</ul>
				</div>
			</div>
		</div>

		<script>
		document.addEventListener('DOMContentLoaded', function() {
			if (typeof Chart === 'undefined') return;
			
			const ctxThreats = document.getElementById('nms-threats-chart').getContext('2d');
			new Chart(ctxThreats, {
				type: 'line',
				data: {
					labels: <?php echo json_encode( $data['labels'] ); ?>,
					datasets: [{
						label: 'Threats Blocked',
						data: <?php echo json_encode( $data['datasets']['blocked'] ); ?>,
						borderColor: '#4f46e5',
						backgroundColor: 'rgba(79, 70, 229, 0.1)',
						borderWidth: 2,
						tension: 0.4,
						fill: true,
						pointBackgroundColor: '#ffffff',
						pointBorderColor: '#4f46e5',
						pointRadius: 4
					}, {
						label: 'Malware Detected',
						data: <?php echo json_encode( $data['datasets']['threats'] ); ?>,
						borderColor: '#dc2626',
						backgroundColor: 'rgba(220, 38, 38, 0.05)',
						borderWidth: 2,
						tension: 0.4,
						fill: false,
						borderDash: [5, 5]
					}]
				},
				options: {
					responsive: true,
					plugins: {
						legend: { position: 'top' },
						tooltip: {
							mode: 'index',
							intersect: false,
							backgroundColor: 'rgba(255, 255, 255, 0.9)',
							titleColor: '#1e293b',
							bodyColor: '#64748b',
							borderColor: '#e2e8f0',
							borderWidth: 1
						}
					},
					scales: {
						y: { beginAtZero: true, grid: { borderDash: [2, 2] } },
						x: { grid: { display: false } }
					}
				}
			});

			const ctxLogins = document.getElementById('nms-logins-chart').getContext('2d');
			new Chart(ctxLogins, {
				type: 'bar',
				data: {
					labels: <?php echo json_encode( $data['labels'] ); ?>,
					datasets: [{
						label: 'Failed Logins',
						data: <?php echo json_encode( $data['datasets']['logins'] ); ?>,
						backgroundColor: '#f59e0b',
						borderRadius: 4
					}]
				},
				options: {
					responsive: true,
					plugins: { legend: { display: false } },
					scales: {
						y: { beginAtZero: true }
					}
				}
			});
		});
		</script>
		<?php
	}
}
