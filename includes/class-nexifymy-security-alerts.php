<?php
/**
 * Email Alerting Module.
 * Sends email notifications for critical security events.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Alerts {

	/**
	 * Option key for alert settings.
	 */
	const OPTION_KEY = 'nexifymy_security_alert_settings';

	/**
	 * Alert types.
	 */
	const ALERT_TYPES = array(
		'threat_detected'  => 'Threat Detected',
		'ip_lockout'       => 'IP Locked Out',
		'waf_block'        => 'WAF Attack Blocked',
		'file_quarantined' => 'File Quarantined',
		'scan_completed'   => 'Scan Completed (with threats)',
	);

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'            => false,
		'recipient_email'    => '',
		'alert_types'        => array( 'threat_detected', 'ip_lockout' ),
		'throttle_minutes'   => 60, // Don't send duplicate alerts within this window.
		'daily_summary'      => false,
		'daily_summary_time' => '08:00',
	);

	/**
	 * Initialize the alerts module.
	 */
	public function init() {
		// Hook into security events.
		add_action( 'nexifymy_security_alert', array( $this, 'trigger_alert' ), 10, 3 );

		// Register settings AJAX.
		add_action( 'wp_ajax_nexifymy_save_alert_settings', array( $this, 'ajax_save_settings' ) );
		add_action( 'wp_ajax_nexifymy_get_alert_settings', array( $this, 'ajax_get_settings' ) );
		add_action( 'wp_ajax_nexifymy_test_alert', array( $this, 'ajax_test_alert' ) );

		// Daily summary cron.
		add_action( 'nexifymy_daily_summary', array( $this, 'send_daily_summary' ) );
		add_action( 'init', array( $this, 'maybe_schedule_daily_summary' ) );
	}

	/**
	 * Get alert settings.
	 *
	 * @return array
	 */
	public static function get_settings() {
		$settings = get_option( self::OPTION_KEY, array() );
		return wp_parse_args( $settings, self::$defaults );
	}

	/**
	 * Update alert settings.
	 *
	 * @param array $settings New settings.
	 * @return bool
	 */
	public static function update_settings( $settings ) {
		return update_option( self::OPTION_KEY, $settings );
	}

	/**
	 * Trigger an alert.
	 * Called via do_action( 'nexifymy_security_alert', $type, $message, $data ).
	 *
	 * @param string $type    Alert type.
	 * @param string $message Alert message.
	 * @param array  $data    Additional data.
	 */
	public function trigger_alert( $type, $message, $data = array() ) {
		$settings = self::get_settings();

		// Check if alerts are enabled.
		if ( ! $settings['enabled'] ) {
			return;
		}

		// Check if this alert type is enabled.
		if ( ! in_array( $type, $settings['alert_types'], true ) ) {
			return;
		}

		// Check recipient.
		$recipient = $settings['recipient_email'];
		if ( empty( $recipient ) ) {
			$recipient = get_option( 'admin_email' );
		}

		// Check throttling.
		if ( $this->is_throttled( $type, $data ) ) {
			return;
		}

		// Send the email.
		$this->send_alert_email( $recipient, $type, $message, $data );

		// Record this alert to prevent duplicates.
		$this->record_alert( $type, $data );
	}

	/**
	 * Check if this alert type is throttled.
	 *
	 * @param string $type Alert type.
	 * @param array  $data Alert data.
	 * @return bool
	 */
	private function is_throttled( $type, $data ) {
		$settings         = self::get_settings();
		$throttle_minutes = absint( $settings['throttle_minutes'] );

		if ( $throttle_minutes <= 0 ) {
			return false;
		}

		// Create a unique key for this alert.
		$key       = 'nexifymy_alert_' . md5( $type . wp_json_encode( $data ) );
		$last_sent = get_transient( $key );

		return (bool) $last_sent;
	}

	/**
	 * Record that an alert was sent.
	 *
	 * @param string $type Alert type.
	 * @param array  $data Alert data.
	 */
	private function record_alert( $type, $data ) {
		$settings         = self::get_settings();
		$throttle_minutes = absint( $settings['throttle_minutes'] );

		if ( $throttle_minutes <= 0 ) {
			return;
		}

		$key = 'nexifymy_alert_' . md5( $type . wp_json_encode( $data ) );
		set_transient( $key, time(), $throttle_minutes * MINUTE_IN_SECONDS );
	}

	/**
	 * Send an alert email.
	 *
	 * @param string $to      Recipient email.
	 * @param string $type    Alert type.
	 * @param string $message Alert message.
	 * @param array  $data    Additional data.
	 */
	private function send_alert_email( $to, $type, $message, $data = array() ) {
		$site_name  = get_bloginfo( 'name' );
		$site_url   = home_url();
		$type_label = isset( self::ALERT_TYPES[ $type ] ) ? self::ALERT_TYPES[ $type ] : $type;

		$subject = sprintf( '[%s] Security Alert: %s', $site_name, $type_label );

		$body  = "Security Alert from SecureWP360\n";
		$body .= "=====================================\n\n";
		$body .= "Site: {$site_name}\n";
		$body .= "URL: {$site_url}\n";
		$body .= 'Time: ' . current_time( 'mysql' ) . "\n\n";
		$body .= "Alert Type: {$type_label}\n\n";
		$body .= "Details:\n";
		$body .= "{$message}\n\n";

		if ( ! empty( $data ) ) {
			$body .= "Additional Information:\n";
			foreach ( $data as $key => $value ) {
				if ( is_array( $value ) ) {
					$value = wp_json_encode( $value );
				}
				$body .= "  - {$key}: {$value}\n";
			}
			$body .= "\n";
		}

		if ( isset( $data['ip_address'] ) || isset( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip    = isset( $data['ip_address'] ) ? $data['ip_address'] : sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
			$body .= "IP Address: {$ip}\n";
		}
		$body .= "\n---\n";
		$body .= "This alert was sent by SecureWP360 plugin.\n";
		$body .= 'Manage your alert settings: ' . admin_url( 'admin.php?page=nexifymy-security-settings' ) . "\n";

		$headers = array( 'Content-Type: text/plain; charset=UTF-8' );

		wp_mail( $to, $subject, $body, $headers );
	}

	/**
	 * Schedule daily summary if enabled.
	 */
	public function maybe_schedule_daily_summary() {
		$settings = self::get_settings();

		if ( ! $settings['daily_summary'] ) {
			// Unschedule if disabled.
			wp_clear_scheduled_hook( 'nexifymy_daily_summary' );
			return;
		}

		if ( ! wp_next_scheduled( 'nexifymy_daily_summary' ) ) {
			// Schedule for the configured time.
			$time_parts = explode( ':', $settings['daily_summary_time'] );
			$hour       = isset( $time_parts[0] ) ? absint( $time_parts[0] ) : 8;
			$minute     = isset( $time_parts[1] ) ? absint( $time_parts[1] ) : 0;

			$next_run = strtotime( "today {$hour}:{$minute}" );
			if ( $next_run < time() ) {
				$next_run = strtotime( "tomorrow {$hour}:{$minute}" );
			}

			wp_schedule_event( $next_run, 'daily', 'nexifymy_daily_summary' );
		}
	}



	/**
	 * Send daily summary email.
	 */
	public function send_daily_summary() {
		$settings = self::get_settings();

		if ( ! $settings['enabled'] || ! $settings['daily_summary'] ) {
			return;
		}

		$recipient = $settings['recipient_email'];
		if ( empty( $recipient ) ) {
			$recipient = get_option( 'admin_email' );
		}

		// Get stats for the last 24 hours.
		$stats = $this->get_24h_stats();

		$site_name = get_bloginfo( 'name' );
		$subject   = sprintf( '[%s] Daily Security Summary', $site_name );

		$body  = "Daily Security Summary from SecureWP360\n";
		$body .= "=============================================\n\n";
		$body .= "Site: {$site_name}\n";
		$body .= "Period: Last 24 hours\n";
		$body .= 'Generated: ' . current_time( 'mysql' ) . "\n\n";

		$body .= "Security Events Summary:\n";
		$body .= "------------------------\n";
		$body .= "  Total Events: {$stats['total']}\n";
		$body .= "  Critical: {$stats['critical']}\n";
		$body .= "  Warnings: {$stats['warning']}\n";
		$body .= "  Info: {$stats['info']}\n\n";

		$body .= "  WAF Blocks: {$stats['waf_blocks']}\n";
		$body .= "  Failed Logins: {$stats['failed_logins']}\n";
		$body .= "  IP Lockouts: {$stats['lockouts']}\n";
		$body .= "  Files Quarantined: {$stats['quarantined']}\n\n";

		if ( $stats['critical'] > 0 || $stats['warning'] > 0 ) {
			$body .= "[!] Action may be required. Review your security logs.\n\n";
		} else {
			$body .= "[OK] Your site appears secure.\n\n";
		}

		// Clean up any unexpected leading/binary characters in these status lines.
		$body = preg_replace( '/\n[^\r\n]*Action may be required\./u', "\nAction may be required.", $body );
		$body = preg_replace( '/\n[^\r\n]*Your site appears secure\./u', "\nYour site appears secure.", $body );

		$body .= 'View full logs: ' . admin_url( 'admin.php?page=nexifymy-security-logs' ) . "\n";
		$body .= "\n---\n";
		$body .= "This summary was sent by SecureWP360 plugin.\n";

		$headers = array( 'Content-Type: text/plain; charset=UTF-8' );

		wp_mail( $recipient, $subject, $body, $headers );
	}

	/**
	 * Get security stats for last 24 hours.
	 *
	 * @return array
	 */
	private function get_24h_stats() {
		global $wpdb;
		$table = $wpdb->prefix . 'nexifymy_security_logs';
		$since = gmdate( 'Y-m-d H:i:s', strtotime( '-24 hours' ) );

		$stats = array(
			'total'         => 0,
			'critical'      => 0,
			'warning'       => 0,
			'info'          => 0,
			'waf_blocks'    => 0,
			'failed_logins' => 0,
			'lockouts'      => 0,
			'quarantined'   => 0,
		);

		// Check if table exists.
		if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ) !== $table ) {
			return $stats;
		}

		// Total by severity.
		$severity_counts = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT severity, COUNT(*) as count FROM {$table} WHERE created_at >= %s GROUP BY severity",
				$since
			),
			ARRAY_A
		);

		foreach ( $severity_counts as $row ) {
			$stats[ $row['severity'] ] = (int) $row['count'];
			$stats['total']           += (int) $row['count'];
		}

		// Specific event counts.
		$event_counts = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT event_type, COUNT(*) as count FROM {$table} WHERE created_at >= %s GROUP BY event_type",
				$since
			),
			ARRAY_A
		);

		foreach ( $event_counts as $row ) {
			switch ( $row['event_type'] ) {
				case 'waf_block':
					$stats['waf_blocks'] = (int) $row['count'];
					break;
				case 'login_failed':
					$stats['failed_logins'] = (int) $row['count'];
					break;
				case 'ip_lockout':
					$stats['lockouts'] = (int) $row['count'];
					break;
				case 'file_quarantined':
					$stats['quarantined'] = (int) $row['count'];
					break;
			}
		}

		return $stats;
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	/**
	 * Save alert settings via AJAX.
	 */
	public function ajax_save_settings() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$settings = array(
			'enabled'            => ! empty( $_POST['enabled'] ),
			'recipient_email'    => sanitize_email( wp_unslash( $_POST['recipient_email'] ?? '' ) ),
			'alert_types'        => isset( $_POST['alert_types'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['alert_types'] ) ) : array(),
			'throttle_minutes'   => absint( $_POST['throttle_minutes'] ?? 60 ),
			'daily_summary'      => ! empty( $_POST['daily_summary'] ),
			'daily_summary_time' => sanitize_text_field( wp_unslash( $_POST['daily_summary_time'] ?? '08:00' ) ),
		);
		self::update_settings( $settings );

		wp_send_json_success(
			array(
				'message'  => 'Alert settings saved.',
				'settings' => $settings,
			)
		);
	}

	/**
	 * Get alert settings via AJAX.
	 */
	public function ajax_get_settings() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		wp_send_json_success( self::get_settings() );
	}

	/**
	 * Send a test alert via AJAX.
	 */
	public function ajax_test_alert() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$settings  = self::get_settings();
		$recipient = $settings['recipient_email'];
		if ( empty( $recipient ) ) {
			$recipient = get_option( 'admin_email' );
		}

		$this->send_alert_email(
			$recipient,
			'test_alert',
			'This is a test alert from SecureWP360. If you received this email, alerts are working correctly.',
			array( 'test' => true )
		);

		wp_send_json_success( 'Test alert sent to ' . $recipient );
	}
}

