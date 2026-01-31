<?php
/**
 * Integration Ecosystem Module.
 * Slack, Discord, Teams, SIEM (Splunk/ELK), and Jira/ServiceNow integration.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Integrations {

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'           => true,

		// Slack.
		'slack_enabled'     => false,
		'slack_webhook_url' => '',
		'slack_channel'     => '#security',
		'slack_events'      => array( 'threat_detected', 'malware_found', 'login_failed' ),

		// Discord.
		'discord_enabled'     => false,
		'discord_webhook_url' => '',
		'discord_events'      => array( 'threat_detected', 'malware_found' ),

		// Microsoft Teams.
		'teams_enabled'     => false,
		'teams_webhook_url' => '',
		'teams_events'      => array( 'threat_detected', 'scan_completed' ),

		// SIEM (Splunk).
		'siem_enabled'      => false,
		'siem_type'         => 'splunk',  // splunk, elasticsearch, generic.
		'siem_endpoint'     => '',
		'siem_token'        => '',
		'siem_index'        => 'wordpress_security',
		'siem_events'       => array( 'all' ),

		// Jira.
		'jira_enabled'      => false,
		'jira_url'          => '',
		'jira_email'        => '',
		'jira_api_token'    => '',
		'jira_project_key'  => '',
		'jira_issue_type'   => 'Bug',
		'jira_priority'     => 'High',
		'jira_events'       => array( 'malware_found', 'plugin_vulnerability' ),

		// ServiceNow.
		'servicenow_enabled'  => false,
		'servicenow_instance' => '',
		'servicenow_username' => '',
		'servicenow_password' => '',
		'servicenow_table'    => 'incident',
	);

	/**
	 * Available events for notifications.
	 */
	private $available_events = array(
		'threat_detected'      => 'High-scoring threat detected',
		'login_failed'         => 'Failed login attempt',
		'user_locked'          => 'User/IP locked out',
		'malware_found'        => 'Malware detected',
		'scan_completed'       => 'Security scan completed',
		'plugin_vulnerability' => 'Vulnerable plugin found',
		'settings_changed'     => 'Settings modified',
		'core_file_modified'   => 'Core file changed',
	);

	/**
	 * Initialize the module.
	 */
	public function init() {
		$settings = $this->get_settings();

		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Register event listeners.
		$this->register_event_listeners();

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_test_integration', array( $this, 'ajax_test_integration' ) );
		add_action( 'wp_ajax_nexifymy_save_integration', array( $this, 'ajax_save_integration' ) );
		add_action( 'wp_ajax_nexifymy_get_integrations', array( $this, 'ajax_get_integrations' ) );
	}

	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['integrations'] ) ) {
				return wp_parse_args( $all_settings['integrations'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Save settings.
	 *
	 * @param array $settings Settings to save.
	 */
	public function save_settings( $settings ) {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			$all_settings['integrations'] = $settings;
			update_option( 'nexifymy_security_settings', $all_settings );
		}
	}

	/**
	 * Register event listeners.
	 */
	private function register_event_listeners() {
		// Threat detected.
		add_action( 'nexifymy_threat_detected', array( $this, 'handle_threat_detected' ) );

		// Login failed.
		add_action( 'wp_login_failed', array( $this, 'handle_login_failed' ) );

		// User locked.
		add_action( 'nexifymy_user_locked', array( $this, 'handle_user_locked' ) );

		// Malware found.
		add_action( 'nexifymy_malware_found', array( $this, 'handle_malware_found' ) );

		// Scan completed.
		add_action( 'nexifymy_scan_completed', array( $this, 'handle_scan_completed' ) );

		// Plugin vulnerability.
		add_action( 'nexifymy_vulnerability_found', array( $this, 'handle_vulnerability_found' ) );
	}

	/*
	 * =========================================================================
	 * EVENT HANDLERS
	 * =========================================================================
	 */

	public function handle_threat_detected( $data ) {
		$this->dispatch_to_all( 'threat_detected', array(
			'title'       => '🚨 Threat Detected',
			'description' => sprintf( 'AI detected threat from IP: %s (Score: %d)', $data['ip'] ?? 'Unknown', $data['score'] ?? 0 ),
			'severity'    => 'critical',
			'data'        => $data,
		) );
	}

	public function handle_login_failed( $username ) {
		$this->dispatch_to_all( 'login_failed', array(
			'title'       => '⚠️ Failed Login Attempt',
			'description' => sprintf( 'Failed login for user: %s from IP: %s', $username, $this->get_client_ip() ),
			'severity'    => 'warning',
			'data'        => array( 'username' => $username, 'ip' => $this->get_client_ip() ),
		) );
	}

	public function handle_user_locked( $data ) {
		$this->dispatch_to_all( 'user_locked', array(
			'title'       => '🔒 User/IP Locked',
			'description' => sprintf( 'IP %s has been locked: %s', $data['ip'] ?? 'Unknown', $data['reason'] ?? '' ),
			'severity'    => 'high',
			'data'        => $data,
		) );
	}

	public function handle_malware_found( $data ) {
		$this->dispatch_to_all( 'malware_found', array(
			'title'       => '🦠 Malware Detected',
			'description' => sprintf( 'Malware found in %d file(s)', count( $data['files'] ?? array() ) ),
			'severity'    => 'critical',
			'data'        => $data,
		) );
	}

	public function handle_scan_completed( $data ) {
		$this->dispatch_to_all( 'scan_completed', array(
			'title'       => '✅ Scan Completed',
			'description' => sprintf( 'Security scan finished. Issues: %d', $data['issues'] ?? 0 ),
			'severity'    => ( $data['issues'] ?? 0 ) > 0 ? 'warning' : 'info',
			'data'        => $data,
		) );
	}

	public function handle_vulnerability_found( $data ) {
		$this->dispatch_to_all( 'plugin_vulnerability', array(
			'title'       => '🔓 Vulnerability Found',
			'description' => sprintf( 'Vulnerable plugin: %s', $data['plugin'] ?? 'Unknown' ),
			'severity'    => 'high',
			'data'        => $data,
		) );
	}

	/**
	 * Dispatch event to all enabled integrations.
	 *
	 * @param string $event Event type.
	 * @param array  $payload Event payload.
	 */
	private function dispatch_to_all( $event, $payload ) {
		$settings = $this->get_settings();

		// Slack.
		if ( ! empty( $settings['slack_enabled'] ) && $this->should_send( $event, $settings['slack_events'] ) ) {
			$this->send_slack( $payload, $settings );
		}

		// Discord.
		if ( ! empty( $settings['discord_enabled'] ) && $this->should_send( $event, $settings['discord_events'] ) ) {
			$this->send_discord( $payload, $settings );
		}

		// Teams.
		if ( ! empty( $settings['teams_enabled'] ) && $this->should_send( $event, $settings['teams_events'] ) ) {
			$this->send_teams( $payload, $settings );
		}

		// SIEM.
		if ( ! empty( $settings['siem_enabled'] ) && $this->should_send( $event, $settings['siem_events'] ) ) {
			$this->send_siem( $event, $payload, $settings );
		}

		// Jira.
		if ( ! empty( $settings['jira_enabled'] ) && $this->should_send( $event, $settings['jira_events'] ) ) {
			$this->create_jira_ticket( $payload, $settings );
		}

		// ServiceNow.
		if ( ! empty( $settings['servicenow_enabled'] ) ) {
			$this->create_servicenow_incident( $payload, $settings );
		}
	}

	/**
	 * Check if event should be sent.
	 *
	 * @param string $event Event type.
	 * @param array  $enabled_events Enabled events.
	 * @return bool
	 */
	private function should_send( $event, $enabled_events ) {
		if ( empty( $enabled_events ) ) {
			return false;
		}

		if ( in_array( 'all', $enabled_events, true ) ) {
			return true;
		}

		return in_array( $event, $enabled_events, true );
	}

	/*
	 * =========================================================================
	 * SLACK
	 * =========================================================================
	 */

	/**
	 * Send notification to Slack.
	 *
	 * @param array $payload Event payload.
	 * @param array $settings Integration settings.
	 * @return bool
	 */
	public function send_slack( $payload, $settings = null ) {
		if ( ! $settings ) {
			$settings = $this->get_settings();
		}

		if ( empty( $settings['slack_webhook_url'] ) ) {
			return false;
		}

		$color = $this->severity_to_color( $payload['severity'] );

		$slack_payload = array(
			'channel'     => $settings['slack_channel'],
			'username'    => 'NexifyMy Security',
			'icon_emoji'  => ':shield:',
			'attachments' => array(
				array(
					'color'      => $color,
					'title'      => $payload['title'],
					'text'       => $payload['description'],
					'footer'     => get_bloginfo( 'name' ) . ' | ' . home_url(),
					'footer_icon'=> 'https://wordpress.org/favicon.ico',
					'ts'         => time(),
					'fields'     => array(
						array(
							'title' => 'Severity',
							'value' => ucfirst( $payload['severity'] ),
							'short' => true,
						),
						array(
							'title' => 'Site',
							'value' => home_url(),
							'short' => true,
						),
					),
				),
			),
		);

		$response = wp_remote_post( $settings['slack_webhook_url'], array(
			'body'    => wp_json_encode( $slack_payload ),
			'headers' => array( 'Content-Type' => 'application/json' ),
			'timeout' => 10,
		) );

		return ! is_wp_error( $response );
	}

	/*
	 * =========================================================================
	 * DISCORD
	 * =========================================================================
	 */

	/**
	 * Send notification to Discord.
	 *
	 * @param array $payload Event payload.
	 * @param array $settings Integration settings.
	 * @return bool
	 */
	public function send_discord( $payload, $settings = null ) {
		if ( ! $settings ) {
			$settings = $this->get_settings();
		}

		if ( empty( $settings['discord_webhook_url'] ) ) {
			return false;
		}

		$color = $this->severity_to_decimal_color( $payload['severity'] );

		$discord_payload = array(
			'username'   => 'NexifyMy Security',
			'avatar_url' => 'https://ps.w.org/wordfence/assets/icon-256x256.png',
			'embeds'     => array(
				array(
					'title'       => $payload['title'],
					'description' => $payload['description'],
					'color'       => $color,
					'footer'      => array(
						'text' => get_bloginfo( 'name' ),
					),
					'timestamp'   => gmdate( 'c' ),
					'fields'      => array(
						array(
							'name'   => 'Severity',
							'value'  => ucfirst( $payload['severity'] ),
							'inline' => true,
						),
						array(
							'name'   => 'Site',
							'value'  => home_url(),
							'inline' => true,
						),
					),
				),
			),
		);

		$response = wp_remote_post( $settings['discord_webhook_url'], array(
			'body'    => wp_json_encode( $discord_payload ),
			'headers' => array( 'Content-Type' => 'application/json' ),
			'timeout' => 10,
		) );

		return ! is_wp_error( $response );
	}

	/*
	 * =========================================================================
	 * MICROSOFT TEAMS
	 * =========================================================================
	 */

	/**
	 * Send notification to Microsoft Teams.
	 *
	 * @param array $payload Event payload.
	 * @param array $settings Integration settings.
	 * @return bool
	 */
	public function send_teams( $payload, $settings = null ) {
		if ( ! $settings ) {
			$settings = $this->get_settings();
		}

		if ( empty( $settings['teams_webhook_url'] ) ) {
			return false;
		}

		$color = $this->severity_to_color( $payload['severity'] );

		// Adaptive Card format.
		$teams_payload = array(
			'@type'      => 'MessageCard',
			'@context'   => 'http://schema.org/extensions',
			'themeColor' => str_replace( '#', '', $color ),
			'summary'    => $payload['title'],
			'sections'   => array(
				array(
					'activityTitle'    => $payload['title'],
					'activitySubtitle' => get_bloginfo( 'name' ),
					'activityImage'    => 'https://wordpress.org/favicon.ico',
					'facts'            => array(
						array(
							'name'  => 'Severity',
							'value' => ucfirst( $payload['severity'] ),
						),
						array(
							'name'  => 'Description',
							'value' => $payload['description'],
						),
						array(
							'name'  => 'Site',
							'value' => home_url(),
						),
						array(
							'name'  => 'Time',
							'value' => current_time( 'Y-m-d H:i:s' ),
						),
					),
					'markdown' => true,
				),
			),
			'potentialAction' => array(
				array(
					'@type'   => 'OpenUri',
					'name'    => 'View Dashboard',
					'targets' => array(
						array(
							'os'  => 'default',
							'uri' => admin_url( 'admin.php?page=nexifymy-security' ),
						),
					),
				),
			),
		);

		$response = wp_remote_post( $settings['teams_webhook_url'], array(
			'body'    => wp_json_encode( $teams_payload ),
			'headers' => array( 'Content-Type' => 'application/json' ),
			'timeout' => 10,
		) );

		return ! is_wp_error( $response );
	}

	/*
	 * =========================================================================
	 * SIEM (Splunk/Elasticsearch)
	 * =========================================================================
	 */

	/**
	 * Send log to SIEM platform.
	 *
	 * @param string $event Event type.
	 * @param array  $payload Event payload.
	 * @param array  $settings Integration settings.
	 * @return bool
	 */
	public function send_siem( $event, $payload, $settings = null ) {
		if ( ! $settings ) {
			$settings = $this->get_settings();
		}

		if ( empty( $settings['siem_endpoint'] ) ) {
			return false;
		}

		$log_entry = array(
			'timestamp'   => gmdate( 'c' ),
			'source'      => 'nexifymy-security',
			'sourcetype'  => 'wordpress:security',
			'host'        => home_url(),
			'event'       => $event,
			'severity'    => $payload['severity'],
			'title'       => $payload['title'],
			'description' => $payload['description'],
			'data'        => $payload['data'] ?? array(),
			'site_name'   => get_bloginfo( 'name' ),
			'wp_version'  => get_bloginfo( 'version' ),
		);

		$headers = array(
			'Content-Type' => 'application/json',
		);

		// Handle different SIEM types.
		switch ( $settings['siem_type'] ) {
			case 'splunk':
				$headers['Authorization'] = 'Splunk ' . $settings['siem_token'];
				$body = array(
					'event'      => $log_entry,
					'index'      => $settings['siem_index'],
					'sourcetype' => 'wordpress_security',
				);
				break;

			case 'elasticsearch':
				if ( ! empty( $settings['siem_token'] ) ) {
					$headers['Authorization'] = 'Bearer ' . $settings['siem_token'];
				}
				$body = $log_entry;
				break;

			default:
				$body = $log_entry;
				break;
		}

		$response = wp_remote_post( $settings['siem_endpoint'], array(
			'body'    => wp_json_encode( $body ),
			'headers' => $headers,
			'timeout' => 15,
		) );

		return ! is_wp_error( $response );
	}

	/*
	 * =========================================================================
	 * JIRA
	 * =========================================================================
	 */

	/**
	 * Create Jira ticket.
	 *
	 * @param array $payload Event payload.
	 * @param array $settings Integration settings.
	 * @return bool|string Ticket key or false.
	 */
	public function create_jira_ticket( $payload, $settings = null ) {
		if ( ! $settings ) {
			$settings = $this->get_settings();
		}

		if ( empty( $settings['jira_url'] ) || empty( $settings['jira_api_token'] ) ) {
			return false;
		}

		$api_url = rtrim( $settings['jira_url'], '/' ) . '/rest/api/2/issue';

		$issue_data = array(
			'fields' => array(
				'project'     => array(
					'key' => $settings['jira_project_key'],
				),
				'summary'     => '[Security] ' . $payload['title'],
				'description' => $this->format_jira_description( $payload ),
				'issuetype'   => array(
					'name' => $settings['jira_issue_type'],
				),
				'priority'    => array(
					'name' => $this->severity_to_jira_priority( $payload['severity'], $settings ),
				),
				'labels'      => array( 'security', 'nexifymy', 'automated' ),
			),
		);

		$auth = base64_encode( $settings['jira_email'] . ':' . $settings['jira_api_token'] );

		$response = wp_remote_post( $api_url, array(
			'body'    => wp_json_encode( $issue_data ),
			'headers' => array(
				'Content-Type'  => 'application/json',
				'Authorization' => 'Basic ' . $auth,
			),
			'timeout' => 15,
		) );

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! empty( $body['key'] ) ) {
			// Log ticket creation.
			if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
				NexifyMy_Security_Logger::log(
					'jira_ticket_created',
					sprintf( 'Jira ticket created: %s', $body['key'] ),
					'info'
				);
			}

			return $body['key'];
		}

		return false;
	}

	/**
	 * Format Jira description.
	 *
	 * @param array $payload Event payload.
	 * @return string
	 */
	private function format_jira_description( $payload ) {
		$description = "*Description:*\n" . $payload['description'] . "\n\n";
		$description .= "*Severity:* " . ucfirst( $payload['severity'] ) . "\n";
		$description .= "*Site:* " . home_url() . "\n";
		$description .= "*Time:* " . current_time( 'Y-m-d H:i:s' ) . "\n\n";

		if ( ! empty( $payload['data'] ) ) {
			$description .= "*Additional Data:*\n{code:json}\n" . wp_json_encode( $payload['data'], JSON_PRETTY_PRINT ) . "\n{code}";
		}

		return $description;
	}

	/**
	 * Map severity to Jira priority.
	 *
	 * @param string $severity Severity level.
	 * @param array  $settings Settings.
	 * @return string
	 */
	private function severity_to_jira_priority( $severity, $settings ) {
		$mapping = array(
			'critical' => 'Highest',
			'high'     => 'High',
			'warning'  => 'Medium',
			'info'     => 'Low',
		);

		return $mapping[ $severity ] ?? $settings['jira_priority'];
	}

	/*
	 * =========================================================================
	 * SERVICENOW
	 * =========================================================================
	 */

	/**
	 * Create ServiceNow incident.
	 *
	 * @param array $payload Event payload.
	 * @param array $settings Integration settings.
	 * @return bool|string Incident number or false.
	 */
	public function create_servicenow_incident( $payload, $settings = null ) {
		if ( ! $settings ) {
			$settings = $this->get_settings();
		}

		if ( empty( $settings['servicenow_instance'] ) ) {
			return false;
		}

		$api_url = sprintf(
			'https://%s.service-now.com/api/now/table/%s',
			$settings['servicenow_instance'],
			$settings['servicenow_table']
		);

		$incident_data = array(
			'short_description' => '[Security] ' . $payload['title'],
			'description'       => $payload['description'] . "\n\nSite: " . home_url() . "\nTime: " . current_time( 'Y-m-d H:i:s' ),
			'urgency'           => $this->severity_to_servicenow_urgency( $payload['severity'] ),
			'impact'            => $this->severity_to_servicenow_impact( $payload['severity'] ),
			'category'          => 'Security',
			'subcategory'       => 'Threat Detection',
		);

		$auth = base64_encode( $settings['servicenow_username'] . ':' . $settings['servicenow_password'] );

		$response = wp_remote_post( $api_url, array(
			'body'    => wp_json_encode( $incident_data ),
			'headers' => array(
				'Content-Type'  => 'application/json',
				'Accept'        => 'application/json',
				'Authorization' => 'Basic ' . $auth,
			),
			'timeout' => 15,
		) );

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		return $body['result']['number'] ?? false;
	}

	/**
	 * Map severity to ServiceNow urgency.
	 *
	 * @param string $severity Severity.
	 * @return string
	 */
	private function severity_to_servicenow_urgency( $severity ) {
		$mapping = array(
			'critical' => '1',
			'high'     => '2',
			'warning'  => '2',
			'info'     => '3',
		);

		return $mapping[ $severity ] ?? '2';
	}

	/**
	 * Map severity to ServiceNow impact.
	 *
	 * @param string $severity Severity.
	 * @return string
	 */
	private function severity_to_servicenow_impact( $severity ) {
		$mapping = array(
			'critical' => '1',
			'high'     => '2',
			'warning'  => '2',
			'info'     => '3',
		);

		return $mapping[ $severity ] ?? '2';
	}

	/*
	 * =========================================================================
	 * HELPER METHODS
	 * =========================================================================
	 */

	/**
	 * Convert severity to hex color.
	 *
	 * @param string $severity Severity level.
	 * @return string
	 */
	private function severity_to_color( $severity ) {
		$colors = array(
			'critical' => '#dc2626',
			'high'     => '#ea580c',
			'warning'  => '#ca8a04',
			'info'     => '#2563eb',
		);

		return $colors[ $severity ] ?? '#6b7280';
	}

	/**
	 * Convert severity to decimal color (for Discord).
	 *
	 * @param string $severity Severity level.
	 * @return int
	 */
	private function severity_to_decimal_color( $severity ) {
		$colors = array(
			'critical' => 14423830,  // #dc2626
			'high'     => 15357964,  // #ea580c
			'warning'  => 13274628,  // #ca8a04
			'info'     => 2454254,   // #2563eb
		);

		return $colors[ $severity ] ?? 7040515;
	}

	/**
	 * Get client IP.
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
	 * Get available events.
	 *
	 * @return array
	 */
	public function get_available_events() {
		return $this->available_events;
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	public function ajax_test_integration() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$type = isset( $_POST['type'] ) ? sanitize_key( $_POST['type'] ) : '';
		$settings = $this->get_settings();

		$test_payload = array(
			'title'       => '🧪 Test Notification',
			'description' => 'This is a test notification from NexifyMy Security.',
			'severity'    => 'info',
			'data'        => array( 'test' => true ),
		);

		$result = false;

		switch ( $type ) {
			case 'slack':
				$result = $this->send_slack( $test_payload, $settings );
				break;
			case 'discord':
				$result = $this->send_discord( $test_payload, $settings );
				break;
			case 'teams':
				$result = $this->send_teams( $test_payload, $settings );
				break;
			case 'siem':
				$result = $this->send_siem( 'test', $test_payload, $settings );
				break;
			case 'jira':
				$result = $this->create_jira_ticket( $test_payload, $settings );
				break;
		}

		if ( $result ) {
			wp_send_json_success( array( 'message' => 'Test notification sent successfully!' ) );
		} else {
			wp_send_json_error( 'Failed to send test notification. Check your settings.' );
		}
	}

	public function ajax_save_integration() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$settings = $this->get_settings();

		// Update from POST data.
		$fields = array(
			'slack_enabled', 'slack_webhook_url', 'slack_channel', 'slack_events',
			'discord_enabled', 'discord_webhook_url', 'discord_events',
			'teams_enabled', 'teams_webhook_url', 'teams_events',
			'siem_enabled', 'siem_type', 'siem_endpoint', 'siem_token', 'siem_index', 'siem_events',
			'jira_enabled', 'jira_url', 'jira_email', 'jira_api_token', 'jira_project_key', 'jira_issue_type', 'jira_priority', 'jira_events',
			'servicenow_enabled', 'servicenow_instance', 'servicenow_username', 'servicenow_password', 'servicenow_table',
		);

		foreach ( $fields as $field ) {
			if ( isset( $_POST[ $field ] ) ) {
				$value = wp_unslash( $_POST[ $field ] );

				if ( is_array( $value ) ) {
					$settings[ $field ] = array_map( 'sanitize_text_field', $value );
				} elseif ( strpos( $field, '_enabled' ) !== false ) {
					$settings[ $field ] = ! empty( $value );
				} elseif ( strpos( $field, '_url' ) !== false ) {
					$settings[ $field ] = esc_url_raw( $value );
				} else {
					$settings[ $field ] = sanitize_text_field( $value );
				}
			}
		}

		$this->save_settings( $settings );

		wp_send_json_success( array( 'message' => 'Integration settings saved.' ) );
	}

	public function ajax_get_integrations() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$settings = $this->get_settings();

		// Mask sensitive fields.
		$masked_fields = array( 'slack_webhook_url', 'discord_webhook_url', 'teams_webhook_url', 'siem_token', 'jira_api_token', 'servicenow_password' );

		foreach ( $masked_fields as $field ) {
			if ( ! empty( $settings[ $field ] ) ) {
				$settings[ $field ] = str_repeat( '•', 8 ) . substr( $settings[ $field ], -4 );
			}
		}

		wp_send_json_success( array(
			'settings' => $settings,
			'events'   => $this->available_events,
		) );
	}
}
