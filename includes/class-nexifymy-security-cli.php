<?php
/**
 * WP-CLI Commands for NexifyMy Security
 * Enables DevOps integration and automation.
 *
 * @package    NexifyMy_Security
 * @subpackage NexifyMy_Security/includes
 */

if ( ! defined( 'ABSPATH' ) || ! defined( 'WP_CLI' ) ) {
	return;
}

class NexifyMy_Security_CLI {

	/**
	 * Scan the site for malware.
	 *
	 * ## OPTIONS
	 *
	 * [--mode=<mode>]
	 * : Scan mode (quick, full, deep). Default: quick.
	 *
	 * [--format=<format>]
	 * : Output format (table, json, yaml). Default: table.
	 *
	 * ## EXAMPLES
	 *
	 *     wp nexify-security scan --mode=full
	 *     wp nexify-security scan --format=json
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Named arguments.
	 */
	public function scan( $args, $assoc_args ) {
		$mode = isset( $assoc_args['mode'] ) ? $assoc_args['mode'] : 'quick';
		$format = isset( $assoc_args['format'] ) ? $assoc_args['format'] : 'table';

		WP_CLI::log( "Starting {$mode} scan..." );

		if ( ! isset( $GLOBALS['nexifymy_scanner'] ) ) {
			WP_CLI::error( 'Scanner module not loaded.' );
		}

		$scanner = $GLOBALS['nexifymy_scanner'];
		$results = $scanner->scan( $mode );

		if ( is_wp_error( $results ) ) {
			WP_CLI::error( $results->get_error_message() );
		}

		$threats = $results['threats_found'] ?? 0;
		$files_scanned = $results['files_scanned'] ?? 0;

		if ( $format === 'json' ) {
			WP_CLI::line( json_encode( $results, JSON_PRETTY_PRINT ) );
		} elseif ( $format === 'yaml' ) {
			WP_CLI::line( $this->array_to_yaml( $results ) );
		} else {
			WP_CLI::success( "Scan complete. Files scanned: {$files_scanned}, Threats found: {$threats}" );

			if ( ! empty( $results['threats'] ) ) {
				WP_CLI\Utils\format_items( 'table', $results['threats'], array( 'file', 'threat', 'severity' ) );
			}
		}
	}

	/**
	 * Export security configuration.
	 *
	 * ## OPTIONS
	 *
	 * [--file=<file>]
	 * : Output file path. Default: stdout.
	 *
	 * [--format=<format>]
	 * : Output format (json, yaml). Default: json.
	 *
	 * ## EXAMPLES
	 *
	 *     wp nexify-security config export --file=security-config.json
	 *     wp nexify-security config export --format=yaml > config.yml
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Named arguments.
	 */
	public function config__export( $args, $assoc_args ) {
		$format = isset( $assoc_args['format'] ) ? $assoc_args['format'] : 'json';
		$file = isset( $assoc_args['file'] ) ? $assoc_args['file'] : null;

		$config = get_option( 'nexifymy_security_settings', array() );
		$config['_exported_at'] = current_time( 'mysql' );
		$config['_site_url'] = get_site_url();

		if ( $format === 'yaml' ) {
			$output = $this->array_to_yaml( $config );
		} else {
			$output = json_encode( $config, JSON_PRETTY_PRINT );
		}

		if ( $file ) {
			file_put_contents( $file, $output );
			WP_CLI::success( "Configuration exported to {$file}" );
		} else {
			WP_CLI::line( $output );
		}
	}

	/**
	 * Import security configuration.
	 *
	 * ## OPTIONS
	 *
	 * <file>
	 * : Configuration file to import.
	 *
	 * [--merge]
	 * : Merge with existing config instead of replacing.
	 *
	 * ## EXAMPLES
	 *
	 *     wp nexify-security config import security-config.json
	 *     wp nexify-security config import config.yml --merge
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Named arguments.
	 */
	public function config__import( $args, $assoc_args ) {
		$file = $args[0];
		$merge = isset( $assoc_args['merge'] );

		if ( ! file_exists( $file ) ) {
			WP_CLI::error( "File not found: {$file}" );
		}

		$contents = file_get_contents( $file );

		// Detect format
		if ( preg_match( '/\.ya?ml$/i', $file ) ) {
			$config = $this->yaml_to_array( $contents );
		} else {
			$config = json_decode( $contents, true );
		}

		if ( empty( $config ) ) {
			WP_CLI::error( 'Invalid configuration file.' );
		}

		// Remove metadata
		unset( $config['_exported_at'], $config['_site_url'] );

		if ( $merge ) {
			$existing = get_option( 'nexifymy_security_settings', array() );
			$config = array_merge( $existing, $config );
		}

		update_option( 'nexifymy_security_settings', $config );
		WP_CLI::success( 'Configuration imported successfully.' );
	}

	/**
	 * Manage firewall rules.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : Action (block, unblock, list).
	 *
	 * [<ip>]
	 * : IP address (required for block/unblock).
	 *
	 * ## EXAMPLES
	 *
	 *     wp nexify-security firewall block 192.168.1.100
	 *     wp nexify-security firewall unblock 192.168.1.100
	 *     wp nexify-security firewall list
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Named arguments.
	 */
	public function firewall( $args, $assoc_args ) {
		$action = $args[0] ?? 'list';
		$ip = $args[1] ?? null;

		switch ( $action ) {
			case 'block':
				if ( ! $ip ) {
					WP_CLI::error( 'IP address required.' );
				}
				$this->block_ip( $ip );
				WP_CLI::success( "Blocked IP: {$ip}" );
				break;

			case 'unblock':
				if ( ! $ip ) {
					WP_CLI::error( 'IP address required.' );
				}
				$this->unblock_ip( $ip );
				WP_CLI::success( "Unblocked IP: {$ip}" );
				break;

			case 'list':
				$blocked = $this->get_blocked_ips();
				WP_CLI\Utils\format_items( 'table', $blocked, array( 'ip', 'reason', 'blocked_at' ) );
				break;

			default:
				WP_CLI::error( "Unknown action: {$action}" );
		}
	}

	/**
	 * View security logs.
	 *
	 * ## OPTIONS
	 *
	 * [--severity=<severity>]
	 * : Filter by severity (info, warning, critical).
	 *
	 * [--limit=<limit>]
	 * : Number of entries to show. Default: 20.
	 *
	 * ## EXAMPLES
	 *
	 *     wp nexify-security logs --severity=critical
	 *     wp nexify-security logs --limit=50
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Named arguments.
	 */
	public function logs( $args, $assoc_args ) {
		$severity = isset( $assoc_args['severity'] ) ? $assoc_args['severity'] : null;
		$limit = isset( $assoc_args['limit'] ) ? absint( $assoc_args['limit'] ) : 20;

		if ( ! class_exists( 'NexifyMy_Security_Logger' ) ) {
			WP_CLI::error( 'Logger not available.' );
		}

		$logs = NexifyMy_Security_Logger::get_logs( $severity, $limit );

		WP_CLI\Utils\format_items( 'table', $logs, array( 'timestamp', 'severity', 'event_type', 'message' ) );
	}

	/**
	 * Get security status.
	 *
	 * ## EXAMPLES
	 *
	 *     wp nexify-security status
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Named arguments.
	 */
	public function status( $args, $assoc_args ) {
		$settings = get_option( 'nexifymy_security_settings', array() );

		$status = array(
			array(
				'Module' => 'WAF',
				'Status' => ! empty( $settings['modules']['waf_enabled'] ) ? 'Enabled' : 'Disabled',
			),
			array(
				'Module' => 'Scanner',
				'Status' => ! empty( $settings['modules']['scanner_enabled'] ) ? 'Enabled' : 'Disabled',
			),
			array(
				'Module' => 'AI Detection',
				'Status' => ! empty( $settings['modules']['ai_detection_enabled'] ) ? 'Enabled' : 'Disabled',
			),
			array(
				'Module' => 'Rate Limiter',
				'Status' => ! empty( $settings['modules']['rate_limiter_enabled'] ) ? 'Enabled' : 'Disabled',
			),
		);

		WP_CLI\Utils\format_items( 'table', $status, array( 'Module', 'Status' ) );
	}

	/**
	 * Helper: Block IP address.
	 */
	private function block_ip( $ip ) {
		$blocked = get_option( 'nexifymy_blocked_ips', array() );
		$blocked[ $ip ] = array(
			'reason' => 'Blocked via CLI',
			'blocked_at' => current_time( 'mysql' ),
		);
		update_option( 'nexifymy_blocked_ips', $blocked );
	}

	/**
	 * Helper: Unblock IP address.
	 */
	private function unblock_ip( $ip ) {
		$blocked = get_option( 'nexifymy_blocked_ips', array() );
		if ( isset( $blocked[ $ip ] ) ) {
			unset( $blocked[ $ip ] );
			update_option( 'nexifymy_blocked_ips', $blocked );
		}
	}

	/**
	 * Helper: Get blocked IPs.
	 */
	private function get_blocked_ips() {
		$blocked = get_option( 'nexifymy_blocked_ips', array() );
		$result = array();

		foreach ( $blocked as $ip => $data ) {
			$result[] = array(
				'ip' => $ip,
				'reason' => $data['reason'] ?? '',
				'blocked_at' => $data['blocked_at'] ?? '',
			);
		}

		return $result;
	}

	/**
	 * Convert array to YAML format.
	 */
	private function array_to_yaml( $array, $indent = 0 ) {
		$yaml = '';
		$prefix = str_repeat( '  ', $indent );

		foreach ( $array as $key => $value ) {
			if ( is_array( $value ) ) {
				$yaml .= $prefix . $key . ":\n";
				$yaml .= $this->array_to_yaml( $value, $indent + 1 );
			} else {
				$yaml .= $prefix . $key . ': ' . $value . "\n";
			}
		}

		return $yaml;
	}

	/**
	 * Convert YAML to array (simple parser).
	 */
	private function yaml_to_array( $yaml ) {
		// This is a simple YAML parser. For production, use symfony/yaml or similar.
		$lines = explode( "\n", $yaml );
		$result = array();
		$current = &$result;
		$stack = array();

		foreach ( $lines as $line ) {
			if ( empty( trim( $line ) ) || $line[0] === '#' ) {
				continue;
			}

			preg_match( '/^(\s*)([^:]+):\s*(.*)$/', $line, $matches );
			if ( $matches ) {
				$indent = strlen( $matches[1] );
				$key = trim( $matches[2] );
				$value = trim( $matches[3] );

				if ( empty( $value ) ) {
					$current[ $key ] = array();
				} else {
					$current[ $key ] = $value;
				}
			}
		}

		return $result;
	}
}

// Register CLI commands
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	WP_CLI::add_command( 'nexify-security', 'NexifyMy_Security_CLI' );
}
