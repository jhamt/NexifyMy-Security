<?php
/**
 * Background Scanner Module.
 * Schedules and runs scans in the background using WP-Cron.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Background_Scanner {

	/**
	 * Cron hook name.
	 */
	const CRON_HOOK = 'nexifymy_scheduled_scan';

	/**
	 * Option key for scheduled scan settings.
	 */
	const SCHEDULE_OPTION = 'nexifymy_scan_schedule';

	/**
	 * Initialize the background scanner.
	 * NOTE: Activation/deactivation hooks are in main plugin file.
	 */
	public function init() {
		// AJAX handlers must always be available so the UI can show a JSON error instead of admin-ajax.php returning "0".
		add_action( 'wp_ajax_nexifymy_set_scan_schedule', array( $this, 'ajax_set_schedule' ) );
		add_action( 'wp_ajax_nexifymy_run_background_scan', array( $this, 'ajax_run_now' ) );
		add_action( 'wp_ajax_nexifymy_get_scan_status', array( $this, 'ajax_get_status' ) );

		if ( ! $this->is_enabled() ) {
			// Ensure nothing keeps running if disabled.
			$this->unschedule_scan();
			return;
		}

		// Register the cron action.
		add_action( self::CRON_HOOK, array( $this, 'run_scheduled_scan' ) );

		// Ensure schedule exists (for manual installs/updates).
		add_action( 'init', array( $this, 'maybe_schedule_scan' ) );
	}

	/**
	 * Whether background scanning is enabled in settings.
	 *
	 * @return bool
	 */
	private function is_enabled() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		return ! isset( $settings['modules']['background_scan_enabled'] ) || (bool) $settings['modules']['background_scan_enabled'];
	}

	/**
	 * Get available schedules.
	 *
	 * @return array
	 */
	public static function get_available_schedules() {
		return array(
			'hourly'     => __( 'Hourly', 'nexifymy-security' ),
			'twicedaily' => __( 'Twice Daily', 'nexifymy-security' ),
			'daily'      => __( 'Daily', 'nexifymy-security' ),
			'weekly'     => __( 'Weekly', 'nexifymy-security' ),
			'disabled'   => __( 'Disabled', 'nexifymy-security' ),
		);
	}

	/**
	 * Schedule the scan cron job.
	 *
	 * @param string $frequency Cron schedule frequency.
	 */
	public function schedule_scan( $frequency = 'daily' ) {
		$this->unschedule_scan();

		update_option( self::SCHEDULE_OPTION, $frequency );

		if ( ! $this->is_enabled() || $frequency === 'disabled' ) {
			return;
		}

		// NOTE: 'weekly' schedule is registered in main plugin file unconditionally.
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), $frequency, self::CRON_HOOK );
		}
	}

	/**
	 * Add weekly schedule to WordPress cron.
	 *
	 * @param array $schedules Existing schedules.
	 * @return array
	 */
	public function add_weekly_schedule( $schedules ) {
		$schedules['weekly'] = array(
			'interval' => WEEK_IN_SECONDS,
			'display'  => __( 'Once Weekly', 'nexifymy-security' ),
		);
		return $schedules;
	}

	/**
	 * Unschedule the scan cron job.
	 */
	public function unschedule_scan() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	/**
	 * Ensure scan is scheduled (for manual installs/updates).
	 */
	public function maybe_schedule_scan() {
		if ( ! $this->is_enabled() ) {
			$this->unschedule_scan();
			return;
		}

		$frequency = get_option( self::SCHEDULE_OPTION, 'daily' );

		if ( $frequency !== 'disabled' && ! wp_next_scheduled( self::CRON_HOOK ) ) {
			$this->schedule_scan( $frequency );
		}
	}

	/**
	 * Run the scheduled scan.
	 */
	public function run_scheduled_scan() {
		if ( ! $this->is_enabled() ) {
			return;
		}

		// Prevent overlapping scans.
		if ( get_transient( 'nexifymy_scan_running' ) ) {
			if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
				NexifyMy_Security_Logger::log( 'scan_skip', 'Skipped: previous scan still running', 'info', array() );
			}
			return;
		}
		set_transient( 'nexifymy_scan_running', time(), 600 ); // 10 min timeout.
		$start_time = time();

		// Increase time limit for background processing.
		set_time_limit( 180 );

		// Get scanner instance.
		require_once NEXIFYMY_SECURITY_PATH . 'modules/scanner.php';
		$scanner = new NexifyMy_Security_Scanner();
		$scanner->init();

		// Use configured scan mode (default: standard).
		$settings = get_option( 'nexifymy_security_settings', array() );
		$mode     = isset( $settings['background_scan']['scan_mode'] ) ? sanitize_key( $settings['background_scan']['scan_mode'] ) : 'standard';

		// Run scan (standard uses incremental for performance).
		$results = $this->run_scan_directly( $mode );

		// Log results.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			$threats  = isset( $results['threats_found'] ) ? $results['threats_found'] : 0;
			$severity = $threats > 0 ? 'critical' : 'info';

			NexifyMy_Security_Logger::log(
				'scheduled_scan',
				sprintf( 'Scheduled scan completed. %d threats found.', $threats ),
				$severity,
				array(
					'mode'          => $mode,
					'files_scanned' => isset( $results['files_scanned'] ) ? $results['files_scanned'] : 0,
					'threats_found' => $threats,
				)
			);
		}

		// Calculate metrics.
		$duration  = time() - $start_time;
		$memory_mb = round( memory_get_peak_usage( true ) / 1024 / 1024, 2 );

		// Store last scan results with metrics.
		update_option(
			'nexifymy_last_scheduled_scan',
			array(
				'time'      => current_time( 'mysql' ),
				'results'   => $results,
				'duration'  => $duration,
				'memory_mb' => $memory_mb,
			)
		);

		// Clear running lock.
		delete_transient( 'nexifymy_scan_running' );
	}

	/**
	 * Run scan directly using the scanner's public method.
	 *
	 * @param string $mode Scan mode.
	 * @return array Scan results.
	 */
	private function run_scan_directly( $mode = 'standard' ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/scanner.php';

		$scanner = new NexifyMy_Security_Scanner();
		$scanner->init();

		// Use the public perform_scan method.
		return $scanner->perform_scan( $mode );
	}

	/**
	 * Set scan schedule via AJAX.
	 */
	public function ajax_set_schedule() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		if ( ! $this->is_enabled() ) {
			wp_send_json_error( 'Background scanning is disabled in settings.' );
		}

		$frequency = isset( $_POST['frequency'] ) ? sanitize_key( $_POST['frequency'] ) : 'daily';
		$available = array_keys( self::get_available_schedules() );

		if ( ! in_array( $frequency, $available, true ) ) {
			wp_send_json_error( 'Invalid frequency' );
		}

		$this->schedule_scan( $frequency );

		wp_send_json_success(
			array(
				'frequency' => $frequency,
				'next_run'  => $this->get_next_scheduled_time(),
			)
		);
	}

	/**
	 * Run a background scan immediately via AJAX.
	 */
	public function ajax_run_now() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		if ( ! $this->is_enabled() ) {
			wp_send_json_error( 'Background scanning is disabled in settings.' );
		}

		// Trigger the scan immediately.
		do_action( self::CRON_HOOK );

		wp_send_json_success(
			array(
				'message' => 'Background scan triggered',
				'results' => get_option( 'nexifymy_last_scheduled_scan' ),
			)
		);
	}

	/**
	 * Get scan schedule status via AJAX.
	 */
	public function ajax_get_status() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		if ( ! $this->is_enabled() ) {
			wp_send_json_success(
				array(
					'frequency' => 'disabled',
					'next_run'  => null,
					'last_scan' => get_option( 'nexifymy_last_scheduled_scan', null ),
					'disabled'  => true,
				)
			);
		}

		$frequency = get_option( self::SCHEDULE_OPTION, 'daily' );
		$last_scan = get_option( 'nexifymy_last_scheduled_scan', null );

		wp_send_json_success(
			array(
				'frequency' => $frequency,
				'next_run'  => $this->get_next_scheduled_time(),
				'last_scan' => $last_scan,
			)
		);
	}

	/**
	 * Get next scheduled scan time.
	 *
	 * @return string|null
	 */
	private function get_next_scheduled_time() {
		$timestamp = wp_next_scheduled( self::CRON_HOOK );
		return $timestamp ? date( 'Y-m-d H:i:s', $timestamp ) : null;
	}
}
