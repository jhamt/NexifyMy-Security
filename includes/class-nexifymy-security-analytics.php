<?php
/**
 * Analytics Module
 *
 * Tracks security metrics and displays analytics charts.
 *
 * @package    NexifyMy_Security
 * @subpackage NexifyMy_Security/includes/modules
 * @since      2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Analytics {

	/**
	 * Unique identifier for the module.
	 */
	const MODULE_ID = 'analytics';

	/**
	 * Initialize the class and set its properties.
	 */
	public function __construct() {
		add_action( 'nexifymy_security_log_event', array( $this, 'track_event' ), 10, 3 );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
	}

	/**
	 * Track a security event.
	 *
	 * @param string $type Event type (e.g., 'auth_failed', 'threat_detected').
	 * @param array  $data Event data.
	 * @param int    $timestamp Unix timestamp.
	 */
	public function track_event( $type, $data, $timestamp ) {
		$stats = get_option( 'nexifymy_security_analytics_daily', array() );
		$date  = date( 'Y-m-d', $timestamp );

		if ( ! isset( $stats[ $date ] ) ) {
			$stats[ $date ] = array(
				'auth_failed'     => 0,
				'threat_detected' => 0,
				'blocked_request' => 0,
				'scans_run'       => 0,
			);
		}

		if ( isset( $stats[ $date ][ $type ] ) ) {
			++$stats[ $date ][ $type ];
		}

		// Keep only last 30 days
		if ( count( $stats ) > 30 ) {
			$stats = array_slice( $stats, -30, 1, true );
		}

		update_option( 'nexifymy_security_analytics_daily', $stats );
	}

	/**
	 * Get analytics data for charts.
	 *
	 * @param int $days Number of days to retrieve.
	 * @return array Analytics data.
	 */
	public function get_chart_data( $days = 7 ) {
		$stats = get_option( 'nexifymy_security_analytics_daily', array() );
		$data  = array(
			'labels'   => array(),
			'datasets' => array(
				'threats' => array(),
				'blocked' => array(),
				'logins'  => array(),
			),
		);

		for ( $i = $days - 1; $i >= 0; $i-- ) {
			$date             = date( 'Y-m-d', strtotime( "-$i days" ) );
			$data['labels'][] = date( 'M j', strtotime( $date ) );

			$day_stats = isset( $stats[ $date ] ) ? $stats[ $date ] : array();

			$data['datasets']['threats'][] = isset( $day_stats['threat_detected'] ) ? $day_stats['threat_detected'] : 0;
			$data['datasets']['blocked'][] = isset( $day_stats['blocked_request'] ) ? $day_stats['blocked_request'] : 0;
			$data['datasets']['logins'][]  = isset( $day_stats['auth_failed'] ) ? $day_stats['auth_failed'] : 0;
		}

		return $data;
	}

	/**
	 * Check if Chart.js needs to be enqueued.
	 */
	public function enqueue_scripts() {
		wp_enqueue_script( 'chartjs', 'https://cdn.jsdelivr.net/npm/chart.js', array(), '4.4.0', true );
	}
}
