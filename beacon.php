<?php
/**
 * Honeypot Beacon Tracker
 *
 * Logs and reacts when a honeypot beacon token is observed.
 *
 * @package NexifyMy_Security
 */

// Prevent direct access without WordPress loaded.
if ( ! defined( 'ABSPATH' ) ) {
	// Bootstrap WordPress if accessed directly.
	$wp_load = __DIR__ . '/../../../wp-load.php';
	if ( file_exists( $wp_load ) ) {
		require_once $wp_load;
	} else {
		// Fallback: log to error_log.
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		error_log( '[SecureWP360] Beacon triggered but WordPress not loaded' );
		http_response_code( 404 );
		exit( 'Not found' );
	}
}

// Primary key matches modules/deception.php; fallback keeps backward compatibility.
// phpcs:ignore WordPress.Security.NonceVerification.Recommended
$beacon_token = '';
if ( isset( $_GET['nexifymy_beacon'] ) ) {
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended
	$beacon_token = sanitize_text_field( wp_unslash( $_GET['nexifymy_beacon'] ) );
} elseif ( isset( $_GET['beacon'] ) ) {
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended
	$beacon_token = sanitize_text_field( wp_unslash( $_GET['beacon'] ) );
}

if ( empty( $beacon_token ) ) {
	http_response_code( 404 );
	exit( 'Not found' );
}

// Primary option key matches modules/deception.php; fallback keeps backward compatibility.
$stored_token = get_option( 'nexifymy_honeypot_beacon_token', '' );
if ( empty( $stored_token ) ) {
	$stored_token = get_option( 'nexifymy_deception_beacon_token', '' );
}

if ( $beacon_token !== $stored_token ) {
	http_response_code( 404 );
	exit( 'Not found' );
}

// Beacon triggered - log the access.
$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : 'unknown';

$data = array(
	'beacon_token' => $beacon_token,
	'ip'           => $ip,
	'user_agent'   => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
	'referer'      => isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '',
	'request_uri'  => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
	'query_string' => isset( $_SERVER['QUERY_STRING'] ) ? sanitize_text_field( wp_unslash( $_SERVER['QUERY_STRING'] ) ) : '',
	'method'       => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '',
	'timestamp'    => current_time( 'mysql' ),
);

// Log via SecureWP360 logger.
if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
	NexifyMy_Security_Logger::log(
		'beacon_triggered',
		sprintf( 'Honeypot beacon triggered by %s - attacker attempted to use fake credentials', $ip ),
		'critical',
		$data
	);
}

// Block the IP immediately.
if ( class_exists( 'NexifyMy_Security_Firewall' ) && method_exists( 'NexifyMy_Security_Firewall', 'block_ip' ) ) {
	NexifyMy_Security_Firewall::block_ip( $ip, 'Honeypot beacon triggered - attempted to use fake credentials' );
}

// Send alert email if configured.
if ( class_exists( 'NexifyMy_Security_Alerts' ) && method_exists( 'NexifyMy_Security_Alerts', 'send_alert' ) ) {
	NexifyMy_Security_Alerts::send_alert(
		'Honeypot Beacon Triggered - Credential Theft Attempt',
		sprintf(
			"A honeypot beacon was triggered, indicating an attacker attempted to use fake credentials from a honeypot file.\n\n" .
			"IP Address: %s\n" .
			"User Agent: %s\n" .
			"Timestamp: %s\n" .
			"Referer: %s\n\n" .
			'This IP has been automatically blocked.',
			$ip,
			$data['user_agent'],
			$data['timestamp'],
			$data['referer']
		),
		'critical'
	);
}

// Return a fake 404 to avoid revealing the beacon.
http_response_code( 404 );
nocache_headers();

echo '<!DOCTYPE html>
<html>
<head>
	<title>404 Not Found</title>
</head>
<body>
	<h1>404 Not Found</h1>
	<p>The requested URL was not found on this server.</p>
</body>
</html>';
exit;
