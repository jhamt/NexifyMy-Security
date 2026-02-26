<?php
/**
 * Module Functionality Test Script
 * Run this via: wp eval-file test-modules.php
 */

if ( ! defined( 'ABSPATH' ) ) {
	require_once __DIR__ . '/../../../wp-load.php';
}

echo "=== SecureWP360 Module Test ===\n\n";

$settings = get_option( 'nexifymy_security_settings', array() );

// Test 1: Module Toggles
echo "1. Testing Module Toggles:\n";
$test_modules = array( 'captcha', 'two_factor', 'geo_blocking', 'waf', 'scanner' );
foreach ( $test_modules as $module ) {
	$key    = $module . '_enabled';
	$status = isset( $settings['modules'][ $key ] ) ? ( $settings['modules'][ $key ] ? 'ENABLED' : 'DISABLED' ) : 'NOT SET';
	echo "   - {$module}: {$status}\n";
}

// Test 2: Captcha Operations
echo "\n2. Testing CAPTCHA Operations:\n";
if ( class_exists( 'NexifyMy_Security_Login_Captcha' ) ) {
	$captcha    = new NexifyMy_Security_Login_Captcha();
	$reflection = new ReflectionClass( $captcha );
	$method     = $reflection->getMethod( 'generate_captcha' );
	$method->setAccessible( true );

	// Test all operations
	$ops_found = array();
	for ( $i = 0; $i < 20; $i++ ) {
		$result = $method->invoke( $captcha );
		if ( preg_match( '/[+\-×÷]/', $result['question'], $match ) ) {
			$ops_found[ $match[0] ] = true;
		}
	}

	echo '   Operations available: ' . implode( ', ', array_keys( $ops_found ) ) . "\n";
	echo '   Division (÷) present: ' . ( isset( $ops_found['÷'] ) ? 'YES ✓' : 'NO ✗' ) . "\n";
} else {
	echo "   CAPTCHA class not found\n";
}

// Test 3: Geo Blocking Settings
echo "\n3. Testing Geo Blocking:\n";
if ( isset( $settings['geo_blocking'] ) ) {
	$geo = $settings['geo_blocking'];
	echo '   Enabled: ' . ( ! empty( $geo['enabled'] ) ? 'YES' : 'NO' ) . "\n";
	echo '   Mode: ' . ( $geo['mode'] ?? 'NOT SET' ) . "\n";
	echo '   Countries: ' . ( ! empty( $geo['countries'] ) ? count( $geo['countries'] ) . ' selected' : 'NONE' ) . "\n";
} else {
	echo "   Settings not configured\n";
}

// Test 4: AJAX Handlers
echo "\n4. Testing AJAX Handlers:\n";
$ajax_handlers = array(
	'nexifymy_toggle_module',
	'nexifymy_save_geo_settings',
	'nexifymy_get_geo_settings',
);
foreach ( $ajax_handlers as $handler ) {
	$registered = has_action( "wp_ajax_{$handler}" );
	echo "   - {$handler}: " . ( $registered ? 'REGISTERED ✓' : 'NOT FOUND ✗' ) . "\n";
}

// Test 5: Module Classes
echo "\n5. Testing Module Classes:\n";
$classes = array(
	'NexifyMy_Security_Login_Captcha',
	'NexifyMy_Security_Two_Factor',
	'NexifyMy_Security_Geo_Blocking',
	'NexifyMy_Security_Firewall',
	'NexifyMy_Security_Scanner',
);
foreach ( $classes as $class ) {
	echo "   - {$class}: " . ( class_exists( $class ) ? 'LOADED ✓' : 'NOT FOUND ✗' ) . "\n";
}

echo "\n=== Test Complete ===\n";
