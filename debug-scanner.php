<?php
/**
 * Debug Scanner Issues
 * This script helps diagnose why the scanner isn't working
 * Access it via: your-site.com/wp-content/plugins/nexifymy-security/debug-scanner.php
 */

// Load WordPress
require_once '../../../wp-load.php';

// Check if user is admin
if ( ! current_user_can( 'manage_options' ) ) {
	die( 'Unauthorized access' );
}

// Get settings
$settings = get_option( 'nexifymy_security_settings', array() );

// Check if scanner class exists
$scanner_file_exists = file_exists( __DIR__ . '/modules/scanner.php' );
$scanner_class_exists = class_exists( 'NexifyMy_Security_Scanner' );
$scanner_global_exists = isset( $GLOBALS['nexifymy_scanner'] );

// Check scanner enabled status
$modules = isset( $settings['modules'] ) ? $settings['modules'] : array();
$scanner_enabled = ! isset( $modules['scanner_enabled'] ) || (bool) $modules['scanner_enabled'];

?>
<!DOCTYPE html>
<html>
<head>
	<title>NexifyMy Security - Scanner Debug</title>
	<style>
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
			max-width: 900px;
			margin: 50px auto;
			padding: 20px;
			background: #f5f5f5;
		}
		.card {
			background: white;
			padding: 30px;
			border-radius: 8px;
			box-shadow: 0 2px 8px rgba(0,0,0,0.1);
			margin-bottom: 20px;
		}
		h1 { margin-top: 0; color: #1e293b; }
		h2 { color: #475569; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }
		.status { padding: 10px 15px; border-radius: 6px; margin: 10px 0; }
		.status-ok { background: #d1fae5; color: #059669; }
		.status-error { background: #fee2e2; color: #dc2626; }
		.status-warning { background: #fef3c7; color: #d97706; }
		code {
			background: #f1f5f9;
			padding: 2px 6px;
			border-radius: 3px;
			font-family: 'Courier New', monospace;
			font-size: 13px;
		}
		pre {
			background: #1e293b;
			color: #e2e8f0;
			padding: 15px;
			border-radius: 6px;
			overflow-x: auto;
			font-size: 12px;
		}
		.check-item {
			padding: 10px;
			margin: 5px 0;
			border-left: 4px solid #e2e8f0;
			background: #f8fafc;
		}
		.check-item.ok { border-left-color: #059669; }
		.check-item.error { border-left-color: #dc2626; }
		.btn {
			display: inline-block;
			padding: 10px 20px;
			background: #4f46e5;
			color: white;
			text-decoration: none;
			border-radius: 6px;
			margin: 10px 5px 10px 0;
		}
		.btn:hover { background: #4338ca; }
		.btn-success { background: #059669; }
		.btn-success:hover { background: #047857; }
	</style>
</head>
<body>
	<div class="card">
		<h1>🔍 Scanner Debug Information</h1>

		<h2>Scanner Status Checks</h2>

		<div class="check-item <?php echo $scanner_file_exists ? 'ok' : 'error'; ?>">
			<strong>Scanner File:</strong> <?php echo $scanner_file_exists ? '✓ Found' : '✗ Not Found'; ?><br>
			<small>Path: <code><?php echo __DIR__ . '/modules/scanner.php'; ?></code></small>
		</div>

		<div class="check-item <?php echo $scanner_class_exists ? 'ok' : 'error'; ?>">
			<strong>Scanner Class:</strong> <?php echo $scanner_class_exists ? '✓ Loaded' : '✗ Not Loaded'; ?><br>
			<small>Class: <code>NexifyMy_Security_Scanner</code></small>
		</div>

		<div class="check-item <?php echo $scanner_global_exists ? 'ok' : 'error'; ?>">
			<strong>Scanner Instance:</strong> <?php echo $scanner_global_exists ? '✓ Initialized' : '✗ Not Initialized'; ?><br>
			<small>Global: <code>$GLOBALS['nexifymy_scanner']</code></small>
		</div>

		<div class="check-item <?php echo $scanner_enabled ? 'ok' : 'error'; ?>">
			<strong>Scanner Module:</strong> <?php echo $scanner_enabled ? '✓ Enabled' : '✗ Disabled'; ?><br>
			<small>Setting: <code>modules['scanner_enabled']</code></small>
		</div>

		<h2>WordPress Settings</h2>
		<pre><?php echo htmlspecialchars( print_r( $settings, true ) ); ?></pre>

		<h2>AJAX Endpoint Test</h2>
		<p>Testing the scanner AJAX endpoint...</p>

		<?php
		// Test AJAX endpoint
		if ( $scanner_class_exists && $scanner_global_exists ) {
			try {
				$_POST['mode'] = 'quick';
				$_POST['nonce'] = wp_create_nonce( 'nexifymy_security_nonce' );

				// Simulate AJAX request
				ob_start();
				$GLOBALS['nexifymy_scanner']->ajax_scan();
				$ajax_output = ob_get_clean();

				echo '<div class="status status-ok">✓ AJAX endpoint is accessible</div>';
				if ( ! empty( $ajax_output ) ) {
					echo '<p><strong>Response:</strong></p>';
					echo '<pre>' . htmlspecialchars( $ajax_output ) . '</pre>';
				}
			} catch ( Exception $e ) {
				echo '<div class="status status-error">✗ AJAX endpoint error: ' . $e->getMessage() . '</div>';
			}
		} else {
			echo '<div class="status status-error">✗ Cannot test AJAX - Scanner not loaded</div>';
		}
		?>

		<h2>Recommended Actions</h2>

		<?php if ( ! $scanner_enabled ) : ?>
			<div class="status status-error">
				<strong>⚠️ Scanner is disabled!</strong><br>
				The scanner module is currently disabled in settings.
			</div>
			<a href="enable-scanner.php" class="btn btn-success">Enable Scanner Module</a>
		<?php elseif ( ! $scanner_class_exists || ! $scanner_global_exists ) : ?>
			<div class="status status-error">
				<strong>⚠️ Scanner not initialized!</strong><br>
				The scanner class or instance is not properly loaded.
			</div>
			<p>Try deactivating and reactivating the plugin:</p>
			<a href="<?php echo admin_url( 'plugins.php' ); ?>" class="btn">Go to Plugins</a>
		<?php else : ?>
			<div class="status status-ok">
				<strong>✓ Everything looks good!</strong><br>
				The scanner should be working. If it's still not working, check the browser console for JavaScript errors.
			</div>
			<a href="<?php echo admin_url( 'admin.php?page=nexifymy-security-scanner' ); ?>" class="btn">Go to Scanner Page</a>
		<?php endif; ?>

		<hr style="margin: 30px 0;">

		<p><small><strong>Note:</strong> Delete these debug files after use for security:<br>
		<code>/wp-content/plugins/nexifymy-security/debug-scanner.php</code><br>
		<code>/wp-content/plugins/nexifymy-security/enable-scanner.php</code></small></p>
	</div>
</body>
</html>
