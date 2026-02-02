<?php
/**
 * Enable Scanner Module
 * Run this file once to enable the scanner module
 * Access it via: your-site.com/wp-content/plugins/nexifymy-security/enable-scanner.php
 */

// Load WordPress
require_once '../../../wp-load.php';

// Check if user is admin
if ( ! current_user_can( 'manage_options' ) ) {
	die( 'Unauthorized access' );
}

// Get current settings
$settings = get_option( 'nexifymy_security_settings', array() );

// Initialize modules array if it doesn't exist
if ( ! isset( $settings['modules'] ) ) {
	$settings['modules'] = array();
}

// Enable scanner module
$settings['modules']['scanner_enabled'] = 1;

// Update settings
$updated = update_option( 'nexifymy_security_settings', $settings );

// Display result
?>
<!DOCTYPE html>
<html>
<head>
	<title>NexifyMy Security - Enable Scanner</title>
	<style>
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
			max-width: 800px;
			margin: 50px auto;
			padding: 20px;
			background: #f5f5f5;
		}
		.card {
			background: white;
			padding: 30px;
			border-radius: 8px;
			box-shadow: 0 2px 8px rgba(0,0,0,0.1);
		}
		.success {
			color: #059669;
			padding: 15px;
			background: #d1fae5;
			border-radius: 6px;
			margin: 20px 0;
		}
		.info {
			color: #0284c7;
			padding: 15px;
			background: #e0f2fe;
			border-radius: 6px;
			margin: 20px 0;
		}
		h1 { margin-top: 0; color: #1e293b; }
		code {
			background: #f1f5f9;
			padding: 2px 6px;
			border-radius: 3px;
			font-family: 'Courier New', monospace;
		}
		.btn {
			display: inline-block;
			padding: 10px 20px;
			background: #4f46e5;
			color: white;
			text-decoration: none;
			border-radius: 6px;
			margin-top: 20px;
		}
		.btn:hover {
			background: #4338ca;
		}
	</style>
</head>
<body>
	<div class="card">
		<h1>🛡️ NexifyMy Security - Scanner Module</h1>

		<?php if ( $updated ) : ?>
			<div class="success">
				<strong>✓ Success!</strong><br>
				Scanner module has been enabled successfully.
			</div>
		<?php else : ?>
			<div class="success">
				<strong>✓ Already Enabled</strong><br>
				Scanner module is already enabled.
			</div>
		<?php endif; ?>

		<div class="info">
			<strong>Current Settings:</strong><br>
			<code>scanner_enabled: <?php echo $settings['modules']['scanner_enabled'] ? 'YES (1)' : 'NO (0)'; ?></code>
		</div>

		<h2>What was done:</h2>
		<ul>
			<li>Loaded WordPress settings</li>
			<li>Set <code>modules['scanner_enabled']</code> to <code>1</code></li>
			<li>Saved to WordPress database</li>
		</ul>

		<h2>Next Steps:</h2>
		<ol>
			<li>Go back to your WordPress admin panel</li>
			<li>Navigate to <strong>Nexify Security → Scanner</strong></li>
			<li>Try clicking one of the scan buttons (Quick, Standard, or Deep)</li>
			<li>The scanner should now work properly</li>
		</ol>

		<a href="<?php echo admin_url( 'admin.php?page=nexifymy-security-scanner' ); ?>" class="btn">
			Go to Scanner Page
		</a>

		<hr style="margin: 30px 0;">

		<p><small><strong>Note:</strong> For security reasons, delete this file after use:<br>
		<code>/wp-content/plugins/nexifymy-security/enable-scanner.php</code></small></p>
	</div>
</body>
</html>
