=== NexifyMy Security ===
Contributors: nexifymy
Tags: security, firewall, malware scanner, brute force, waf
Requires at least: 5.0
Tested up to: 6.4
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A modern, lightweight, and powerful security plugin for WordPress with WAF, malware scanning, and brute force protection.

== Description ==

NexifyMy Security is a comprehensive WordPress security solution designed to protect your website from common threats and attacks.

= Key Features =

* **Web Application Firewall (WAF)** - Real-time protection against SQL injection, XSS, LFI, and malicious bots
* **Malware Scanner** - Three scanning modes (Quick, Standard, Deep) with heuristic threat detection
* **Brute Force Protection** - Rate limiting for login attempts with configurable thresholds
* **Quarantine System** - Safely isolate threats instead of immediate deletion
* **Background Scanning** - Scheduled scans via WP-Cron (hourly, daily, weekly)
* **Security Logging** - Full audit trail of security events
* **Configurable Settings** - IP whitelist, trusted proxies, scan exclusions, and more

= How It Works =

1. **WAF Protection**: Scans all incoming requests (GET, POST, cookies, headers, JSON bodies) for malicious patterns
2. **Scanner**: Analyzes PHP files for suspicious code, backdoors, and malware signatures
3. **Rate Limiter**: Tracks failed login attempts and temporarily blocks repeat offenders
4. **Quarantine**: Moves suspicious files to a protected directory for review

= Requirements =

* WordPress 5.0 or higher
* PHP 7.4 or higher

== Installation ==

1. Upload the `nexifymy-security` folder to `/wp-content/plugins/`
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Navigate to 'NexifyMy Security' in the admin menu to configure settings

== Frequently Asked Questions ==

= Will this plugin slow down my website? =

No. NexifyMy Security is designed to be lightweight. The WAF runs efficiently on each request, and background scans are scheduled to run during off-peak times.

= What happens when a threat is detected during scanning? =

Detected threats are listed in the scan results. You can choose to quarantine them (recommended) which moves them to a secure location where they cannot execute. From quarantine, you can review, restore (if false positive), or permanently delete files.

= How do I whitelist my IP address? =

Go to NexifyMy Security > Settings > IP Configuration and add your IP address to the whitelist (one IP per line).

= Can I use this behind a CDN or load balancer? =

Yes! Add your CDN/proxy IP addresses to "Trusted Proxies" in the settings. This allows the plugin to correctly identify client IPs from X-Forwarded-For headers.

= Is the scanner resource-intensive? =

The scanner is optimized with incremental scanning (only checks modified files on subsequent scans) and configurable file size limits. You can also exclude specific paths from scanning.

== Screenshots ==

1. Dashboard with security score and quick actions
2. Malware scanner with three scanning modes
3. Quarantine management interface
4. Comprehensive settings page
5. Security logs viewer

== Changelog ==

= 1.0.0 =
* Initial release
* Web Application Firewall with OWASP-inspired rules
* Three-mode malware scanner (Quick, Standard, Deep)
* Brute force protection with configurable thresholds
* Quarantine system for safe threat handling
* Background scheduled scans
* Full security logging
* Comprehensive settings page

== Upgrade Notice ==

= 1.0.0 =
Initial release of NexifyMy Security.

== Troubleshooting ==

= WAF is blocking legitimate requests (false positives) =

1. Check NexifyMy Security > Logs to identify which rule triggered
2. Go to Settings > Email Alerts and enable "Log-only mode" temporarily
3. Add your IP to the whitelist, or add specific URL paths to the allowlist
4. Disable specific rule types (SQLi, XSS, LFI) if needed

= Scanner is timing out on large sites =

1. Use "Quick" or "Standard" scan modes instead of "Deep"
2. Add large directories (like vendor/) to excluded paths
3. Reduce max file size in settings
4. Standard mode uses incremental scanning automatically

= Background scans not running =

1. Verify WP-Cron is working (install WP Crontrol plugin to check)
2. Ensure the plugin is activated and background scans are enabled
3. Check if your host disables WP-Cron (some hosts do)
4. Try reducing scan frequency from hourly to daily

= Rate limiter locked me out =

1. Wait for lockout to expire (default: 15 minutes)
2. Access your site via SSH/FTP and add your IP to whitelist
3. Or delete the transient: `wp transient delete nexifymy_rl_YOUR_IP`

= How to verify the plugin is working =

1. Check the Dashboard for security score and recent events
2. Look at Logs for WAF blocks and scan results
3. Try a test: visit `yoursite.com/?test=<script>alert(1)</script>` (should be blocked)

== Privacy Policy ==

NexifyMy Security logs security events including IP addresses to help you identify and respond to threats. This data is stored in your WordPress database and is not transmitted to external servers.

**Data Collected:**
* IP addresses of blocked requests
* Timestamps of security events
* File paths of detected threats
* Login attempt information

**Data Retention:**
* Log retention is configurable (default: 30 days)
* All data is deleted when the plugin is uninstalled (if cleanup option enabled)

For more information, visit [nexifymy.com/privacy](https://nexifymy.com/privacy).
