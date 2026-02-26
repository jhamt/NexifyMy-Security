# SecureWP360 - Installation & Configuration

## System Requirements

To ensure optimal performance and compatibility, your server should meet the following minimum requirements:

- **WordPress Version:** 5.0 or higher
- **PHP Version:** 7.4 or higher (PHP 8.x recommended)
- **Database:** MySQL 5.6+ or MariaDB 10.1+
- **Memory Limit:** `WP_MEMORY_LIMIT` should be set to at least `128M` (256M recommended for Deep Scanning).

## Installation

### Method 1: Upload via WordPress Admin

1.  Download the plugin ZIP file (e.g., `nexifymy-security.zip`).
2.  Log in to your WordPress dashboard.
3.  Navigate to **Plugins** -> **Add New Plugin**.
4.  Click the **Upload Plugin** button at the top of the screen.
5.  Select the `nexifymy-security.zip` file and click **Install Now**.
6.  Once the installation is complete, click **Activate Plugin**.

### Method 2: Manual Upload via FTP/SFTP

1.  Extract the `nexifymy-security.zip` file on your computer.
2.  Connect to your server using an FTP client (like FileZilla or Cyberduck).
3.  Navigate to the `/wp-content/plugins/` directory.
4.  Upload the extracted `nexifymy-security` folder.
5.  Log in to your WordPress dashboard, go to **Plugins**, and click **Activate** next to SecureWP360.

---

## Global Configuration Overview

All configuration for SecureWP360 is managed through the centralized **SecureWP360** menu in your WordPress dashboard sidebar.

### Centralized Settings Storage

Under the hood, SecureWP360 is designed for performance. It stores _all_ of its configuration data in a single, serialized WordPress option named `nexifymy_security_settings`.

This prevents unnecessary database queries on every page load, as WordPress retrieves this single option and caches it in memory.

### The Dashboard

Upon activation, the plugin initializes with a default set of robust, best-practice security rules enabled.

The main Dashboard provides:

- **Security Score:** An instant, calculated metric of your site's overall health.
- **Live Metrics:** Charts displaying recent blocks, traffic spikes, and threat categories via the `NexifyMy_Security_Analytics` class.
- **Quick Toggles:** Easily enable or disable primary defenses without diving deep into module settings.

### Module Configuration

To dive deeper, navigate to the specific settings pages for each feature category (e.g., **Firewall**, **Scanner**, **Login Security**).

If a module is turned off globally (via the main toggle), its specific settings will not impact the site until it is re-enabled.

### Default Configurations on Activation

When activated for the first time, SecureWP360 establishes the following critical defaults:

- **Firewall:** Enabled (Blocks bad bots and fake scrapers immediately).
- **Rate Limiter:** Enabled (Limits to 5 attempts per 5 minutes, 30-minute lockout).
- **Notifications:** Enabled (Alerts sent to the site admin email).
- **Background Scanner:** Scheduled to run daily.
- **Deception/Honeypots:** Active.

_(Note: Advanced features like Sandbox execution testing or P2P Intelligence sharing may require manual enablement depending on your environment.)_
