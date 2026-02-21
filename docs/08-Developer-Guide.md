# NexifyMy Security - Developer Guide

NexifyMy Security is designed with extensibility in mind. This guide details how developers can hook into the plugin, run CLI commands, and build brand new modules.

## WP-CLI Integration

The plugin registers the `wp nexifymy` command for seamless terminal management.

**Available Commands:**

- `wp nexifymy scan trigger`: Initiates a comprehensive malware scan immediately.
- `wp nexifymy scan status`: Displays the progress and findings of the current scan.
- `wp nexifymy quarantine list`: Shows all quarantined files.
- `wp nexifymy quarantine restore <file_id>`: Restores a file from quarantine back to its original path.
- `wp nexifymy config set <module> <key> <value>`: Updates a specific setting.

---

## Action and Filter Hooks

Developers can hook into the plugin's lifecycle to intercept data or trigger custom logic.

### Actions

- `do_action( 'nexifymy_waf_blocked', $ip_address, $reason, $payload )`
  Fired immediately when the Web Application Firewall blocks a malicious request. Useful for triggering custom external alerts.

- `do_action( 'nexifymy_malware_detected', $file_path, $severity_level )`
  Fired when the scanner identifies a suspicious or malicious file.

- `do_action( 'nexifymy_user_locked_out', $user_id, $ip_address, $duration )`
  Fired when the Rate Limiter temporaily bans a user or IP due to excessive login attempts.

### Filters

- `apply_filters( 'nexifymy_waf_rules', $rules_array )`
  Allows developers to add custom Regex signatures to the WAF's blocklist or remove existing rules that cause false positives in a specific environment.

- `apply_filters( 'nexifymy_trusted_ips', $ip_array )`
  Dynamically add IP addresses to the global allowlist, bypassing WAF and rate limiting completely (e.g., dynamically adding office IPs).

---

## Creating a Custom Module

The architecture allows you to easily plug your own discrete security features into the NexifyMy dashboard.

**Step 1: Create the Class File**
Create a new PHP file in `/modules/your-custom-module.php`:

```php
<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class NexifyMy_Security_Custom_Module {

    private static $defaults = array(
        'enabled' => true,
        'custom_setting' => 'default_value'
    );

    public function init() {
        // Register your WordPress hooks here
        add_action('wp_footer', array($this, 'inject_security_headers'));

        // Register AJAX handlers
        add_action('wp_ajax_nexifymy_custom_action', array($this, 'handle_ajax'));
    }

    public function get_settings() {
        $global = NexifyMy_Security_Settings::get('modules', 'custom_module', array());
        return wp_parse_args($global, self::$defaults);
    }

    public function inject_security_headers() {
        $settings = $this->get_settings();
        if ($settings['enabled']) {
             // Implementation logic
             NexifyMy_Security_Logger::log('info', 'Custom module executed.');
        }
    }
}
```

**Step 2: Initialize the Module**
In the main plugin file (`nexifymy-security.php`), inside `nexifymy_security_init()`:

```php
// Load Custom Module
if ( nexifymy_security_is_module_enabled( $settings, 'custom_module_enabled', true ) ) {
    require_once NEXIFYMY_SECURITY_PATH . 'modules/your-custom-module.php';
    $GLOBALS['nexifymy_custom_module'] = new NexifyMy_Security_Custom_Module();
    $GLOBALS['nexifymy_custom_module']->init();
}
```

**Step 3: Register Default Settings**
Add your `custom_module_enabled` setting to the `$defaults` array inside the `nexifymy_security_activate()` function.

## Internal Testing Infrastructure

The plugin uses a custom mockup environment for PHPUnit testing, located in `tests/bootstrap.php`. It mocks over 50+ WordPress functions (`get_option`, `$wpdb`) allowing tests to run entirely decoupled from a live WordPress installation.

Run tests via: `./vendor/bin/phpunit`
