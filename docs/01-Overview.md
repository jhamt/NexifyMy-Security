# SecureWP360 - Overview & Architecture

## Introduction

Welcome to the documentation for **SecureWP360**, a modern, lightweight, and powerful security plugin for WordPress.

Version: **2.1.0**
Requires: WordPress 5.0+, PHP 7.4+

SecureWP360 provides a unified defense system, combining traditional rule-based protection (WAF, malware scanning) with advanced artificial intelligence, behavioral analysis, and peer-to-peer threat intelligence.

With over 35 distinct security modules, it offers enterprise-grade protection while maintaining a minimal performance footprint.

## Core Philosophy

SecureWP360 is built on three core principles:

1.  **Early Execution:** Security checks must happen before malicious code can run.
2.  **Zero-Trust:** Never trust input, regardless of the source or authentication status.
3.  **Performance-First:** Heavy operations (scanning, AI modeling) are throttled or offloaded to background processes to ensure the site remains fast for legitimate visitors.

## Architecture & Execution Flow

To provide maximum protection, the plugin employs a specialized execution pipeline.

### 1. Early Execution (Pre-Hook Phase)

Unlike standard WordPress plugins that wait for the `plugins_loaded` or `init` hooks, SecureWP360's most critical defenses fire immediately upon PHP execution.

- **When it runs:** Before WordPress has fully initialized its core logic.
- **What runs:**
  - The **Web Application Firewall (WAF)** (`modules/firewall.php`)
  - The **Rate Limiter** (`modules/rate-limiter.php`)
- **Why it matters:** This prevents early-execution exploits and zero-day vulnerabilities in other plugins or themes before they even have a chance to load.

_Note: For safety during installation and updates, this early execution is skipped on admin pages (`/wp-admin`), the login page, and during plugin activation/deactivation processes._

### 2. Standard Initialization (`plugins_loaded` hook)

After the early defenses have secured the perimeter, the rest of the plugin initializes at priority `1` on the `plugins_loaded` hook.

- **i18n (Internationalization):** The text domain is loaded first to ensure translations are available.
- **Core Systems:** The centralized `NexifyMy_Security_Settings` class and the Logger are initialized.
- **Module Loading:** All of the 35+ specialized security modules check their enablement status in the settings array and initialize if active.

### 3. Module System

Every major feature in SecureWP360 is built as an independent, standalone PHP class inside the `modules/` directory.

Modules are designed to be explicitly toggled on or off via the `nexifymy_security_settings` database option. The global instance of each active module is stored in the `$GLOBALS` array (e.g., `$GLOBALS['nexifymy_waf']`).

### 4. Database Structure

The plugin creates specialized custom tables at activation for high-performance logging and data tracking:

- `{prefix}nexifymy_security_logs`: Centralized event log for all modules.
- `{prefix}nexifymy_traffic`: Live traffic monitoring.
- `{prefix}nexifymy_user_activity`: Comprehensive audit trail for administrator actions.
- `{prefix}nexifymy_behavior_log`: AI behavioral data tracking.
- `{prefix}sentinel_user_profiles`: Per-user baselines for anomalous activity detection.

_(These tables are completely removed upon uninstallation if the cleanup option is enabled.)_
