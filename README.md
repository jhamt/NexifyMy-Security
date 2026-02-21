# NexifyMy Security

A modern, lightweight, and powerful security plugin for WordPress.

NexifyMy Security transcends standard static defenses by combining traditional rule-based protection (OWASP Top 10 WAF, rate limiting, and malware scanning) with advanced artificial intelligence, behavioral analysis, and peer-to-peer threat intelligence.

With over 35 distinct, highly-optimized security modules, it provides enterprise-grade protection while maintaining a zero-trust architecture and a minimal performance footprint.

---

## 📚 Complete Documentation

Given the extensive feature set, the comprehensive documentation has been organized into dedicated modules instead of one massive file.

**Start exploring the documentation here:**

- **[1. Overview & Architecture](docs/01-Overview.md)** - Learn about the early-execution flow and database design.
- **[2. Installation & Configuration](docs/02-Installation-and-Configuration.md)** - System requirements and global settings.
- **[3. Core Modules](docs/03-Core-Modules.md)** - WAF, Rate Limiter, Malware Scanner, Quarantine, and User Activity Logs.
- **[4. Advanced Modules](docs/04-Advanced-Modules.md)** - AI Threat Detection, Predictive Hunting, P2P Intelligence, Supply Chain Security, and Sandbox.
- **[5. Authentication & Access Controls](docs/05-Authentication-and-Access.md)** - WebAuthn (Passkeys), 2FA, Geo Blocking, and Time-Bound Permissions.
- **[6. APIs & Integrations](docs/06-APIs-and-Integrations.md)** - Webhooks (Slack/Discord), REST API Security, GraphQL protection, and CDN integration.
- **[7. Compliance & Performance](docs/07-Compliance-and-Performance.md)** - GDPR/CCPA reporting, Database integrity, and performance optimization.
- **[8. Developer Guide](docs/08-Developer-Guide.md)** - Hooks (Actions/Filters), WP-CLI commands, and instructions for building custom modules.

---

## ⚡ Quick Start

### Installation

1. Upload the `nexifymy-security` folder to your `/wp-content/plugins/` directory.
2. Activate the plugin through the **Plugins** menu in WordPress.

_Alternatively, upload the ZIP file directly through **Plugins -> Add New -> Upload Plugin**._

### Initial Configuration

Upon activation, the plugin automatically enables critical defenses:

- **Web Application Firewall (WAF)** immediately blocks SQLi, XSS, and LFI payloads.
- **Rate Limiter** protects against brute-force login attempts.
- **Background Scanner** schedules daily integrity checks.

Navigate to the **NexifyMy Security** menu in your WordPress dashboard to access the Live Traffic metrics, review your Security Score, and toggle the 30+ other specialized modules on or off according to your technical needs.

---

## 🛠️ Testing & Development

NexifyMy Security includes a standalone PHPUnit test suite running decoupled from a live WordPress database.

```bash
# Install development dependencies
composer install

# Check coding standards (WordPress ruleset)
composer phpcs

# Run the full test suite
composer test

# Run a specific module test
./vendor/bin/phpunit tests/test-firewall.php
```

See the [Developer Guide](docs/08-Developer-Guide.md) for more details on the testing infrastructure and extending the plugin via hooks.

---

### License

This plugin is licensed under the GPLv2 (or later).
