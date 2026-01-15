# NexifyMy Security 🛡️

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-GPLv2-orange)
![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-blue)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-purple)

**NexifyMy Security** is a modern, lightweight, and powerful security plugin for WordPress. It provides a comprehensive defense suite including a Web Application Firewall (WAF), heuristic malware scanner, and intelligent brute force protection—all designed to protect your website without slowing it down.

## 🚀 Key Features

- **🔥 Advanced WAF**: Real-time protection against SQL injection, XSS, LFI, and malicious bots.
- **🔍 Malware Scanner**: Three scanning modes (Quick, Standard, Deep) with heuristic threat detection.
- **🛡️ Brute Force Protection**: Smart rate limiting to block repeated login failures and aggressive crawlers.
- **📦 Quarantine System**: Safely isolate threats in a hardened directory instead of immediate deletion.
- **🕐 Background Scanning**: Automated, rigorous security checks scheduled via WP-Cron.
- **📝 Audit Logging**: Detailed security event logs with retention policies and daily auto-purge.
- **⚙️ Granular Control**: IP whitelisting, trusted proxies support, and customizable exclusion rules.

## ⚙️ How It Works

1.  **WAF Protocol**: Intercepts every incoming request (GET, POST, Headers, JSON) to block malicious payloads before they reach WordPress.
2.  **Heuristic Analysis**: The scanner doesn't just look for filenames; it analyzes code patterns for base64 encoding, shell exec functions, and known malware signatures.
3.  **Intelligent Locking**: The rate limiter tracks IP behavior, temporarily blocking offenders while allowing legitimate users to pass.

## 📥 Installation

1.  Download the repository.
2.  Upload the `nexifymy-security` folder to your `/wp-content/plugins/` directory.
3.  Activate the plugin through the **Plugins** menu in WordPress.
4.  Navigate to **NexifyMy Security** in the admin sidebar to configure your protection level.

## 🛑 Troubleshooting

### WAF False Positives

If legitimate requests are being blocked:

- Check **Logs** to identify the specific rule.
- Enable **"Log-only mode"** in Settings > Email Alerts temporarily.
- Add your IP to the **Whitelist**.

### Scanner Timeouts

For large sites:

- Use **Quick** or **Standard** scan modes.
- Exclude heavy directories (e.g., `node_modules`, `vendor`).
- The scanner uses **incremental** logic to skip unchanged files in Standard mode.

## 🔒 Privacy & Data

NexifyMy Security stores data locally in your WordPress database:

- **Logged Data**: Offending IPs, timestamps, and event types.
- **Retention**: Configurable (defaults to 30 days).
- **Privacy**: No sensitive data is sent to external servers.

## 🤝 Contributing

Contributions are welcome! Please submit a Pull Request or open an Issue to help us improve NexifyMy Security.

## 📜 License

This project is licensed under the GNU General Public License v2 or later.
