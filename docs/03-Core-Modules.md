# SecureWP360 - Core Modules

SecureWP360 features a robust, modular architecture with 35+ specialized security components. This document covers the essential foundational modules that provide the first line of defense.

---

## Firewall (WAF)

The **Web Application Firewall (WAF)** is the most critical component, designed to inspect all incoming HTTP/HTTPS requests before they reach WordPress core or other plugins.

**Execution Timing:**
Runs _before_ the standard `plugins_loaded` hook for maximum protection against early-execution exploits.

**Key Protections:**

- **OWASP Top 10 Rules:** Deep inspection for SQL Injection (SQLi), Cross-Site Scripting (XSS), and Local File Inclusion (LFI).
- **Zero-Trust API Security:** Identity-aware rules applied specifically to REST API endpoints.
- **Recursive Payload Scanning:** Analyzes nested arrays in `$_GET`, `$_POST`, `$_COOKIE`, headers, and raw JSON payloads.
- **Bot Protection:** Options to block known bad bots and fake scrapers impersonating legitimate crawlers.

---

## Rate Limiter & Brute Force Protection

Prevents automated guessing of passwords and DDoS attempts on sensitive endpoints.

**Execution Timing:**
Runs immediately alongside the WAF on frontend requests. Specifically hooks into `authenticate` for WordPress login protection.

**Key Features:**

- **Login Protection:** Limits failed authentication attempts within a sliding time window (default: 5 attempts in 5 minutes).
- **Temporary Lockouts:** Automatically bans offending IP addresses using fast, memory-efficient WordPress transients (`nexifymy_rl_lockout_{md5(ip)}`).
- **Configurable Thresholds:** customizable attempt limits, time windows, and penalty durations.

---

## Malware Scanner

A comprehensive, multi-tiered file and database scanning engine that hunts for hidden malicious code.

**Scanning Modes:**

- **Quick Scan:** Focuses on core files, active themes, and active plugins.
- **Standard Scan:** Includes the entire `wp-content` directory and database options.
- **Deep Mode:** Performs intensive heuristic analysis across all files, looking for obfuscated PHP and unknown threats.

**Detection Mechanisms (5-Tier Classification):**

1.  **CONFIRMED_MALWARE:** Exact signature matches for known shells and backdoors.
2.  **SUSPICIOUS:** Matches heuristic patterns (e.g., heavily obfuscated `eval()` blocks).
3.  **POTENTIALLY_DANGEROUS:** Uses risky functions (`exec`, `system`) in unusual contexts.
4.  **UNKNOWN/UNVERIFIED:** Code that warrants manual review.
5.  **CLEAN:** Verified safe code.

**Signature Database:**
Regularly updated via `signature-updater.php`, pulling threat intelligence from established sources.

---

## Background Scanner

Automates the Malware Scanner to ensure continuous protection without manual intervention.

**Key Features:**

- **Cron-Driven:** Uses WordPress pseudo-cron (e.g., `nexifymy_scheduled_scan`) to run daily, weekly, or monthly.
- **Resource Throttling:** Designed to scan in batches, preventing severe CPU/Memory spikes that could take the site offline.

---

## Quarantine & Cleanup

When threats are detected, these modules handle mitigation safely.

**Quarantine (`quarantine.php`):**

- Moves infected files out of their execution path to `wp-content/nexifymy-quarantine/`.
- Secures the quarantine directory with strict `.htaccess` rules to prevent execution of quarantined malware.
- Allows administrators to review and restore files if a false positive occurs.

**Cleanup (`cleanup.php`):**

- Handles the safe deletion of confirmed malware.
- Reverts altered core files back to their pristine, original state.

---

## Live Traffic & User Activity Logging

Provides complete visibility into who is accessing the site and what administrators are modifying.

**Live Traffic (`live-traffic.php`):**

- Logs incoming requests to the `{prefix}nexifymy_traffic` custom database table.
- Records response codes, geographic origin (Country), and explicitly flags requests blocked by the WAF.
- Capped at a default of 5000 rows to prevent database bloat.

**User Activity Log (`user-activity-log.php`):**

- Creates an audit trail of authenticated user actions in the `{prefix}nexifymy_user_activity` table.
- Tracks plugin activations, setting changes, updates, and user profile modifications.

---

## Self-Protection & Hardening

Secures the WordPress environment and protects the security plugin itself from being disabled by attackers.

**Hardening (`hardening.php`):**

- Disables PHP execution in hazardous directories (e.g., `wp-content/uploads`).
- Hides WordPress version numbers.
- Disables the built-in file editor (`DISALLOW_FILE_EDIT`).

**Self-Protection (`self-protection.php`):**

- Prevents unauthorized deactivation of the SecureWP360 plugin.
- Locks down crucial security settings against tampering by compromised administrator accounts.
