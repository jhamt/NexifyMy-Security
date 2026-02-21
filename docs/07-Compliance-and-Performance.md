# NexifyMy Security - Compliance & Performance

## Compliance Reporting (GDPR, CCPA)

Helps organizations meet strict data privacy regulations by managing how security logs identify users.

**Key Features:**

- **IP Anonymization:** Options to automatically hash or partially redact IP addresses in the `nexifymy_traffic` and `nexifymy_security_logs` tables to comply with data minimization principles.
- **Data Export/Erasure:** Integrates with the core WordPress Privacy tools, allowing users to request a complete export of their security-related activity or request the deletion of their telemetry data.
- **Audit Readiness:** Generates compliance reports mapping the deployed security controls to specific regulatory requirements (e.g., PCI-DSS, GDPR).

---

## Consent Management

Manages user permissions related to non-essential security tracking.

**Key Features:**

- **Cookie Integration:** Works alongside standard Cookie Notice plugins to ensure advanced behavioral tracking (AI Threat Detection) only activates _after_ the user has consented to analytical/tracking cookies.
- **Consent Logs:** Records when a user grants or revokes consent in a dedicated `{prefix}nexifymy_consent_records` table to demonstrate compliance in the event of an audit.

---

## Database Security

Secures the foundation of the WordPress installation against direct data manipulation.

**Key Features:**

- **Prefix Modification:** Automatically scrambles or changes the default `wp_` database prefix to prevent automated SQLi scanners from easily targeting known table names.
- **Scheduled Backups:** Built-in capability to generate and securely store SQL dumps of the database on a cron schedule.
- **Query Analysis:** Monitors for unusual or highly complex SQL queries that bypass standard ORM layers, flagging potential injection attempts that slipped past the WAF.

---

## Core Repair

Maintains the integrity of the WordPress installation.

**Key Features:**

- **File Integrity Monitoring:** Continuously compares core WordPress files, plugins, and themes against known good checksums provided by the WordPress.org API.
- **One-Click Reversion:** If a core file (like `wp-includes/functions.php`) is modified maliciously, the administrator can restore it to its pristine state with a single click.

---

## Performance Optimizer

Ensures that heavy security features do not negatively impact the site's Time to First Byte (TTFB).

**Key Features:**

- **Throttled Background Scans:** Distributes the intensive I/O operations of the Malware Scanner across multiple cron events, preventing CPU spikes.
- **Caching Integration:** Bypasses live traffic logging and deep WAF inspection for explicitly cached static assets (images, CSS, JS) to reduce overhead.
- **Database Pruning:** Automatically trims the activity logs and traffic tables (e.g., deleting records older than 30 days) to keep database queries fast and efficient.
