# NexifyMy Security - APIs & Integrations

## Advanced API Security

Secures custom endpoints and built-in REST API functionality within WordPress.

**Key Features:**

- **REST API Lockdown:** Disables the WordPress REST API for unauthenticated users (with options to whitelist specific endpoints for public functionality).
- **Zero-Trust Integration:** The core WAF is identity-aware, applying strict OWASP rules specifically tailored to API payloads (JSON, XML).
- **JWT Integrity:** Enforces validation of JSON Web Tokens for custom headless setups extending beyond standard cookie authentication.

---

## GraphQL Security

Protects systems using WPGraphQL, preventing resource exhaustion and overly complex queries.

**Key Features:**

- **Query Depth Limiting:** Blocks GraphQL queries that extend beyond a specific nested depth (e.g., depth limit of 5), preventing DoS attacks via complex relational lookups.
- **Introspection Disabling:** Hides the GraphQL schema from unauthenticated public scanning, reducing the attack surface.
- **Mutation Protection:** Applies standard WAF sanitization to GraphQL mutations to prevent injection vulnerabilities.

---

## Integrations (Webhooks)

Connects NexifyMy Security to your existing enterprise communication and monitoring tools.

**Supported Platforms:**

- Slack
- Discord
- Microsoft Teams
- Jira Service Management
- ServiceNow
- Generic SIEM endpoints (Splunk, Elastic, Datadog)

**Key Features:**

- **Granular Routing:** Send high-priority alerts (e.g., CONFIRMED_MALWARE discovered) to an Incident Response channel, while sending lower-priority notices (e.g., Plugin Update Available) to a general logging channel.
- **JSON Payloads:** Structured data delivery containing IP addresses, context, and immediate action links (e.g., "Add to Blocklist" directly from Slack).

---

## Content Delivery Network (CDN) Integration

Ensures NexifyMy Security correctly identifies the originating IP address when the site is placed behind a proxy.

**Key Features:**

- **Header Selection:** Allows configuration of the correct IP originating header (`CF-Connecting-IP`, `X-Forwarded-For`, `X-Real-IP`, etc.) based on the specific provider (Cloudflare, Fastly, Akamai).
- **IP Spoofing Protection:** Validates that the requests containing these headers actually originate from the known IP ranges of the selected CDN provider, rather than a malicious actor attempting to spoof their IP address.

---

## Developer REST API

Provides a programmable interface for managing the security posture of the WordPress installation remotely.

**Endpoints:**
Located under `/wp-json/nexifymy-security/v1/`

**Key Features:**

- **Remote Management:** Retrieve security metrics, trigger background malware scans, or check the status of the WAF programmatically.
- **Blocklist/Allowlist Automation:** API endpoints to add or remove IP addresses from access control lists dynamically based on external threat intelligence platforms.
- **Authentication:** Requires an Application Password or a valid administrative session nonce.
