# SecureWP360 - Authentication & Access Controls

This document details the modules responsible for securing the WordPress login experience, managing user access, and preventing unauthorized entry.

---

## Two-Factor Authentication (2FA)

Adds an essential second layer of security beyond passwords.

**Key Features:**

- **Hardware Tokens & Apps:** Supports standard TOTP authentication apps (Google Authenticator, Authy, etc.).
- **Role-Based Enforcment:** Administrators can force specific user roles (e.g., Administrators, Editors) to setup 2FA before they are allowed to access the dashboard.
- **Recovery Codes:** Generates secure backup codes for users in case they lose access to their authenticator device.

---

## Password Security

Enforces strong password practices across the platform.

**Key Features:**

- **Complexity Rules:** Forces users to create strong passwords (minimum length, mixed case, numbers, symbols).
- **Compromised Password Check:** Integrates with databases of known breached passwords (e.g., HaveIBeenPwned) to prevent users from setting vulnerable credentials.
- **Forced Resets:** Administrators can force bulk or individual password resets.

---

## Passkey (WebAuthn) Support

Provides a modern, passwordless authentication experience leveraging the secure hardware built into users' devices.

**Key Features:**

- **FIDO2 Compliance:** Supports biometric logins (FaceID, TouchID, Windows Hello) or physical security keys (YubiKey).
- **Phishing Resistance:** WebAuthn protocols make login credentials inherently resistant to phishing attacks, as the key is bound to the origin domain.

---

## Login Captcha

Stops automated credential stuffing and brute force bots before they invoke the Rate Limiter.

**Key Features:**

- **Integration Options:** Supports popular CAPTCHA providers (reCAPTCHA, hCaptcha, Turnstile).
- **Implementation:** Displays on the default `wp-login.php` form, password reset forms, and WooCommerce login endpoints.

---

## Hide Login URL

Obscures the default entry point to the WordPress administrative area.

**Key Features:**

- **Custom Slugs:** Changes `/wp-admin` and `wp-login.php` to a custom string (e.g., `yoursite.com/secure-entrance`).
- **Redirection:** Automatically redirects automated bots looking for the default URLs to a 404 page or a custom deceptive honeypot page.

---

## Geo Blocking

Restricts access to the WordPress login area (or the entire site) based on the user's geographical location.

**Key Features:**

- **Country-Level Control:** Block or allow specific countries (e.g., blocking countries known for high volumes of automated bot traffic).
- **IP Databases:** Utilizes updated MaxMind or similar IP-to-Country databases.
- **Exceptions:** Configure specific IP ranges or user agents to bypass Geo Blocking rules.

---

## Time-Bound Permissions

Implements the principle of least privilege by granting temporary access rather than permanent administrative roles.

**Key Features:**

- **Temporary Escalation:** Allows a standard user to become an Administrator for a strictly defined period (e.g., 2 hours).
- **Automatic Revocation:** The system automatically demotes the user back to their original role once the timer expires.
- **Audit Logging:** Logs all actions taken while the user was temporarily elevated to ensure accountability.
