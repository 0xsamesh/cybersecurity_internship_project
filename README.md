# Secure Node.js User Management System

This repository demonstrates a hardened Node.js Express application developed during a Cybersecurity Internship to mitigate OWASP top vulnerabilities.

### Project Overview
The initial codebase contained critical vulnerabilities (SQL Injection and Stored XSS) on its login and profile systems. Over a three-phase analysis, it was intentionally exploited and subsequently secured utilizing strict defense-in-depth principles.

### Security Enhancements Implemented:
* **Input Sanitization:** Uses the `validator` package to strictly escape input metrics, neutralizing Document Object Model (DOM) injection attacks (XSS).
* **Authentication:** Insecure sessions were ripped out and replaced with stateless JSON Web Tokens (JWT).
* **Data Protection:** Database vulnerabilities mitigated using strict Parameterized Queries, and plaintext passwords are securely hashed at rest with `bcrypt` (Salted 10-Rounds).
* **Network/Transport Security:** HTTP Response headers restricted via `Helmet.js` middleware to enforce strict HTTP constraints.
* **Application Auditing:** All authentication activity (successes and failures) is automatically tracked into a `security.log` audit file using the `winston` framework.
