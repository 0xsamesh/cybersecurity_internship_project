# Secure Node.js User Management System

A hardened Node.js + Express user-management app built during a **Cybersecurity Internship** (Developer Hubs). The project starts from an intentionally vulnerable login/profile system, exploits it, then secures it end-to-end using defense-in-depth principles.

> Built around a three-phase workflow: **assess → exploit → remediate.**

---

## What it does

A minimal web app with **signup**, **login**, and an editable **profile bio**, backed by an in-memory SQLite database. The same app is the attack surface *and* the demonstration of the fixes.

## Vulnerabilities found and fixed

| Vulnerability | How it was exploited | Fix implemented |
|---|---|---|
| **SQL Injection** | `admin' OR '1'='1` in the username field bypassed auth | Parameterized queries (`?` placeholders) so input can never alter query logic |
| **Stored XSS** | `<script>alert('XSS')</script>` saved in the bio executed on render | `validator.escape()` on all input/output, neutralizing HTML tags |
| **Plaintext passwords** | Credentials stored as-is in the database | `bcrypt` hashing, salted at a 10-round cost factor |
| **Insecure sessions** | Weak/guessable session handling | Stateless **JWT** auth issued on successful `bcrypt.compare` |
| **Missing security headers** | Default Express headers, MIME-sniff / clickjacking exposure | `helmet()` middleware enforcing strict response headers |
| **No audit trail** | Failed logins left no trace | `winston` logger writing all auth events to `security.log` |

## Tech stack

`Node.js` · `Express` · `SQLite3` · `bcrypt` · `jsonwebtoken` · `helmet` · `validator` · `winston`

## Run it locally

```bash
npm install
npm start
```

Then open **http://localhost:3000**. A default admin account is seeded on startup:

- **Username:** `admin`
- **Password:** `supersecretpassword123!`

All authentication activity (logins, failures, JWT issuance, profile edits) is written to `security.log`.

## Routes

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/signup` · `/login` | Auth forms |
| `POST` | `/signup` · `/login` | Create account / authenticate, issue JWT |
| `POST` | `/api/login` | JSON endpoint returning a bearer token |
| `GET` | `/profile` | Protected page (JWT-guarded) |
| `POST` | `/profile` | Update bio (sanitized before storage) |

---

*Author: Abdul Sammi · BS Digital Forensics & Cybersecurity · Cybersecurity Intern, Developer Hubs.*
