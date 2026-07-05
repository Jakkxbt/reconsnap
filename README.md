# reconsnap

**Fast external recon + security-posture snapshot. One command, no dependencies.**

`reconsnap` gives you a quick outside-in view of a domain's public security posture and a
letter grade — the same class of check as [securityheaders.com](https://securityheaders.com)
or Mozilla Observatory, but from your terminal and across several categories at once.

It is **passive and read-only**: every check is a normal request a browser or DNS resolver
would make. No exploitation, no brute force, no intrusive scanning.

```
  reconsnap  v1.0.0 · passive external snapshot
  target: example.com

  ● Header missing  content-security-policy — the strongest defence against XSS/injection
  ● TLS             TLSv1.3, cert by Let's Encrypt
  ● Email           no DMARC record — no phishing protection

  Grade: C  (72/100 external posture)
```

## What it checks

- **Security headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **TLS** — protocol version, certificate issuer, expiry
- **Email spoofing protection** — SPF and DMARC (including whether DMARC is actually enforced)
- **Attack surface** — subdomains visible in Certificate Transparency logs
- **Info leaks** — version-exposing `Server` headers

## Install

No dependencies — just Python 3.8+.

```bash
git clone https://github.com/Jakkxbt/reconsnap
cd reconsnap
python3 reconsnap.py example.com
```

Optionally drop it on your `PATH`:

```bash
chmod +x reconsnap.py && sudo ln -s "$PWD/reconsnap.py" /usr/local/bin/reconsnap
reconsnap example.com
```

## Usage

```bash
reconsnap example.com           # readable report + grade
reconsnap example.com --json    # machine-readable JSON
```

## Scope & ethics

Only run `reconsnap` against domains you own or are explicitly authorised to assess.
It is passive, but you are still responsible for where you point it.

## Going deeper

`reconsnap` only sees what faces the public internet. It won't find authentication flaws,
business-logic bugs, injection, access-control issues, or chained exploits — the things that
actually get organisations compromised. Those need a real engagement.

Prefer a browser? The same grade is available as a hosted web report at
**[grade.cobrasec.pro](https://grade.cobrasec.pro)**.

**[CobraSEC](https://cobrasec.pro)** does offensive security and adversary emulation — we test
what a passive snapshot can't reach. If `reconsnap` graded your surface, book an engagement to
see what's behind it.

---

MIT License · built by [@jakkxbt](https://github.com/Jakkxbt)
