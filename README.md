# reconsnap

**Fast external recon + security-posture snapshot. One command, no dependencies.**

`reconsnap` gives you a quick outside-in view of a domain's public security posture and a
letter grade — the same class of check as [securityheaders.com](https://securityheaders.com)
or Mozilla Observatory, but from your terminal and across several categories at once.

It is **passive and read-only**: every check is a normal request a browser or DNS resolver
would make. No exploitation, no brute force, no intrusive scanning.

```
  reconsnap  v1.1.0 · passive external snapshot
  target: example.com

  ● Header missing  content-security-policy — the strongest defence against XSS/injection
  ● TLS             TLSv1.3, cert by Let's Encrypt
  ● Email           SPF + DMARC enforced (p=reject)
  ● Cookies         cookie(s) set without SameSite — CSRF exposure
  ● Disclosure      security.txt published — clear route to report issues
  ● Exposure        28 subdomains visible in certificate transparency, 11 responding live

  live hosts: api.example.com, cdn.example.com, mail.example.com, ...

  Grade: B  (84/100 external posture)
```

## What it checks

- **Security headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **TLS** — protocol version, certificate issuer, expiry
- **Email spoofing protection** — SPF and DMARC (including whether DMARC is actually enforced)
- **Attack surface** — subdomains from Certificate Transparency logs, then probed concurrently so you see which ones are **actually live**
- **Cookie flags** — `Secure`, `HttpOnly`, `SameSite` on any cookies the site sets
- **Disclosure maturity** — RFC 9116 `security.txt`
- **Info leaks** — version-exposing `Server` and `X-Powered-By` headers

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
reconsnap example.com                 # readable report + grade
reconsnap example.com --json          # machine-readable JSON
reconsnap example.com --no-live       # skip subdomain liveness probing (pure passive)
reconsnap example.com --max-live 200  # probe up to 200 subdomains for liveness (default 75)
reconsnap example.com --workers 40    # concurrency for liveness probing (default 20)
```

**Exit codes** (handy for CI or chaining): `0` = grade A/B, `1` = C/D, `2` = F.

```bash
reconsnap example.com || echo "posture needs attention"
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
