#!/usr/bin/env python3
"""
reconsnap — fast external recon + security-posture snapshot.

Passive, read-only, single-target. No exploitation, no brute force, no intrusive
scanning — every check is a normal request a browser or resolver would make. It
gives you a quick outside-in picture of a domain's public exposure and a letter
grade, the same class of check as securityheaders.com or Mozilla Observatory.

Zero third-party dependencies — Python 3.8+ standard library only.

    reconsnap example.com
    reconsnap example.com --json

Only run this against domains you are authorised to assess.
"""
import sys
import ssl
import json
import socket
import argparse
import datetime
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

__version__ = "1.0.0"
UA = "reconsnap/1.0 (+https://cobrasec.pro)"
TIMEOUT = 8

C = {"r": "\033[1;31m", "y": "\033[1;33m", "g": "\033[1;32m",
     "c": "\033[1;36m", "d": "\033[0;90m", "b": "\033[1m", "x": "\033[0m"}
if not sys.stdout.isatty():
    C = {k: "" for k in C}


def _get(url, method="GET"):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    return urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx)


def doh_txt(name):
    """DNS TXT lookup over Cloudflare DoH — no dnspython needed."""
    url = "https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode(
        {"name": name, "type": "TXT"})
    req = urllib.request.Request(url, headers={"accept": "application/dns-json", "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = json.load(r)
        return [a["data"].strip('"') for a in data.get("Answer", []) if a.get("type") == 16]
    except Exception:
        return []


# ── checks ──────────────────────────────────────────────────────────────────
def check_subdomains(domain):
    """Certificate-transparency subdomain discovery via crt.sh (passive, public)."""
    subs = set()
    try:
        with _get(f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json") as r:
            for row in json.load(r):
                for n in row.get("name_value", "").split("\n"):
                    n = n.strip().lstrip("*.").lower()
                    if n.endswith(domain) and "@" not in n:
                        subs.add(n)
    except Exception:
        pass
    return sorted(subs)


def check_live(host):
    try:
        with _get(f"https://{host}", method="HEAD") as r:
            return host, r.status
    except Exception:
        return host, None


def check_headers(domain):
    wanted = {
        "strict-transport-security": "HSTS — forces HTTPS, blocks downgrade attacks",
        "content-security-policy": "CSP — the strongest defence against XSS/injection",
        "x-frame-options": "Anti-clickjacking (frame embedding control)",
        "x-content-type-options": "Stops MIME-sniffing attacks",
        "referrer-policy": "Controls how much URL data leaks to other sites",
        "permissions-policy": "Restricts powerful browser features",
    }
    present, missing, server = {}, {}, None
    try:
        with _get(f"https://{domain}") as r:
            hdrs = {k.lower(): v for k, v in r.headers.items()}
        server = hdrs.get("server")
        for h, why in wanted.items():
            (present if h in hdrs else missing)[h] = why
    except Exception:
        return None
    return {"present": present, "missing": missing, "server": server}


def check_tls(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                cert = ss.getpeercert()
                proto = ss.version()
        na = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=datetime.timezone.utc)
        days = (na - datetime.datetime.now(datetime.timezone.utc)).days
        return {"protocol": proto, "expires_days": days,
                "issuer": dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "?")}
    except Exception as e:
        return {"error": str(e)[:80]}


def check_email(domain):
    spf = any(t.lower().startswith("v=spf1") for t in doh_txt(domain))
    dmarc_recs = doh_txt(f"_dmarc.{domain}")
    dmarc = next((t for t in dmarc_recs if t.lower().startswith("v=dmarc1")), None)
    policy = None
    if dmarc:
        for part in dmarc.split(";"):
            if part.strip().lower().startswith("p="):
                policy = part.split("=", 1)[1].strip().lower()
    return {"spf": spf, "dmarc": bool(dmarc), "dmarc_policy": policy}


# ── scoring ─────────────────────────────────────────────────────────────────
def grade(score):
    return ("A", "g") if score >= 90 else ("B", "g") if score >= 80 else \
           ("C", "y") if score >= 70 else ("D", "y") if score >= 55 else ("F", "r")


def run(domain):
    print(f"\n{C['r']}{C['b']}  reconsnap{C['x']} {C['d']}v{__version__} · CobraSEC · passive external snapshot{C['x']}")
    print(f"{C['d']}  target: {domain}   (passive checks only — authorised targets only){C['x']}\n")

    hdr = check_headers(domain)
    tls = check_tls(domain)
    email = check_email(domain)
    subs = check_subdomains(domain)

    score = 100
    lines = []

    # headers (35)
    if hdr is None:
        lines.append((C['r'], "HTTPS", "site did not respond on https — could not assess headers"))
        score -= 20
    else:
        miss = hdr["missing"]
        score -= min(35, len(miss) * 7)
        if not miss:
            lines.append((C['g'], "Headers", "all key security headers present — solid"))
        else:
            for h, why in miss.items():
                lines.append((C['y'], "Header missing", f"{h} — {why}"))
        if hdr.get("server") and any(c.isdigit() for c in hdr["server"]):
            lines.append((C['y'], "Info leak", f"Server header exposes version: {hdr['server']}"))
            score -= 4

    # tls (25)
    if "error" in tls:
        lines.append((C['r'], "TLS", f"TLS problem: {tls['error']}"))
        score -= 25
    else:
        d = tls["expires_days"]
        old = tls["protocol"] in ("TLSv1", "TLSv1.1", "SSLv3")
        if old:
            lines.append((C['r'], "TLS", f"weak protocol {tls['protocol']} — upgrade to TLS 1.2+"))
            score -= 15
        else:
            lines.append((C['g'], "TLS", f"{tls['protocol']}, cert by {tls['issuer']}"))
        if d < 0:
            lines.append((C['r'], "TLS", "certificate has EXPIRED")); score -= 15
        elif d < 15:
            lines.append((C['y'], "TLS", f"certificate expires in {d} days")); score -= 5

    # email (25)
    if not email["spf"]:
        lines.append((C['r'], "Email", "no SPF record — domain is easy to spoof")); score -= 12
    if not email["dmarc"]:
        lines.append((C['r'], "Email", "no DMARC record — no phishing protection")); score -= 13
    elif email["dmarc_policy"] in (None, "none"):
        lines.append((C['y'], "Email", "DMARC present but policy is 'none' (monitor only)")); score -= 5
    if email["spf"] and email["dmarc"] and email["dmarc_policy"] in ("quarantine", "reject"):
        lines.append((C['g'], "Email", f"SPF + DMARC enforced (p={email['dmarc_policy']})"))

    # exposure (advisory)
    if subs:
        lines.append((C['c'], "Exposure", f"{len(subs)} subdomains visible in certificate transparency"))

    score = max(0, min(100, score))
    g, gc = grade(score)

    for col, tag, msg in lines:
        print(f"  {col}●{C['x']} {C['b']}{tag:14}{C['x']} {msg}")
    if subs:
        print(f"\n  {C['d']}sample subdomains:{C['x']} " + ", ".join(subs[:8]) +
              (f" (+{len(subs) - 8} more)" if len(subs) > 8 else ""))

    print(f"\n  {C['b']}Grade: {C[gc]}{g}{C['x']}  {C['d']}({score}/100 external posture){C['x']}")
    print(f"\n{C['d']}  ── This is a passive surface snapshot. It sees only what faces the public.{C['x']}")
    print(f"{C['d']}  A CobraSEC engagement tests what this can't reach — auth, logic flaws,{C['x']}")
    print(f"{C['d']}  injection, chained exploits, real impact.{C['x']}")
    print(f"  {C['c']}→ Full web report:   https://grade.cobrasec.pro{C['x']}")
    print(f"  {C['c']}→ Book an engagement: https://cobrasec.pro{C['x']}\n")

    return {"domain": domain, "score": score, "grade": g,
            "headers": hdr, "tls": tls, "email": email, "subdomains": subs}


def main():
    ap = argparse.ArgumentParser(
        prog="reconsnap",
        description="Passive external recon + security-posture snapshot (CobraSEC).")
    ap.add_argument("domain", help="domain to assess, e.g. example.com")
    ap.add_argument("--json", action="store_true", help="output raw JSON instead of a report")
    ap.add_argument("--version", action="version", version=f"reconsnap {__version__}")
    args = ap.parse_args()

    domain = args.domain.strip().lower()
    for p in ("https://", "http://"):
        if domain.startswith(p):
            domain = domain[len(p):]
    domain = domain.split("/")[0].split(":")[0]
    if "." not in domain:
        ap.error("that doesn't look like a domain (e.g. example.com)")

    if args.json:
        # quiet mode: build the same data without the report chrome
        for k in C:
            C[k] = ""
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            result = run(domain)
        print(json.dumps(result, indent=2))
    else:
        run(domain)


if __name__ == "__main__":
    main()
