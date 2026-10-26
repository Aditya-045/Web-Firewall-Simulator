"""
Real, key-free source/metadata lookup for URLs:
  - DNS resolution -> actual resolved IP address (Python stdlib socket)
  - WHOIS lookup   -> real registrar / creation date (python-whois library,
                      which queries WHOIS servers directly over port 43,
                      same protocol a `whois` CLI command uses)

No third-party paid API and no API key involved anywhere in this module.
Network failures are caught and reported honestly as "unavailable" rather
than faked.

This module is the single owner of DNS/WHOIS lookups. network_checks.py
(the deterministic URL-verification layer used by model_manager.predict_url)
imports and reuses whois_lookup() from here rather than re-implementing it,
so a URL scan never queries WHOIS twice. resolve_ip() stays for backward
compatibility and for anything that only wants the single-IP/display shape;
network_checks.check_dns_detail() does its own richer multi-record lookup
for the actual scoring path.
"""
import socket
from datetime import datetime, timezone

import tldextract

# See network_checks.py for why remote suffix-list fetching is disabled.
_tld_extract = tldextract.TLDExtract(suffix_list_urls=())

try:
    import whois as pywhois
except ImportError:
    pywhois = None

# Empirically, python-whois's underlying socket calls can take roughly 2x
# whatever socket.setdefaulttimeout() is set to before giving up (it appears
# to make a sequential two-hop lookup -- first to a root/IANA whois server,
# then to the TLD-specific one -- each bounded by the same timeout). This is
# set and restored locally around each call rather than left as a permanent
# process-wide default, so it can't silently affect unrelated socket usage
# elsewhere in the app.
WHOIS_SOCKET_TIMEOUT_SECONDS = 4


def resolve_ip(raw_url: str) -> dict:
    try:
        ext = _tld_extract(raw_url if "//" in raw_url else "http://" + raw_url)
        host = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    except Exception as e:
        return {"host": None, "ip_address": None, "resolved": False, "error": f"could not parse domain: {e}"}

    try:
        ip = socket.gethostbyname(host)
        return {"host": host, "ip_address": ip, "resolved": True}
    except Exception as e:
        return {"host": host, "ip_address": None, "resolved": False, "error": str(e)}


def whois_lookup(raw_url: str) -> dict:
    try:
        ext = _tld_extract(raw_url if "//" in raw_url else "http://" + raw_url)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    except Exception as e:
        return {"domain": None, "available": False, "error": f"could not parse domain: {e}"}

    if pywhois is None:
        return {"domain": domain, "available": False, "error": "python-whois not installed"}

    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(WHOIS_SOCKET_TIMEOUT_SECONDS)
    try:
        w = pywhois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None

        # Computed here, while creation_date is still a real datetime object,
        # so callers that need the numeric age (network_checks.check_domain_age)
        # never have to re-parse the stringified version below. Many
        # registrars redact this for privacy (GDPR WHOIS redaction) --
        # that comes back as age_days: None, reported honestly as "unknown"
        # rather than guessed at.
        age_days = None
        if isinstance(creation_date, datetime):
            cd = creation_date if creation_date.tzinfo else creation_date.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - cd).days

        return {
            "domain": domain,
            "available": True,
            "registrar": w.registrar,
            "creation_date": str(creation_date) if creation_date else None,
            "age_days": age_days,
            "country": w.country,
            "org": w.org,
        }
    except Exception as e:
        return {"domain": domain, "available": False, "error": str(e)}
    finally:
        socket.setdefaulttimeout(old_timeout)


def get_source_metadata(raw_url: str) -> dict:
    """Kept for backward compatibility / standalone use. scan.py's URL
    route no longer calls this directly -- network_checks.run_all_network_checks()
    already includes this same dns+whois data (plus everything else), so
    calling both would mean looking the same domain up twice."""
    return {
        "dns": resolve_ip(raw_url),
        "whois": whois_lookup(raw_url),
    }
