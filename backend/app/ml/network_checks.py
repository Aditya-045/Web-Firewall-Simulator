"""
network_checks.py -- Deterministic, network-level URL verification layer.
============================================================================
Everything in this module is a real check against the live network --
actual DNS lookups, an actual TLS handshake, an actual HTTP redirect
fetch, a real public DNS blackhole list query -- never a simulated or
hardcoded result. This is the piece that makes URL scanning a genuine
hybrid system instead of "ML model, full stop": the ML model
(model_manager.predict_url) and the lexical/string-only heuristics
(heuristics.url_heuristic_score) only ever look at the URL text itself,
so they can be fooled by a URL that merely *looks* fine. These checks look
at what the URL actually *does* when you follow it.

WHAT'S CHECKED
--------------
  - DNS: does it resolve, to how many addresses, with what TTL
         (very low TTL + many addresses is a fast-flux hosting signature)
  - Private/reserved IP: does the hostname resolve inside a private,
         loopback, link-local, or otherwise non-public address range
         (a public login/payment page has no legitimate reason to)
  - DNSBL: is the resolved IP already listed on a public, free, keyless
         DNS blackhole list (Spamhaus ZEN)
  - TLS: does the host actually serve a valid certificate; is it expired,
         self-signed, or issued for a different hostname than requested
  - Redirects: how many hops, how many distinct domains crossed, does the
         chain silently downgrade from https back to http
  - Domain age: from WHOIS, since newly-registered domains are one of the
         best-established phishing signals in the literature
  - Punycode/IDN: is the hostname Punycode-encoded (xn--), the mechanism
         behind homograph/lookalike-character attacks
  - Port: does the URL specify a non-standard port

SSRF GUARD -- READ BEFORE MODIFYING
------------------------------------
A URL scanner that blindly connects to whatever an untrusted user submits
is itself a security hole: without a guard, this feature would let anyone
use this backend as a proxy to probe internal infrastructure (cloud
metadata endpoints like 169.254.169.254, internal admin panels, etc).
run_all_network_checks() therefore resolves DNS FIRST, standalone, checks
whether any resolved address is private/loopback/link-local/reserved, and
if so SKIPS the TLS and redirect checks entirely -- it does not attempt
the connection and then flag it after the fact. Do not reorder this to run
DNS concurrently with the TLS/redirect checks; that would reopen the SSRF
hole by racing the connection attempt against the safety check.

Known residual risk (not fully mitigated here): DNS rebinding, where the
resolved IP changes between this check and the later connection attempt.
A fully rigorous fix pins the IP from this resolution and connects to that
exact address (with SNI still set to the original hostname) rather than
letting TLS/requests re-resolve the hostname themselves. That's a real
hardening step worth doing for a production deployment; it isn't done here
to keep this change scoped to "block the obvious, common case," not a
complete network-security audit.

FAILURE HANDLING
-----------------
Unlike url_heuristic_score (which only ever looks at the URL string and
therefore always succeeds), every function here talks to the real network
and can legitimately fail: DNS timeout, firewall, target down, WHOIS
server slow (empirically, python-whois's blocking call can take roughly
2x whatever timeout is configured -- see source_lookup.py). A failed check
contributes nothing to the suspicion score rather than being treated as
either "safe" or "malicious" by default; its own result dict's
error/resolved/reachable field says exactly what could and couldn't be
verified, and that honesty is preserved all the way out to the API
response via source_metadata so nothing is hidden behind one number.

DNSBL RESOLVER REQUIREMENT (important)
---------------------------------------
Spamhaus refuses queries that arrive via public/open resolvers such as
8.8.8.8 or 1.1.1.1, answering with a 127.255.255.x error code instead of
a real result. check_dnsbl() recognises that and reports the zone under
"refused_by" (result: UNKNOWN, not clean and not listed). On a server
whose /etc/resolv.conf points at a public resolver, the DNSBL check will
therefore be effectively disabled until you point it at your own
recursive resolver (e.g. a local unbound/bind instance).

DNSBL USAGE POLICY NOTE
-------------------------
Spamhaus's and SORBS's public DNSBL mirrors are free and require no API
key, but they do have usage policies around high-volume automated/
commercial querying (see https://www.spamhaus.org/organization/dnsblusage/).
That's fine for the query volume an interactive scanner with a handful of
concurrent users generates. For a high-traffic production deployment,
either self-host a DNSBL mirror (free rsync zone transfer) or use a
licensed data feed instead of hitting the public resolver directly --
don't just scale this up as-is without checking that first.
"""
import ipaddress
import logging
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import tldextract

# suffix_list_urls=() disables tldextract's attempt to fetch a live public
# suffix list over the network at runtime; it falls back to its bundled
# snapshot, which is current enough for TLD extraction and -- importantly
# for a security tool meant to run on restricted/firewalled municipal or
# enterprise networks (see SRS) -- never depends on an outbound fetch to a
# third-party domain succeeding.
_tld_extract = tldextract.TLDExtract(suffix_list_urls=())

from app.ml.source_lookup import whois_lookup

try:
    import dns.resolver
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False

logger = logging.getLogger("threat_scanner.network_checks")

CONNECT_TIMEOUT = 4          # seconds, per individual DNS/TLS connection attempt
REQUEST_TIMEOUT = 6          # seconds, per HTTP redirect-chain fetch
FUTURE_TIMEOUT = 10          # seconds, hard ceiling waited on each background check
MAX_REDIRECTS = 5
COMMON_PORTS = {80, 443, 8080, 8443}
# Spamhaus ZEN only by default. SORBS (dnsbl.sorbs.net) was announced as being
# shut down in 2024; that could not be verified from the sandbox this was
# written in, so it is NOT included -- confirm its status yourself before
# adding it back. Any zone added here must follow the 127.0.0.x listing /
# 127.255.255.x refusal convention that check_dnsbl() interprets.
DNSBL_ZONES = ["zen.spamhaus.org"]
SCAN_USER_AGENT = "Mozilla/5.0 (compatible; ThreatScannerBot/1.0; automated security scan)"


def _parse_host_port(raw_url: str):
    """Mirrors the scheme-less-input normalization url_features.py already
    uses, so a URL scored identically by the ML/lexical layers is parsed
    identically here too."""
    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z]+://", url):
        url = "http://" + url
    parsed = urlparse(url)
    return url, parsed, parsed.hostname, parsed.port


# --------------------------------------------------------------- DNS ----
def _check_dns_detail_impl(hostname: str) -> dict:
    """Richer than source_lookup.resolve_ip(): every A record (not just
    one) and the record's TTL, via dnspython when available. A very low
    TTL combined with several frequently-rotating A records is the classic
    "fast-flux" hosting fingerprint malware/phishing infrastructure uses
    to dodge takedowns -- a legitimate site has no reason to do this.

    Layered on purpose, in this order:
      1. If the "hostname" is already a literal IP address (common in
         phishing URLs that skip DNS entirely, e.g. http://192.168.1.1/
         login), there is nothing to resolve -- it already is the address.
         Caught here explicitly; without this, step 3 below sends a
         literal IP string to a DNS "A" query, which fails outright and
         would incorrectly report "does not resolve" for the single most
         obvious private-IP-literal phishing pattern this module exists
         to catch.
      2. socket.gethostbyname_ex() goes through the OS's FULL resolution
         stack -- /etc/hosts, NSS, DNS, mDNS where configured -- which is
         what correctly resolves names like "localhost". Step 3's raw DNS
         query to an external resolver legitimately can't see hosts-file
         entries at all, since they never touch the network; without this
         step, a URL like "http://localhost/admin" would incorrectly
         report "does not resolve" instead of correctly being caught by
         the private-IP check downstream.
      3. dnspython, best-effort, to enrich with the real TTL when a
         genuine DNS record exists. A failure here (expected for
         hosts-file-only names like localhost, which has no real DNS
         record) does NOT erase an already-successful step-2 resolution.
    """
    result = {"resolved": False, "ip_addresses": [], "ttl": None, "error": None, "method": None}
    if not hostname:
        result["error"] = "no hostname to resolve"
        return result

    try:
        ipaddress.ip_address(hostname)
        result["resolved"] = True
        result["ip_addresses"] = [hostname]
        result["method"] = "literal_ip"
        return result
    except ValueError:
        pass  # not a literal IP -- proceed to actual resolution below

    try:
        _, _, addrs = socket.gethostbyname_ex(hostname)
        if addrs:
            result["resolved"] = True
            result["ip_addresses"] = sorted(set(addrs))
            result["method"] = "socket"
    except Exception as e:
        result["error"] = str(e)

    if _HAS_DNSPYTHON:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = CONNECT_TIMEOUT
            resolver.lifetime = CONNECT_TIMEOUT
            answer = resolver.resolve(hostname, "A")
            result["resolved"] = True
            result["ip_addresses"] = sorted({r.address for r in answer})
            result["ttl"] = answer.rrset.ttl
            result["method"] = "dnspython"
            result["error"] = None
        except Exception as e:
            if not result["resolved"]:
                result["error"] = str(e)

    return result


def check_dns_detail(hostname: str) -> dict:
    """Public entry point. Wraps _check_dns_detail_impl() and guarantees the
    two fields the frontend's MetadataPanel.jsx has always read --
    `host` and `ip_address` -- on EVERY return path, alongside the richer
    `ip_addresses` list / `ttl` / `method` added for scoring.

    This is a UI contract, not a nicety: the original resolve_ip() returned
    {host, ip_address, resolved}, and MetadataPanel.jsx renders "Resolved
    host" / "IP address" from exactly those names. Returning only
    `ip_addresses` made both rows show "unavailable" even when DNS resolved
    fine. Do not remove these two keys without updating the frontend.
    `host` is the hostname that was actually resolved; `ip_address` is the
    first resolved address (None if nothing resolved).
    """
    result = _check_dns_detail_impl(hostname)
    ips = result.get("ip_addresses") or []
    result["host"] = hostname
    result["ip_address"] = ips[0] if ips else None
    return result


# -------------------------------------------------------- private IP ----
def check_private_ip(ip_addresses: list) -> dict:
    """Flags a resolved address as private/loopback/link-local/reserved/
    multicast. A public-facing URL -- especially one posing as a bank or
    login page -- resolving inside a private address range is a strong,
    unambiguous signal: either SSRF bait, a local-network phishing rig, or
    a poisoned/misconfigured DNS response. Legitimate public websites
    never do this, so this is one of the few findings in this module
    treated as a hard override rather than just a scored contribution --
    see model_manager._finalize_url()."""
    flagged = []
    for ip in ip_addresses:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            flagged.append(ip)
    return {"has_private_ip": bool(flagged), "flagged_ips": flagged}


# -------------------------------------------------------------- DNSBL ----
def check_dnsbl(ip_addresses: list) -> dict:
    """Queries free, keyless public DNS blackhole lists by reversing each
    IPv4 address and looking it up as a subdomain of the blocklist zone --
    exactly the mechanism any mail server's spam filter uses, no API key
    involved, just a plain DNS lookup. IPv6 addresses are skipped (these
    particular public lists are IPv4-only). See the module docstring for
    the usage-policy note on query volume."""
    listed_on = []
    refused_by = set()
    checked_any = False
    for ip in ip_addresses:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.version != 4:
            continue
        reversed_ip = ".".join(reversed(ip.split(".")))
        for zone in DNSBL_ZONES:
            query = f"{reversed_ip}.{zone}"
            try:
                _, _, answers = socket.gethostbyname_ex(query)
            except socket.gaierror:
                checked_any = True
                continue  # NXDOMAIN -- not listed; the expected, common case
            except Exception as e:
                logger.debug("DNSBL query failed for %s: %s", query, e)
                continue

            # A DNS answer is NOT automatically a listing. DNSBLs use the
            # 127.0.0.0/24 range for real listings (the last octet encodes
            # the list/category), but they ALSO answer with codes in
            # 127.255.255.0/24 to say "your query was refused" -- notably
            # Spamhaus does this for queries arriving via public/open
            # resolvers (e.g. 8.8.8.8, 1.1.1.1) and for excessive query
            # volume. Treating those as listings would flag EVERY url as
            # malicious on any deployment using a public resolver, so they
            # are recorded as "refused/unusable", never as a hit.
            real_listing = False
            for a in answers:
                try:
                    ans = ipaddress.ip_address(a)
                except ValueError:
                    continue
                if ans in ipaddress.ip_network("127.255.255.0/24"):
                    refused_by.add(zone)
                elif ans in ipaddress.ip_network("127.0.0.0/24"):
                    real_listing = True
            if real_listing:
                checked_any = True
                listed_on.append({"ip": ip, "list": zone})
            elif zone not in refused_by:
                checked_any = True

    return {
        "listed": bool(listed_on),
        "listed_on": listed_on,
        "checked": checked_any,
        # Zones that answered with a refusal code. If this is non-empty the
        # DNSBL result for that zone is "unknown", NOT "clean" -- the fix
        # is to point the server at its own recursive resolver rather than
        # a public one.
        "refused_by": sorted(refused_by),
    }


# ---------------------------------------------------------------- TLS ----
def check_tls_certificate(hostname: str, port: int = 443) -> dict:
    """Actually opens a TLS connection and inspects the certificate the
    server presents, independent of whatever scheme the URL string
    claims. Flags: no working TLS at all, an expired certificate, a
    certificate whose subject/SAN doesn't match the hostname being
    visited (the classic MITM / typosquat-infrastructure-reuse
    signature), and self-signed certificates.

    Only called after run_all_network_checks() has already confirmed the
    target does NOT resolve to a private/reserved address -- see the SSRF
    guard note in the module docstring. Never call this directly on a
    hostname you haven't already DNS/private-IP-checked."""
    result = {
        "serves_tls": False, "valid": False, "hostname_matches": False,
        "self_signed": False, "expired": False, "days_until_expiry": None,
        "issuer": None, "subject": None, "error": None,
    }
    if not hostname:
        result["error"] = "no hostname"
        return result

    def _extract_cert_fields(cert: dict):
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        result["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
        result["subject"] = subject.get("commonName")
        result["self_signed"] = bool(issuer) and issuer == subject
        not_after = cert.get("notAfter")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                result["days_until_expiry"] = days_left
                result["expired"] = days_left < 0
            except ValueError:
                pass

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
        result["serves_tls"] = True
        result["valid"] = True          # default context already validated chain + hostname to get here
        result["hostname_matches"] = True
        _extract_cert_fields(cert)

    except ssl.SSLCertVerificationError as e:
        # Chain or hostname validation failed. Retry once WITHOUT
        # verification purely to inspect what's actually wrong
        # (expired/self-signed/mismatched) -- getpeercert() needs a
        # completed handshake to return anything at all.
        result["serves_tls"] = True
        result["valid"] = False
        result["error"] = str(e)
        msg = str(e).lower()
        result["hostname_matches"] = "hostname mismatch" not in msg and "doesn't match" not in msg
        try:
            noverify_ctx = ssl._create_unverified_context()
            with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
                with noverify_ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    cert = tls_sock.getpeercert()
            _extract_cert_fields(cert)
        except Exception as e2:
            logger.debug("Unverified TLS retry also failed for %s: %s", hostname, e2)

    except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError) as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)

    return result


# --------------------------------------------------------- redirects ----
def check_redirect_chain(raw_url: str) -> dict:
    """Actually follows the URL's redirect chain (HEAD first, falling
    back to a streamed GET -- never downloading the body -- for servers
    that reject HEAD, which some phishing kits do) and inspects it for
    cloaking patterns: many hops, hopping across multiple unrelated
    domains, or silently downgrading from https back to http mid-chain.
    This also unwinds link-shortener URLs to reveal what they actually
    point at, which the lexical is_shortener heuristic can't do on its
    own since it never leaves the URL string.

    Same SSRF-guard precondition as check_tls_certificate(): only called
    after the target has been confirmed to resolve to a public address."""
    result = {
        "reachable": False, "hop_count": 0, "chain": [], "distinct_domains": [],
        "protocol_downgrade": False, "final_url": None, "error": None,
    }
    url, _, _, _ = _parse_host_port(raw_url)
    headers = {"User-Agent": SCAN_USER_AGENT}

    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS

    try:
        resp = session.head(url, allow_redirects=True, timeout=REQUEST_TIMEOUT, headers=headers)
        if resp.status_code in (405, 501) or (not resp.history and resp.status_code >= 400):
            resp = session.get(url, allow_redirects=True, timeout=REQUEST_TIMEOUT, headers=headers, stream=True)
            resp.close()  # never read the body -- only the chain/headers matter here
    except requests.exceptions.TooManyRedirects as e:
        result["error"] = f"too many redirects (possible redirect loop): {e}"
        return result
    except requests.exceptions.SSLError as e:
        result["error"] = f"TLS error during redirect fetch: {e}"
        return result
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
        return result

    result["reachable"] = True
    chain = [h.url for h in resp.history] + [resp.url]
    result["chain"] = chain
    result["hop_count"] = len(resp.history)
    result["final_url"] = resp.url

    domains = []
    for u in chain:
        try:
            ext = _tld_extract(u)
            dom = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            if dom and dom not in domains:
                domains.append(dom)
        except Exception:
            pass
    result["distinct_domains"] = domains

    for i in range(len(chain) - 1):
        if chain[i].startswith("https://") and chain[i + 1].startswith("http://"):
            result["protocol_downgrade"] = True
            break

    return result


# ------------------------------------------------------- domain age ----
def check_domain_age(whois_data: dict) -> dict:
    """Thin wrapper around the age_days source_lookup.whois_lookup()
    already computes (see that module for why it's computed there rather
    than re-parsed from the stringified creation_date here). A domain
    registered very recently is one of the single strongest, most
    well-established phishing signals in the literature -- disposable
    attack infrastructure gets stood up right before a campaign, whereas
    legitimate brands' domains are typically years old. Redacted/unknown
    creation dates (common under GDPR WHOIS privacy) are reported as
    "unknown", never silently treated as either safe or suspicious."""
    age_days = whois_data.get("age_days") if whois_data else None
    return {
        "age_days": age_days,
        "is_new_domain": age_days is not None and age_days < 90,
        "known": age_days is not None,
    }


# --------------------------------------------------------- punycode ----
def check_punycode(hostname: str) -> dict:
    """Flags Punycode-encoded hostname labels (the ASCII "xn--" prefix).
    Legitimate internationalized domain names do use this encoding, but
    it's also the standard mechanism behind homograph/lookalike-character
    phishing (e.g. a Cyrillic "а" standing in for a Latin "a" so
    "аpple.com" renders as "apple.com"). This is a signal to weigh
    alongside everything else, not a verdict on its own -- most Punycode
    domains are perfectly legitimate non-English sites."""
    is_punycode = any(label.startswith("xn--") for label in (hostname or "").split("."))
    return {"is_punycode": is_punycode}


# -------------------------------------------------------------- port ----
def check_nonstandard_port(port) -> dict:
    """A URL explicitly specifying an unusual port is worth a second
    look: public-facing login/payment pages have essentially no
    legitimate reason to run on anything but 80/443 (or occasionally
    8080/8443 behind a proxy), while phishing kits and malware C2 panels
    frequently run on arbitrary high ports instead."""
    if port is None:
        return {"has_nonstandard_port": False, "port": None}
    return {"has_nonstandard_port": port not in COMMON_PORTS, "port": port}


# -------------------------------------------------------- orchestration --
def _unreachable_result(reason: str) -> dict:
    return {
        "serves_tls": False, "valid": False, "hostname_matches": False,
        "self_signed": False, "expired": False, "days_until_expiry": None,
        "issuer": None, "subject": None, "error": reason,
    }


def _unreachable_redirects(reason: str) -> dict:
    return {
        "reachable": False, "hop_count": 0, "chain": [], "distinct_domains": [],
        "protocol_downgrade": False, "final_url": None, "error": reason,
    }


def run_all_network_checks(raw_url: str) -> dict:
    """Runs every network-level check above and returns the raw result of
    each. Never raises: an individual check that times out or errors just
    reports that honestly in its own result rather than taking down the
    whole scan (see the module docstring's FAILURE HANDLING section).

    DNS resolution and the private-IP check run FIRST and standalone, not
    concurrently with the TLS/redirect checks -- this is the SSRF guard
    described at the top of this file. If the target resolves to a
    private/reserved address, the TLS and redirect checks are skipped
    entirely rather than attempted-then-flagged.

    The remaining checks (WHOIS, TLS, redirects) are independent I/O-bound
    operations run concurrently via a thread pool so total latency stays
    close to the slowest single check rather than their sum. Each result
    is still waited on with its own hard timeout (FUTURE_TIMEOUT) and the
    pool is shut down with wait=False, so a single unusually slow WHOIS
    server (observed empirically to occasionally take well past its own
    configured timeout) can never stall the response -- that thread is
    simply abandoned to finish or die on its own in the background.
    """
    url, parsed, hostname, port = _parse_host_port(raw_url)

    dns_result = check_dns_detail(hostname)
    ip_addresses = dns_result.get("ip_addresses", [])
    private_ip_result = check_private_ip(ip_addresses)

    if private_ip_result["has_private_ip"]:
        logger.info("SSRF guard: %s resolves to private/reserved IP(s) %s -- skipping TLS/redirect checks",
                    hostname, private_ip_result["flagged_ips"])
        whois_result = whois_lookup(raw_url)
        return {
            "dns": dns_result,
            "whois": whois_result,
            "tls": _unreachable_result("skipped: target resolves to a private/reserved IP address"),
            "redirects": _unreachable_redirects("skipped: target resolves to a private/reserved IP address"),
            "dnsbl": {"listed": False, "listed_on": [], "checked": False},
            "private_ip": private_ip_result,
            "domain_age": check_domain_age(whois_result),
            "punycode": check_punycode(hostname),
            "port": check_nonstandard_port(port),
        }

    pool = ThreadPoolExecutor(max_workers=3)
    try:
        whois_future = pool.submit(whois_lookup, raw_url)
        tls_future = pool.submit(check_tls_certificate, hostname)
        redirect_future = pool.submit(check_redirect_chain, raw_url)

        try:
            whois_result = whois_future.result(timeout=FUTURE_TIMEOUT)
        except FutureTimeoutError:
            whois_result = {"domain": None, "available": False, "error": "WHOIS lookup timed out"}

        try:
            tls_result = tls_future.result(timeout=FUTURE_TIMEOUT)
        except FutureTimeoutError:
            tls_result = _unreachable_result("TLS check timed out")

        try:
            redirect_result = redirect_future.result(timeout=FUTURE_TIMEOUT)
        except FutureTimeoutError:
            redirect_result = _unreachable_redirects("redirect-chain check timed out")
    finally:
        # wait=False: don't block the response on a straggling background
        # thread (e.g. a slow WHOIS server) that already missed its own
        # timeout above -- let it finish or die on its own.
        pool.shutdown(wait=False)

    dnsbl_result = check_dnsbl(ip_addresses)
    domain_age_result = check_domain_age(whois_result)
    punycode_result = check_punycode(hostname)
    port_result = check_nonstandard_port(port)

    return {
        "dns": dns_result,
        "whois": whois_result,
        "tls": tls_result,
        "redirects": redirect_result,
        "dnsbl": dnsbl_result,
        "private_ip": private_ip_result,
        "domain_age": domain_age_result,
        "punycode": punycode_result,
        "port": port_result,
    }


def network_heuristic_score(raw_url: str) -> tuple:
    """Combines every deterministic check above into a single 0..1
    suspicion score, a human-readable reasons list (same spirit as
    heuristics.url_heuristic_score, just sourced from live network signals
    instead of the URL string alone), and a hard_flag boolean for the
    handful of findings severe and unambiguous enough to override the ML
    model's opinion outright (see model_manager._finalize_url).

    Returns (score, reasons, hard_flag, details) -- details is the full
    raw per-check dict from run_all_network_checks(), returned alongside
    the score precisely so nothing is hidden behind one opaque number; it
    is surfaced to the API response as source_metadata.
    """
    details = run_all_network_checks(raw_url)
    score = 0.0
    reasons = []
    hard_flag = False

    dns_r = details["dns"]
    if not dns_r.get("resolved"):
        score += 0.15
        reasons.append("Domain name does not currently resolve (DNS lookup failed)")
    else:
        # Fast-flux needs BOTH a very low TTL AND several rotating
        # addresses. A low TTL alone is routine for CDNs and load-balanced
        # major sites (github.com answers with a ~36s TTL), and a large
        # address list alone is routine for CDNs too, so neither is scored
        # on its own -- doing so mislabels well-run legitimate sites.
        ips = dns_r.get("ip_addresses", [])
        if dns_r.get("ttl") is not None and dns_r["ttl"] < 120 and len(ips) >= 3:
            score += 0.10
            reasons.append(
                f"Very low DNS TTL ({dns_r['ttl']}s) combined with {len(ips)} A records "
                "-- possible fast-flux hosting"
            )

    if details["private_ip"]["has_private_ip"]:
        score = 1.0
        hard_flag = True
        reasons.append(
            "Resolves to a private/reserved IP address ("
            + ", ".join(details["private_ip"]["flagged_ips"])
            + ") -- a public URL should never point inside a private network"
        )

    if details["dnsbl"]["listed"]:
        score = 1.0
        hard_flag = True
        lists = ", ".join(sorted({e["list"] for e in details["dnsbl"]["listed_on"]}))
        reasons.append(f"Resolved IP address is listed on a live DNS blackhole list ({lists})")

    tls_r = details["tls"]
    if dns_r.get("resolved") and not details["private_ip"]["has_private_ip"]:
        if not tls_r.get("serves_tls"):
            score += 0.10
            reasons.append("Host does not serve a working TLS certificate on port 443")
        else:
            if tls_r.get("expired"):
                score += 0.20
                reasons.append("TLS certificate has expired")
            if not tls_r.get("hostname_matches"):
                score += 0.25
                reasons.append("TLS certificate does not match the requested hostname (possible MITM/typosquat infrastructure)")
            if tls_r.get("self_signed"):
                score += 0.15
                reasons.append("TLS certificate is self-signed")
            days_left = tls_r.get("days_until_expiry")
            if days_left is not None and 0 <= days_left < 7:
                score += 0.05
                reasons.append(f"TLS certificate expires in {days_left} day(s)")

    redirect_r = details["redirects"]
    if redirect_r.get("reachable"):
        if redirect_r["hop_count"] >= 3:
            score += 0.10
            reasons.append(f"Long redirect chain ({redirect_r['hop_count']} hops)")
        if len(redirect_r.get("distinct_domains", [])) >= 3:
            score += 0.15
            reasons.append(
                f"Redirect chain crosses {len(redirect_r['distinct_domains'])} different domains "
                f"({' -> '.join(redirect_r['distinct_domains'])})"
            )
        if redirect_r.get("protocol_downgrade"):
            score += 0.15
            reasons.append("Redirect chain downgrades from HTTPS to HTTP partway through")

    age_r = details["domain_age"]
    if age_r.get("known"):
        if age_r["age_days"] < 30:
            score += 0.25
            reasons.append(f"Domain was registered only {age_r['age_days']} day(s) ago")
        elif age_r["age_days"] < 90:
            score += 0.10
            reasons.append(f"Domain was registered recently ({age_r['age_days']} days ago)")

    if details["punycode"]["is_punycode"]:
        score += 0.15
        reasons.append("Hostname uses Punycode/IDN encoding (possible homograph/lookalike attack)")

    if details["port"]["has_nonstandard_port"]:
        score += 0.10
        reasons.append(f"URL specifies a non-standard port ({details['port']['port']})")

    return min(score, 1.0), reasons, hard_flag, details
