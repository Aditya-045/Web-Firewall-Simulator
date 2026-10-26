"""
Offline regression tests for the hybrid URL-scoring algorithm. No network,
no trained model, no pytest needed -- run from the backend/ folder:

    python scripts/test_hybrid_scoring.py

Covers: DNSBL response interpretation (incl. the 127.255.255.x refusal
codes that must NOT count as listings), every network_heuristic_score rule,
and the model_manager blend / override behaviour. Network-dependent
behaviour (real DNS, TLS, redirects, WHOIS, a real blocklist hit) is NOT
covered here -- that needs a live environment.
"""
import os
import socket
import sys
from copy import deepcopy
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from app.ml import network_checks as nc  # noqa: E402
from app.ml.model_manager import ModelManager  # noqa: E402

failures = []


def expect(label, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {label} {detail}")
    if not ok:
        failures.append(label)


# ---------------------------------------------------------------- DNSBL
def dnsbl(side_effect):
    with patch.object(nc.socket, "gethostbyname_ex", side_effect=side_effect):
        return nc.check_dnsbl(["198.51.100.7"])

r = dnsbl(lambda q: (q, [], ["127.0.0.2"]))
expect("DNSBL: 127.0.0.2 is a listing", r["listed"])
r = dnsbl(socket.gaierror(-2, "NXDOMAIN"))
expect("DNSBL: NXDOMAIN is clean", not r["listed"] and r["checked"])
for code in ("127.255.255.254", "127.255.255.252", "127.255.255.255"):
    r = dnsbl(lambda q, c=code: (q, [], [c]))
    expect(f"DNSBL: refusal {code} is NOT a listing",
           not r["listed"] and r["refused_by"] == ["zen.spamhaus.org"])

# ------------------------------------------------- network score rules
CLEAN = {
    "dns": {"resolved": True, "ip_addresses": ["203.0.113.10"], "ttl": 3600, "error": None, "method": "dnspython"},
    "whois": {"available": True, "age_days": 4000},
    "tls": {"serves_tls": True, "valid": True, "hostname_matches": True, "self_signed": False,
            "expired": False, "days_until_expiry": 60, "issuer": "CA", "subject": "x", "error": None},
    "redirects": {"reachable": True, "hop_count": 0, "chain": ["https://x"], "distinct_domains": ["x.com"],
                  "protocol_downgrade": False, "final_url": "https://x", "error": None},
    "dnsbl": {"listed": False, "listed_on": [], "checked": True, "refused_by": []},
    "private_ip": {"has_private_ip": False, "flagged_ips": []},
    "domain_age": {"age_days": 4000, "is_new_domain": False, "known": True},
    "punycode": {"is_punycode": False},
    "port": {"has_nonstandard_port": False, "port": None},
}


def net(mutator):
    d = deepcopy(CLEAN)
    mutator(d)
    with patch.object(nc, "run_all_network_checks", return_value=d):
        return nc.network_heuristic_score("http://x")


def rule(label, mutator, score, hard=False):
    s, _, h, _ = net(mutator)
    expect(f"NET: {label}", abs(s - score) < 1e-9 and h == hard, f"(score={s:.2f} hard={h})")


rule("clean site scores 0", lambda d: None, 0.0)
rule("low TTL alone is not flagged", lambda d: d["dns"].update(ttl=36), 0.0)
rule("many IPs alone is not flagged", lambda d: d["dns"].update(ip_addresses=["1.1.1.1"] * 6), 0.0)
rule("low TTL + 4 IPs = fast-flux", lambda d: d["dns"].update(ttl=60, ip_addresses=["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]), 0.10)
rule("does not resolve", lambda d: d["dns"].update(resolved=False, ip_addresses=[]), 0.15)
rule("domain 5 days old", lambda d: d["domain_age"].update(age_days=5), 0.25)
rule("domain 60 days old", lambda d: d["domain_age"].update(age_days=60), 0.10)
rule("domain age unknown", lambda d: d["domain_age"].update(age_days=None, known=False), 0.0)
rule("no TLS", lambda d: d["tls"].update(serves_tls=False), 0.10)
rule("expired cert", lambda d: d["tls"].update(expired=True), 0.20)
rule("hostname mismatch", lambda d: d["tls"].update(hostname_matches=False), 0.25)
rule("self-signed", lambda d: d["tls"].update(self_signed=True), 0.15)
rule("redirects: long + cross-domain + downgrade",
     lambda d: d["redirects"].update(hop_count=4, distinct_domains=["a.com", "b.com", "c.com"], protocol_downgrade=True), 0.40)
rule("punycode", lambda d: d["punycode"].update(is_punycode=True), 0.15)
rule("non-standard port", lambda d: d["port"].update(has_nonstandard_port=True, port=31337), 0.10)
rule("private IP is a hard flag", lambda d: d["private_ip"].update(has_private_ip=True, flagged_ips=["10.0.0.5"]), 1.0, True)
rule("DNSBL listing is a hard flag", lambda d: d["dnsbl"].update(listed=True, listed_on=[{"ip": "1.2.3.4", "list": "zen.spamhaus.org"}]), 1.0, True)

# ------------------------------------------ frontend (MetadataPanel.jsx) contract
# The UI reads dns.host / dns.ip_address / dns.resolved and
# whois.available / registrar / creation_date / country. Losing any of
# these makes the "Source details" panel show "unavailable" for data that
# was actually collected. Offline: localhost resolves via the hosts file.
for label, host, patcher in [
    ("resolved name (localhost)", "localhost", None),
    ("literal IP", "203.0.113.9", None),
    ("empty hostname", "", None),
    ("unresolvable name", "no-such-host.invalid", None),
]:
    d = nc.check_dns_detail(host)
    has_keys = all(k in d for k in ("host", "ip_address", "resolved", "ip_addresses"))
    consistent = (d["ip_address"] == (d["ip_addresses"][0] if d["ip_addresses"] else None)) and d["host"] == host
    expect(f"UI CONTRACT dns: {label}", has_keys and consistent,
           f"(host={d['host']!r} ip_address={d['ip_address']!r} resolved={d['resolved']})")

d = nc.check_dns_detail("localhost")
expect("UI CONTRACT dns: resolved => ip_address is a real address", d["resolved"] and d["ip_address"] == "127.0.0.1")
d = nc.check_dns_detail("no-such-host.invalid")
expect("UI CONTRACT dns: unresolved => ip_address None, resolved False", d["ip_address"] is None and d["resolved"] is False)

# Full run_all_network_checks output (private-IP short-circuit path, WHOIS stubbed so it stays offline)
with patch.object(nc, "whois_lookup", return_value={"domain": "localhost", "available": False, "error": "stub"}):
    full = nc.run_all_network_checks("http://localhost:8000/x")
expect("UI CONTRACT: short-circuit path still carries dns.host/ip_address",
       full["dns"]["host"] == "localhost" and full["dns"]["ip_address"] == "127.0.0.1")
expect("UI CONTRACT: top-level keys the panel destructures exist", "dns" in full and "whois" in full)

# ----------------------------------------------------------- the blend
mm = ModelManager.__new__(ModelManager)


def blend(label, ml, lex, netscore, hard, verdict, path=None):
    r = mm._finalize_url(ml, lex, [], netscore, [], {}, hard)
    ok = r["verdict"] == verdict and (path is None or r["detection_path"] == path)
    expect(f"BLEND: {label}", ok, f"-> {r['verdict']} {r['final_confidence']:.3f} [{r['detection_path']}]")


blend("confident ML phishing, clean network, is still malicious", 0.99, 0.30, 0.0, False, "malicious", "ml_high_confidence")
blend("mid-confidence ML false positive is tempered by clean network", 0.70, 0.15, 0.0, False, "safe")
blend("everything clean is safe", 0.02, 0.0, 0.0, False, "safe")
blend("blocklist/private-IP overrides a 'safe' ML score", 0.05, 0.0, 1.0, True, "malicious", "network_override")
blend("several bad network findings are not 'safe' despite low ML", 0.05, 0.10, 0.70, False, "malicious", "network_high_suspicion")
blend("a single weak network signal does not convict", 0.05, 0.0, 0.25, False, "safe")

print()
if failures:
    print(f"{len(failures)} FAILED: {failures}")
    sys.exit(1)
print("ALL TESTS PASSED")
