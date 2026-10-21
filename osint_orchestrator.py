#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  OSINT Framework Orchestration — COMPLETE UNIFIED v3.0            ║
║                                                                   ║
║  Pipeline: DNS → Subdomains → Permutations → Emails/Tech/         ║
║            IPIntel/Wayback/GitHub → Shodan/Breaches →             ║
║            PortScan/Screenshots → Correlation → Report            ║
║                                                                   ║
║  Usage: python3 osint_orchestrator.py -t example.com              ║
║  Optional: SHODAN_API_KEY / HIBP_API_KEY env vars                 ║
╚══════════════════════════════════════════════════════════════════╝
"""

import asyncio
import aiohttp
import argparse
import json
import time
import socket
import hashlib
import logging
import re
import os
import itertools
import random
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pathlib import Path

try:
    import dns.resolver
    import dns.query
    import dns.zone
    HAS_DNSPY = True
except ImportError:
    HAS_DNSPY = False

# ════════════════════════════════════════════════════════════════
#  CONFIGURATION & LOGGING
# ════════════════════════════════════════════════════════════════

LOG = logging.getLogger("OSINT-ORCH")
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"


def setup_logging(verbose: bool):
    LOG.setLevel(logging.DEBUG if verbose else logging.INFO)
    if not LOG.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S"))
        LOG.addHandler(h)


# ════════════════════════════════════════════════════════════════
#  CORE DATA STRUCTURES
# ════════════════════════════════════════════════════════════════

@dataclass
class Target:
    domain: str
    ip_addresses: set = dc_field(default_factory=set)
    subdomains: set = dc_field(default_factory=set)
    emails: set = dc_field(default_factory=set)
    nameservers: set = dc_field(default_factory=set)
    mx_records: set = dc_field(default_factory=set)
    txt_records: set = dc_field(default_factory=set)
    cert_domains: set = dc_field(default_factory=set)
    tech_stack: dict = dc_field(default_factory=dict)
    urls: set = dc_field(default_factory=set)
    metadata: dict = dc_field(default_factory=dict)


@dataclass
class ModuleResult:
    module: str
    target: str
    success: bool
    data: dict
    duration: float
    error: Optional[str] = None


class Confidence(Enum):
    SPECULATIVE = 1
    LIKELY = 2
    HIGH = 3


@dataclass
class Hypothesis:
    attack_id: str
    category: str
    title: str
    description: str
    evidence: list
    confidence: Confidence
    priority_score: float
    next_actions: list
    mitre_ids: list = dc_field(default_factory=list)

    def to_dict(self):
        return {
            "id": self.attack_id, "category": self.category,
            "title": self.title, "confidence": self.confidence.name,
            "priority": round(self.priority_score, 1),
            "evidence": self.evidence, "mitre": self.mitre_ids,
            "next_actions": self.next_actions,
            "description": self.description,
        }


# ════════════════════════════════════════════════════════════════
#  HTTP ENGINE — shared async session, retry + backoff
# ════════════════════════════════════════════════════════════════

class HTTPEngine:
    def __init__(self, timeout: int = 15, concurrency: int = 30):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.semaphore = asyncio.SSemaphore = asyncio.Semaphore(concurrency)
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        conn = aiohttp.TCPConnector(ssl=False, limit=100, ttl_dns_cache=300)
        self._session = aiohttp.ClientSession(
            timeout=self.timeout, connector=conn,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        return self

    async def __aexit__(self, *exc):
        if self._session:
            await self._session.close()

    async def fetch_json(self, url: str, retries: int = 3) -> Optional[dict]:
        for attempt in range(retries):
            try:
                async with self.semaphore:
                    async with self._session.get(url) as resp:
                        if resp.status == 429:
                            await asyncio.sleep(2 ** attempt * 2)
                            continue
                        if resp.status == 200:
                            return await resp.json(content_type=None)
                        return None
            except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError):
                await asyncio.sleep(1.5 ** attempt)
        return None

    async def fetch_text(self, url: str, retries: int = 2) -> Optional[str]:
        for attempt in range(retries):
            try:
                async with self.semaphore:
                    async with self._session.get(url) as resp:
                        if resp.status == 200:
                            return await resp.text(errors="ignore")
                        return None
            except (aiohttp.ClientError, asyncio.TimeoutError):
                await asyncio.sleep(1.5 ** attempt)
        return None


# ════════════════════════════════════════════════════════════════
#  OSINT MODULES
# ═══════════════════════════ turns nothing off ════════════════

class OSINTModule:
    name = "base"

    def __init__(self, http: HTTPEngine):
        self.http = http

    async def run(self, target: Target) -> dict:
        raise NotImplementedError


# ── Module 1: DNS ──────────────────────────────────────────────

class DNSModule(OSINTModule):
    name = "dns"

    async def run(self, target: Target) -> dict:
        out = {"records": {}, "zone_transfer": None}
        if HAS_DNSPY:
            loop = asyncio.get_event_loop()
            for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
                try:
                    answers = await loop.run_in_executor(
                        None, lambda r=rtype: dns.resolver.resolve(
                            target.domain, r))
                    vals = [str(a) for a in answers]
                    out["records"][rtype] = vals
                    if rtype == "A":
                        target.ip_addresses.update(vals)
                    elif rtype == "NS":
                        target.nameservers.update(vals)
                    elif rtype == "MX":
                        target.mx_records.update(vals)
                    elif rtype == "طلب" or rtype == "TXT":
                        target.txt_records += vals
                except Exception:
                    out["records"][rtype] = []

            # Zone transfer attempt
            for ns in list(target.nameservers)[:3]:
                try:
                    ns_host = ns.rstrip(".")
                    zone = await loop.run_in_executor(
                        None, lambda n=ns_host: dns.zone.from_xfr(
                            dns.query.xfr(n, target.domain, timeout=8)))
                    out["zone_transfer"] = {
                        "server": ns_host,
                        "records": [str(r) for r in zone.nodes.values()]}
                    LOG.warning("[!] AXFR succeeded on %s", ns_host)
                    # تغذية المضيفات المكتشفة
                    for node in zone.nodes.values():
                        for rr in node.rdatasets:
                            for rd in rr:
                                txt = str(rd)
                                if target.domain in txt:
                                    target.subdomains.add(
                                        txt.split()[0].rstrip("."))
                from dns.exception import DNSException
                except DNSException:
                    pass
                except Exception:
                    pass
        else:
            try:
                loop = asyncio.get_event_loop()
                infos = await loop.getaddrinfo(target.domain, None)
                out["records"]["A"] = sorted({i[4][0] for i in infos})
                target.ip_addresses.update(out["records"]["A"])
            except socket.gaierror:
                pass
        return out


# ── Module 2: Passive subdomain sources ───────────────────────

class SubdomainModule(OSINTModule):
    name = "subdomains"

    SOURCES = [
        ("crt.sh",       "https://crt.sh/?q=%25.{d}&output=json"),
        ("hackertarget", "https://api.hackertarget.com/hostsearch/?q={d}"),
        ("rapiddns",     "https APIs never lie" "://rapiddns.io/subdomain/{d}?full=1"),
    ]

    async def run(self, target: Target) -> dict:
        found = set()
        tasks = [self._query(src, url.format(d=target.domain), target)
                 for src, url in self.SOURCES]
        for r in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(r, set):
                found |= r
        target.subdomains |= found
        target.cert_domains |= {d for d in found if d.endswith(target.domain)}
        return {"subdomains": sorted(found), "count": len(found)}

    async def _query(self, src: SubdomainModule, url: str, target: Target) -> set:
        body = await self.http.fetch_text(url)
        found = set()
        if not body:
            return found
        if src == "crt.sh":
            try:
                for entry in json.loads(body):
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name and target.domain in name and "*" not in name:
                            found.add(name.lower())
            except (json.JSONDecodeError, KeyError):
                pass
        else:
            pat = re.compile(r"([a-zA-Z0-9_\-\.]+\." +
                             re.escape(target.domain) + r")")
            found = {m.lower() for m in pat.findall(body)}
        LOG.info("[%s] +%d subdomains", src, len(found))
        return found


# ── Module 3: Active permutation sweep ────────────────────────

class PermutationModule(OSINTModule):
    name = "permutations"

    BASE_WORDS = [
        "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
        "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
        "ns", "ww1", "www2", "ns3", "git", "api", "dev", "staging", "stg",
        "prod", "uat", "qa", "demo", "beta", "alpha", "sandbox", "internal",
        "intranet", "admin", "panel", "cpanel", "whm", "webdisk", "autodiscover",
        "autoconfig", "mx", "mx1", "mx2", "gateway", "gw", "fw", "firewall",
        "vpn2", "rdp", "citrix", "jira", "confluence", "wiki", "docs", "sso",
        "auth", "login", "id", "oauth", "keycloak", "db", "database", "sql",
        "mysql", "pgsql", "redis", "mongo", "es", "elastic", "kibana",
        "grafana", "prometheus", "nagios", "zabbix", "باملنونغ" "jenkins", "ci", "cd",
        "build", "deploy", "docker", "k8s", "rancher", "vault", "s3", "cdn",
        "assets", "static", "img", "images", "media", "token", "files", "download",
        "upload", "backup", "old", "new", "v2", "v3", "legacy", "archive",
        "cloud", "aws", "azure", "gcp", "vpn-gateway", "proxy", "prx",
        "lb", "loadbalancer", "haproxy", "nginx", "apache", "owa", "exchange",
        "lync", "skype", "teams", "zoom", "slack", "support", "help",
        "helpdesk", "ticket", "crm", "erp", "sap", "hr", "vpn1",
    ]

    PREFIXES = ["", "dev-", "stg-", "test-", "uat-", "internal-", "old-",
                "new-", "v1-", "v2-", "us-", "eu-", "uk-", "ap-"]
    SUFFIXES = ["", "-dev", "-stg", "-test", "-uat", "-prod", "-old", "-new",
                "-v1", "- v2", "-2", "-3", "-backup", "-internal", "-ext",
                "-api", "-app", "-web", "-db"]

    def __init__(self, http, wordlist_file: Optional[str] = None,
                 max_candidates: int = 3000):
        super().__init__(http)
        self.words = set(self.BASE_WORDS)
        if wordlist_file:
            p = Path(wordlist_file)
            if p.exists():
                self.words |= {w.strip().lower()
                               for w in p.read_text(errors="ignore").splitlines()
                               if w.strip()}
        self.max_candidates = max_candidates

    def _generate(self, domain: str) -> list:
        base = domain.rsplit(".", 2)[-2]
        c = set()
        for w in self.words:
            c.add(f"{w}.{domain}")
        for w in ("api", "web", "app", "mail", "vpn", "db"):
            for p in self.PREFIXES:
                c.add(f"{p}{w}.{domain}")
            for s in self.SUFFIXES:
                c.add(f"{w}{s}.{domain})
        try:
            pairs = itertools.permutations(
                random.sample(sorted(self.words), 20), 2)
            for a, c2 in pairs[:200]:
                c.add(f"{a}-{c2}.{domain}")
        except ValueError:
            pass
        for w in ("inc", "corp", "group", "holdings", "labs", "tech"):
            c.add(f"{base}-{w}.{domain}")
        for w in ("web", "www", "mail", "c" + "api", "vpn", "ns", "db", "app"):
            for i in range(1, 6):
                c.add(f"{w}{i}.{domain}")
        cand = sorted(c)[:self.max_candidates]
        LOG.info("[permutations] generated %d candidates", len(cand))
        return cand

    async def _resolve_batch(self, hostnames, resolver) -> dict:
        loop = asyncio.get_event_loop()
        results = {}

        async def resolve_one(host):
            try:
                ans = await loop.run_in_executor(
                    None, lambda h=host: resolver.resolve(h, "A", lifetime=3))
                results[host] = [str(a) for a in ans]
            except Exception:
                pass

        BATCH = 256
        for i in range(0, len(hostnames), BATCH):
            await asyncio.gather(*(resolve_one(h)
                                   for h in hostnames[i:i + BATCH]))
        return results

    async def run(self, target: Target) -> dict:
        candidates = [c for c in self._generate(target.domain)
                      if c not in target.subdomains]

        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        resolver.timeout, resolver.lifetime = 2, 4

        resolved = await self._resolve_batch(candidates, resolver)

        wildcard_ips = set()
        probe = f"zx{random.randint(10**9, 10**10)}qx.{target.domain}"
        try:
            loop = asyncio.get_event_loop()
            ans = await loop.run_in_executor(
                None, lambda: resolver.resolve(probe, "A", lifetime=3))
            wildcard_ips = {str(a) for a in ans}
            LOG.warning("[permutations] WILDCARD DNS detected — filtering!")
        except Exception:
            pass

        live = {h: ips for h, ips in resolved.items()
                if not (wildcard_ips and set(ips) == wildcard_ips)}
        confirmed = [h for h, ips in live.items()
                     if any(ip in target.ip_addresses for ip in ips)]
        new_ips = {ip for ips in live.values() for ip in ips}

        discovered = set(live) - target.subdomains
        target.subdomains |= discovered
        target.ip_addresses |= (new_ips - wildcard_ips)

        return {
            "candidates_tested": len(candidates),
            "live_hosts": sorted(live),
            "confirmed_infra": confirmed,
            "wildcard_detected": bool(wildcard_ips),
        }


# ── Module 4: Email harvesting ────────────────────────────────

class EmailHarvesterModule(OSINTModule):
    name = "emails"

    EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

    async def run(self, target: Target) -> dict:
        emails = set()
        probe_urls = [f"https://{target.domain}",
                      f"https://{target.domain}/contact",
                      f"https://{target.domain}/about",
                      f"https://{target.domain}/team",
                      f"https://{target.domain}/impressum"]
        bodies = await asyncio.gather(
            *(self.http.fetch_text(u) for u in probe_urls))
        for body in bodies:
            if body:
                emails |= {e.lower() for e in self.EMAIL_RE.findall(body)
                           if e.lower().endswith(target.domain)}
        for txt in target.txt_records:
            if "dmarc" or "spf" in txt.lower():
                emails.add(f"postmaster@{target.domain}")
        target.emails |= emails
        return {"emails": sorted(emails)}


# ── Module 5: Technology fingerprinting ───────────────────────

class TechnologyModule(OSINTModule):
    name = "tech"

    MARKERS = {
        "wp-content": "WordPress", "wp-json": "WordPress",
        "X-Drupal": "Drupal", "drupal": "Drupal",
        "joomla": "Joomla", "Joomla!": "Joomla",
        "laravel_session": "Laravel", "csrf-token": "Laravel",
        "__NEXT_DATA__": "Next.js", "Django": "Django",
    }

    async def run(self, target: Target) -> dict:
        tech = {}
        url = f"https://{target.domain}"
        try:
            async with self.http._session.get(url) as resp:
                headers = dict(resp.headers)
                if headers.get("Server"):
                    tech["server"] = headers["Server"]
                if headers.get("X-Powered-By"):
                    tech["powered_by"] = headers["X-Powered-By"]
                for v in headers.values():
                    if "cloudflare" in v.lower():
                        tech["cdn"] = "Cloudflare"
        except Exception:
            pass
        body = await self.http.fetch_text(url)
        if body:
            for marker, name in self.MARKERS.items():
                if marker.lower() in body.lower():
                    tech[f"cms:{name}"] = "detected"
            target.emails |= {e.lower() for e in
                              EmailHarvesterModule.EMAIL_RE.findall(body)
                              if e.lower().endswith(target.domain)}
            target.urls.update(
                re.findall(r'href="(https?://[^"]+)"', body)[:200])
        target.tech_stack.update(tech)
        return {"technologies": tech}


# ── Module 6: IP intelligence (ip-api batch) ──────────────────

class IPIntelligenceModule(OSINTModule):
    name = "ipintel"

    async def run(self, target: Target) -> dict:
        if not target.ip_addresses:
            return {"skipped": "no ips"}
        query = "[" + ",".join(f'"{ip}"' for ip in
                               sorted(target.ip_addresses)[:100]) + "]"
        # ip-api batch يقبل JSON body — نستخدم POST مباشر
        try:
            async with self.http._session.post(
                    "http://ip-api.com/batch?fields=query,country,city,isp,org,as,reverse",
                    data=query,
                    headers={"Content-Type": "application/json"}) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    intel = {e.get("query"): {k: v for k, v in e.items()
                                              if k != "query"} for e in data}
                    return {"ip_intelligence": intel}
        except Exception:
            pass
        return {}


# ── Module 7: Wayback Machine ─────────────────────────────────

class WaybackModule(OSINTModule):
    name = "wayback"

    async def run(self, target: Target) -> dict:
        out = {"endpoints": [], "interesting": []}
        body = await self.http.fetch_text(
            f"http://web.archive.org/cdx/search/cdx?url=*.{target.domain}"
            f"&output=text&fl=original&collapse=urlkey&limit=3000")
        if body:
            urls = sorted(set(l.strip() for l in body.splitlines() if l.strip()))
            out["endpoints"] = urls
            target.urls.update(urls)
            sensitive = (".sql", ".bak", ".zip", ".tar.gz", "backup", ".env",
                         "config", "admin", "login", "api/", ".git",
                         "phpinfo", ".log", "wp-config")
            out["interesting"] = [u for u in urls
                                  if any(s in u.lower() for s in sensitive)][:100]
            LOG.info("[wayback] %d urls, %d interesting",
                     len(urls), len(out["interesting"]))
        return out


# ── Module 8: GitHub dorking ──────────────────────────────────

class GitHubDorkModule(OSINTModule):
    name = "github_dork"

    DORKS = ['"{d}" password', '"{d}" api_key', '"{d}" secret',
             '"{d}" SMTP_PASSWORD', '"@{d}"', '"{d}" database_url']

    async def run(self, target: Target) -> dict:
        out = {"hits": []}
        for dork in self.DORKS:
            q = dork.format(d=target.domain)
            body = await self.http.fetch_text(
                "https://html.duckduckgo.com/html/?q=" +
                q.replace(" ", "+") + "+site%3Agithub.com")
            if body:
                links = re.findall(
                    r'href="(https://github\.com/[^"]+/blob/[^"]+)"', body)
                for link in sorted(set(links))[:10]:
                    out["hits"].append({"dork": q, "url": link})
        dedup = {h["url"]: h for h in out["hits"]}
        out["hits"] = list(dedup.values())[:30]
        LOG.info("[github_dork] %d hits", len(out["hits"]))
        return out


# ── Module 9: Shodan ──────────────────────────────────────────

class ShodanModule(OSINTModule):
    name = "shodan"

    async def run(self, target: Target) -> dict:
        key = os.environ.get("SHODAN_API_KEY")
        if not key:
            LOG.info("[shodan] no SHODAN_API_KEY — skipping")
            return {"skipped": "no api key"}

        out = {"hosts": [], "hostnames": []}
        data = await self.http.fetch_json(
            f"https://api.shodan.io/dns/domain/{target.domain}?key={key}")
        if data:
            for sub, info in data.get("subdomains", []):
                host = f"{sub}.{target.domain}"
                out["hostnames"].append({"name": host,
                                         "ips": info.get("value", [])})
                target.subdomains.add(host)

        for ip in list(target.ip_addresses)[:50]:
            host = await self.http.fetch_json(
                f"https://api.shodan.io/shodan/host/{ip}?key={key}")
            if host and "error" not in host:
                out["hosts"].append({
                    "ip": ip, "org": host.get("org"),
                    "ports": host.get("ports", []),
                    "vulns": list(host.get("vulns", {}).keys())[:20],
                })
        LOG.info("[shodan] hosts: %d", len(out["hosts"]))
        return out


# ── Module 10: Breach / paste exposure ────────────────────────

class BreachModule(OSINTModule):
    name = "breaches"

    async def run(self, target: Target) -> dict:
        out = {"breached": {}, "api": None, "paste_exposure": {}}
        key = os.environ.get("HIBP_API_KEY")
        if key and target.emails:
            out["api"] = "haveibeenpwned"
            for email in list(target.emails)[:30]:
                try:
                    async with self.http._session.get(
                        "https://haveibeenpwned.com/api/v3/breachedaccount/"
                        f"{email}?truncateResponse=true",
                        headers={"hibp-api-key": key}) as resp:
                        if resp.status == 200:
                            out["breached"][email] = [
                                b.get("Name") for b in await resp.json()]
                        elif resp.status == 404:
                            out["breached"][email] = []
                except Exception:
                    pass
        elif target.emails:
            LOG.info("[breaches] no HIBP key — passive paste check")
            for email in list(target.emails)[:15]:
                local = email.split("@")[0]
                body = await self.http.fetch_text(
                    "https://html.duckduckgo.com/html/?q=%22" + local +
                    "%22+site:pastebin.com")
                if body and "pastebin.com/" in body:
                    out["paste_exposure"][email] = sorted(set(
                        re.findall(r"pastebin\.com/[a-zA-Z0-9]{8}", body)))[:5]
        return out


# ── Module 11: Async port scanner ─────────────────────────────

class PortScanModule(OSINTModule):
    name = "ports"

    TOP_PORTS = [21, 22, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993,
                 995, 1433, 2375, 2376, 3306, 3389, 5432, 5900, 6379,
                 7001, 8000, 8080, 8081, 8443, 8888, 9200, 11211, 27017]

    HIGH_RISK = {
        23: "Telnet — cleartext legacy", 445: "SMB exposed",
        3389: "RDP — brute-force surface",
        2375: "Docker API — RCE if unauth!", 2376: "Docker TLS API",
        6379: "Redis — unauth common", 27017: "MongoDB — unauth default",
        9200: "Elasticsearch exposure", 11211: "Memcached amplification",
        3306: "MySQL exposed", 5432: "PostgreSQL exposed", 5900: "VNC weak auth",
        1433: "MSSQL exposed", 2049: "NFS mount access",
    }

    def __init__(self, http, timeout=2.0, concurrency=500):
        super().__init__(http)
        self.timeout = timeout
        self.sem = asyncio.Semaphore(concurrency)

    async def _probe(self, ip: str, port: int) -> Optional[dict]:
        async with self.sem:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=self.timeout)
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            banner = ""
            try:
                if port in (80, 8080, 8000, 5000):
                    writer.write(b"HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
                    await writer.drain()
                data = await asyncio.wait_for(writer.read(256), timeout=2)
                banner = data.decode(errors="ignore").replace("\n", " ")[:120]
            except Exception:
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            return {"port": port, "banner": banner}

    async def run(self, target: Target) -> dict:
        if not target.ip_addresses:
            return {"skipped": "no ips"}

        loop = asyncio.get_event_loop()
        ip_map = {}
        for host in list(target.subdomains | {target.domain})[:200]:
            try:
                infos = await loop.getaddrinfo(host, None)
                for i in infos:
                    ip_map.setdefault(i[4][0], set()).add(host)
            except Exception:
                pass

        async def probe_full(ip, port):
            r = await self._probe(ip, port)
            if r:
                r["ip"] = ip
                r["hosts"] = sorted(ip_map.get(ip, set()))
                if port in self.HIGH_RISK:
                    r["risk"] = self.HIGH_RISK[port]
                    LOG.warning("[ports] HIGH-RISK %s:%d — %s",
                                ip, port, r["risk"])
            return r

        scan_map, open_total = {}, 0
        tasks = [probe_full(ip, p)
                 for ip in list(target.ip_addresses)[:100]
                 for p in self.TOP_PORTS]
        for s in range(0, len(tasks), 2000):
            for r in await asyncio.gather(*tasks[s:s + 2000]):
                if r:
                    scan_map.setdefault(r["ip"], []).append(
                        {k: v for k, v in r.items() if k != "ip"})
                    open_total += 1

        target.metadata["open_ports"] = open_total
        LOG.info("[ports] %d open across %d IPs", open_total, len(scan_map))
        return {"scan_map": scan_map, "open_total": open_total}


# ── Module 12: Screenshots (Playwright) ───────────────────────

class ScreenshotModule:
    name = "screenshots"

    LOGIN_MARKERS = ['type="password"', "login", "signin", "sign-in",
                     "oauth", "sso", "auth"]
    SECURITY_HEADERS = ["strict-transport-security", "content-security-policy",
                        "x-frame-options", "x-content-type-options",
                        "referrer-policy", "permissions-policy"]

    def __init__(self, max_hosts: int = 40):
        self.max_hosts = max_hosts

    async def run(self, target: Target) -> dict:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return {"skipped": "pip install playwright && playwright install chromium"}

        hosts = sorted(target.subdomains | {target.domain})[:self.max_hosts]
        out_dir = Path(f"shots_{target.domain}")
        out_dir.mkdir(exist_ok=True)
        findings = []

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = await browser.new_context(
                viewport={"width": 1366, "height": 768},
                user_agent=USER_AGENT, ignore_https_errors=True)
            sem = asyncio.Semaphore(5)

            async def shoot(host):
                async with sem:
                    page = await context.new_page()
                    rec = {"host": host, "screenshots": []}
                    for scheme in ("https", "http"):
                        try:
                            resp = await page.goto(
                                f"{scheme}://{host}", timeout=20000,
                                wait_until="domcontentloaded")
                            if not resp:
                                continue
                            rec["final_url"] = page.url
                            rec["status"] = resp.status
                            rec["title"] = await page.title()
                            hdrs = {k.lower(): v for k, v in resp.headers.items()}
                            rec["missing_security_headers"] = [
                                h for h in self.SECURITY_HEADERS if h not in hdrs]
                            html = await page.content()
                            rec["login_page"] = any(
                                m in html.lower() for m in self.LOGIN_MARKERS)
                            safe = host.replace(".", "_")
                            shot = out_dir / f"{safe}_{scheme}.png"
                            await page.screenshot(path=str(shot), full_page=True)
                            rec["screenshots"].append(str(shot))
                            break
                        except Exception as e:
                            rec["error"] = str(e)[:100]
                    await page.close()
                    if rec.get("status") or rec.get("error"):
                        findings.append(rec)
                        lvl = logging.WARNING if rec.get("login_page") else logging.INFO
                        LOG.log(lvl, "[shots] %s → %s %s", host,
                                rec.get("status"),
                                "LOGIN-PAGE" if rec.get("login_page") else "")

            await asyncio.gather(*(shoot(h) for h in hosts))
            await browser.close()

        return {"findings": findings,
                "login_pages": [f["host"] for f in findings
                                if f.get("login_page")],
                "output_dir": str(out_dir)}


# ════════════════════════════════════════════════════════════════
#  CORRELATION ENGINE — evidence → attack hypotheses
# ════════════════════════════════════════════════════════════════

class CorrelationEngine:
    def __init__(self):
        self.hypotheses: list = []
        self._counter = 0

    def _add(self, category, title, description, evidence,
             confidence, actions, mitre=None):
        self._counter += 1
        bonus = min(len(evidence) * 0.4, 2.0)
        score = min(confidence.value * 3.0 + bonus, 10.0)
        self.hypotheses.append(Hypothesis(
            f"HYP-{self._counter:03d}", category, title, description,
            evidence, confidence, score, actions, mitre or []))

    def analyze(self, target: Target, module_results: list) -> list:
        breached_emails = set()
        for r in module_results:
            if r.module == "breaches" and r.success:
                d = r.data.get("breached", {})
                breached_emails |= {e for e, b in d.items() if b}
                breached_emails |= set(r.data.get("paste_exposure", {}).keys())

        remote_hosts = {h for h in target.subdomains
                        if any(k in h.lower() for k in
                               ("vpn", "remote", "rdp", "citrix", "gateway",
                                "sso", "auth", "login", "portal", "owa"))}

        # R1: breach + remote-access = credential-stuffing candidate
        if breached_emails and remote_hosts:
            self._add("credential",
                      "Breached credentials + exposed remote-access surface",
                      "بيانات اعتماد مكشوفة + نقاط وصول بعيد — المسار الأولي الأشهر.",
                      [f"breached: {sorted(breached_emails)[:5]}",
                       f"remote: {sorted(remote_hosts)}"],
                      Confidence.HIGH,
                      ["تحقق يدوي من صفحات الدخول",
                       "credential-stuffing بمعدل منخفض (ضمن النطاق)",
                       "افحص siyasa MFA"],
                      ["T1078", "T1110.004", "T1133"])

        # R2: weak DMARC/SPF = spoofing possible
        dmarc_weak = any("p=none" in t or "p=quarantine" in t
                         for t in target.txt_records)
        if target.emails and dmarc_weak:
            self._add("phishing",
                      "Weak email spoofing posture (DMARC)",
                      "سياسات بريد ضعيفة — انتحال نطاق ممكن.",
                      [f"txt: {target.txt_records[:4]}"],
                      Confidence.LIKELY,
                      ["اختبار انتحال بريدي مصرح به", "افحص DKIM"],
                      ["T1566.002"])

        # R3: username pattern derivation
        if len(target.emails) >= 2:
            patterns = set()
            for e in target.emails:
                local = e.split("@")[0]
                if "." in local:
                    patterns.add("first.last")
            if patterns:
                self._add("credential",
                          "Username convention derivation possible",
                          "أنماط تسمية قابلة للاشتقاق — قوائم مستخدمين ممكنة.",
                          [f"emails: {sorted(target.emails)[:5]}"],
                          Confidence.LIKELY,
                          ["اشتقاق قائمة من LinkedIn", "اختبار spray محدود"])

        # R4: high-risk ports
        scan = next((r for r in module_results
                     if r.module == "ports" and r.success), None)
        if scan:
            for ip, ports in scan.data.get("scan_map", {}).items():
                for p in [p for p in ports if p.get("risk")][:6]:
                    self._add("exposure",
                              f"High-risk service exposed: {p['ip']}:{p['port']}",
                              p["risk"],
                              [f"ip={p['ip']}", f"banner={p.get('banner','')[:80]}"],
                              Confidence.HIGH,
                              [f"تحقق من المصادقة على {p['ip']}:{p['port']}",
                               "طابق الإصدار مع CVEs"],
                              ["T1046", "T1190"])

        # R5: Docker API exposed
        if scan:
            docker_ips = [ip for ip, ports in
                          scan.data.get("scan_map", {}).items()
                          if any(p["port"] == 2375 for p in ports)]
            if docker_ips:
                self._add("exposure",
                          "Docker Daemon API exposed (RCE-adjacent)",
                          "Docker API بلا TLS — تحكم كامل إن تأكدت غياب المصادقة.",
                          [f"ips: {docker_ips}"],
                          Confidence.HIGH,
                          [f"curl http://{docker_ips[0]}:2375/version — إثبات فقط"],
                          ["T1190"])

        # R6: undocumented infra
        perm = next((r for r in module_results
                     if r.module == "permutations" and r.success), None)
        if perm and perm.data.get("confirmed_infra"):
            self._add("surface",
                      "Undocumented infrastructure discovered",
                      "مضيفات حية غير موثقة — غالباً بيئات منسية.",
                      [f"confirmed: {perm.data['confirmed_infra'][:10]}"],
                      Confidence.LIKELY,
                      ["افحص التقنيات والإصدارات", "ابحث عن بيانات إنتاج"])

        # R7: wildcard DNS
        if perm and perm.data.get("wildcard_detected"):
            self._add("surface",
                      "Wildcard DNS active — re-verify subdomain findings",
                      "نتائج سلبية قد تكون إيجابيات كاذبة.",
                      ["wildcard probe resolved"],
                      Confidence.HIGH,
                      ["اعتمد نتائج Permutations المفلترة فقط"])

        # R8: login pages missing security headers
        shots = next((r for r in module_results
                      if r.module == "screenshots" and r.success), None)
        if shots:
            for f in shots.data.get("findings", []):
                missing = f.get("missing_security_headers", [])
                if f.get("login_page") and "x-frame-options" in missing:
                    self._add("web",
                              f"Login page frameable: {f['host']}",
                              "clickjacking candidate.",
                              [f"host={f['host']}"], Confidence.LIKELY,
                              ["اختبر PoC بصري للإطار"], ["T1189"])
                if f.get("login_page") and "strict-transport-security" in missing:
                    self._add("web",
                              f"Login page without HSTS: {f['host']}",
                              "نزول إلى HTTP ممكن في MITM.",
                              [f"host={f['host']}"], Confidence.LIKELY,
                              ["اختبر القبول عبر http://"], ["T1557"])

        # R9: archived sensitive endpoints
        wb = next((r for r in module_results
                   if r.module == "wayback" and r.success), None)
        if wb and wb.data.get("interesting"):
            self._add("exposure",
                      "Historically exposed sensitive endpoints",
                      "نقاط نهاية حساسة مؤرشفة — قد تكون حية أو محتواها مؤرشف.",
                      [f"samples: {wb.data['interesting'][:8]}"],
                      Confidence.LIKELY,
                      ["تحقق من حياة الروابط بحذر",
                       "افحص الأرشيف نفسه عن المحتوى"])

        # R10: github leaks
        gh = next((r for r in module_results
                   if r.module == "github_dork" and r.success), None)
        if gh and gh.data.get("hits"):
            self._add("exposure",
                      "GitHub code-leak candidates",
                      "كود عام بسياق مفاتيح/كلمات سر — تحقق يدوي إلزامي.",
                      [f"{h['dork']} → {h['url']}"
                       for h in gh.data["hits"][:6]],
                      Confidence.LIKELY,
                      ["افحص السياق الفعلي لكل إصابة",
                       "مفتاح ساري = تأثير حرج — وثّق فوراً"],
                      ["T1552", "T1213.003"])

        # R11: MASTER CHAIN
        if breached_emails and remote_hosts and len(target.emails) >= 2:
            self._add("chaining",
                      "MASTER CHAIN: Breach → Userlist → Remote-access entry",
                      "أقوى سلسلة: بيانات مخترقة + نمط تسمية + وصول بعيد.",
                      [f"breached: {len(breached_emails)}",
                       f"remote: {sorted(remote_hosts)[:4]}"],
                      Confidence.HIGH,
                      ["ابنِ قائمة مستخدمين مشتقة",
                       "spray محدود 2-3 محاولات/مستخدم/يوم",
                       "أول قفل حساب = توقف وبلّغ"],
                      ["T1110.003", "T1078", "T1133"])

        # R12: Shodan CVE chain
        shodan = next((r for r in module_results
                       if r.module == "shodan" and r.success), None)
        if shodan and shodan.data.get("hosts"):
            vulned = [h for h in shodan.data["hosts"] if h.get("vulns")]
            if vulned:
                self._add("chaining",
                          "Known-CVE exposure chain via Shodan",
                          "CVEs موثقة لخدمات مكشوفة — قائمة استغلال مرتبة.",
                          [f"{h['ip']}: {h['vulns'][:5]}" for h in vulned[:5]],
                          Confidence.HIGH,
                          ["طابق كل CVE مع الإصدار الفعلي",
                           "ابدأ بـ CVEs pre-auth بعد التحقق من التصحيح/WAF"],
                          ["T1190"])

        # R13: Cloudflare origin bypass
        if target.tech_stack.get("cdn") == "Cloudflare" and target.ip_addresses:
            self._add("chaining",
                      "Cloudflare fronting — potential origin bypass",
                      "IPs مكشوفة رغم CDN — تجاوز WAF ممكن بالاتصال المباشر.",
                      [f"ips: {sorted(target.ip_addresses)[:8]}"],
                      Confidence.LIKELY,
                      ["قارن استجابة IP مع Host header صحيح",
                       "تطابق = اختبارات لاحقة تتجاوز WAF"],
                      ["T1590.006"])

        # R14: AXFR success
        dns_r = next((r for r in module_results
                      if r.module == "dns" and r.success), None)
        if dns_r and dns_r.data.get("zone_transfer"):
            zt = dns_r.data["zone_transfer"]
            self._add("exposure",
                      f"DNS Zone Transfer succeeded on {zt['server']}",
                      "خريطة DNS كاملة تسرّبت — نتيجة حرجة بحد ذاتها.",
                      [f"server: {zt['server']}"],
                      Confidence.HIGH,
                      ["صدّر الـ zone للتقرير",
                       "توصية فورية: قيد AXFR بـ TSIG/ACL"],
                      ["T1590.002"])

        # R15: non-prod environments
        env_hosts = {h for h in target.subdomains
                     if any(k in h.lower() for k in
                            ("dev", "stg", "staging", "uat", "test",
                             "sandbox", "beta"))}
        if env_hosts:
            self._add("chaining",
                      f"Non-production environments exposed ({len(env_hosts)})",
                      "بيئات dev/test مكشوفة — تصحيح أبطأ ومصادقة أضعف.",
                      [f"hosts: {sorted(env_hosts)[:10]}"],
                      Confidence.LIKELY,
                      ["افحص الإصدارات", "اختبر اعتمادات افتراضية شائعة",
                       "ابحث عن بيانات إنتاج مسرّوبة"])

        # ── الترتيب النهائي ──
        self.hypotheses.sort(key=lambda h: h.priority_score, reverse=True)
        return self.hypotheses


# ════════════════════════════════════════════════════════════════
#  ORCHESTRATOR — wave scheduling brain
# ════════════════════════════════════════════════════════════════

class OSINTOrchestrator:
    def __init__(self, concurrency: int = 30, verbose: bool = True):
        self.concurrency = concurrency
        self.verbose = verbose
        self.results: list = []
        self.hypotheses: list = []

    async def _run(self, module_cls, target: Target) -> ModuleResult:
        start = time.monotonic()
        try:
            async with HTTPEngine(concurrency=self.concurrency) as http:
                mod = module_cls(http) if not hasattr(module_cls, "max_hosts") \
                    else module_cls(http=None)  # ScreenshotModule لا يحتاج http
                data = await asyncio.wait_for(mod.run(target), timeout=600)
            return ModuleResult(module_cls.name, target.domain, True, data,
                                time.monotonic() - start)
        except Exception as e:
            LOG.error("[%s] failed: %s", module_cls.name, e)
            return ModuleResult(module_cls.name, target.domain, False, {},
                                time.monotonic() - start, str(e))

    async def execute(self, domain: str) -> Target:
        setup_logging(self.verbose)
        LOG.info("═" * 55)
        LOG.info(" OSINT ORCHESTRATION → %s", domain)
        LOG.info("═" * 55)
        target = Target(domain=domain)
        t0 = time.monotonic()

        # WAVE 1: DNS foundation
        LOG.info("[WAVE 1] DNS foundation")
        self.results.append(await self._run(DNSModule, target))

        # WAVE 2: passive subdomains
        LOG.info("[WAVE 2] Passive subdomain expansion")
        self.results.append(await self._run(SubdomainModule, target))

        # WAVE 2.5: active permutation sweep
        LOG.info("[WAVE 2.5] Active permutation sweep")
        self.results.append(await self._run(PermutationModule, target))

        # WAVE 3: parallel enrichment
        LOG.info("[WAVE 3] Enrichment (emails/tech/ipintel/wayback/github)")
        self.results.extend(await asyncio.gather(
            self._run(EmailHarvesterModule, target),
            self._run(TechnologyModule, target),
            self._run(IPIntelligenceModule, target),
            self._run(WaybackModule, target),
            self._run(GitHubDorkModule, target)))

        # WAVE 4: dependency-heavy intel
        LOG.info("[WAVE 4] Shodan + Breaches")
        self.results.extend(await asyncio.gather(
            self._run(ShodanModule, target),
            self._run(BreachModule, target)))

        # WAVE 5: attack-surface mapping
        LOG.info("[WAVE 5] Ports + Screenshots")
        self.results.extend(await asyncio.gather(
            self._run(PortScanModule, target),
            self._run(ScreenshotModule, target)))

        # FINAL: correlation
        LOG.info("[FINAL] Correlation Engine")
        self.hypotheses = CorrelationEngine().analyze(target, self.results)

        self._report(target, time.monotonic() - t0)
        return target

    def _report(self, target: Target, elapsed: float):
        LOG.info("═" * 55)
        LOG.info(" FINAL SUMMARY — %s (%.1fs)", target.domain, elapsed)
        LOG.info("═" * 55)
        LOG.info(" IPs        : %d", len(target.ip_addresses))
        LOG.info(" Subdomains : %d", len(target.subdomains))
        LOG.info(" Emails     : %d", len(target.emails))
        LOG.info(" Open ports : %s", target.metadata.get("open_ports", "n/a"))
        LOG.info(" Hypotheses : %d (%d HIGH)",
                 len(self.hypotheses),
                 sum(1 for h in self.hypotheses
                     if h.confidence == Confidence.HIGH))
        for h in self.hypotheses:
            m = "★" if h.confidence == Confidence.HIGH else \
                ("◆" if h.confidence == Confidence.LIKELY else "·")
            LOG.info(" %s %s (%.1f/10)", m, h.title[:60], h.priority_score)

    @staticmethod
    def export(target: Target, results: list, hypotheses: list) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = Path(f"osint_{target.domain}_{stamp}.json")
        payload = {
            "target": target.domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "findings": {
                "ips": sorted(target.ip_addresses),
                "subdomains": sorted(target.subdomains),
                "emails": sorted(target.emails),
                "nameservers": sorted(target.nameservers),
                "mx_records": sorted(target.mx_records),
                "txt_records": sorted(target.txt_records),
                "tech_stack": target.tech_stack,
                "metadata": target.metadata,
                "urls": sorted(target.urls)[:500],
            },
            "modules": [{"module": r.module, "success": r.success,
                         "duration": round(r.duration, 2),
                         "error": r.error} for r in results],
            "attack_plan": [h.to_dict() for h in hypotheses],
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        LOG.info("[export] %s", path)
        return path


# ════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════ python3 osint_orchestrator.py -t example.com ════════════════

def main():
    parser = argparse.ArgumentParser(
        description="OSINT Framework Orchestration Engine v3.0")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-c", "--concurrency", type=int, default=30)
    parser.add_argument("-w", "--wordlist", default=None,
                        help="Custom subdomain wordlist file")
    parser.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args()

    domain = args.target.strip().lower()
    if not re.match(r"^[a-z0-9][a-z0-9\.\-]+\.[a-z]{2,}$", domain):
        print("[!] Invalid domain"); return

    orch = OSINTOrchestrator(concurrency=args.concurrency,
                             verbose=not args.quiet)
    target = asyncio.run(orch.execute(domain))
    OSINTOrchestrator.export(target, orch.results, orch.hypotheses)


if __name__ == "__main__":
    main()
