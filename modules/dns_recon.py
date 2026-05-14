"""
VaktScan DNS recon module.

Exhaustive DNS attack-surface scan over a list of domains:

  - A / AAAA  records
  - MX        records  (mail-server fingerprint)
  - NS        records  (authoritative server fingerprint)
  - TXT       records  (general)
  - SPF       record   (presence + permissive `+all` / missing detection)
  - DMARC     record   (presence + permissive `p=none` detection)
  - DKIM      selectors (common selector list, presence detection)
  - SOA       record   (zone metadata)
  - CAA       record   (certificate authority authorization)
  - DNSKEY    record   (DNSSEC signed?)

  Per authoritative nameserver discovered:
  - AXFR zone transfer attempt    (full zone dump = CRITICAL)
  - version.bind CHAOS TXT        (BIND/PowerDNS banner)
  - Recursion-desired query test  (open-resolver = HIGH)

Findings use the canonical reporting schema (matches main.save_results_to_csv).

Implementation: pure-stdlib asyncio + a small DNS wire-format encoder/decoder.
No third-party dependency (so it works without dnspython vendored).
"""

import asyncio
import os
import random
import socket
import struct
import time
from typing import Any

MODULE_NAME = 'DNS'

# Public resolvers we use to look up authoritative nameservers when the
# target's own nameservers aren't yet known.
DEFAULT_RESOLVERS = ('1.1.1.1', '8.8.8.8', '9.9.9.9')

# Record-type constants.
RR_A = 1
RR_NS = 2
RR_CNAME = 5
RR_SOA = 6
RR_MX = 15
RR_TXT = 16
RR_AAAA = 28
RR_DNSKEY = 48
RR_CAA = 257
RR_ANY = 255
RR_AXFR = 252

QCLASS_IN = 1
QCLASS_CHAOS = 3

COMMON_DKIM_SELECTORS = (
    'default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'mail',
    'dkim', 'dkim1', 'cm', 'mailo', 'mta', 'sib', 's1', 's2', 'smtp',
)


# ─── DNS wire-format helpers (stdlib only) ────────────────────────────────────

def _encode_name(name: str) -> bytes:
    out = b''
    for label in name.rstrip('.').split('.'):
        if not label:
            continue
        b = label.encode('idna')
        out += bytes([len(b)]) + b
    return out + b'\x00'


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    parts = []
    while True:
        if offset >= len(data):
            return '.'.join(parts), offset
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            # Compressed pointer.
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            sub, _ = _decode_name(data, ptr)
            parts.append(sub)
            offset += 2
            return '.'.join(p for p in parts if p), offset
        offset += 1
        parts.append(data[offset:offset + length].decode('utf-8', errors='replace'))
        offset += length
    return '.'.join(parts), offset


def _build_query(name: str, qtype: int, qclass: int = QCLASS_IN, rd: bool = True) -> tuple[bytes, int]:
    tx_id = random.randint(0, 0xFFFF)
    flags = 0x0100 if rd else 0x0000  # RD=1 means recursion desired
    header = struct.pack('>HHHHHH', tx_id, flags, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack('>HH', qtype, qclass)
    return header + question, tx_id


def _parse_response(data: bytes) -> dict:
    if len(data) < 12:
        return {'error': 'short'}
    tx_id, flags, qd, an, ns, ar = struct.unpack('>HHHHHH', data[:12])
    rcode = flags & 0x000F
    aa = bool(flags & 0x0400)
    ra = bool(flags & 0x0080)
    tc = bool(flags & 0x0200)
    offset = 12
    for _ in range(qd):
        _, offset = _decode_name(data, offset)
        offset += 4  # qtype + qclass

    answers: list[dict] = []
    for _ in range(an):
        name, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlen = struct.unpack('>HHIH', data[offset:offset + 10])
        offset += 10
        rdata_raw = data[offset:offset + rdlen]
        rec = {'name': name, 'type': rtype, 'class': rclass, 'ttl': ttl}
        if rtype == RR_A and rdlen == 4:
            rec['data'] = '.'.join(str(b) for b in rdata_raw)
        elif rtype == RR_AAAA and rdlen == 16:
            rec['data'] = ':'.join(rdata_raw[i:i + 2].hex() for i in range(0, 16, 2))
        elif rtype == RR_CNAME:
            rec['data'], _ = _decode_name(data, offset)
        elif rtype == RR_NS:
            rec['data'], _ = _decode_name(data, offset)
        elif rtype == RR_MX:
            pref = struct.unpack('>H', rdata_raw[:2])[0]
            exchange, _ = _decode_name(data, offset + 2)
            rec['data'] = f'{pref} {exchange}'
        elif rtype == RR_TXT:
            txt_parts: list[str] = []
            sub_off = 0
            while sub_off < rdlen:
                slen = rdata_raw[sub_off]
                sub_off += 1
                txt_parts.append(rdata_raw[sub_off:sub_off + slen].decode('utf-8', errors='replace'))
                sub_off += slen
            rec['data'] = ''.join(txt_parts)
        elif rtype == RR_SOA:
            mname, soa_off = _decode_name(data, offset)
            rname, soa_off = _decode_name(data, soa_off)
            if soa_off + 20 <= len(data):
                serial, refresh, retry, expire, minimum = struct.unpack('>IIIII', data[soa_off:soa_off + 20])
                rec['data'] = f'{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}'
            else:
                rec['data'] = f'{mname} {rname}'
        elif rtype == RR_CAA and rdlen >= 2:
            flags_ = rdata_raw[0]
            tag_len = rdata_raw[1]
            tag = rdata_raw[2:2 + tag_len].decode('utf-8', errors='replace')
            value = rdata_raw[2 + tag_len:].decode('utf-8', errors='replace')
            rec['data'] = f'{flags_} {tag} "{value}"'
        elif rtype == RR_DNSKEY:
            rec['data'] = rdata_raw.hex()[:64]
        else:
            rec['data'] = rdata_raw.hex()[:128]
        offset += rdlen
        answers.append(rec)

    return {'rcode': rcode, 'aa': aa, 'ra': ra, 'tc': tc, 'answers': answers}


# ─── UDP / TCP transports ─────────────────────────────────────────────────────

class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, fut: 'asyncio.Future[bytes]'):
        self._fut = fut
        self._transport: Any = None

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data, addr):
        if not self._fut.done():
            self._fut.set_result(data)

    def error_received(self, exc):
        if not self._fut.done():
            self._fut.set_exception(exc)

    def connection_lost(self, exc):
        if exc and not self._fut.done():
            self._fut.set_exception(exc)


async def _udp_query(server: str, payload: bytes, timeout: float = 4.0) -> bytes:
    loop = asyncio.get_running_loop()
    fut: 'asyncio.Future[bytes]' = loop.create_future()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _UDPProtocol(fut), remote_addr=(server, 53)
    )
    try:
        transport.sendto(payload)
        return await asyncio.wait_for(fut, timeout=timeout)
    finally:
        transport.close()


async def _tcp_query(server: str, payload: bytes, timeout: float = 6.0) -> bytes:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(server, 53), timeout=timeout
    )
    try:
        framed = struct.pack('>H', len(payload)) + payload
        writer.write(framed)
        await writer.drain()
        length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        length = struct.unpack('>H', length_bytes)[0]
        return await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _query(server: str, name: str, qtype: int, qclass: int = QCLASS_IN, rd: bool = True, prefer_tcp: bool = False, timeout: float = 4.0) -> dict:
    payload, _ = _build_query(name, qtype, qclass, rd)
    try:
        if prefer_tcp:
            data = await _tcp_query(server, payload, timeout=timeout)
        else:
            try:
                data = await _udp_query(server, payload, timeout=timeout)
            except Exception:
                data = await _tcp_query(server, payload, timeout=timeout)
    except Exception as e:
        return {'error': str(e), 'answers': []}
    parsed = _parse_response(data)
    return parsed


# ─── AXFR (zone transfer) — multi-message TCP ────────────────────────────────

async def _try_axfr(server: str, zone: str, timeout: float = 8.0) -> list[dict]:
    """Return a list of answer records if AXFR succeeds, else []."""
    payload, _ = _build_query(zone, RR_AXFR, QCLASS_IN, rd=False)
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(server, 53), timeout=timeout)
    except Exception:
        return []
    try:
        writer.write(struct.pack('>H', len(payload)) + payload)
        await writer.drain()
        out: list[dict] = []
        # AXFR can come back as multiple messages until the trailing SOA.
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=deadline - time.time())
                length = struct.unpack('>H', length_bytes)[0]
                msg = await asyncio.wait_for(reader.readexactly(length), timeout=deadline - time.time())
            except Exception:
                break
            parsed = _parse_response(msg)
            out.extend(parsed.get('answers', []))
            # AXFR closes after the trailing SOA — stop when we see two SOAs.
            soa_count = sum(1 for a in out if a.get('type') == RR_SOA)
            if soa_count >= 2:
                break
        return out
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ─── Finding helper (canonical schema) ────────────────────────────────────────

def _finding(domain: str, status: str, severity: str, vulnerability: str, details: str, evidence: str = '') -> dict:
    return {
        'status': status,
        'severity': severity,
        'vulnerability': vulnerability,
        'details': details,
        'target': domain,
        'resolved_ip': 'N/A',
        'port': 53,
        'url': f'dns://{domain}',
        'payload_url': evidence or f'dns://{domain}',
        'module': MODULE_NAME,
        'service_version': 'N/A',
        'http_status': 'N/A',
        'page_title': 'N/A',
        'content_length': 'N/A',
        'server': domain,
    }


# ─── Per-domain checks ────────────────────────────────────────────────────────

async def check_basic_records(domain: str, resolver: str) -> tuple[list[dict], dict]:
    """Return (findings, recovered_records). recovered_records contains the
    A/MX/NS/SOA/TXT/CAA data we'll re-use in later checks."""
    findings: list[dict] = []
    recovered: dict[str, list[str]] = {'A': [], 'AAAA': [], 'MX': [], 'NS': [], 'TXT': [], 'CAA': [], 'SOA': [], 'DNSKEY': []}

    queries = [
        ('A',      RR_A),
        ('AAAA',   RR_AAAA),
        ('MX',     RR_MX),
        ('NS',     RR_NS),
        ('SOA',    RR_SOA),
        ('TXT',    RR_TXT),
        ('CAA',    RR_CAA),
        ('DNSKEY', RR_DNSKEY),
    ]
    for label, rtype in queries:
        resp = await _query(resolver, domain, rtype)
        if resp.get('error'):
            continue
        for ans in resp.get('answers', []):
            data = ans.get('data', '')
            if data:
                recovered[label].append(data)

    if not recovered['A'] and not recovered['AAAA']:
        findings.append(_finding(
            domain, 'INFO', 'INFO',
            f'No A/AAAA records for {domain}',
            f'Resolver {resolver} returned no address records. Domain may be MX/TXT-only or misconfigured.',
        ))

    if not recovered['CAA']:
        findings.append(_finding(
            domain, 'INFO', 'LOW',
            f'No CAA record published for {domain}',
            'Without a CAA record, any public CA can issue certificates for this domain.',
        ))

    if not recovered['DNSKEY']:
        findings.append(_finding(
            domain, 'INFO', 'LOW',
            f'DNSSEC not enabled for {domain}',
            'No DNSKEY records returned. Zone is not DNSSEC-signed; cache poisoning is easier.',
        ))

    return findings, recovered


def _spf_findings(domain: str, txt_records: list[str]) -> list[dict]:
    out: list[dict] = []
    spf_records = [t for t in txt_records if t.lower().startswith('v=spf1')]
    if not spf_records:
        out.append(_finding(
            domain, 'VULNERABLE', 'MEDIUM',
            f'SPF record missing on {domain}',
            'No "v=spf1" TXT record found. Anyone can spoof mail purporting to come from this domain.',
        ))
        return out
    if len(spf_records) > 1:
        out.append(_finding(
            domain, 'VULNERABLE', 'MEDIUM',
            f'Multiple SPF records on {domain}',
            f'RFC 7208 forbids multiple SPF records; mail receivers may reject mail entirely. Records: {spf_records}',
        ))
    spf = spf_records[0]
    if ' +all' in spf or spf.endswith('+all'):
        out.append(_finding(
            domain, 'VULNERABLE', 'HIGH',
            f'SPF "+all" allows any sender for {domain}',
            f'SPF record ends in +all: any host may send mail as @{domain}. Record: {spf}',
        ))
    elif ' ?all' in spf or spf.endswith('?all'):
        out.append(_finding(
            domain, 'INFO', 'LOW',
            f'SPF "?all" is neutral for {domain}',
            f'SPF policy is neutral (?all). Spoofing is not actively rejected. Record: {spf}',
        ))
    else:
        out.append(_finding(
            domain, 'INFO', 'INFO',
            f'SPF record present for {domain}',
            f'Record: {spf}',
        ))
    return out


async def check_dmarc(domain: str, resolver: str) -> list[dict]:
    resp = await _query(resolver, f'_dmarc.{domain}', RR_TXT)
    txts = [a['data'] for a in resp.get('answers', []) if a.get('data', '').lower().startswith('v=dmarc1')]
    if not txts:
        return [_finding(
            domain, 'VULNERABLE', 'MEDIUM',
            f'DMARC record missing on {domain}',
            'No "v=DMARC1" TXT record at _dmarc.<domain>. Mail spoofing detection / report channels are absent.',
        )]
    record = txts[0]
    findings: list[dict] = [_finding(
        domain, 'INFO', 'INFO',
        f'DMARC record present for {domain}',
        f'Record: {record}',
    )]
    if 'p=none' in record.lower():
        findings.append(_finding(
            domain, 'VULNERABLE', 'MEDIUM',
            f'DMARC policy is "p=none" on {domain}',
            'DMARC is in monitor-only mode; spoofed mail is not actively rejected or quarantined.',
        ))
    if 'sp=none' in record.lower():
        findings.append(_finding(
            domain, 'INFO', 'LOW',
            f'DMARC subdomain policy is "sp=none" on {domain}',
            'Subdomains inherit no-enforcement; subdomain spoofing remains possible.',
        ))
    return findings


async def check_dkim_selectors(domain: str, resolver: str) -> list[dict]:
    """Presence-only DKIM probe across common selectors."""
    found: list[str] = []
    for selector in COMMON_DKIM_SELECTORS:
        host = f'{selector}._domainkey.{domain}'
        resp = await _query(resolver, host, RR_TXT)
        for ans in resp.get('answers', []):
            data = ans.get('data', '')
            # DKIM identification requires the v=DKIM1 tag. Matching on
            # bare 'p=' or 'k=rsa' produced false positives on wildcard
            # DNS responses (e.g. unrelated TXT records carrying p=reject
            # from DMARC).
            if 'v=dkim1' in data.lower():
                found.append(selector)
                break
    if not found:
        return [_finding(
            domain, 'INFO', 'LOW',
            f'No common DKIM selectors found for {domain}',
            f'Probed selectors: {", ".join(COMMON_DKIM_SELECTORS)}. The domain may use a custom selector — check mail headers.',
        )]
    return [_finding(
        domain, 'INFO', 'INFO',
        f'DKIM selectors present on {domain}',
        f'Active selectors: {", ".join(found)}.',
    )]


async def check_nameservers(domain: str, nameservers: list[str]) -> list[dict]:
    """Per-nameserver: version.bind banner + AXFR + open recursion."""
    findings: list[dict] = []

    for ns_name in nameservers:
        # Resolve NS to an IP so we can hit it directly.
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(ns_name.rstrip('.'), 53)
            ns_ip = next((i[4][0] for i in infos if i[0] == socket.AF_INET), None)
        except Exception:
            ns_ip = None
        if not ns_ip:
            continue

        # version.bind CHAOS TXT
        try:
            ver_resp = await _query(ns_ip, 'version.bind', RR_TXT, qclass=QCLASS_CHAOS, rd=False, timeout=4.0)
            for ans in ver_resp.get('answers', []):
                data = ans.get('data', '')
                if data:
                    findings.append(_finding(
                        domain, 'INFO', 'LOW',
                        f'Nameserver version banner ({ns_name})',
                        f'CHAOS TXT version.bind returned {data!r} from {ns_ip}. Known-version banner aids attacker fingerprinting.',
                        evidence=f'dns://{ns_ip}',
                    ))
        except Exception:
            pass

        # Open recursion test — query an unrelated zone with RD=1.
        try:
            rec_resp = await _query(ns_ip, 'example.com', RR_A, rd=True, timeout=4.0)
            if rec_resp.get('ra') and rec_resp.get('answers'):
                findings.append(_finding(
                    domain, 'VULNERABLE', 'HIGH',
                    f'Open recursive resolver on {ns_name}',
                    f'Nameserver {ns_ip} answered recursive A query for example.com with RA=1. Can be abused for DNS amplification attacks.',
                    evidence=f'dns://{ns_ip}',
                ))
        except Exception:
            pass

        # AXFR
        try:
            axfr = await _try_axfr(ns_ip, domain, timeout=6.0)
            if axfr:
                findings.append(_finding(
                    domain, 'CRITICAL', 'CRITICAL',
                    f'AXFR zone transfer allowed on {ns_name}',
                    f'AXFR against {ns_ip} returned {len(axfr)} records. Full zone contents (hosts, subdomains, mail config) exposed.',
                    evidence=f'dns://{ns_ip}',
                ))
        except Exception:
            pass

    return findings


def _wildcard_findings(domain: str, txt_records: list[str], a_records: list[str]) -> list[dict]:
    """Heuristic wildcard hint — for each NS-style domain we'd usually need a
    separate probe; surface a quick signal when TXT mentions wildcards."""
    out: list[dict] = []
    for t in txt_records:
        if '*' in t and 'spf1' not in t.lower():
            out.append(_finding(
                domain, 'INFO', 'LOW',
                f'TXT record contains wildcard-style entry for {domain}',
                f'TXT: {t}. Verify whether the zone uses wildcard records (a likely auto-cPanel default).',
            ))
            break
    return out


# ─── Orchestrator ─────────────────────────────────────────────────────────────

async def scan_domain(domain: str, resolver: str = DEFAULT_RESOLVERS[0]) -> list[dict]:
    findings: list[dict] = []
    base, recovered = await check_basic_records(domain, resolver)
    findings.extend(base)
    findings.extend(_spf_findings(domain, recovered.get('TXT', [])))
    findings.extend(await check_dmarc(domain, resolver))
    findings.extend(await check_dkim_selectors(domain, resolver))
    findings.extend(_wildcard_findings(domain, recovered.get('TXT', []), recovered.get('A', [])))

    # NS records — strip the trailing dot before passing them in.
    nameservers = sorted({ns.rstrip('.') for ns in recovered.get('NS', []) if ns})
    if nameservers:
        findings.append(_finding(
            domain, 'INFO', 'INFO',
            f'Authoritative nameservers for {domain}',
            'Nameservers: ' + ', '.join(nameservers),
        ))
        findings.extend(await check_nameservers(domain, nameservers))
    return findings


async def run_dns_recon(domains: list[str], resolver: str = DEFAULT_RESOLVERS[0], concurrency: int = 20) -> list[dict]:
    sem = asyncio.Semaphore(max(1, concurrency))
    out: list[dict] = []

    async def worker(d: str):
        async with sem:
            try:
                findings = await scan_domain(d, resolver)
                out.extend(findings)
            except Exception:
                pass

    print(f"[*] DNS recon over {len(domains)} domain(s) using resolver {resolver}...")
    await asyncio.gather(*(worker(d) for d in domains))
    return out


# ─── Public entry point matching VaktScan module convention ──────────────────

async def run(domains: list[str], resolver: str = DEFAULT_RESOLVERS[0], concurrency: int = 20) -> list[dict]:
    """Compat shim: same signature shape callers expect from sibling modules."""
    return await run_dns_recon(domains, resolver=resolver, concurrency=concurrency)
