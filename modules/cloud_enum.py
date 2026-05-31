"""
VaktScan cloud asset enumeration module.

Permutation-based bucket/storage enumeration for:
  - AWS S3 (s3.amazonaws.com)
  - Azure Blob Storage (blob.core.windows.net)
  - GCP Google Cloud Storage (storage.googleapis.com)

No API keys required — pure public HTTP probes.
"""

import asyncio
import ipaddress
import json
import re
import socket
from typing import Any

import httpx

MODULE_NAME = 'cloud_enum'

_TIMEOUT = httpx.Timeout(5.0, connect=5.0)

# ─── Finding helper ────────────────────────────────────────────────────────────

def _finding(
    status: str,
    severity: str,
    vulnerability: str,
    details: str,
    host: str,
    url: str,
    payload_url: str = '',
    resolved_ip: str = '',
) -> dict:
    return {
        'status': status,
        'severity': severity,
        'vulnerability': vulnerability,
        'details': details,
        'target': host,
        'resolved_ip': resolved_ip or '',
        'port': 443,
        'url': url,
        'payload_url': payload_url or url,
        'module': MODULE_NAME,
        'service_version': 'N/A',
        'http_status': 'N/A',
        'page_title': 'N/A',
        'content_length': 'N/A',
    }


# ─── Permutation generator ─────────────────────────────────────────────────────

def _permutations(domain: str) -> list[str]:
    """
    Return a deduplicated list of bucket-name candidates derived from *domain*.
    Dots are replaced with hyphens so names are valid S3/Azure/GCS identifiers.
    """
    base = domain.replace('.', '-').lower()
    # Also produce a short base (first label only) for e.g. "example" from "example.com"
    first = domain.split('.')[0].lower()

    raw = [
        domain,                     # original (dots kept for uniqueness check, replaced below)
        f'www-{base}',
        f'{base}-backup',
        f'{base}-assets',
        f'{base}-static',
        f'{base}-data',
        f'{base}-files',
        f'{base}-logs',
        f'{base}-dev',
        f'{base}-staging',
        f'{base}-prod',
        f'backup-{base}',
        f'assets-{base}',
        f'static-{base}',
        f'{first}-backup',
        f'{first}-assets',
        f'{first}-static',
        f'{first}-data',
        f'{first}-dev',
        f'{first}-staging',
        f'{first}-prod',
        f'backup-{first}',
        f'assets-{first}',
        f'static-{first}',
        first,
        base,
    ]

    seen: set[str] = set()
    out: list[str] = []
    for name in raw:
        # Ensure the permutation is a valid bucket label (replace dots with hyphens,
        # lowercase, strip leading/trailing hyphens)
        name = name.replace('.', '-').lower().strip('-')
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


# ─── SSRF / metadata endpoint helper ──────────────────────────────────────────

def _resolves_to_metadata_ip(domain: str) -> bool:
    """Return True if *domain* resolves to the link-local metadata IP 169.254.169.254."""
    try:
        addr = socket.gethostbyname(domain)
        return ipaddress.ip_address(addr) == ipaddress.ip_address('169.254.169.254')
    except Exception:
        return False


# ─── AWS S3 ────────────────────────────────────────────────────────────────────

async def _probe_s3_bucket(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    domain: str,
    perm: str,
) -> list[dict]:
    """Probe two S3 URL styles for a single permutation and return findings."""
    urls = [
        f'https://{perm}.s3.amazonaws.com/',
        f'https://s3.amazonaws.com/{perm}/',
    ]
    findings: list[dict] = []

    for url in urls:
        try:
            async with sem:
                r = await client.get(url)
        except Exception:
            continue

        if r.status_code == 200:
            # Try to extract a snippet of visible content for context
            snippet = r.text[:300].strip() if r.text else ''
            findings.append(_finding(
                status='VULNERABLE',
                severity='HIGH',
                vulnerability='S3 Bucket Publicly Readable',
                details=(
                    f'S3 bucket "{perm}" is publicly accessible and lists/returns content. '
                    f'Snippet: {snippet!r}'
                ),
                host=domain,
                url=url,
                payload_url=url,
            ))
        elif r.status_code == 403:
            findings.append(_finding(
                status='INFO',
                severity='INFO',
                vulnerability='S3 Bucket Exists (Access Denied)',
                details=(
                    f'S3 bucket "{perm}" exists but access is denied (HTTP 403). '
                    f'Bucket is private but confirms infrastructure footprint.'
                ),
                host=domain,
                url=url,
                payload_url=url,
            ))
        # 404 → bucket doesn't exist; skip

    return findings


async def _enumerate_s3(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    domain: str,
) -> list[dict]:
    findings: list[dict] = []

    # SSRF metadata check
    if _resolves_to_metadata_ip(domain):
        findings.append(_finding(
            status='VULNERABLE',
            severity='CRITICAL',
            vulnerability='EC2 Metadata SSRF Indicator',
            details=(
                f'Domain "{domain}" resolves to 169.254.169.254 (EC2 instance metadata endpoint). '
                f'This may indicate a Server-Side Request Forgery (SSRF) vulnerability allowing '
                f'credential theft via the metadata API.'
            ),
            host=domain,
            url=f'http://169.254.169.254/latest/meta-data/',
            payload_url=f'http://169.254.169.254/latest/meta-data/',
        ))

    perms = _permutations(domain)
    tasks = [_probe_s3_bucket(client, sem, domain, p) for p in perms]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    # Deduplicate by (vulnerability, url)
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for f in findings:
        key = (f['vulnerability'], f['url'])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


# ─── Azure Blob Storage ────────────────────────────────────────────────────────

async def _probe_azure_blob(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    domain: str,
    perm: str,
) -> list[dict]:
    """Probe Azure Blob storage account URLs for a single permutation."""
    urls = [
        f'https://{perm}.blob.core.windows.net/{perm}/',
        f'https://{perm}.blob.core.windows.net/',
    ]
    findings: list[dict] = []

    for url in urls:
        try:
            async with sem:
                r = await client.get(url)
        except Exception:
            continue

        if r.status_code == 200:
            findings.append(_finding(
                status='VULNERABLE',
                severity='HIGH',
                vulnerability='Azure Blob Container Publicly Readable',
                details=(
                    f'Azure Blob storage account "{perm}" is publicly accessible '
                    f'and returns content (HTTP 200).'
                ),
                host=domain,
                url=url,
                payload_url=url,
            ))
        elif r.status_code in (400, 403):
            body = r.text or ''
            if any(kw in body for kw in ('BlobAccessTierNotSupported', 'PublicAccessNotPermitted',
                                          'AuthorizationFailure', 'StorageAccountAlreadyExists',
                                          'BlobServiceProperties', 'InvalidResourceName',
                                          'ResourceNotFound', 'ContainerNotFound',
                                          'AccountNameInvalid')):
                # Any Azure-specific XML error means the storage account exists
                findings.append(_finding(
                    status='INFO',
                    severity='INFO',
                    vulnerability='Azure Blob Container Exists (Private)',
                    details=(
                        f'Azure Blob storage account "{perm}" exists but access is restricted '
                        f'(HTTP {r.status_code}). Confirms cloud infrastructure footprint.'
                    ),
                    host=domain,
                    url=url,
                    payload_url=url,
                ))

    return findings


async def _check_azure_ad_tenant(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    domain: str,
) -> list[dict]:
    """Check whether domain has an Azure AD tenant via OIDC discovery endpoint."""
    url = f'https://login.microsoftonline.com/{domain}/.well-known/openid-configuration'
    try:
        async with sem:
            r = await client.get(url)
    except Exception:
        return []

    if r.status_code != 200:
        return []

    try:
        data = r.json()
    except Exception:
        return []

    # Extract tenant ID from issuer URI, e.g.
    # "https://sts.windows.net/{tenant_id}/"
    tenant_id = ''
    issuer = data.get('issuer', '')
    m = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', issuer, re.I)
    if m:
        tenant_id = m.group(0)

    if not tenant_id:
        # Fall back: look anywhere in the JSON blob
        m = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                      r.text, re.I)
        if m:
            tenant_id = m.group(0)

    if tenant_id:
        return [_finding(
            status='INFO',
            severity='INFO',
            vulnerability='Azure AD Tenant Discovered',
            details=(
                f'Azure AD tenant for domain "{domain}" discovered. '
                f'Tenant ID: {tenant_id}. '
                f'This confirms the organisation uses Microsoft 365 / Azure AD.'
            ),
            host=domain,
            url=url,
            payload_url=url,
        )]
    return []


async def _enumerate_azure(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    domain: str,
) -> list[dict]:
    findings: list[dict] = []

    perms = _permutations(domain)
    blob_tasks = [_probe_azure_blob(client, sem, domain, p) for p in perms]
    tenant_task = _check_azure_ad_tenant(client, sem, domain)

    all_tasks = blob_tasks + [tenant_task]
    results = await asyncio.gather(*all_tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    # Deduplicate
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for f in findings:
        key = (f['vulnerability'], f['url'])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


# ─── GCP Cloud Storage ─────────────────────────────────────────────────────────

async def _probe_gcs_bucket(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    domain: str,
    perm: str,
) -> list[dict]:
    """Probe GCS bucket URLs for a single permutation."""
    urls = [
        f'https://storage.googleapis.com/{perm}/',
        f'https://{perm}.storage.googleapis.com/',
    ]
    findings: list[dict] = []

    for url in urls:
        try:
            async with sem:
                r = await client.get(url)
        except Exception:
            continue

        if r.status_code == 200:
            snippet = r.text[:300].strip() if r.text else ''
            findings.append(_finding(
                status='VULNERABLE',
                severity='HIGH',
                vulnerability='GCS Bucket Publicly Readable',
                details=(
                    f'GCS bucket "{perm}" is publicly accessible and returns content (HTTP 200). '
                    f'Snippet: {snippet!r}'
                ),
                host=domain,
                url=url,
                payload_url=url,
            ))
        elif r.status_code == 403:
            findings.append(_finding(
                status='INFO',
                severity='INFO',
                vulnerability='GCS Bucket Exists (Access Denied)',
                details=(
                    f'GCS bucket "{perm}" exists but access is denied (HTTP 403). '
                    f'Bucket is private but confirms infrastructure footprint.'
                ),
                host=domain,
                url=url,
                payload_url=url,
            ))
        # 404 → bucket does not exist; skip

    return findings


async def _enumerate_gcs(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    domain: str,
) -> list[dict]:
    findings: list[dict] = []

    # GCP metadata SSRF check (same endpoint as AWS)
    if _resolves_to_metadata_ip(domain):
        findings.append(_finding(
            status='VULNERABLE',
            severity='CRITICAL',
            vulnerability='GCP Metadata SSRF Indicator',
            details=(
                f'Domain "{domain}" resolves to 169.254.169.254 (GCP instance metadata endpoint). '
                f'This may indicate a Server-Side Request Forgery (SSRF) vulnerability allowing '
                f'credential theft via the metadata API.'
            ),
            host=domain,
            url='http://169.254.169.254/computeMetadata/v1/',
            payload_url='http://169.254.169.254/computeMetadata/v1/',
        ))

    perms = _permutations(domain)
    tasks = [_probe_gcs_bucket(client, sem, domain, p) for p in perms]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    # Deduplicate
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for f in findings:
        key = (f['vulnerability'], f['url'])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


# ─── Public entry point ────────────────────────────────────────────────────────

async def enumerate_cloud_assets(domain: str, concurrency: int = 50) -> list[dict]:
    """
    Enumerate publicly accessible cloud storage assets for *domain*.

    Probes AWS S3, Azure Blob Storage, and GCP GCS using permutation-based
    bucket names derived from the domain. No API keys required.

    Returns a list of finding dicts in VaktScan canonical format.
    """
    sem = asyncio.Semaphore(concurrency)

    # Follow redirects so virtual-hosted S3 URLs that redirect are handled,
    # but cap at 3 to avoid redirect loops.
    transport = httpx.AsyncHTTPTransport(retries=0)
    async with httpx.AsyncClient(
        timeout=_TIMEOUT,
        follow_redirects=True,
        max_redirects=3,
        verify=False,          # many cloud endpoints have valid certs, but avoid failures on edge cases
        transport=transport,
        headers={'User-Agent': 'VaktScan/1.0 cloud-enum'},
    ) as client:
        s3_task    = _enumerate_s3(client, sem, domain)
        azure_task = _enumerate_azure(client, sem, domain)
        gcs_task   = _enumerate_gcs(client, sem, domain)

        s3_findings, azure_findings, gcs_findings = await asyncio.gather(
            s3_task, azure_task, gcs_task, return_exceptions=True
        )

    all_findings: list[dict] = []
    for bucket in (s3_findings, azure_findings, gcs_findings):
        if isinstance(bucket, list):
            all_findings.extend(bucket)

    return all_findings
