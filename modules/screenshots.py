"""
VaktScan Screenshots Module

Visual triage of alive web hosts.

Captures screenshots of alive URLs using ``gowitness`` (preferred) or
``aquatone`` (fallback). Tools are detected with :func:`shutil.which`; if
neither is installed the module skips gracefully (one info line, returns ``[]``)
and never attempts to install anything.

Screenshots are written under ``<output_dir>/screenshots/`` together with a
simple manifest (``manifest.csv`` and ``index.html``) mapping each URL to its
screenshot file. Canonical INFO findings are emitted via
:func:`modules.schema.normalize_finding`, one per captured URL plus a summary.

The public entry point is :func:`capture_screenshots`. It is defensive by
design: empty input, a missing tool, or a failing tool run all result in a
graceful skip rather than a crash.
"""

import asyncio
import csv
import html
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone

from modules.progress import heartbeat
from modules.schema import normalize_finding

MODULE_NAME = "screenshots"

# ANSI colours, matching the conventions used across the other modules.
_CYAN = "\033[96m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_GRAY = "\033[90m"
_RESET = "\033[0m"

_IMAGE_EXTS = (".png", ".jpeg", ".jpg", ".webp", ".gif")

# Ordered preference: gowitness first, aquatone as a fallback.
_TOOLS = ("gowitness", "aquatone")


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _norm(text):
    """Lowercase and strip everything but ``[a-z0-9]`` for fuzzy comparison."""
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def _resolve_tool():
    """Return ``(name, binary_path)`` for the first available screenshot tool.

    An explicit override may be supplied via ``VAKT_GOWITNESS_BIN`` /
    ``VAKT_AQUATONE_BIN``. Returns ``(None, None)`` if neither tool is present.
    """
    for name in _TOOLS:
        override = os.environ.get(f"VAKT_{name.upper()}_BIN")
        if override:
            expanded = os.path.expanduser(override)
            if os.path.isabs(expanded) and os.path.exists(expanded):
                return name, expanded
        path = shutil.which(name)
        if path:
            return name, path
    return None, None


def _host_of(url):
    rest = re.sub(r"^\w+://", "", (url or "").strip())
    hostport = rest.split("/", 1)[0]
    return hostport.split(":", 1)[0] or (url or "").strip()


def _url_keys(url):
    """Ordered candidate match keys for a URL, most specific first.

    e.g. ``https://example.com:8443/x`` ->
    ``["httpsexamplecom8443", "httpsexamplecom", "examplecom8443", "examplecom"]``
    """
    u = (url or "").strip()
    m = re.match(r"^(\w+)://(.*)$", u)
    scheme, rest = (m.group(1), m.group(2)) if m else ("", u)
    hostport = rest.split("/", 1)[0]
    host = hostport.split(":", 1)[0]

    candidates = []
    if scheme:
        candidates.append(_norm(scheme + hostport))
        candidates.append(_norm(scheme + host))
    candidates.append(_norm(hostport))
    candidates.append(_norm(host))

    seen, ordered = set(), []
    for key in candidates:
        if key and key not in seen:
            seen.add(key)
            ordered.append(key)
    return ordered


def _list_images(shots_dir):
    """Recursively list image files under ``shots_dir`` (aquatone nests them)."""
    found = []
    for root, _dirs, files in os.walk(shots_dir):
        for name in files:
            if name.lower().endswith(_IMAGE_EXTS):
                found.append(os.path.join(root, name))
    return sorted(found)


def _map_urls_to_images(urls, images):
    """Best-effort ``url -> image_path`` mapping; each image used at most once.

    Matching is tolerant of the differing filename schemes gowitness and
    aquatone use across versions (dashes, underscores, hashes). Unmatched URLs
    map to ``None`` unless a clean 1:1 leftover assignment is possible.
    """
    stems = [(img, _norm(os.path.splitext(os.path.basename(img))[0])) for img in images]
    used = set()
    mapping = {}

    for url in urls:
        match = None
        for key in _url_keys(url):
            # Prefer an exact stem match before falling back to a substring one.
            for img, stem in stems:
                if img not in used and stem == key:
                    match = img
                    break
            if match:
                break
            for img, stem in stems:
                if img not in used and key and key in stem:
                    match = img
                    break
            if match:
                break
        if match:
            used.add(match)
        mapping[url] = match

    # If exactly as many images went unmatched as URLs, assume a 1:1 ordering
    # (covers hash-only filenames that carry no host token to match against).
    leftover_urls = [u for u in urls if mapping[u] is None]
    leftover_imgs = [img for img, _stem in stems if img not in used]
    if leftover_urls and len(leftover_urls) == len(leftover_imgs):
        for url, img in zip(leftover_urls, leftover_imgs):
            mapping[url] = img

    return mapping


# --------------------------------------------------------------------------- #
# Tool drivers
# --------------------------------------------------------------------------- #
async def _run_cmd(cmd, stdin_data=None, timeout=600):
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    payload = stdin_data.encode() if stdin_data is not None else None
    stdout, stderr = await asyncio.wait_for(proc.communicate(input=payload), timeout=timeout)
    return proc.returncode, stdout, stderr


def _gowitness_variants(binary, urls_file, shots_dir, concurrency):
    """Candidate command lines for the (incompatible) gowitness CLI versions.

    Modern (v3+):  ``gowitness scan file -f <file> --screenshot-path <dir>``
    Legacy (v2):   ``gowitness file -f <file> -P <dir>``

    Each is tried with and without the ``--threads`` flag so that a version
    which rejects the flag still gets a chance to run.
    """
    threads = str(max(1, int(concurrency)))
    return [
        [binary, "scan", "file", "-f", urls_file, "--screenshot-path", shots_dir, "--threads", threads],
        [binary, "scan", "file", "-f", urls_file, "--screenshot-path", shots_dir],
        [binary, "file", "-f", urls_file, "-P", shots_dir, "--threads", threads],
        [binary, "file", "-f", urls_file, "-P", shots_dir],
    ]


async def _capture_gowitness(binary, urls_file, shots_dir, concurrency):
    """Run gowitness, trying each CLI variant until screenshots appear."""
    before = set(_list_images(shots_dir))
    errors = []
    for cmd in _gowitness_variants(binary, urls_file, shots_dir, concurrency):
        try:
            rc, _out, err = await _run_cmd(cmd)
        except Exception as exc:  # noqa: BLE001 - defensive: skip on any failure
            errors.append(str(exc))
            continue
        after = set(_list_images(shots_dir))
        if after - before:
            return sorted(after)
        if rc not in (0, None) and err:
            tail = err.decode(errors="replace").strip().splitlines()
            if tail:
                errors.append(tail[-1])
    if errors:
        print(f"{_GRAY}[!] gowitness produced no screenshots: {errors[-1]}{_RESET}")
    return sorted(before)


async def _capture_aquatone(binary, urls, shots_dir, concurrency):
    """Run aquatone, which reads target URLs from stdin."""
    before = set(_list_images(shots_dir))
    cmd = [binary, "-out", shots_dir, "-threads", str(max(1, int(concurrency))), "-silent"]
    try:
        await _run_cmd(cmd, stdin_data="\n".join(urls) + "\n")
    except Exception as exc:  # noqa: BLE001 - defensive: skip on any failure
        print(f"{_GRAY}[!] aquatone failed: {exc}{_RESET}")
    return sorted(set(_list_images(shots_dir)))


# --------------------------------------------------------------------------- #
# Manifest writers
# --------------------------------------------------------------------------- #
def _write_manifest_csv(path, shots_dir, mapping):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "screenshot"])
        for url, img in mapping.items():
            rel = os.path.relpath(img, shots_dir) if img else ""
            writer.writerow([url, rel])


def _write_index_html(path, shots_dir, mapping, tool_name):
    captured = sum(1 for img in mapping.values() if img)
    cards = []
    for url, img in mapping.items():
        safe_url = html.escape(url)
        if img:
            rel = html.escape(os.path.relpath(img, shots_dir))
            body = f'<a href="{rel}" target="_blank"><img src="{rel}" loading="lazy" alt="{safe_url}"></a>'
        else:
            body = '<div class="missing">no screenshot captured</div>'
        cards.append(
            f'<figure class="card"><figcaption><a href="{safe_url}" target="_blank">'
            f"{safe_url}</a></figcaption>{body}</figure>"
        )
    document = (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>VaktScan Screenshots</title><style>"
        "body{font-family:system-ui,sans-serif;margin:1.5rem;background:#111;color:#eee}"
        "h1{font-size:1.2rem}"
        ".grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:1rem}"
        ".card{margin:0;background:#1c1c1c;border:1px solid #333;border-radius:6px;overflow:hidden}"
        ".card img{width:100%;height:auto;display:block}"
        ".card figcaption{padding:.5rem;font-size:.8rem;word-break:break-all;border-bottom:1px solid #333}"
        ".card a{color:#6cb6ff;text-decoration:none}"
        ".missing{padding:2rem;text-align:center;color:#888}"
        "</style></head><body>"
        f"<h1>VaktScan Screenshots &mdash; {captured}/{len(mapping)} captured "
        f"via {html.escape(tool_name)}</h1>"
        f'<div class="grid">{"".join(cards)}</div>'
        "</body></html>\n"
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(document)


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
def _screenshot_finding(url, screenshot_rel, tool_name):
    return normalize_finding({
        "status": "INFO",
        "severity": "INFO",
        "vulnerability": "Web Service Screenshot Captured",
        "target": _host_of(url),
        "url": url,
        "payload_url": screenshot_rel,
        "module": MODULE_NAME,
        "details": f"Screenshot captured with {tool_name}: {screenshot_rel}",
        "timestamp": _now(),
    })


def _summary_finding(urls, captured, tool_name, manifest_csv, index_html):
    return normalize_finding({
        "status": "INFO",
        "severity": "INFO",
        "vulnerability": "Screenshot Visual Triage Summary",
        "url": index_html,
        "payload_url": manifest_csv,
        "module": MODULE_NAME,
        "details": (
            f"Captured {captured}/{len(urls)} screenshot(s) with {tool_name}. "
            f"Manifest: {manifest_csv} | Gallery: {index_html}"
        ),
        "timestamp": _now(),
    })


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
async def capture_screenshots(alive_urls: list[str], output_dir: str, concurrency: int = 10) -> list[dict]:
    """Screenshot ``alive_urls`` and return canonical INFO findings.

    Returns ``[]`` on empty input, when no screenshot tool is installed, or if
    the tool run fails outright. Never raises for those cases.
    """
    urls = sorted({u.strip() for u in (alive_urls or []) if u and u.strip()})
    if not urls:
        return []

    tool_name, binary = _resolve_tool()
    if not binary:
        print(f"{_YELLOW}[!] Neither gowitness nor aquatone found in PATH. "
              f"Skipping screenshot capture.{_RESET}")
        return []

    shots_dir = os.path.join(output_dir, "screenshots")
    os.makedirs(shots_dir, exist_ok=True)

    fd, urls_file = tempfile.mkstemp(prefix="vakt_shots_", suffix=".txt")
    print(f"{_CYAN}[*] Capturing screenshots of {len(urls)} alive URL(s) with {tool_name} "
          f"(concurrency: {concurrency})...{_RESET}")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(urls) + "\n")

        try:
            async with heartbeat("screenshots", f"Screenshotting with {tool_name}"):
                if tool_name == "gowitness":
                    images = await _capture_gowitness(binary, urls_file, shots_dir, concurrency)
                else:
                    images = await _capture_aquatone(binary, urls, shots_dir, concurrency)
        except Exception as exc:  # noqa: BLE001 - defensive: never crash the scan
            print(f"{_YELLOW}[!] Screenshot capture failed ({tool_name}): {exc}. Skipping.{_RESET}")
            return []
    finally:
        try:
            os.remove(urls_file)
        except OSError:
            pass

    mapping = _map_urls_to_images(urls, images)
    captured = sum(1 for img in mapping.values() if img)

    manifest_csv = os.path.join(shots_dir, "manifest.csv")
    index_html = os.path.join(shots_dir, "index.html")
    try:
        _write_manifest_csv(manifest_csv, shots_dir, mapping)
        _write_index_html(index_html, shots_dir, mapping, tool_name)
    except OSError as exc:
        print(f"{_YELLOW}[!] Failed to write screenshot manifest: {exc}{_RESET}")

    findings = []
    for url, img in mapping.items():
        if not img:
            continue
        rel = os.path.relpath(img, shots_dir)
        findings.append(_screenshot_finding(url, rel, tool_name))
    findings.append(_summary_finding(urls, captured, tool_name, manifest_csv, index_html))

    print(f"{_GREEN}[+] Screenshots: captured {captured}/{len(urls)} URL(s). "
          f"Manifest: {manifest_csv}{_RESET}")
    return findings
