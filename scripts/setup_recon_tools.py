#!/usr/bin/env python3
"""
Utility script to set up the external binaries required by VaktScan's recon
modules.

It focuses on the tooling consumed by:
  * modules/recon.py           → amass, subfinder, assetfinder, findomain, gau,
                                 waybackurls, crtsh, sublist3r, knockpy, bbot, censys
  * modules/dns_resolve.py     → puredns, massdns, dnsx, alterx, asnmap, dnsgen
  * modules/dir_enum.py        → ffuf, dirsearch
  * modules/httpx_runner.py    → httpx
  * modules/nmap_runner.py     → nmap
  * modules/nuclei_runner.py   → nuclei
  * modules/param_discovery.py → paramspider, arjun, gf, uro
  * modules/tech_fingerprint.py→ webanalyze
  * modules/favicon_jarm.py    → jarm / pyjarm
  * modules/testssl_runner.py  → testssl / testssl.sh

Usage:
    python scripts/setup_recon_tools.py            # Just report tool status
    python scripts/setup_recon_tools.py --install  # Attempt to install missing tools

The installation flow loosely follows the helper that powers the Xeref project
and relies on apt/go for packages plus GitHub releases when needed.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class ToolSpec:
    name: str
    binary: str
    install_cmd: str
    description: str
    requires_go: bool = False


GO_BASED_TOOLS = {
    "assetfinder",
    "ffuf",
    "httpx",
    "dnsx",
    "asnmap",
    "alterx",
    "gf",
    "gowitness",
    "puredns",
    "webanalyze",
}

TOOL_SPECS: Dict[str, ToolSpec] = {
    "amass": ToolSpec(
        name="amass",
        binary="amass",
        install_cmd=(
            "tmpdir=$(mktemp -d) && "
            "arch=$(uname -m) && "
            "case \"$arch\" in "
            "x86_64|amd64) asset=\"amass_linux_amd64.tar.gz\" ;; "
            "aarch64|arm64) asset=\"amass_linux_arm64.tar.gz\" ;; "
            "armv7l) asset=\"amass_linux_armv7.tar.gz\" ;; "
            "armv6l) asset=\"amass_linux_armv6.tar.gz\" ;; "
            "i386|i686) asset=\"amass_linux_386.tar.gz\" ;; "
            "*) echo \"Unsupported architecture: $arch\" && exit 1 ;; "
            "esac && "
            "curl -sL \"https://github.com/owasp-amass/amass/releases/download/v5.0.1/$asset\" "
            "-o \"$tmpdir/$asset\" && "
            "tar -xzf \"$tmpdir/$asset\" -C \"$tmpdir\" && "
            "bin_path=$(find \"$tmpdir\" -type f -name amass -perm -111 | head -n 1) && "
            "[ -n \"$bin_path\" ] || { echo 'amass binary not found in archive'; exit 1; } && "
            "sudo install -m 755 \"$bin_path\" /usr/local/bin/amass && "
            "rm -rf \"$tmpdir\""
        ),
        description="OWASP Amass v5.0.1 binary download (architecture-aware) for passive subdomain enumeration.",
    ),
    "subfinder": ToolSpec(
        name="subfinder",
        binary="subfinder",
        install_cmd=(
            "tmpdir=$(mktemp -d) && "
            "arch=$(uname -m) && "
            "case \"$arch\" in "
            "x86_64|amd64) asset=\"subfinder_2.11.0_linux_amd64.zip\" ;; "
            "aarch64|arm64) asset=\"subfinder_2.11.0_linux_arm64.zip\" ;; "
            "armv7l|armv7) asset=\"subfinder_2.11.0_linux_arm.zip\" ;; "
            "armv6l|armv6) asset=\"subfinder_2.11.0_linux_arm.zip\" ;; "
            "i386|i686) asset=\"subfinder_2.11.0_linux_386.zip\" ;; "
            "*) echo \"Unsupported architecture: $arch\" && exit 1 ;; "
            "esac && "
            "curl -sL \"https://github.com/projectdiscovery/subfinder/releases/download/v2.11.0/$asset\" "
            "-o \"$tmpdir/$asset\" && "
            "unzip -q \"$tmpdir/$asset\" -d \"$tmpdir\" && "
            "bin_path=$(find \"$tmpdir\" -type f -name subfinder -perm -111 | head -n 1) && "
            "[ -n \"$bin_path\" ] || { echo 'subfinder binary not found in archive'; exit 1; } && "
            "sudo install -m 755 \"$bin_path\" /usr/local/bin/subfinder && "
            "rm -rf \"$tmpdir\""
        ),
        description="ProjectDiscovery subfinder v2.11.0 binary download (architecture-aware).",
    ),
    "assetfinder": ToolSpec(
        name="assetfinder",
        binary="assetfinder",
        install_cmd=(
            "go install -v github.com/tomnomnom/assetfinder@latest && "
            "sudo install -m 755 \"$(go env GOPATH)/bin/assetfinder\" /usr/local/bin/assetfinder"
        ),
        description="Tomnomnom assetfinder for quick passive enumeration.",
        requires_go=True,
    ),
    "findomain": ToolSpec(
        name="findomain",
        binary="findomain",
        install_cmd=(
            "tmpdir=$(mktemp -d) && "
            "curl -sL https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip "
            "-o \"$tmpdir/findomain.zip\" && "
            "unzip -o \"$tmpdir/findomain.zip\" -d \"$tmpdir\" >/dev/null && "
            "sudo install -m 755 \"$tmpdir/findomain\" /usr/local/bin/findomain && "
            "rm -rf \"$tmpdir\""
        ),
        description="Findomain binary release for fast passive enumeration.",
    ),
    "sublist3r": ToolSpec(
        name="sublist3r",
        binary="sublist3r",
        install_cmd="sudo apt update && sudo apt install -y sublist3r",
        description="Sublist3r Python tool leveraged as a fallback data source.",
    ),
    "knockpy": ToolSpec(
        name="knockpy",
        binary="knockpy",
        install_cmd="sudo apt update && sudo apt install -y knockpy",
        description="Knockpy DNS brute-force helper leveraged by the recon module.",
    ),
    "bbot": ToolSpec(
        name="bbot",
        binary="bbot",
        install_cmd=(
            "pip3 install --user bbot --break-system-packages && "
            "echo '[*] Note: add ~/.local/bin to your PATH if bbot is not found.'"
        ),
        description="bbot subdomain enumeration framework (requires ~/.local/bin in PATH).",
    ),
    "gau": ToolSpec(
        name="gau",
        binary="gau",
        install_cmd=(
            "tmpdir=$(mktemp -d) && "
            "arch=$(uname -m) && "
            "case \"$arch\" in "
            "x86_64|amd64) asset=\"gau_2.2.4_linux_amd64.tar.gz\" ;; "
            "aarch64|arm64) asset=\"gau_2.2.4_linux_arm64.tar.gz\" ;; "
            "armv7l|armv7) asset=\"gau_2.2.4_linux_armv7.tar.gz\" ;; "
            "i386|i686) asset=\"gau_2.2.4_linux_386.tar.gz\" ;; "
            "*) echo \"Unsupported architecture: $arch\" && exit 1 ;; "
            "esac && "
            "curl -sL \"https://github.com/lc/gau/releases/download/v2.2.4/$asset\" "
            "-o \"$tmpdir/$asset\" && "
            "tar -xzf \"$tmpdir/$asset\" -C \"$tmpdir\" && "
            "bin_path=$(find \"$tmpdir\" -type f -name gau -perm -111 | head -n 1) && "
            "[ -n \"$bin_path\" ] || { echo 'gau binary not found in archive'; exit 1; } && "
            "sudo install -m 755 \"$bin_path\" /usr/local/bin/gau && "
            "rm -rf \"$tmpdir\""
        ),
        description="Gather all URLs (gau) v2.2.4 release binary for archived URL scraping.",
    ),
    "censys": ToolSpec(
        name="censys",
        binary="censys",
        install_cmd="pip3 install --user censys --break-system-packages",
        description="Censys CLI client (configure API credentials via `censys config`).",
    ),
    "crtsh": ToolSpec(
        name="crtsh",
        binary="crtsh",
        install_cmd=(
            "tmpdir=$(mktemp -d) && "
            "git clone https://github.com/YashGoti/crtsh.py.git \"$tmpdir/crtsh\" && "
            "cd \"$tmpdir/crtsh\" && mv crtsh.py crtsh && chmod +x crtsh && "
            "sudo install -m 755 crtsh /usr/local/bin/crtsh && rm -rf \"$tmpdir\""
        ),
        description="crt.sh command-line helper for certificate transparency lookups.",
    ),
    "dirsearch": ToolSpec(
        name="dirsearch",
        binary="dirsearch",
        install_cmd="sudo apt update && sudo apt install -y dirsearch",
        description="Dirsearch directory brute-forcer used on alive HTTP targets.",
    ),
    "ffuf": ToolSpec(
        name="ffuf",
        binary="ffuf",
        install_cmd=(
            "go install -v github.com/ffuf/ffuf@latest && "
            "sudo install -m 755 \"$(go env GOPATH)/bin/ffuf\" /usr/local/bin/ffuf"
        ),
        description="Fuzz Faster U Fool for active subdomain fuzzing (DirEnumerator).",
        requires_go=True,
    ),
    "httpx": ToolSpec(
        name="httpx",
        binary="httpx",
        install_cmd=(
            "tmpdir=$(mktemp -d) && "
            "arch=$(uname -m) && "
            "case \"$arch\" in "
            "x86_64|amd64) asset=\"httpx_1.7.4_linux_amd64.zip\" ;; "
            "aarch64|arm64) asset=\"httpx_1.7.4_linux_arm64.zip\" ;; "
            "armv7l|armv7) asset=\"httpx_1.7.4_linux_arm.zip\" ;; "
            "armv6l|armv6) asset=\"httpx_1.7.4_linux_arm.zip\" ;; "
            "i386|i686) asset=\"httpx_1.7.4_linux_386.zip\" ;; "
            "*) echo \"Unsupported architecture: $arch\" && exit 1 ;; "
            "esac && "
            "curl -sL \"https://github.com/projectdiscovery/httpx/releases/download/v1.7.4/$asset\" "
            "-o \"$tmpdir/$asset\" && "
            "unzip -q \"$tmpdir/$asset\" -d \"$tmpdir\" && "
            "bin_path=$(find \"$tmpdir\" -type f -name httpx -perm -111 | head -n 1) && "
            "[ -n \"$bin_path\" ] || { echo 'httpx binary not found in archive'; exit 1; } && "
            "sudo install -m 755 \"$bin_path\" /usr/local/bin/httpx && "
            "rm -rf \"$tmpdir\""
        ),
        description="ProjectDiscovery httpx v1.7.4 binary download (architecture-aware).",
    ),
    "waybackurls": ToolSpec(
        name="waybackurls",
        binary="waybackurls",
        install_cmd=(
            "tmpdir=$(mktemp -d) && "
            "arch=$(uname -m) && "
            "case \"$arch\" in "
            "x86_64|amd64) asset=\"waybackurls-linux-amd64-0.1.0.tgz\" ;; "
            "aarch64|arm64) asset=\"waybackurls-linux-arm64-0.1.0.tgz\" ;; "
            "i386|i686) asset=\"waybackurls-linux-386-0.1.0.tgz\" ;; "
            "*) echo \"Unsupported architecture: $arch\" && exit 1 ;; "
            "esac && "
            "curl -sL \"https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/$asset\" "
            "-o \"$tmpdir/$asset\" && "
            "tar -xzf \"$tmpdir/$asset\" -C \"$tmpdir\" && "
            "bin_path=$(find \"$tmpdir\" -type f -name waybackurls -perm -111 | head -n 1) && "
            "[ -n \"$bin_path\" ] || { echo 'waybackurls binary not found in archive'; exit 1; } && "
            "sudo install -m 755 \"$bin_path\" /usr/local/bin/waybackurls && "
            "rm -rf \"$tmpdir\""
        ),
        description="waybackurls v0.1.0 release binary for archived URL enumeration.",
    ),
    "nmap": ToolSpec(
        name="nmap",
        binary="nmap",
        install_cmd="sudo apt update && sudo apt install -y nmap",
        description="Nmap security scanner used by nmap_runner for service probing.",
    ),
    "nuclei": ToolSpec(
        name="nuclei",
        binary="nuclei",
        install_cmd=(
            "tmpdir=$(mktemp -d) && "
            "arch=$(uname -m) && "
            "case \"$arch\" in "
            "x86_64|amd64) asset=\"nuclei_3.6.2_linux_amd64.zip\" ;; "
            "aarch64|arm64) asset=\"nuclei_3.6.2_linux_arm64.zip\" ;; "
            "armv7l|armv7) asset=\"nuclei_3.6.2_linux_arm.zip\" ;; "
            "armv6l|armv6) asset=\"nuclei_3.6.2_linux_arm.zip\" ;; "
            "i386|i686) asset=\"nuclei_3.6.2_linux_386.zip\" ;; "
            "*) echo \"Unsupported architecture: $arch\" && exit 1 ;; "
            "esac && "
            "curl -sL \"https://github.com/projectdiscovery/nuclei/releases/download/v3.6.2/$asset\" "
            "-o \"$tmpdir/$asset\" && "
            "unzip -q \"$tmpdir/$asset\" -d \"$tmpdir\" && "
            "bin_path=$(find \"$tmpdir\" -type f -name nuclei -perm -111 | head -n 1) && "
            "[ -n \"$bin_path\" ] || { echo 'nuclei binary not found in archive'; exit 1; } && "
            "sudo install -m 755 \"$bin_path\" /usr/local/bin/nuclei && "
            "rm -rf \"$tmpdir\""
        ),
        description="ProjectDiscovery nuclei v3.6.2 binary download (architecture-aware).",
    ),
    "dnsx": ToolSpec(
        name="dnsx",
        binary="dnsx",
        install_cmd=(
            "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && "
            "sudo install -m 755 \"$(go env GOPATH)/bin/dnsx\" /usr/local/bin/dnsx"
        ),
        description="ProjectDiscovery dnsx fast multi-purpose DNS toolkit used by dns_resolve.",
        requires_go=True,
    ),
    "asnmap": ToolSpec(
        name="asnmap",
        binary="asnmap",
        install_cmd=(
            "go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest && "
            "sudo install -m 755 \"$(go env GOPATH)/bin/asnmap\" /usr/local/bin/asnmap"
        ),
        description="ProjectDiscovery asnmap for ASN/CIDR-to-IP mapping during recon.",
        requires_go=True,
    ),
    "alterx": ToolSpec(
        name="alterx",
        binary="alterx",
        install_cmd=(
            "go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest && "
            "sudo install -m 755 \"$(go env GOPATH)/bin/alterx\" /usr/local/bin/alterx"
        ),
        description="ProjectDiscovery alterx permutation-based subdomain wordlist generator.",
        requires_go=True,
    ),
    "gf": ToolSpec(
        name="gf",
        binary="gf",
        install_cmd=(
            "go install -v github.com/tomnomnom/gf@latest && "
            "sudo install -m 755 \"$(go env GOPATH)/bin/gf\" /usr/local/bin/gf"
        ),
        description="Tomnomnom gf grep-pattern helper used by param_discovery.",
        requires_go=True,
    ),
    "gowitness": ToolSpec(
        name="gowitness",
        binary="gowitness",
        install_cmd=(
            "go install -v github.com/sensepost/gowitness@latest && "
            "sudo install -m 755 \"$(go env GOPATH)/bin/gowitness\" /usr/local/bin/gowitness"
        ),
        description="Sensepost gowitness web screenshot utility for alive HTTP targets.",
        requires_go=True,
    ),
    "puredns": ToolSpec(
        name="puredns",
        binary="puredns",
        install_cmd=(
            "go install -v github.com/d3mondev/puredns/v2@latest && "
            "sudo install -m 755 \"$(go env GOPATH)/bin/puredns\" /usr/local/bin/puredns"
        ),
        description="puredns fast wildcard-aware DNS resolver (preferred dns_resolve backend).",
        requires_go=True,
    ),
    "webanalyze": ToolSpec(
        name="webanalyze",
        binary="webanalyze",
        install_cmd=(
            "go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest && "
            "sudo install -m 755 \"$(go env GOPATH)/bin/webanalyze\" /usr/local/bin/webanalyze"
        ),
        description="rverton webanalyze (Wappalyzer engine) used by tech_fingerprint.",
        requires_go=True,
    ),
    "arjun": ToolSpec(
        name="arjun",
        binary="arjun",
        install_cmd="pip3 install --user arjun --break-system-packages",
        description="Arjun HTTP parameter discovery suite (active param mining in param_discovery).",
    ),
    "paramspider": ToolSpec(
        name="paramspider",
        binary="paramspider",
        install_cmd=(
            "pip3 install --user "
            "git+https://github.com/devanshbatham/paramspider "
            "--break-system-packages"
        ),
        description="ParamSpider passive parameter harvester (installed from git; PyPI name is a placeholder).",
    ),
    "uro": ToolSpec(
        name="uro",
        binary="uro",
        install_cmd="pip3 install --user uro --break-system-packages",
        description="uro URL-list declutter helper used by param_discovery.",
    ),
    "dnsgen": ToolSpec(
        name="dnsgen",
        binary="dnsgen",
        install_cmd="pip3 install --user dnsgen --break-system-packages",
        description="dnsgen DNS permutation wordlist generator used on the dns_resolve path.",
    ),
    "jarm": ToolSpec(
        name="jarm",
        binary="pyjarm",
        install_cmd="pip3 install --user pyjarm --break-system-packages",
        description="pyjarm JARM TLS fingerprinting CLI/library (binary `pyjarm`, import `jarm`) for favicon_jarm.",
    ),
    "testssl": ToolSpec(
        name="testssl",
        binary="testssl.sh",
        install_cmd=(
            "if [ ! -x /opt/testssl.sh/testssl.sh ]; then "
            "sudo rm -rf /opt/testssl.sh && "
            "sudo git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl.sh; "
            "fi && "
            "sudo ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh && "
            "sudo ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl"
        ),
        description="testssl.sh TLS/SSL scanner (git clone into /opt, symlinked as testssl/testssl.sh).",
    ),
    "massdns": ToolSpec(
        name="massdns",
        binary="massdns",
        install_cmd=(
            "tmpdir=$(mktemp -d) && "
            "git clone --depth 1 https://github.com/blechschmidt/massdns \"$tmpdir/massdns\" && "
            "make -C \"$tmpdir/massdns\" && "
            "sudo install -m 755 \"$tmpdir/massdns/bin/massdns\" /usr/local/bin/massdns && "
            "rm -rf \"$tmpdir\""
        ),
        description="massdns high-performance DNS resolver (built from source; wildcard-filter fallback for dns_resolve).",
    ),
}


def run_shell(cmd: str) -> bool:
    """Runs a shell command, streaming output live."""
    print(f"\n[+] Executing:\n    {cmd}")
    result = subprocess.run(cmd, shell=True, executable="/bin/bash")
    if result.returncode != 0:
        print(f"[!] Command failed with exit code {result.returncode}.")
    return result.returncode == 0


def check_tool(binary: str) -> bool:
    """Returns True if the binary is resolvable in PATH."""
    return shutil.which(binary) is not None


def get_help_output(path: str) -> str:
    """Returns combined help output for a candidate binary."""
    try:
        result = subprocess.run(
            [path, "--help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return (result.stdout or "") + (result.stderr or "")
    except Exception:
        return ""


def is_projectdiscovery_httpx(path: str) -> bool:
    """Checks whether the resolved httpx binary is the ProjectDiscovery tool."""
    help_text = get_help_output(path)
    if not help_text:
        return False
    if "Usage:" in help_text and "[flags]" in help_text:
        return True
    if "-l, -list" in help_text:
        return True
    if "<URL> [OPTIONS]" in help_text:
        return False
    return False


def resolve_projectdiscovery_httpx() -> str | None:
    """Finds a ProjectDiscovery-compatible httpx binary if one is present."""
    candidates = [
        os.environ.get("VAKT_HTTPX_BIN"),
        "/usr/local/bin/httpx",
        os.path.expanduser("~/.bbot/tools/httpx"),
        shutil.which("httpx"),
        shutil.which("pd-httpx"),
    ]
    seen = set()
    for candidate in candidates:
        if not candidate:
            continue
        path = os.path.expanduser(candidate)
        if not os.path.isabs(path):
            path = shutil.which(path)
        if not path or path in seen:
            continue
        seen.add(path)
        if is_projectdiscovery_httpx(path):
            return path
    return None


def check_httpx_tool() -> bool:
    """Returns True only when a ProjectDiscovery-compatible httpx is available."""
    return resolve_projectdiscovery_httpx() is not None


def ensure_go_available() -> bool:
    """Ensures Go is available when any Go-based tool is being installed."""
    if shutil.which("go"):
        return True
    print(
        "[!] Go toolchain not found, but Go-based tools were requested.\n"
        "    Install Go first (https://golang.org/doc/install) and re-run."
    )
    return False


def summarize_status(status: List[str]) -> None:
    print("\n=== Summary ===")
    for line in status:
        print(line)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check/install external binaries required by the recon modules."
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Attempt to install every missing tool using the predefined commands.",
    )
    tool_choices = sorted(TOOL_SPECS.keys())
    parser.add_argument(
        "--tools",
        nargs="+",
        choices=tool_choices,
        metavar="TOOL",
        help="Only process a subset of tools (default: all).",
    )
    parser.add_argument(
        "tool_args",
        nargs="*",
        choices=tool_choices,
        metavar="TOOL",
        help="Optional positional tool list (alias of --tools for convenience).",
    )
    args = parser.parse_args()

    selected = args.tools or args.tool_args or list(TOOL_SPECS.keys())
    status_lines: List[str] = []
    
    def tool_is_ready(spec: ToolSpec) -> bool:
        if spec.name == "httpx":
            return check_httpx_tool()
        return check_tool(spec.binary)

    go_needed = any(
        TOOL_SPECS[tool].requires_go and not tool_is_ready(TOOL_SPECS[tool])
        for tool in selected
    )
    if go_needed and args.install and not ensure_go_available():
        sys.exit(1)

    for tool in selected:
        spec = TOOL_SPECS[tool]
        if tool_is_ready(spec):
            status_lines.append(f"[OK] {spec.name:11s} → {spec.description}")
            continue

        msg = f"[MISSING] {spec.name} → {spec.description}"
        print(msg)
        status_lines.append(msg)

        print(f"    Suggested install command:\n    {spec.install_cmd}")
        if not args.install:
            continue

        print(f"[*] Installing {spec.name} ...")
        if not run_shell(spec.install_cmd):
            status_lines.append(f"[FAIL] {spec.name} installation failed.")
            continue

        if tool_is_ready(spec):
            status_lines.append(f"[OK] {spec.name} installed successfully.")
        else:
            status_lines.append(
                f"[WARN] {spec.name} install command completed but binary still missing."
            )

    summarize_status(status_lines)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Setup interrupted by user.")
        sys.exit(1)
