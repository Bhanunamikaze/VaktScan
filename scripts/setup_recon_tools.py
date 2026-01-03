#!/usr/bin/env python3
"""
Utility script to set up the external binaries required by VaktScan's recon
modules.

It focuses on the tooling consumed by:
  * modules/recon.py          → amass, subfinder, assetfinder, findomain, etc.
  * modules/dir_enum.py       → ffuf
  * modules/httpx_runner.py   → httpx
  * modules/nmap_runner.py    → nmap

Usage:
    python scripts/setup_recon_tools.py            # Just report tool status
    python scripts/setup_recon_tools.py --install  # Attempt to install missing tools

The installation flow loosely follows the helper that powers the Xeref project
and relies on apt/go for packages plus GitHub releases when needed.
"""

from __future__ import annotations

import argparse
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


GO_BASED_TOOLS = {"assetfinder", "ffuf", "httpx"}

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

    go_needed = any(
        TOOL_SPECS[tool].requires_go and not check_tool(TOOL_SPECS[tool].binary)
        for tool in selected
    )
    if go_needed and args.install and not ensure_go_available():
        sys.exit(1)

    for tool in selected:
        spec = TOOL_SPECS[tool]
        if check_tool(spec.binary):
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

        if check_tool(spec.binary):
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
