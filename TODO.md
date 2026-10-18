# VaktScan - Open Backlog

Current pipeline: subcommand CLI (scan / enum / probe / dns / cloud / js-paths / google-dork)
→ subdomain enum → scope filter (`--exclude` → `--include-only` → `--company-only`)
→ DNS hygiene + dangling-CNAME takeover → DNS recon + cloud enum + CT monitor (parallel)
→ port scan → httpx → domain scan → web checks → JS paths → nuclei → dirsearch (heavy web tools serial)
→ service vuln checks → gau/wayback
→ archived-URL scan → JS paths → NVD/EPSS/CISA-KEV enrichment → Nmap CVE scripts (open ports only)
→ inventory delta → CSV + unified searchable HTML (always) / JSON / SARIF (opt-in).

Everything in the original roadmap (false-positive oracles, service/recon checks, CLI redesign,
SSL/TLS, extra security modules, orchestration §12, ASM roadmap §13 HIGH/MEDIUM, HTML report,
scope control, asset classifier) is shipped. Only the items below are still open.

---

## Documentation
- [x] Add a screenshot / GIF of a real scan run to README. (`docs/scan-resume.png`)

## Progress-feedback follow-ups (deferred from the frozen-dashboard fix)
- [x] Per-tool heartbeats in the recon phase - ffuf vhost fuzz, `testssl` (300s silent/host),
      and `service_recon` shell-outs now update live dashboard tasks.

## Recon breadth
- [x] Email security: MX record banner grabbing, SMTP open-relay tests, and BIMI checks are
      implemented in `dns_recon` and run from the standard DNS scan.

## Resume
- [x] Make an *interrupted* web-probe itself resumable - DONE. The web-probe is now a
      first-class checkpointed phase (`web_probing` → `web_probing_complete`): completed
      URLs are persisted (`completed_web_urls`) and skipped on resume, so an interrupt
      continues from the not-yet-probed URLs instead of restarting or being skipped
      entirely. Hostname attribution on resume was already fixed. (Closes B8.)

## Horizontal expansion follow-up
- [x] Feed `reverse_hosts` / `related_domains` from `horizontal_expand` back into the live-host
      pipeline, with checkpoint payload reuse on resume.

## LOW
- [x] Integrate Dirsearch/GAU/Wayback discoveries into findings/inventory/SARIF as compact
      per-target summaries; retain every raw URL in the unified HTML artifacts.
- [x] Cloud provider breadth: DigitalOcean Spaces, Alibaba OSS, and non-Blob Azure services.
- [x] CSP directive analysis (`unsafe-inline`, `unsafe-eval`, wildcard sources, missing `frame-ancestors`).
