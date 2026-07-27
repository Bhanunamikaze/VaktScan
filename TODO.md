# VaktScan - Open Backlog

Current pipeline: subcommand CLI (scan / enum / probe / dns / cloud / js-paths / google-dork)
→ subdomain enum → scope filter (`--exclude` → `--include-only` → `--company-only`)
→ DNS hygiene + dangling-CNAME takeover → DNS recon + cloud enum + CT monitor (parallel)
→ port scan → httpx → web checks → nuclei → service vuln checks → dirsearch → gau/wayback
→ archived-URL scan → JS paths → NVD/EPSS/CISA-KEV enrichment → Nmap CVE scripts (open ports only)
→ inventory delta → CSV + HTML (always) / JSON / SARIF (opt-in).

Everything in the original roadmap (false-positive oracles, service/recon checks, CLI redesign,
SSL/TLS, extra security modules, orchestration §12, ASM roadmap §13 HIGH/MEDIUM, HTML report,
scope control, asset classifier) is shipped. Only the items below are still open.

---

## Documentation
- [ ] Add a screenshot / GIF of a real scan run to README.

## Progress-feedback follow-ups (deferred from the frozen-dashboard fix)
- [ ] Per-tool heartbeats in the recon phase - ffuf vhost fuzz, `testssl` (300s silent/host),
      and `service_recon` shell-outs still run without a live task update. Needs `main.py` task
      wiring (these are silent-but-working, not frozen-dashboard bugs).

## Recon breadth
- [ ] Email security (extend `dns_recon`): MX record banner grabbing (mail server version),
      SMTP open-relay test, BIMI record check.

## Resume
- [x] Make an *interrupted* web-probe itself resumable - DONE. The web-probe is now a
      first-class checkpointed phase (`web_probing` → `web_probing_complete`): completed
      URLs are persisted (`completed_web_urls`) and skipped on resume, so an interrupt
      continues from the not-yet-probed URLs instead of restarting or being skipped
      entirely. Hostname attribution on resume was already fixed. (Closes B8.)

## Horizontal expansion follow-up
- [ ] Feed `reverse_hosts` / `related_domains` from `horizontal_expand` back into the live-host
      pipeline to compound scope (currently reported but not re-scanned).

## LOW
- [ ] Integrate raw dirsearch/gau/wayback outputs into the unified findings/inventory/SARIF pipeline.
- [ ] Cloud provider breadth (DigitalOcean Spaces, Alibaba OSS, non-Blob Azure).
- [ ] CSP directive analysis (`unsafe-inline`, wildcard sources, missing `frame-ancestors`).
