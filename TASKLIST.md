# VaktScan resume, load-safety, and reporting task list

## Completed and verified

- [x] Preserve and resume the exact `onit.com-89a8ec83db95a767` checkpoint.
- [x] Prevent completed subdomain enumeration from running again on resume.
- [x] Recover legacy enumeration, DNS-resolution, and HTTPX artifacts into the checkpoint.
- [x] Resume completed passive DNS, cloud, CT, DNS-hygiene, takeover, dork, and horizontal stages.
- [x] Checkpoint domain checks, web checks, JS analysis, Nuclei, and Dirsearch independently.
- [x] Reuse completed preliminary web-port and HTTPX discovery instead of repeating it.
- [x] Ensure resumed scans do not skip required downstream work after recon.
- [x] Send only one canonical HTTPS-preferred origin per unique hostname/IP to Nuclei and Dirsearch.
- [x] Apply the same target deduplication inside the Nuclei and Dirsearch modules as defense in depth.
- [x] Prevent two processes from sharing and corrupting the same scan checkpoint.
- [x] Reduce network pressure that could exhaust the local router/NAT table:
  - [x] Keep HTTP-heavy stages at the normal `-c 100` throughput by default.
  - [x] Run request-amplifying recon stages sequentially.
  - [x] Keep Dirsearch at its original 20 targets × 30 threads (up to 600 workers).
  - [x] Keep Nuclei at concurrency 50, 150 requests/second, and bulk size 100.
  - [x] Keep JS analysis at 20 workers by default.
  - [x] Apply the same safeguards to direct-target and streaming web-probe paths.
- [x] Keep tuning user-controllable with flags:
  - [x] `-c/--concurrency`
  - [x] `--web-concurrency`
  - [x] `--nuclei-concurrency`
  - [x] `--nuclei-rate-limit`
  - [x] `--nuclei-bulk-size`
  - [x] `--dirsearch-threads`
  - [x] `--dirsearch-parallel`
  - [x] `--js-threads`
- [x] Retain environment-variable equivalents for automation.
- [x] Build a self-contained, single-page unified HTML report.
- [x] Add navigation and global search across assets, services, findings, directories, and tool output.
- [x] Include checkpoint inventory, HTTPX data, open ports, vulnerabilities, Dirsearch discoveries, and expandable raw text artifacts.
- [x] Escape target/tool-controlled content in HTML output.
- [x] Generate a current report snapshot from the saved `onit.com` state.
- [x] Include the user's `requirements.sh` update in the earlier fixes commit.
- [x] Run the complete offline regression suite (527 tests passing, plus 13 subtests).

## Final live verification

- [x] Commit the network-safety, per-stage resume, CLI-tuning, report, tests, and this task list.
- [ ] Start `python main.py scan onit.com` from `onit.com-89a8ec83db95a767`.
- [ ] Confirm enumeration, DNS recon, preliminary port discovery, and HTTPX are reused rather than rerun.
- [ ] Confirm Nuclei and Dirsearch each receive 140 unique hostname/IP origins, not 1,449 URLs.
- [ ] Monitor process/request concurrency and workstation connectivity during the live run.
- [ ] Confirm no scanner child processes remain after interruption or completion.
- [ ] Confirm the final unified HTML report is generated under `reports/onit.com/`.

## Existing `TODO.md` backlog audit

- [x] Add a README screenshot/GIF of a real scan run.
- [x] Add live heartbeats for ffuf, testssl, and service-recon shell-outs.
- [x] Email-security recon: MX banners, SMTP relay checks, and BIMI are already implemented and wired into DNS recon.
- [x] Feed horizontal-expansion reverse hosts and related domains into the scoped live-host pipeline.
- [x] Normalize raw Dirsearch/GAU/Wayback discoveries into findings so inventory and SARIF receive them (the unified HTML embeds the complete raw artifacts).
- [x] Add DigitalOcean Spaces, Alibaba OSS, and non-Blob Azure storage probes.
- [x] Add CSP directive analysis for unsafe inline/eval, wildcard sources, and missing `frame-ancestors`.
- [x] Update `TODO.md` to reflect verified completions.
