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
  - [x] Bound HTTP-heavy stages independently from general scan concurrency.
  - [x] Run request-amplifying recon stages sequentially.
  - [x] Reduce Dirsearch defaults from 600 potential workers to 2 targets × 5 threads.
  - [x] Reduce Nuclei defaults to concurrency 10, 25 requests/second, and bulk size 20.
  - [x] Reduce JS analysis to 10 workers by default.
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
- [x] Run the complete offline regression suite (467 tests passing).

## Final live verification

- [x] Commit the network-safety, per-stage resume, CLI-tuning, report, tests, and this task list.
- [ ] Start `python main.py scan onit.com` from `onit.com-89a8ec83db95a767`.
- [ ] Confirm enumeration, DNS recon, preliminary port discovery, and HTTPX are reused rather than rerun.
- [ ] Confirm Nuclei and Dirsearch each receive 140 unique hostname/IP origins, not 1,449 URLs.
- [ ] Monitor process/request concurrency and workstation connectivity during the live run.
- [ ] Confirm no scanner child processes remain after interruption or completion.
- [ ] Confirm the final unified HTML report is generated under `reports/onit.com/`.
