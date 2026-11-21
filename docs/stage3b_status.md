# Stage 3b status

## Phase 0 — pre-steps: complete

- UTC: Sat Nov 21 13:36:56 UTC 2026
- Inspected the Stage 3a and 3b drafts, architecture, thresholds, decisions, cases, current gateway and backend, and relevant scripts.
- Evidence archive: `evidence/archive/20261121T133650Z/`. Existing archives were preserved.
- Stage 2 gateway backup: `evidence/archive/stage2_gateway_backup/20261121T133650Z/app.py`. SHA-256 matches the current gateway: `C86A5821EFFC5DE13CF001D7D7CE5530A2B59493E8A666C755E6ED2083FB9263`.
- The real gateway remains unchanged and still uses the Stage 2 allow-all hook.
- Not done: Phases 1–6; no Stage 3b live run or case CSV exists.
- Open issue: the prior draft adapter and integration need verification in the real package before security claims can be made.
## Phase 1 — library and adapter promotion: complete

- UTC: Sat Nov 21 13:48:27 UTC 2026
- Promoted `security.py`, `risk_state.py`, `security_config.py` and `security_adapter.py` to `gateway/`; kept both draft directories as history.
- Copied their four test files into `tests/` and pinned PyJWT 2.10.1 and coverage 7.8.2 in `requirements.txt`.
- Evidence: `evidence/logs/stage3b_phase1_pytest.txt` reports **68 passed in 10.74s**. This is the promoted-library test set; it does not claim the Stage 2 tests were rerun.
- Not done: the real gateway is not yet wired; Phases 2–6 and all live Stage 3b evidence remain outstanding.
- Open issue: the first test invocation timed out in automatic approval review; the retry completed successfully.

## Resume check

- Verified the saved Phase 1 test output reports 68 passed and the gateway still contains the Stage 2 allow-all hook. Phase 2 remains incomplete.

UTC: Sat Nov 21 18:26:22 UTC 2026

## Phase 2 — integration draft, incomplete

- Draft integration and tests are in the current Codex workspace under `phase2_check/`, not promoted to the real gateway.
- A local trial reported 69 passed, 5 skipped; all five async application tests were skipped because pytest-asyncio is missing from the Windows venv. This does not verify gateway integration. No evidence report was saved and Phase 2 checks have not passed.
- The real gateway remains unchanged. Scripts, coverage gaps, full integration checks, live evidence, and Phases 3–6 remain outstanding.

UTC: Sat Nov 21 18:41:12 UTC 2026

## Phase 2 — resumed, integration applied, incomplete

- A new hash-verified Stage 2 backup is at `evidence/archive/stage2_gateway_backup/20261121T183948Z/app.py`.
- Applied the integration draft to `gateway/app.py` and its preliminary tests to `tests/test_apps.py`. The application now invokes the adapter in middleware and initializes the engine in lifespan, but it has not passed integration checks.
- The Docker image rebuild is in progress. All Phase 2 requirements, including container tests, run scripts, coverage, and live checks, remain unverified. Phases 3–6 have not been started.

UTC: Sat Nov 21 18:45:19 UTC 2026

## Phase 2 — container test checkpoint, incomplete

- Saved `evidence/logs/stage3b_phase2_pytest.txt`: `74 passed in 5.56s`, zero reported failures or skips, for the promoted `tests/` suite.
- Test command: `docker run --rm -v C:\CN-SentinelGate-3:/work -v C:\sentinelGate\.venv\Lib\site-packages\jwt:/opt/venv/lib/python3.12/site-packages/jwt:ro -w /work sentinelgate-stage2 bash -c "python -m pytest -q -p no:cacheprovider tests/"`. This preliminary run used the existing Stage 2 image plus a read-only mounted PyJWT 2.10.1 package; it is not a run of the newly built image.
- The initial unqualified `pytest` collection failed with six import mismatch errors due to duplicate filenames in archived draft test directories. The promoted suite was selected explicitly.
- The new image build remains in progress. The run scripts, additional coverage and config tests, post-integration coverage, and other Phase 2 acceptance checks remain unfinished; do not start Phase 3 yet.

UTC: Sat Nov 21 19:03:47 UTC 2026

## Phase 2 — resumed integration and container checks; incomplete

- The rebuilt `sentinelgate:latest` image is available. The promoted suite in `evidence/logs/stage3b_phase2_pytest.txt` reports `90 passed in 3.62s`, zero failures and zero skips. Run via Docker with the project mounted at /work; the exact in-container command and UTC timestamp are in the file.
- Added malformed claim, required claim, state capacity and invalid configuration tests. Added HEAD support and enabled the dedicated structured decision logger; adjusted its test. Updated `scripts/stage2_up.sh` to create a per-run secret if absent and start uvicorn with `--no-proxy-headers --forwarded-allow-ips '' --workers 1`.
- `evidence/logs/stage3_coverage.txt` reports 96% total, 84% gateway/app.py, 96% security.py, 100% security_adapter.py, and 97% security_config.py. Gateway startup and readiness lines 39–45 and 80–87 remain uncovered; security.py lists lines 48, 92, 96, 106, 178, 210 and branch 20->22; security_config.py lists line 62.
- A privileged Docker probe created and removed only `sg-probe` successfully. This does not verify the project topology.
- Still incomplete: the Stage 2 verification script and concurrency client need authentication and real rerun; startup secrets, effective override logging, oversized claims, configuration bounds, HEAD forwarding and related integration details require further checks. Phase 2 is not complete. Phases 3–6 and their live evidence remain outstanding.

UTC: Sat Nov 21 19:41:23 UTC 2026

## Phase 2 continuation — incomplete

- Archived the prior test output and the initial plain-pytest collection failure under `evidence/archive/20261121T193818Z/`. The failure had five import errors because plain pytest did not include the project root on its import path. `pytest.ini` now limits discovery to `tests/` and includes the project root.
- Rebuilt-image run with only the project mounted: `evidence/logs/stage3b_phase2_pytest.txt` reports `91 passed in 2.67s`, zero failures, zero skips. The exact Docker command is recorded in the evidence.
- Updated README, `scripts/stage2_verify.sh`, and `scripts/concurrency.py`: the live script uses a disposable in-memory token, relaxes the bucket to capacity/refill 100 for its concurrency run, and limits client-side capture snap length to 64 bytes to avoid recording HTTP credentials. `evidence/logs/stage2_integration.txt` records authenticated health, readiness, info, echo, 50 successful concurrency responses and Stage 2 cleanup. Initial health polls reported connection refused while services started; subsequent polls succeeded.
- Added `max_claim_bytes` (default 256, override `SG_MAX_CLAIM_BYTES`), an oversized claim test and additional configuration bounds validation. These changes are covered by the suite but still require the requested deeper validation checks and documentation.
- Still incomplete: validate startup secret and effective config behavior, HEAD forwarding, configuration boundaries, rerun and explain branch coverage after the latest changes, and verify evidence command completeness and secret hygiene. Phase 2 is not complete; do not start Phase 3 yet. Phases 3–6 remain outstanding.

UTC: Sat Nov 21 19:43:29 UTC 2026

## Phase 2 coverage and integration tests — incomplete

- `evidence/logs/stage3b_phase2_pytest.txt` reports `103 passed in 2.47s`, no failures or skips, in the rebuilt image with only the project mounted.
- Startup tests cover missing and short secrets, one effective environment override with redaction, and HEAD rejection and forwarding. Additional tests cover malformed JWT decode, nonfinite claims, nested suspicious values, and configuration bounds.
- `evidence/logs/stage3_coverage.txt` reports 98% total, security.py 99%, security_config.py 100%, security_adapter.py 100%, and gateway/app.py 91%. Current security.py uncovered items: branch 20->22 skips adding a handler when one already exists (logger initialization; no input risk); line 92 catches an expired-token exception even though expiry is checked manually (defensive library exception; no input gap because expiry edges are tested); line 212 is a trivial delegation wrapper (no input gap). Config has no uncovered lines.
- Earlier security.py lines 48, 92, 96, 106, 178, 210 and security_config.py line 62 shifted after edits; capacity, malformed decode, nonfinite claims and nested lists now have tests. The prior logger branch and expired-token defensive branch remain as described above.
- Phase 2 is not yet signed off: review complete config bounds and effective override reporting, document the added limit, inspect exact command and secret hygiene of live evidence, and confirm reproduction. Phases 3–6 have not started.

UTC: Sat Nov 21 19:46:15 UTC 2026

## Phase 2 — latest verification; still open

- `evidence/logs/stage3b_phase2_pytest.txt` reports `104 passed in 3.05s`, zero failures, zero skips, in sentinelgate:latest with only the project mounted. The image includes its own PyJWT and pytest-asyncio.
- `evidence/logs/stage3_coverage.txt` reports 104 passed and 98% total; security.py 99%, security_config.py 100%, security_adapter.py 100%. Remaining security lines and branches are explained in the preceding entry. The new test sets every SG security field override and verifies the complete effective configuration and redaction in the startup log.
- Reran `docker run --rm --privileged -v C:\CN-SentinelGate-3:/work -w /work sentinelgate:latest bash scripts/stage2_verify.sh`. `evidence/logs/stage2_integration.txt` reports authenticated info/echo, `PASS: run credential strings absent from searched files`, and `Stage 2 cleanup passed.` `evidence/logs/stage2_concurrency.json` records 50 HTTP 200 responses and total 1732.612 ms with SG_BUCKET_CAPACITY=100 and SG_BUCKET_REFILL_PER_SECOND=100. Startup health retries initially produced connection refused before both services became healthy.
- The private scan checks the script-generated secret and its main token; the concurrency client independently mints another token, which was not separately checked. Exact evidence-command completeness and a fully scoped scan remain open, so Phase 2 is not marked complete. The Stage 3 cases and Phases 3–6 remain undone.

UTC: Sat Nov 21 19:47:34 UTC 2026

## Phase 2 — latest live rerun; incomplete

- The independently minted concurrency token is now privately scanned in memory against project files; `evidence/logs/stage2_concurrency.json` reports `token_scan: passed`, 50 HTTP 200 responses and total 2046.196 ms. This scan runs before the later packet capture; the concurrency requests themselves occur before capture starts.
- `evidence/logs/stage2_integration.txt` reports the main run credential strings absent from searched project files and `Stage 2 cleanup passed`. This run used the relaxed capacity/refill overrides of 100.
- The full container test suite remains at 104 passed, zero failures and zero skips. No Stage 3 case has run.
- Phase 2 remains open: audit and repair evidence command recording (some live-log descriptions omit actual flags and use placeholders), then reverify the complete phase. Phase 3 and later phases remain undone.

UTC: Sat Nov 21 20:34:27 UTC 2026

## Phase 3 — extra client addresses: complete

- Phase 2 is signed off by the user. Implemented `scripts/sg-case-addresses.sh` and `scripts/sg-verify-addresses.sh`; updated the Stage 2 startup and health checks to use 10.10.1.250 for gateway health polling. Backend startup uses a listening-socket check.
- `evidence/routing/stage3_address_verification.txt` records all 15 case addresses plus 10.10.1.250, successful ping and one-off health requests from each, repeated idempotent setup and teardown, and `PASS: case addresses removed; no sg namespaces or root interfaces remain`.
- Phase 4 live cases, rejection capture, timing, and secret checks are not done.

## Final cleanup list

- After Phase 4, repair earlier evidence files that use command placeholders instead of exact flags, as requested by the user.

UTC: Sat Nov 21 20:43:10 UTC 2026

## Phase 4 — live security verification: complete

- Added `scripts/stage3_verify.sh` and `scripts/stage3_cases.py`. The final run used a random in-memory secret and recorded overrides `SG_BAN_BASE_SECONDS=10` and `SG_BUCKET_REFILL_PER_SECOND=0.001`; the latter makes SC-11's no-refill burst reproducible.
- `evidence/logs/stage3_cases.csv` and `stage3_cases_summary.txt` contain all SC-01–SC-15: 15 matched expected status, reason, backend reachability and source identity. Rejected-case request IDs and backend counts are recorded; full decision records are in `evidence/logs/gateway.log` and backend records in `backend.log`.
- `evidence/captures/stage3/backend-cases.pcapng` and `summary.txt` contain real backend-side packets: 5 backend-bound packets in the SC-01 window and 0 in the SC-04 window. The capture started before these requests.
- `evidence/logs/stage3_run.txt` records the real ban response with Retry-After 10, followed by SC-13 success after waiting. Its logged score was 29.38, below the 30-point probation value because the request occurred after expiry and decay continued. SC-14 recovered below elevated to 37.31. The SC-15 forged-header rejection scored the real 10.10.1.25 source, and the valid case passed from that source.
- `evidence/logs/stage3_secret_scan.txt` reports `PASS: run secret and all minted token strings absent from project files`. Stage 1 cleanup evidence `evidence/routing/cleanup-20261121T204146Z-919687811.txt` reports `Cleanup verification passed.`
- Phase 4 had no case mismatches in the final run. Subsequent project stages and the optional performance side task were not started, as requested.

## Final cleanup list

- Replaced the `[specified protocol fields]` placeholders in the three current Stage 2 capture summaries with the flags from their actual generating script, and corrected that script for future runs. Archived historical evidence was preserved. Other historical command descriptions have not been exhaustively audited.
- Corrected the current Stage 3 capture-summary filter quoting so those displayed tshark commands can be reproduced.

## Stage 3 closeout — blocked

- Case integrity comparison: evidence/logs/stage3_cases_integrity.txt reports no changes to expected values, request specs, source IPs or backend expectations.
- Performance scripts and documentation updates were not applied: automatic approval review of project-folder writes timed out, including the permitted retry. Concurrency measurements and command-description cleanup remain undone.
- Known gaps: older evidence command descriptions have not been exhaustively audited.
