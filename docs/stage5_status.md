# Stage 5 status

## Design milestone

- Reviewed architecture, Stage 4 status, security case definitions, topology and startup scripts, and evidence layout. Capture points are sg-client/sg-c0, sg-r1/sg-r11, sg-gateway/sg-g0 and sg-gateway/sg-g1. The topology places client-to-gateway and gateway-to-backend traffic on separate TCP connections.
- Planned four simultaneous full-packet captures per case, independent source addresses, isolated scenario folders and timestamped runs; pcapng files will contain disposable bearer tokens and must remain private. P-07 includes earlier allowed requests before the first 429, so an entire P4 capture cannot be empty: the rejected request must be correlated separately.
- The existing scripts/run_stage1_checks.sh invokes preflight.sh, which configures netem; the explicit no-netem instruction prevents running that entire script unchanged. Cleanup will instead be verified directly with namespace, interface, address and process checks, and this limitation will be reported.
- No captures or verification have been performed yet.

## Captures milestone

- Ran `docker run --rm --privileged --network none -v C:\CN-SentinelGate-3:/work -w /work sentinelgate:latest bash scripts/stage5_capture.sh`. All ten scenarios produced four pcapng files in evidence/captures/stage5/20261121T215817Z/. Each capture log reports zero dropped packets; capinfos records the requested capture length of 262144. Empty files are genuine zero-packet captures, including P-09 at P2–P4.
- P-03 P4 contains two packets, so its backend-side traffic requires correlation rather than an assumption of an empty capture. P-07 P4 also contains traffic from the successful requests preceding the first 429. Verification remains in progress.
- The run recorded a pass for the binary-inclusive grep for the run secret in evidence and a pass for direct namespace/interface/capture-process cleanup. No screenshots were generated.

## Verification milestone

- The capture-derived verification.csv reports all checks passed for frame lengths and reported drops. P-01 TTLs are 64, 63, 62 and 64 at P1–P4. The captured request ID is present on client and backend sides; the client connection is 10.10.1.11:59826 to 10.10.3.10:8000 and the independent upstream connection is 10.10.4.1:54495 to 10.10.4.10:9000. Each capture labels that connection stream 0 independently, which does not make them the same stream. P4 shows X-Forwarded-For 10.10.1.11 and no Authorization header for the captured request.
- P-03 P4 frames 1–2 are a FIN/ACK on the prior upstream connection; no matching rejected request ID appears. P-04–P-06 and P-08 have empty P4 captures. P-07 includes 20 earlier allowed requests at P4, but the rejected 429 request ID does not appear there. These observations support the absence of a matching HTTP request in the capture, not proof against all possible traffic outside the capture/filter.
- P-09 P1 frames 2 and 4 show ICMP type 3 code 0 from 10.10.1.1; no P-09 packets reached P2–P4. P-10 P4 frames 6 and 12 use stream 1 and source port 60971, showing upstream connection reuse for the two observed requests. P-06 returned 400; P-08 returned 403 banned.
- Existing test suite ran once with the project mounted and network disabled: 126 passed. See evidence/logs/stage5_pytest.txt. The profile was parsed without warnings and decoded the P4 request in tshark; graphical Wireshark was not available for testing.

## Documentation milestone

- Added docs/packet_evidence.md with paths, capture-derived request/response/SYN/FIN frame numbers, suggested display filters and screenshot filenames for every scenario and capture point. The pcapng files contain plaintext disposable tokens; the guide tells the student to mask Authorization in report screenshots and preserve the captures. No screenshot or screenshot imitation was created.
- Published evidence/captures/stage5/MANIFEST.csv and wireshark_profile/ as well as timestamped copies in the run folder. The manifest includes capture commands, packet counts, drop reports, hashes, tool versions and first/last packet times; empty captures have no packet timestamps. Process-level verification timestamps are separate from first/last packet times.
- The reusable scripts/stage5_capture.sh now invokes capture and derived analysis, retains timestamped runs, copies existing gateway/backend logs before startup, runs direct cleanup checks, performs the secret scan and runs the test suite. The original capture run and the separate analysis and test commands passed; the assembled script was amended afterwards and has not itself been rerun end-to-end in its final form. The original Stage 1 check script was not run because it invokes netem, which was prohibited. The Wireshark profile loaded in tshark without parse warnings; its GUI columns and graphical import remain unverified.
- The capture runner used during this run overwrote the then-current evidence/logs/gateway.log and backend.log via the existing Stage 2 startup script; those earlier files were not archived by that version of the runner. Subsequent versions copy them before startup. This is an evidence-preservation deviation.
- Stage 5 evidence is available for annotation with the limitations above. No Stage 6 work was started.

## End-to-end rerun — 2026-11-23 UTC

- Ran `docker run --rm --privileged --network none -v C:\CN-SentinelGate-3:/work -w /work sentinelgate:latest bash scripts/stage5_capture.sh`. The run completed with 126 tests passed. Evidence is in `evidence/captures/stage5/20261123T030641Z/`; routing evidence is in `evidence/routing/stage5/20261123T030641Z.txt`.
- The derived verification reports zero capture drops and no truncated frames. P-01 TTL values were 64, 63, 62, 64; P-09 returned ICMP type 3 code 0 from 10.10.1.1; P-10 reused its observed backend connection. Cleanup and binary-inclusive secret scan passed according to run.txt.
- This rerun generated a new packet guide and current manifest, but the guide retains a stale statement about P-03 P4: this run captured zero packets there. The script does not archive previous Stage 5 evidence, and its manifest does not include the configuration overrides. These remain outstanding; the end-to-end run alone does not establish all requested acceptance criteria.

## Final Stage 5 close-out — 2026-11-23 UTC

- The assembled script was run as `docker run --rm --privileged --network none -v C:\CN-SentinelGate-3:/work -w /work sentinelgate:latest bash scripts/stage5_capture.sh`. The run is `evidence/captures/stage5/20261123T040252Z/`; its run.txt records cleanup and the binary-inclusive grep secret scan passing, and pytest.txt records 126 passed. Routing evidence is `evidence/routing/stage5/20261123T040252Z.txt`.
- Previous Stage 5 evidence, the packet guide, and existing gateway.log/backend.log were copied before startup to `evidence/archive/stage5-20261123T040252Z/`. An earlier capture runner overwrote the then-current gateway.log and backend.log without first archiving them; those earlier log contents were not preserved by that run.
- The manifest records the run-log overrides SG_BUCKET_REFILL_PER_SECOND=0.001 and SG_BAN_BASE_SECONDS=30. The guide is generated from the current run's capture summaries and verification results; P-03 P4 contains zero packets in this run.
- The derived verification reports zero capture drops, no truncated frames, TTLs 64/63/62/64, and distinct P-01 client and backend tuples with the same request ID. No rejected request ID appeared in the P4 HTTP data. P-07 includes earlier successful backend traffic; P-08 P4 contains two TCP FIN/ACK teardown packets and no HTTP request, so an entirely empty P4 capture was not achieved for P-08. This is a capture-scoped observation, not proof about traffic outside the capture.
- Graphical Wireshark profile import remains unverified. No screenshots or Stage 6 work were created.
