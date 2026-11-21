# AI-use log

## Session 2026-11-21 (Asia/Karachi)

- The user supplied the proposal, course requirements, operating constraints, and requested Stage 1 only. The user confirmed a three-person team; the contradictory course wording still needs instructor confirmation.
- The assistant drafted the Docker environment, topology and verification scripts, architecture notes and this log. The user authorized downloading Ubuntu 24.04 and use of Docker.
- The assistant tested an initial diagnostic in an Alpine container: namespace creation, netem and veth packet capture succeeded. It was a preliminary check, not the final Ubuntu evidence. An initial sandboxed Docker connection returned permission denied; Docker access succeeded outside the sandbox.
- User-authored changes and user verification: not reported in this session. Do not infer or invent contributions.
- The assistant ran the Ubuntu preflight and topology checks in Docker on 2026-11-20 UTC (2026-11-21 Asia/Karachi). Namespace creation, netem, capture, ping, traceroute, backend isolation and repeated setup/cleanup checks passed. See the saved preflight, topology and cleanup logs for commands and output. The user did not personally verify these checks in this session.

## Stage 2 session

- The user specified Stage 2 requirements and supplied the scope and acceptance criteria. The assistant authored the Stage 2 code, scripts, tests and documentation; verification is in progress and only saved outputs establish results.
- User-written changes: to be completed by the user.
- User verification: to be completed by the user. The user reported a Command Prompt mount error; the earlier command used PowerShell syntax.

- The assistant ran pytest, the namespace integration, packet captures, and repeat-start/stop checks. The first integration attempt failed because the client inherited IP forwarding; the script was corrected and the failed evidence archived. The first capture attempt had empty client-side traces; it was archived and capture startup synchronization was corrected. The subsequent run passed the scripted checks; consult saved evidence for actual values.
- The assistant also ran the separate repeated startup/shutdown test. No user verification or user-authored code has been reported for this session.

## Stage 3 session, 2026-11-21

- The user supplied the Stage 3 security specification. The assistant archived Stage 2 evidence and drafted separate configuration, risk-state, and security-check modules; they are incomplete and not integrated into the gateway.
- The assistant ran three initial fake-clock state tests in an isolated Ubuntu container; they passed. Complete Stage 3 tests and live security verification have not been run.
- User-written changes and user verification in this session: not reported; to be filled by the user.

## Stage 3a session, 2026-11-21

- The user requested isolated security-library work and no Stage 2 gateway modifications or namespace tests. The assistant developed library modules, fake-clock tests, lab token helper, case definitions, and documentation. The user did not report writing code or personally verifying the Stage 3a tests in this session; user contributions and verification should be completed by the user.
- An intermediate pytest run failed because assertions were placed in the wrong test; the assistant corrected the test. The final saved test output records the subsequent result. No live security verification was performed.

## Stage 3b session

- The user requested integration and live verification. The assistant archived prior evidence and drafted the triggering-ban change, ASGI peer adapter and gateway integration in a separate work-in-progress directory. The adapter and draft integration have only been tested locally; they are not deployed to the working gateway.
- An initial Windows pytest run skipped an async test because the plugin was missing; the assistant changed that test to run the coroutine explicitly. An isolated Ubuntu branch-coverage run completed; the saved report is for the pre-integration draft test run. No live Stage 3b run has been completed.
- User-authored changes and user verification during this session: not reported; to be completed by the user.

## Stage 3b phased session

- The user requested phased completion and verification. The assistant archived evidence, made a hash-verified Stage 2 gateway backup, promoted the security library and adapter, and ran their Phase 1 tests. Stage 2 gateway integration and live checks remain unfinished.
- User-written changes and personal verification in this session: not reported; user to fill in.

## Stage 3b continuation
- AI assisted with gateway HEAD support and decision logging, container tests, test coverage, and the Stage 2 start script. The integration and live verification remain incomplete.
- Student contributions and independent verification: to be completed by the student.

- Stage 3b continuation: AI updated container testing, token-based Stage 2 verification, security claim/configuration handling, and tests. Student-authored work and independent verification: student to fill in.

## Stage 4

AI assisted with observability implementation, tests, and live verification.

### Student contributions and independent verification — student to complete

Describe what you wrote, changed, and verified yourself here.
