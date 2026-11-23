# Stage 6 status

## M1 — design and harness in progress

- Read the requested design and prior-stage documents, Stage 3 case definitions and topology and case scripts. No previous Stage 6 status was present. `docs/experiments.md` records the proposed definitions before any experiment runs.
- `evidence/experiments/stage6_capability_probe.txt` records a real container probe: installed `tc` rejects `netem ... seed`, and `command -v ethtool` exits 1. The `nstat` executable is present. Seeded netem and offload collection therefore need an explicitly documented workable approach before the harness can satisfy the design.
- M1 is incomplete: scripts, tests and saved pytest output are not yet built. No pilot or full experiment has been run.
- Added preliminary `scripts/sg-stage6-netem.sh` and `scripts/sg-stage6-address.sh`; these helpers have not yet been tested. The netem helper currently omits a seed because the installed `tc` rejected that option. The remaining M1 harness and tests are outstanding.
