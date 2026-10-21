# Changes

## Unreleased

- Add a 30-second per-domain deadline shared by CLI and GUI; CLI can override it with --deadline.
- Run network probes in a disposable spawned process so blocking OS DNS calls and HTTP reads can be stopped.
- Preserve completed-stage snapshots on timeout, mark JSON with timed_out=true, force an Inconclusive verdict and exit CLI with code 1. Always clean up worker processes and pipe-reader threads.
- Add 33 offline tests and CI for Python 3.10–3.14 on Linux, plus Python 3.12 on Windows.
- Require actual TCP/443 attempts before reporting TCP drop; a port-80-only report is inconclusive.
- Require failed TLS observations for every system-resolved address before classifying a DNS/TLS discrepancy. An untested address is not a failure.
- Compare SNI and no-SNI controls on the same IP. Successful application evidence takes priority over TCP/SNI failure samples.
- Reduce the confidence of the legacy Clean label and describe its limited evidence.
- Reject NaN/infinite timeouts; return nonzero on partial CLI failures while preserving successful JSON reports.
- Configure UTF-8 output on Windows so Russian --help works when output is redirected by CI or a shell pipeline.
- Separate CLI dependencies from optional GUI dependencies. Add Arch and Windows setup instructions, MIT license and ignore rules for generated files.
- Remove generated .pyc caches from version control; they remain recoverable from Git history.

Historical verdict labels remain unchanged for JSON compatibility. No release tag has been created; real Arch and GUI integration testing is still needed.
# Unreleased fixes

- Render external CLI text literally, preventing Rich markup errors and terminal control injection.
- Validate DoH response shapes, DNS status, address record types and families; provider failures remain isolated.
- Reject malformed DNS hostnames before starting diagnostics, with length checked after IDNA conversion.
- Show a GUI error for non-UTF-8 domain files instead of raising an unhandled callback exception.

