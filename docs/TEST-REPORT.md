# Verification report

Tested on 2026-10-27 using native Windows PowerShell 5.1 on two Windows Server 2019 x64 machines. Server A used Datacenter with PowerShell 5.1.17763.8510; Server B used Standard with PowerShell 5.1.17763.8024.

| Machine | Process | Safety regressions | Isolated round trips | Live read suite | Actual HKLM suite |
|---|---|---:|---:|---:|---:|
| Server A | x64 | 20 passed | 12 passed | 13 passed | 14 passed |
| Server A | x86 | 20 passed | 12 passed | 13 passed | 14 passed |
| Server B | x64 | 20 passed | 12 passed | 13 passed | 14 passed |
| Server B | x86 | 20 passed | 12 passed | 13 passed | 14 passed |

**236 successful checks across 16 suite invocations; zero failures.** These counts include repeated checks across environments, not 236 distinct test cases. Uploaded script hashes matched the release files and remote staging cleanup succeeded on both servers.

## Coverage and fixes

The original implementation reproduced partial writes when a later payload entry was invalid. Complete payload and target validation now runs before import writes. Regression cases include malformed paths, duplicate names and sections, invalid value data and scalar metadata, and valid deeply nested keys.

Actual HKLM tests created disposable synthetic DSNs in both Registry32 and Registry64 views from each process architecture. They verified exact value types and data, DSN index restoration, replacement of matching definitions, preservation of unrelated data, distinct same-name x86/x64 DSNs, and cleanup. Pre-existing ODBC contents were compared and preserved.

Encrypted round trips, independent format compatibility, wrong passwords and tampering were tested. Safety-backup corruption and payload mismatch prevented import. Export replacement preserved an existing backup when final commit failure was injected; native successful replacement also passed. Fault injection used an in-memory test copy of the function. Native ACL-based failure attempts were inconclusive and are not claimed as proof of that failure path.

## Limits

Interactive GUI acceptance and connections to real databases were not tested. Driver installation and external credential migration are outside scope. Import has no transaction or automatic rollback for unexpected registry I/O failure or interruption. Tests used synthetic credentials; no homelab credentials or registry exports are included in this repository.

## Reproduce

See the commands in [README](../README.md#tests). The supplied test scripts exercise disposable registry entries; the HKLM suite requires elevation on an authorized test machine. The compatibility fixture contains synthetic data and uses password `TestFixture-Password-2026!`.
