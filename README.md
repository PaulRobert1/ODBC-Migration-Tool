# ODBC Migration Tool

A Windows PowerShell 5.1 GUI for exporting and importing **32-bit System DSNs, 64-bit System DSNs, and the current account's User DSNs** in a password-encrypted backup.

**[Download the tool (ZIP)](https://github.com/PaulRobert1/ODBC-Migration-Tool/releases/latest/download/ODBC-Migration-Tool.zip)** · [Releases](https://github.com/PaulRobert1/ODBC-Migration-Tool/releases) · [Usage guide](docs/USAGE.md) · [Test report](docs/TEST-REPORT.md)

## Quick start

1. Download the ZIP above and extract it to a local folder.
2. Open **Windows PowerShell 5.1** as the Windows account whose User DSNs you want to migrate. Run as administrator when importing System DSNs.
3. From the extracted folder, launch:

```powershell
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\ODBC-Migration-GUI.ps1
```

Choose **Export encrypted...** on the source machine, then **Import encrypted...** on the destination. Use a backup password of at least 12 characters. Install matching ODBC drivers on the destination separately.

Export includes all captured DSN registry sections; selecting a row in the grid does not restrict the export. The GUI also opens the 32-bit and 64-bit ODBC administrators.

## What it preserves

- Separate 32-bit and 64-bit machine-wide DSNs using explicit Windows registry views.
- Current-account User DSNs; other user profiles and File DSNs are not included.
- Nested registry keys and value kinds, including strings, expandable strings, multi-strings, DWORD, QWORD and binary data.
- Usernames and passwords **only when actually stored in the DSN registry**. Credential Manager, DPAPI and driver-managed credentials are not recovered; DPAPI-bound values may not work on another machine.

## Import safety

The tool validates the entire payload before registry writes, including malformed names/data, duplicate entries, section platforms, architecture and elevation requirements. Matching DSNs are replaced and unrelated entries are preserved.

Before GUI import, it creates an encrypted pre-import backup, reopens it, and compares it with the captured state. Import does not start if verification fails. Existing export files are replaced without first deleting the previous valid file.

**Import is not transactional.** An unexpected registry I/O failure or process interruption can still leave partial changes. Recovery details and the limits of merge-based restoration are in the [usage guide](docs/USAGE.md#recovery).

## Requirements

- Windows PowerShell 5.1 with Windows Forms; .NET Framework 4.7.2 or later.
- Administrator rights for System DSN imports.
- The correct x86/x64 ODBC drivers installed on the target machine.

Native testing covered two Windows Server 2019 machines, under both x86 and x64 PowerShell, including actual HKLM ODBC round trips in both views. Interactive GUI acceptance, real database connections and automatic rollback are not claimed. See the [observed test results](docs/TEST-REPORT.md).

## Encrypted format

`ODBCPACK-V1`: AES-256-CBC with PKCS7 padding, HMAC-SHA256 authentication, and separate encryption/authentication keys derived using PBKDF2-HMAC-SHA256 with 200,000 rounds. Each pack has a random salt and IV. The original independent compatibility fixture remains supported.

## Tests

```powershell
# Disposable HKCU tests; no real ODBC writes
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ODBC-Migration-SelfTest.ps1 -SkipLiveRead
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ODBC-Migration-SafetyTests.ps1

# Adds read-only enumeration of live DSNs and drivers
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ODBC-Migration-SelfTest.ps1

# Elevated, authorized test machine only: disposable DSNs in actual HKLM ODBC paths
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\HKLM-SelfTest.ps1 -ScriptPath .\ODBC-Migration-GUI.ps1
```

Repeat with `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` to exercise a 32-bit process. Each HKLM test run checks both registry views and removes its own test entries. The included encrypted fixture and its documented password contain synthetic test data only.
