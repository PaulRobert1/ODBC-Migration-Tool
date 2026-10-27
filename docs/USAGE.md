# Usage guide

## Download and launch

Download [ODBC-Migration-Tool.zip](https://github.com/PaulRobert1/ODBC-Migration-Tool/releases/latest/download/ODBC-Migration-Tool.zip), extract it, and open Windows PowerShell 5.1 in that folder. If Windows has blocked the downloaded scripts, unblock those files after reviewing their origin:

```powershell
Get-ChildItem -Path .\*.ps1 | Unblock-File
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\ODBC-Migration-GUI.ps1
```

The execution-policy option applies to this launch. It does not change the machine's execution policy. Use Windows PowerShell 5.1; PowerShell 7 is not the verified runtime for this tool.

To import System DSNs, open PowerShell with **Run as administrator**. Use the same account whose User DSNs you need: elevating with a different account changes which HKCU profile is accessed.

## Export on the source machine

1. Launch the GUI and use **Refresh** to inspect the DSN list.
2. Choose **Export encrypted...** and select a `.odbcpack` destination.
3. Enter and confirm a password of at least 12 characters.
4. Wait for the completion message and retain the password separately from the file.

The export captures all available 32-bit/64-bit System DSN sections and current-account User DSNs. Grid selection does not filter the export. Password-like fields are indicated without displaying their contents.

Transfer the encrypted file to the destination through your normal approved method. ODBC drivers are not included. The tool does not recover external credentials; drivers or applications may prompt for them again.

## Import on the destination machine

1. Install the matching ODBC drivers, with the required 32-bit and/or 64-bit architecture.
2. Launch the tool under the intended account, elevated if the pack contains System DSNs.
3. Choose **Import encrypted...**, select the pack, and enter its password.
4. Review the DSN count and missing-driver notice, then confirm import.
5. The tool captures the destination state, writes a uniquely named `ODBC-before-import-...odbcpack` in Documents (or the profile folder when Documents is unavailable), authenticates it and compares its contents with the capture.
6. After verification, it imports the pack. Keep the displayed backup path and the same password for recovery.
7. Open **ODBC 32-bit** or **ODBC 64-bit** to inspect the result and test connections using the appropriate installed driver/application.

Matching DSN definitions are replaced, including removal of obsolete attributes. Unrelated DSNs and index entries are preserved. A wrong password, tampered pack or malformed registry payload is rejected before import writes.

## Recovery

Import is a merge, not a transaction. Unexpected registry access failures, concurrent changes or an interrupted process can leave a partial import even when input validation passed.

After resolving the failure, use **Import encrypted...** to import the verified pre-import backup with the same password. This restores captured definitions for matching DSNs. It does **not** remove DSNs newly introduced by the failed import; remove those only after independently confirming they were absent before the operation. Do not treat this as an automatic rollback guarantee.

If the password is lost, this tool cannot decrypt the backup or recover it. Keep the pack and password available for your recovery procedure.

## Common errors

| Symptom | Action |
|---|---|
| Administrator rights required | Reopen Windows PowerShell elevated as the intended account. |
| Wrong password or modified/corrupted backup | Check the password and file integrity; obtain a clean copy of the pack. |
| Invalid backup payload | Use an original valid export. Do not bypass validation to force registry writes. |
| Safety backup verification fails | Import has not started. Check destination storage/access and retry with a valid backup location. |
| Export replacement fails | The previous valid destination is not deliberately deleted. Check filesystem support, file locks and permissions. |
| Missing driver warning | Install the correct driver and architecture; the tool does not install it. |
| Connection fails after migration | Check driver availability, server/network settings and any externally stored credentials. A registry round trip is not a database-login test. |

## Verify a download

Each release includes a ZIP checksum file and `SHA256SUMS` inside the ZIP. To calculate the downloaded ZIP hash:

```powershell
Get-FileHash .\ODBC-Migration-Tool.zip -Algorithm SHA256
```

Compare it with `ODBC-Migration-Tool.zip.sha256` from the same release. Compare extracted file hashes with the corresponding entries in `SHA256SUMS` if needed.
