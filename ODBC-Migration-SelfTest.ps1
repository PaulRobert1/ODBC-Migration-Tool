#Requires -Version 5.1
<#
.SYNOPSIS
  Safe local checks for ODBC-Migration-GUI.ps1.
.DESCRIPTION
  Parses the real GUI script, loads only its function definitions (never launches
  its GUI), tests encryption and registry tree round-trips using TEMPORARY keys
  under HKCU\Software\ODBCMigrationSelfTest, and optionally reads the real ODBC
  DSN registry sections WITHOUT modifying them.

  This script does not import DSNs or change genuine ODBC configuration.
.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ODBC-Migration-SelfTest.ps1
.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ODBC-Migration-SelfTest.ps1 -SkipLiveRead
#>
param(
    [string]$ScriptPath,
    [switch]$SkipLiveRead
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
    $ScriptPath = Join-Path $PSScriptRoot 'ODBC-Migration-GUI.ps1'
}
if (-not [IO.File]::Exists($ScriptPath)) {
    throw "Script not found: $ScriptPath"
}

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([bool]$Condition, [string]$Reason)
    if (-not $Condition) { throw $Reason }
}
function Invoke-Check {
    param([string]$Name, [scriptblock]$Code)
    try {
        & $Code
        $script:passed++
        Write-Host "[PASS] $Name" -ForegroundColor Green
    } catch {
        $script:failed++
        Write-Host "[FAIL] $Name : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Windows PowerShell's REAL parser, not a text-based bracket counter.
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    ([IO.Path]::GetFullPath($ScriptPath)), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) {
    foreach ($issue in $parseErrors) {
        Write-Host "[FAIL] Parse: line $($issue.Extent.StartLineNumber): $($issue.Message)" -ForegroundColor Red
    }
    exit 1
}
$script:passed++
Write-Host '[PASS] Windows PowerShell parser reports no syntax errors' -ForegroundColor Green

# Load function definitions ONLY. This does not execute the main GUI file,
# access its application window, or trigger ODBC import/export handlers.
$needed = @(
    'Get-RegistryBase','Read-RegistryTree','Get-OdbcSnapshot','Get-NodeChild',
    'Get-DsnRows','New-RandomBytes','New-EncryptionKeys','Protect-OdbcBackup',
    'Unprotect-OdbcBackup','Test-SubkeyName','Write-RegistryTree',
    'Get-InstalledDriverNames','Get-MissingDrivers',
    'Assert-OdbcSnapshot','Assert-RegistryTree'
)
$definitions = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $needed -contains $node.Name
}, $true) | Sort-Object { $_.Extent.StartOffset })
foreach ($name in $needed) {
    if (@($definitions | Where-Object { $_.Name -eq $name }).Count -ne 1) {
        throw "Could not uniquely locate function '$name' in source script."
    }
}
$functionSource = ($definitions | ForEach-Object { $_.Extent.Text }) -join [Environment]::NewLine
. ([scriptblock]::Create($functionSource))
$script:RegPath = 'SOFTWARE\ODBC\ODBC.INI'
$script:Magic = [Text.Encoding]::ASCII.GetBytes('ODBCPACK-V1')
$script:KdfRounds = 200000

$guid = [Guid]::NewGuid().ToString('N')
$scratch = 'Software\ODBCMigrationSelfTest\' + $guid
$tempFile = Join-Path ([IO.Path]::GetTempPath()) ("odbc-selftest-$guid.odbcpack")
$tamperedFile = "$tempFile.modified"
$weakFile = "$tempFile.weak"
$badFile = "$tempFile.bad"
$secret = 'FAKE_ODBC_SECRET_' + $guid
$password = 'SelfTestOnly-' + $guid
$base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::CurrentUser,
    [Microsoft.Win32.RegistryView]::Default)
try {
    # Populate an isolated simulated ODBC tree. No genuine DSN is touched.
    $source = $base.CreateSubKey("$scratch\Source")
    try {
        $dsn = $source.CreateSubKey('Example_DSN')
        try {
            $dsn.SetValue('Server', 'localhost', [Microsoft.Win32.RegistryValueKind]::String)
            $dsn.SetValue('UID', 'fake_user', [Microsoft.Win32.RegistryValueKind]::String)
            $dsn.SetValue('PWD', $secret, [Microsoft.Win32.RegistryValueKind]::String)
            $dsn.SetValue('Blob', [byte[]]@(0,1,2,127,255), [Microsoft.Win32.RegistryValueKind]::Binary)
            $dsn.SetValue('Items', [string[]]@('First','Second'), [Microsoft.Win32.RegistryValueKind]::MultiString)
            $dsn.SetValue('Count', [int]65535, [Microsoft.Win32.RegistryValueKind]::DWord)
            $dsn.SetValue('Big', [long]9223372036854775807, [Microsoft.Win32.RegistryValueKind]::QWord)
            $dsn.SetValue('Expanded', '%TEMP%\output', [Microsoft.Win32.RegistryValueKind]::ExpandString)
        } finally { $dsn.Dispose() }
        $index = $source.CreateSubKey('ODBC Data Sources')
        try { $index.SetValue('Example_DSN', 'Fake Test Driver') }
        finally { $index.Dispose() }
        $tree = Read-RegistryTree -Key $source -Name 'ODBC.INI'
    } finally { $source.Dispose() }

    $snapshot = [pscustomobject]@{
        Format   = 'ODBCPACK-V1'
        Created  = [DateTime]::UtcNow.ToString('o')
        Computer = 'SYNTHETIC-TEST'
        Account  = 'FAKE-ACCOUNT'
        Sections = @([pscustomobject]@{
            Scope = 'User'; Platform = 'Shared'; Node = $tree
        })
    }

    Invoke-Check 'Recursive registry read: strings, binary, DWORD, QWORD, MULTI_SZ, EXPAND_SZ' {
        $node = Get-NodeChild -Node $tree -Name 'Example_DSN'
        Assert-True ($null -ne $node) 'Example_DSN missing in registry snapshot.'
        $byName = @{}
        foreach ($v in @($node.Values)) { $byName[$v.Name] = $v }
        Assert-True ($byName['PWD'].Data -ceq $secret) 'Stored credential field was not captured.'
        Assert-True ($byName['Blob'].Kind -eq 'Binary') 'Binary type changed.'
        Assert-True ($byName['Items'].Kind -eq 'MultiString') 'MultiString type changed.'
        Assert-True (@($byName['Items'].Data).Count -eq 2) 'MultiString entries lost.'
        Assert-True ($byName['Big'].Data -eq '9223372036854775807') 'QWORD precision lost.'
        Assert-True ($byName['Expanded'].Data -eq '%TEMP%\output') 'Expandable value was expanded.'
    }

    Invoke-Check 'DSN enumeration and detection of stored password-like fields' {
        $rows = @(Get-DsnRows -Snapshot $snapshot)
        Assert-True ($rows.Count -eq 1) "Expected 1 DSN, got $($rows.Count)."
        Assert-True ($rows[0].Name -eq 'Example_DSN') 'Unexpected DSN name.'
        Assert-True ($rows[0].Driver -eq 'Fake Test Driver') 'Unexpected driver mapping.'
        Assert-True ($rows[0].Credential -eq 'Field present') 'Stored PWD field not detected.'
    }

    Invoke-Check 'Registry import: replaces matching DSN, preserves unrelated entries' {
        $dest = $base.CreateSubKey("$scratch\Destination")
        try {
            $old = $dest.CreateSubKey('Example_DSN')
            try { $old.SetValue('Obsolete', 'should_disappear') }
            finally { $old.Dispose() }
            $unrelated = $dest.CreateSubKey('Keep_This_DSN')
            try { $unrelated.SetValue('Server', 'unrelated-host') }
            finally { $unrelated.Dispose() }
            $destIndex = $dest.CreateSubKey('ODBC Data Sources')
            try { $destIndex.SetValue('Keep_This_DSN', 'Unrelated Test Driver') }
            finally { $destIndex.Dispose() }
            Write-RegistryTree -Key $dest -Tree $tree -Root $true
            $restored = $dest.OpenSubKey('Example_DSN')
            try {
                Assert-True ($restored.GetValue('Obsolete') -eq $null) 'Stale DSN attribute was not removed.'
                Assert-True ($restored.GetValue('PWD') -ceq $secret) 'Credential field not restored.'
                Assert-True ($restored.GetValueKind('Blob') -eq [Microsoft.Win32.RegistryValueKind]::Binary) 'Binary kind not preserved.'
                Assert-True ([Convert]::ToBase64String($restored.GetValue('Blob')) -eq 'AAECf/8=') 'Binary bytes changed.'
                Assert-True ($restored.GetValueKind('Items') -eq [Microsoft.Win32.RegistryValueKind]::MultiString) 'MULTI_SZ kind not preserved.'
                Assert-True (@($restored.GetValue('Items')).Count -eq 2) 'MULTI_SZ content changed.'
                Assert-True ([long]$restored.GetValue('Big') -eq [long]::MaxValue) 'QWORD not restored.'
                Assert-True ($restored.GetValue('Expanded', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) -eq '%TEMP%\output') 'Expandable raw value changed.'
            } finally { if ($null -ne $restored) { $restored.Dispose() } }
            $kept = $dest.OpenSubKey('Keep_This_DSN')
            try { Assert-True ($kept.GetValue('Server') -eq 'unrelated-host') 'Unrelated DSN was overwritten.' }
            finally { if ($null -ne $kept) { $kept.Dispose() } }
            $indexRestored = $dest.OpenSubKey('ODBC Data Sources')
            try {
                Assert-True ($indexRestored.GetValue('Keep_This_DSN') -eq 'Unrelated Test Driver') 'Unrelated DSN index lost.'
                Assert-True ($indexRestored.GetValue('Example_DSN') -eq 'Fake Test Driver') 'Restored DSN index missing.'
            } finally { if ($null -ne $indexRestored) { $indexRestored.Dispose() } }
        } finally { $dest.Dispose() }
    }

    # This fixture was independently generated using Python's cryptography
    # library to the documented ODBCPACK-V1 wire format (not PowerShell code).
    $fixturePath = Join-Path $PSScriptRoot 'ODBC-Synthetic-Test.odbcpack'
    if ([IO.File]::Exists($fixturePath)) {
        Invoke-Check 'Decrypt independent AES/PBKDF2/HMAC compatibility fixture' {
            $fixture = Unprotect-OdbcBackup -Password 'TestFixture-Password-2026!' -Path $fixturePath
            $synthetic = Get-NodeChild -Node $fixture.Sections[0].Node -Name 'Synthetic_DSN'
            Assert-True ($null -ne $synthetic) 'Independent fixture did not decrypt correctly.'
            $value = @($synthetic.Values | Where-Object { $_.Name -eq 'PWD' })
            Assert-True ($value.Count -eq 1 -and $value[0].Data -ceq 'FAKE_PASSWORD_NOT_REAL') 'Independent fixture contents changed.'
        }
    }

    Invoke-Check 'Encrypted .odbcpack round trip, including fake stored password' {
        Protect-OdbcBackup -Snapshot $snapshot -Password $password -Path $tempFile
        $loaded = Unprotect-OdbcBackup -Password $password -Path $tempFile
        $node = Get-NodeChild -Node $loaded.Sections[0].Node -Name 'Example_DSN'
        $pwd = @($node.Values | Where-Object { $_.Name -eq 'PWD' })
        Assert-True ($pwd.Count -eq 1 -and $pwd[0].Data -ceq $secret) 'Failed round-trip of stored password field.'
        Assert-True ($loaded.Sections[0].Scope -eq 'User') 'Section type changed.'
    }

    Invoke-Check 'Encrypted file does not contain plaintext DSN credentials' {
        $bytes = [IO.File]::ReadAllBytes($tempFile)
        $asText = [Text.Encoding]::UTF8.GetString($bytes)
        Assert-True (-not $asText.Contains($secret)) 'The test password appears in ciphertext.'
        Assert-True (-not $asText.Contains('fake_user')) 'The user name appears in ciphertext.'
    }

    Invoke-Check 'Incorrect backup password fails authentication' {
        $rejected = $false
        try { $null = Unprotect-OdbcBackup -Password 'not-the-password' -Path $tempFile }
        catch { $rejected = $true }
        Assert-True $rejected 'Wrong password was accepted.'
    }

    Invoke-Check 'Modified .odbcpack bytes fail authentication' {
        $bytes = [IO.File]::ReadAllBytes($tempFile)
        $offset = $bytes.Length - 40
        $bytes[$offset] = [byte]([int]$bytes[$offset] -bxor 1)
        [IO.File]::WriteAllBytes($tamperedFile, $bytes)
        $rejected = $false
        try { $null = Unprotect-OdbcBackup -Password $password -Path $tamperedFile }
        catch { $rejected = $true }
        Assert-True $rejected 'Tampered encrypted backup was accepted.'
    }

    Invoke-Check 'Short encryption password is rejected' {
        $rejected = $false
        try { Protect-OdbcBackup -Snapshot $snapshot -Password 'short' -Path $weakFile }
        catch { $rejected = $true }
        Assert-True $rejected 'Backup accepted a password shorter than 12 characters.'
    }

    Invoke-Check 'Malformed or duplicated backup sections are rejected' {
        $invalid = [pscustomobject]@{
            Format = 'ODBCPACK-V1'
            Sections = @($snapshot.Sections[0], $snapshot.Sections[0])
        }
        Protect-OdbcBackup -Snapshot $invalid -Password $password -Path $badFile
        $rejected = $false
        try { $null = Unprotect-OdbcBackup -Password $password -Path $badFile }
        catch { $rejected = $true }
        Assert-True $rejected 'Duplicate backup sections were accepted.'
    }

    Invoke-Check 'Malicious registry subkey paths are rejected' {
        foreach ($name in @('..\Outside', 'x/y', '')) {
            $rejected = $false
            try { Test-SubkeyName -Name $name }
            catch { $rejected = $true }
            Assert-True $rejected "Invalid subkey '$name' was accepted."
        }
    }

    if (-not $SkipLiveRead) {
        Invoke-Check 'Live ODBC DSNs can be enumerated (READ ONLY; not displayed)' {
            $actual = Get-OdbcSnapshot
            $expected = if ([Environment]::Is64BitOperatingSystem) { 3 } else { 2 }
            Assert-True (@($actual.Sections).Count -eq $expected) 'Unexpected system/user registry section count.'
            $null = @(Get-DsnRows -Snapshot $actual)
            $null = @(Get-MissingDrivers -Snapshot $actual)
        }
    }
} finally {
    foreach ($file in @($tempFile,$tamperedFile,$weakFile,$badFile)) {
        if ([IO.File]::Exists($file)) { [IO.File]::Delete($file) }
    }
    try {
        # Only delete our per-test key, NOT any ODBC\ODBC.INI key.
        $base.DeleteSubKeyTree($scratch, $false)
    } catch {
        Write-Warning "Could not remove temporary test key HKCU\$scratch : $($_.Exception.Message)"
    }
    $base.Dispose()
}
Write-Host ("`nRESULT: {0} PASS; {1} FAIL" -f $script:passed, $script:failed)
if ($script:failed -gt 0) { exit 1 }
exit 0
