#Requires -Version 5.1
<#
.SYNOPSIS
  Secure ODBC DSN export/import GUI for Windows (32-bit and 64-bit system DSNs,
  plus the current Windows user's DSNs).

.DESCRIPTION
  Saves the ODBC.INI registry trees, including any credentials actually stored
  as registry values, into a password-encrypted .odbcpack file.

  This does NOT recover passwords held in Windows Credential Manager, DPAPI
  stores, or proprietary driver storage. It does NOT copy/install ODBC drivers
  or File DSNs (*.dsn). DPAPI-bound registry values may not work on a new host.

  Encrypted file: magic + random salt + random IV + AES-256-CBC ciphertext
  + HMAC-SHA256, with independent keys from PBKDF2-HMAC-SHA256 (200,000 rounds).
  No plaintext .reg, .json, or password file is written to disk.

.NOTES
  Run with Windows PowerShell 5.1 and .NET Framework 4.7.2+ on Windows.
  Run elevated as the SAME Windows user whose User DSNs are to be copied.
  Import merges with existing DSNs, replacing registry values for matching DSNs.
  Export/import is limited to current-user DSNs and machine-wide System DSNs.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
    [void][System.Windows.Forms.MessageBox]::Show(
        'Start PowerShell with -STA and try again.', 'ODBC Migration',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error)
    return
}

$script:RegPath = 'SOFTWARE\ODBC\ODBC.INI'
$script:Magic = [System.Text.Encoding]::ASCII.GetBytes('ODBCPACK-V1')
$script:KdfRounds = 200000

function Test-IsAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RegistryBase {
    param(
        [ValidateSet('System', 'User')][string]$Scope,
        [ValidateSet('32-bit', '64-bit', 'Shared')][string]$Platform
    )
    $hive = if ($Scope -eq 'System') {
        [Microsoft.Win32.RegistryHive]::LocalMachine
    } else {
        [Microsoft.Win32.RegistryHive]::CurrentUser
    }
    $view = if ($Scope -eq 'System' -and $Platform -eq '32-bit') {
        [Microsoft.Win32.RegistryView]::Registry32
    } elseif ([System.Environment]::Is64BitOperatingSystem) {
        [Microsoft.Win32.RegistryView]::Registry64
    } else {
        [Microsoft.Win32.RegistryView]::Registry32
    }
    return [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
}

function Read-RegistryTree {
    param(
        [Microsoft.Win32.RegistryKey]$Key,
        [string]$Name
    )
    $values = New-Object 'System.Collections.Generic.List[object]'
    $subkeys = New-Object 'System.Collections.Generic.List[object]'

    foreach ($valueName in $Key.GetValueNames()) {
        $kind = $Key.GetValueKind($valueName)
        $raw = $Key.GetValue(
            $valueName, $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $kindString = $kind.ToString()
        switch ($kindString) {
            { $_ -in @('Binary', 'None', 'Unknown') } {
                $bytes = if ($null -eq $raw) { [byte[]]@() } else { [byte[]]$raw }
                $data = [Convert]::ToBase64String($bytes)
                break
            }
            'MultiString' {
                $data = @([string[]]$raw)
                break
            }
            default {
                # All scalar values are serialized as strings, avoiding JSON
                # precision loss for REG_QWORD and preserving expandable text.
                $data = [string]$raw
            }
        }
        $values.Add([pscustomobject]@{
            Name = [string]$valueName
            Kind = $kindString
            Data = $data
        })
    }

    foreach ($childName in $Key.GetSubKeyNames()) {
        $childKey = $Key.OpenSubKey($childName, $false)
        try {
            if ($null -ne $childKey) {
                $subkeys.Add((Read-RegistryTree -Key $childKey -Name $childName))
            }
        } finally {
            if ($null -ne $childKey) { $childKey.Dispose() }
        }
    }

    return [pscustomobject]@{
        Name    = $Name
        Values  = @($values.ToArray())
        Subkeys = @($subkeys.ToArray())
    }
}

function Get-OdbcSnapshot {
    $sections = New-Object 'System.Collections.Generic.List[object]'
    $descriptors = @(
        [pscustomobject]@{ Scope='System'; Platform='32-bit' },
        [pscustomobject]@{ Scope='User'; Platform='Shared' }
    )
    if ([System.Environment]::Is64BitOperatingSystem) {
        $descriptors = @(
            [pscustomobject]@{ Scope='System'; Platform='64-bit' }
        ) + $descriptors
    }
    foreach ($descriptor in $descriptors) {
        $base = Get-RegistryBase -Scope $descriptor.Scope -Platform $descriptor.Platform
        try {
            $key = $base.OpenSubKey($script:RegPath, $false)
            try {
                $tree = if ($null -ne $key) {
                    Read-RegistryTree -Key $key -Name 'ODBC.INI'
                } else { $null }
            } finally {
                if ($null -ne $key) { $key.Dispose() }
            }
        } finally {
            $base.Dispose()
        }
        $sections.Add([pscustomobject]@{
            Scope    = $descriptor.Scope
            Platform = $descriptor.Platform
            Node     = $tree
        })
    }
    return [pscustomobject]@{
        Format    = 'ODBCPACK-V1'
        Created   = [DateTime]::UtcNow.ToString('o')
        Computer  = $env:COMPUTERNAME
        Account   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Sections  = @($sections.ToArray())
    }
}

function Get-NodeChild {
    param($Node, [string]$Name)
    if ($null -eq $Node) { return $null }
    foreach ($child in @($Node.Subkeys)) {
        if ([string]$child.Name -ieq $Name) { return $child }
    }
    return $null
}

function Get-DsnRows {
    param($Snapshot)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($section in @($Snapshot.Sections)) {
        if ($null -eq $section.Node) { continue }
        $mapping = @{}
        $index = Get-NodeChild -Node $section.Node -Name 'ODBC Data Sources'
        if ($null -ne $index) {
            foreach ($entry in @($index.Values)) {
                $mapping[[string]$entry.Name] = [string]$entry.Data
            }
        }
        $seen = @{}
        foreach ($dsnKey in @($section.Node.Subkeys)) {
            $dsnName = [string]$dsnKey.Name
            if ($dsnName -ieq 'ODBC Data Sources') { continue }
            $seen[$dsnName] = $true
            $driver = if ($mapping.ContainsKey($dsnName)) {
                $mapping[$dsnName]
            } else {
                $driverEntry = @($dsnKey.Values | Where-Object { $_.Name -ieq 'Driver' } | Select-Object -First 1)
                if ($driverEntry.Count -gt 0) { [string]$driverEntry[0].Data } else { '(unregistered)' }
            }
            $hasPasswordField = $false
            foreach ($value in @($dsnKey.Values)) {
                if ($value.Name -match '(?i)(pass|pwd|secret|token)' -and
                    $null -ne $value.Data -and [string]$value.Data -ne '') {
                    $hasPasswordField = $true
                    break
                }
            }
            $rows.Add([pscustomobject]@{
                Scope      = [string]$section.Scope
                Platform   = [string]$section.Platform
                Name       = $dsnName
                Driver     = $driver
                Credential = if ($hasPasswordField) { 'Field present' } else { 'Not in DSN' }
            })
        }
        foreach ($name in $mapping.Keys) {
            if ($seen.ContainsKey($name)) { continue }
            $rows.Add([pscustomobject]@{
                Scope      = [string]$section.Scope
                Platform   = [string]$section.Platform
                Name       = $name
                Driver     = $mapping[$name]
                Credential = 'No DSN settings key'
            })
        }
    }
    return $rows.ToArray()
}

function New-RandomBytes {
    param([int]$Count)
    $data = New-Object byte[] $Count
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($data) } finally { $rng.Dispose() }
    return ,$data
}

function New-EncryptionKeys {
    param([string]$Password, [byte[]]$Salt)
    $kdf = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
        $Password, $Salt, $script:KdfRounds,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try {
        $keyMaterial = $kdf.GetBytes(64)
    } finally {
        $kdf.Dispose()
    }
    $enc = New-Object byte[] 32
    $mac = New-Object byte[] 32
    [Buffer]::BlockCopy($keyMaterial, 0, $enc, 0, 32)
    [Buffer]::BlockCopy($keyMaterial, 32, $mac, 0, 32)
    [Array]::Clear($keyMaterial, 0, $keyMaterial.Length)
    return [pscustomobject]@{ Encrypt=$enc; Authenticate=$mac }
}

function Protect-OdbcBackup {
    param([object]$Snapshot, [string]$Password, [string]$Path)
    if ([string]::IsNullOrWhiteSpace($Password) -or $Password.Length -lt 12) {
        throw 'The backup password must contain at least 12 characters.'
    }
    $json = $Snapshot | ConvertTo-Json -Depth 100 -Compress
    $plain = [System.Text.Encoding]::UTF8.GetBytes($json)
    $salt = New-RandomBytes -Count 16
    $iv = New-RandomBytes -Count 16
    $keys = New-EncryptionKeys -Password $Password -Salt $salt
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $keys.Encrypt
        $aes.IV = $iv
        $transform = $aes.CreateEncryptor()
        try { $cipher = $transform.TransformFinalBlock($plain, 0, $plain.Length) }
        finally { $transform.Dispose() }
    } finally {
        $aes.Dispose()
        [Array]::Clear($plain, 0, $plain.Length)
    }
    $stream = New-Object System.IO.MemoryStream
    try {
        $stream.Write($script:Magic, 0, $script:Magic.Length)
        $stream.Write($salt, 0, $salt.Length)
        $stream.Write($iv, 0, $iv.Length)
        $stream.Write($cipher, 0, $cipher.Length)
        $body = $stream.ToArray()
    } finally { $stream.Dispose() }
    $hmac = [System.Security.Cryptography.HMACSHA256]::new([byte[]]$keys.Authenticate)
    try { $tag = $hmac.ComputeHash($body) } finally { $hmac.Dispose() }
    [Array]::Clear($keys.Encrypt, 0, $keys.Encrypt.Length)
    [Array]::Clear($keys.Authenticate, 0, $keys.Authenticate.Length)

    $output = New-Object byte[] ($body.Length + $tag.Length)
    [Buffer]::BlockCopy($body, 0, $output, 0, $body.Length)
    [Buffer]::BlockCopy($tag, 0, $output, $body.Length, $tag.Length)
    $temporary = "$Path.partial-$PID"
    try {
        [System.IO.File]::WriteAllBytes($temporary, $output)
        if ([System.IO.File]::Exists($Path)) {
            # Replace on the same volume; never delete the last valid backup
            # before committing its replacement. Do not fall back to deletion.
            [System.IO.File]::Replace($temporary, $Path, [System.Management.Automation.Language.NullString]::Value)
        } else {
            [System.IO.File]::Move($temporary, $Path)
        }
    } finally {
        if ([System.IO.File]::Exists($temporary)) { [System.IO.File]::Delete($temporary) }
    }
}

function Unprotect-OdbcBackup {
    param([string]$Password, [string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $minimum = $script:Magic.Length + 16 + 16 + 16 + 32
    if ($bytes.Length -lt $minimum -or $bytes.Length -gt 104857600) {
        throw 'Invalid ODBC backup size.'
    }
    for ($i=0; $i -lt $script:Magic.Length; $i++) {
        if ($bytes[$i] -ne $script:Magic[$i]) { throw 'Unsupported ODBC backup format.' }
    }
    $salt = New-Object byte[] 16
    $iv = New-Object byte[] 16
    [Buffer]::BlockCopy($bytes, $script:Magic.Length, $salt, 0, 16)
    [Buffer]::BlockCopy($bytes, $script:Magic.Length + 16, $iv, 0, 16)
    $bodyLength = $bytes.Length - 32
    $body = New-Object byte[] $bodyLength
    [Buffer]::BlockCopy($bytes, 0, $body, 0, $bodyLength)
    $tag = New-Object byte[] 32
    [Buffer]::BlockCopy($bytes, $bodyLength, $tag, 0, 32)
    $keys = New-EncryptionKeys -Password $Password -Salt $salt
    try {
        $hmac = [System.Security.Cryptography.HMACSHA256]::new([byte[]]$keys.Authenticate)
        try { $expected = $hmac.ComputeHash($body) } finally { $hmac.Dispose() }
        $difference = 0
        for ($i=0; $i -lt 32; $i++) {
            $difference = $difference -bor ([int]$tag[$i] -bxor [int]$expected[$i])
        }
        if ($difference -ne 0) {
            throw 'Wrong password or modified/corrupted backup.'
        }
        $cipherStart = $script:Magic.Length + 32
        $cipherLen = $bodyLength - $cipherStart
        $aes = [System.Security.Cryptography.Aes]::Create()
        try {
            $aes.KeySize = 256
            $aes.BlockSize = 128
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aes.Key = $keys.Encrypt
            $aes.IV = $iv
            $decryptor = $aes.CreateDecryptor()
            try { $plain = $decryptor.TransformFinalBlock($bytes, $cipherStart, $cipherLen) }
            finally { $decryptor.Dispose() }
        } finally { $aes.Dispose() }
        try {
            $json = [System.Text.Encoding]::UTF8.GetString($plain)
            try { $snapshot = $json | ConvertFrom-Json }
            catch { throw 'Invalid JSON content in ODBC backup.' }
        } finally {
            [Array]::Clear($plain, 0, $plain.Length)
        }
    } finally {
        [Array]::Clear($keys.Encrypt, 0, $keys.Encrypt.Length)
        [Array]::Clear($keys.Authenticate, 0, $keys.Authenticate.Length)
    }
    Assert-OdbcSnapshot -Snapshot $snapshot
    return $snapshot
}

function Test-SubkeyName {
    param([string]$Name)
    if ([string]::IsNullOrEmpty($Name) -or $Name.Length -gt 255 -or
        $Name -match '[\\/]' -or $Name.IndexOf([char]0) -ge 0) {
        throw "Invalid registry subkey name in backup."
    }
}

function Assert-RegistryTree {
    param($Tree, [int]$Depth = 0)
    if ($null -eq $Tree -or $Depth -gt 100 -or
        $Tree.Name -isnot [string] -or $Tree.Values -isnot [array] -or
        $Tree.Subkeys -isnot [array]) { throw 'Malformed registry tree in backup.' }
    Test-SubkeyName -Name $Tree.Name
    $names = @{}
    foreach ($entry in $Tree.Values) {
        if ($null -eq $entry -or $entry.Name -isnot [string] -or
            $entry.Name.Length -gt 16383 -or $entry.Name.IndexOf([char]0) -ge 0 -or
            $entry.Kind -isnot [string]) { throw 'Invalid registry value in backup.' }
        if ($names.ContainsKey($entry.Name)) { throw 'Duplicate registry value in backup.' }
        $names[$entry.Name] = $true
        # Validate all conversions before SetValue can run. Do not include
        # supplied data in errors: registry values may contain credentials.
        try {
            switch ($entry.Kind) {
                { $_ -in @('String','ExpandString') } {
                    if ($entry.Data -isnot [string]) { throw 'Invalid string.' }
                }
                'MultiString' {
                    if ($entry.Data -isnot [array]) { throw 'Invalid array.' }
                    foreach ($item in $entry.Data) {
                        if ($item -isnot [string] -or $item.IndexOf([char]0) -ge 0) { throw 'Invalid string array.' }
                    }
                }
                'DWord' {
                    if ($entry.Data -isnot [string]) { throw 'Invalid integer.' }
                    $null = [int]::Parse($entry.Data, [Globalization.CultureInfo]::InvariantCulture)
                }
                'QWord' {
                    if ($entry.Data -isnot [string]) { throw 'Invalid integer.' }
                    $null = [long]::Parse($entry.Data, [Globalization.CultureInfo]::InvariantCulture)
                }
                { $_ -in @('Binary','None','Unknown') } {
                    if ($entry.Data -isnot [string]) { throw 'Invalid bytes.' }
                    $null = [Convert]::FromBase64String($entry.Data)
                }
                default { throw 'Invalid kind.' }
            }
        } catch { throw 'Invalid registry value type or data in backup.' }
    }
    $children = @{}
    foreach ($child in $Tree.Subkeys) {
        if ($null -eq $child -or $child.Name -isnot [string]) { throw 'Invalid registry child in backup.' }
        if ($children.ContainsKey($child.Name)) { throw 'Duplicate registry child in backup.' }
        $children[$child.Name] = $true
        Assert-RegistryTree -Tree $child -Depth ($Depth + 1)
    }
}

function Assert-OdbcSnapshot {
    param($Snapshot)
    # The catch also sanitizes missing-property errors under StrictMode.
    try {
        if ($null -eq $Snapshot -or $Snapshot.Format -isnot [string] -or $Snapshot.Format -cne 'ODBCPACK-V1' -or
            $Snapshot.Sections -isnot [array] -or
            $Snapshot.Sections.Count -lt 1 -or $Snapshot.Sections.Count -gt 3) {
            throw 'Invalid envelope.'
        }
        $ids = @{}
        foreach ($section in $Snapshot.Sections) {
            if ($null -eq $section -or $section.Scope -isnot [string] -or
                $section.Platform -isnot [string] -or $section.Scope -notin @('System','User')) { throw 'Invalid scope.' }
            if (($section.Scope -eq 'System' -and $section.Platform -notin @('32-bit','64-bit')) -or
                ($section.Scope -eq 'User' -and $section.Platform -ne 'Shared')) { throw 'Invalid platform.' }
            $id = "$($section.Scope):$($section.Platform)"
            if ($ids.ContainsKey($id)) { throw 'Duplicate section.' }
            $ids[$id] = $true
            if ($null -ne $section.Node) {
                if ($section.Node.Name -ne 'ODBC.INI') { throw 'Invalid root.' }
                Assert-RegistryTree -Tree $section.Node
            }
        }
    } catch { throw 'Invalid ODBC backup payload. No registry changes were made by validation.' }
}

function Assert-OdbcImportTarget {
    param($Snapshot)
    Assert-OdbcSnapshot -Snapshot $Snapshot
    foreach ($section in $Snapshot.Sections) {
        if ($null -eq $section.Node -or $section.Scope -ne 'System') { continue }
        if ($section.Platform -eq '64-bit' -and -not [Environment]::Is64BitOperatingSystem) {
            throw 'Cannot import 64-bit System DSNs onto a 32-bit Windows installation.'
        }
        if (-not (Test-IsAdministrator)) {
            throw 'Administrator rights required to restore System DSNs.'
        }
    }
}

function Save-VerifiedOdbcBackup {
    param($Snapshot, [string]$Password, [string]$Path)
    Assert-OdbcSnapshot -Snapshot $Snapshot
    Protect-OdbcBackup -Snapshot $Snapshot -Password $Password -Path $Path
    $verified = Unprotect-OdbcBackup -Password $Password -Path $Path
    $expected = ConvertTo-Json -InputObject $Snapshot -Depth 100 -Compress
    $actual = ConvertTo-Json -InputObject $verified -Depth 100 -Compress
    if ($expected -cne $actual) { throw 'Encrypted safety backup verification failed. Import was not started.' }
}

function Write-RegistryTree {
    param(
        [Microsoft.Win32.RegistryKey]$Key,
        $Tree,
        [bool]$Root = $false
    )
    if ($Root) { Assert-RegistryTree -Tree $Tree }
    foreach ($entry in @($Tree.Values)) {
        $name = [string]$entry.Name
        $kind = [string]$entry.Kind
        switch ($kind) {
            'String'       { $value = [string]$entry.Data; $type = [Microsoft.Win32.RegistryValueKind]::String }
            'ExpandString' { $value = [string]$entry.Data; $type = [Microsoft.Win32.RegistryValueKind]::ExpandString }
            'MultiString'  { $value = [string[]]@($entry.Data); $type = [Microsoft.Win32.RegistryValueKind]::MultiString }
            'DWord'        { $value = [int]::Parse([string]$entry.Data, [Globalization.CultureInfo]::InvariantCulture); $type = [Microsoft.Win32.RegistryValueKind]::DWord }
            'QWord'        { $value = [long]::Parse([string]$entry.Data, [Globalization.CultureInfo]::InvariantCulture); $type = [Microsoft.Win32.RegistryValueKind]::QWord }
            'Binary'       { $value = [Convert]::FromBase64String([string]$entry.Data); $type = [Microsoft.Win32.RegistryValueKind]::Binary }
            'None'         { $value = [Convert]::FromBase64String([string]$entry.Data); $type = [Microsoft.Win32.RegistryValueKind]::None }
            'Unknown'      { $value = [Convert]::FromBase64String([string]$entry.Data); $type = [Microsoft.Win32.RegistryValueKind]::Binary }
            default        { throw 'Unknown registry value type in backup.' }
        }
        $Key.SetValue($name, $value, $type)
    }
    foreach ($child in @($Tree.Subkeys)) {
        $name = [string]$child.Name
        Test-SubkeyName -Name $name
        # Replace an existing DSN's key so obsolete attributes do not survive.
        # ODBC Data Sources is the index: merge it and preserve unrelated DSNs.
        if ($Root -and $name -ine 'ODBC Data Sources') {
            $existing = $Key.OpenSubKey($name, $false)
            if ($null -ne $existing) {
                $existing.Dispose()
                $Key.DeleteSubKeyTree($name, $false)
            }
        }
        $newKey = $Key.CreateSubKey($name)
        try { Write-RegistryTree -Key $newKey -Tree $child -Root $false }
        finally { $newKey.Dispose() }
    }
}

function Import-OdbcSnapshot {
    param($Snapshot)
    Assert-OdbcImportTarget -Snapshot $Snapshot
    foreach ($section in @($Snapshot.Sections)) {
        if ($null -eq $section.Node) { continue }
        if ($section.Scope -eq 'System' -and $section.Platform -eq '64-bit' -and
            -not [System.Environment]::Is64BitOperatingSystem) {
            throw 'Cannot import 64-bit System DSNs onto a 32-bit Windows installation.'
        }
        $base = Get-RegistryBase -Scope $section.Scope -Platform $section.Platform
        try {
            $root = $base.CreateSubKey($script:RegPath)
            try { Write-RegistryTree -Key $root -Tree $section.Node -Root $true }
            finally { $root.Dispose() }
        } finally { $base.Dispose() }
    }
}

function Get-InstalledDriverNames {
    param([ValidateSet('32-bit','64-bit')][string]$Platform)
    if ($Platform -eq '64-bit' -and -not [Environment]::Is64BitOperatingSystem) { return @() }
    $base = Get-RegistryBase -Scope 'System' -Platform $Platform
    try {
        $key = $base.OpenSubKey('SOFTWARE\ODBC\ODBCINST.INI\ODBC Drivers', $false)
        try {
            if ($null -eq $key) { return @() }
            return @($key.GetValueNames())
        } finally {
            if ($null -ne $key) { $key.Dispose() }
        }
    } finally { $base.Dispose() }
}

function Get-MissingDrivers {
    param($Snapshot)
    $drivers32 = @(Get-InstalledDriverNames -Platform '32-bit')
    $drivers64 = @(Get-InstalledDriverNames -Platform '64-bit')
    $warnings = New-Object 'System.Collections.Generic.List[string]'
    foreach ($row in @(Get-DsnRows -Snapshot $Snapshot)) {
        $driver = [string]$row.Driver
        if ([string]::IsNullOrWhiteSpace($driver) -or
            $driver -eq '(unregistered)' -or $driver -match '[\\/]') { continue }
        $available = if ($row.Scope -eq 'User') {
            (@($drivers32) + @($drivers64)) -contains $driver
        } elseif ($row.Platform -eq '32-bit') {
            $drivers32 -contains $driver
        } else {
            $drivers64 -contains $driver
        }
        if (-not $available) {
            $warnings.Add("$($row.Platform) / $($row.Name): $driver")
        }
    }
    return @($warnings | Select-Object -Unique)
}

function Show-BackupPasswordDialog {
    param([ValidateSet('Export','Import')][string]$Mode)
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = if ($Mode -eq 'Export') { 'Encrypt ODBC backup' } else { 'Unlock ODBC backup' }
    $dialog.Size = New-Object System.Drawing.Size(440, $(if ($Mode -eq 'Export') { 245 } else { 205 }))
    $dialog.FormBorderStyle = 'FixedDialog'
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false
    $dialog.StartPosition = 'CenterParent'

    $message = New-Object System.Windows.Forms.Label
    $message.Location = New-Object System.Drawing.Point(18, 16)
    $message.Size = New-Object System.Drawing.Size(395, 36)
    $message.Text = if ($Mode -eq 'Export') {
        'Choose a strong password (12+ characters). You need it to restore this backup.'
    } else { 'Enter the password used when exporting this backup.' }
    $dialog.Controls.Add($message)

    $password = New-Object System.Windows.Forms.TextBox
    $password.Location = New-Object System.Drawing.Point(20, 61)
    $password.Width = 385
    $password.UseSystemPasswordChar = $true
    $dialog.Controls.Add($password)

    $confirm = $null
    if ($Mode -eq 'Export') {
        $confirm = New-Object System.Windows.Forms.TextBox
        $confirm.Location = New-Object System.Drawing.Point(20, 101)
        $confirm.Width = 385
        $confirm.UseSystemPasswordChar = $true
        $dialog.Controls.Add($confirm)
        $hint = New-Object System.Windows.Forms.Label
        $hint.Text = 'Confirm password'
        $hint.Location = New-Object System.Drawing.Point(20, 84)
        $hint.AutoSize = $true
        $dialog.Controls.Add($hint)
    }
    $buttonY = if ($Mode -eq 'Export') { 155 } else { 110 }
    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'OK'
    $ok.Location = New-Object System.Drawing.Point(241, $buttonY)
    $ok.Size = New-Object System.Drawing.Size(75, 29)
    $dialog.Controls.Add($ok)
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'
    $cancel.Location = New-Object System.Drawing.Point(329, $buttonY)
    $cancel.Size = New-Object System.Drawing.Size(75, 29)
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $dialog.Controls.Add($cancel)
    $dialog.AcceptButton = $ok
    $dialog.CancelButton = $cancel
    $ok.Add_Click({
        if ($Mode -eq 'Export') {
            if ($password.Text.Length -lt 12) {
                [void][System.Windows.Forms.MessageBox]::Show('Use at least 12 characters.', 'Password')
                return
            }
            if ($password.Text -cne $confirm.Text) {
                [void][System.Windows.Forms.MessageBox]::Show('Passwords do not match.', 'Password')
                return
            }
        } elseif ([string]::IsNullOrEmpty($password.Text)) {
            [void][System.Windows.Forms.MessageBox]::Show('Enter the backup password.', 'Password')
            return
        }
        $dialog.Tag = $password.Text
        $dialog.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $dialog.Close()
    })
    try {
        $result = $dialog.ShowDialog($form)
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            return [string]$dialog.Tag
        }
        return $null
    } finally { $dialog.Dispose() }
}

function Show-Error {
    param([string]$Message)
    [void][System.Windows.Forms.MessageBox]::Show(
        $form, $Message, 'ODBC Migration - Error',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error)
}

# ------------------------------ GUI ---------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = 'ODBC Migration Tool | 32-bit + 64-bit | Encrypted'
$form.ClientSize = New-Object System.Drawing.Size(950, 600)
$form.MinimumSize = New-Object System.Drawing.Size(820, 530)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$title = New-Object System.Windows.Forms.Label
$title.Text = 'ODBC connection migration'
$title.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 17)
$title.Location = New-Object System.Drawing.Point(20, 16)
$title.AutoSize = $true
$form.Controls.Add($title)

$subtitle = New-Object System.Windows.Forms.Label
$subtitle.Text = 'System DSNs: 32/64-bit  |  User DSNs: current Windows account (shared view)  |  Password fields copied only if stored in the DSN registry.'
$subtitle.Location = New-Object System.Drawing.Point(22, 57)
$subtitle.Size = New-Object System.Drawing.Size(900, 39)
$subtitle.Anchor = 'Top,Left,Right'
$form.Controls.Add($subtitle)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Location = New-Object System.Drawing.Point(22, 104)
$grid.Size = New-Object System.Drawing.Size(906, 380)
$grid.Anchor = 'Top,Bottom,Left,Right'
$grid.ReadOnly = $true
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.RowHeadersVisible = $false
$grid.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
$grid.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
[void]$grid.Columns.Add('Scope','Scope')
[void]$grid.Columns.Add('Platform','Platform')
[void]$grid.Columns.Add('Name','DSN name')
[void]$grid.Columns.Add('Driver','ODBC driver')
[void]$grid.Columns.Add('Credential','Password-like field')
$grid.Columns['Scope'].FillWeight = 70
$grid.Columns['Platform'].FillWeight = 65
$grid.Columns['Name'].FillWeight = 170
$grid.Columns['Driver'].FillWeight = 185
$grid.Columns['Credential'].FillWeight = 100
$form.Controls.Add($grid)

$refresh = New-Object System.Windows.Forms.Button
$refresh.Text = 'Refresh'
$refresh.Location = New-Object System.Drawing.Point(22, 498)
$refresh.Size = New-Object System.Drawing.Size(110, 34)
$refresh.Anchor = 'Bottom,Left'
$form.Controls.Add($refresh)

$export = New-Object System.Windows.Forms.Button
$export.Text = 'Export encrypted...'
$export.Location = New-Object System.Drawing.Point(142, 498)
$export.Size = New-Object System.Drawing.Size(178, 34)
$export.Anchor = 'Bottom,Left'
$form.Controls.Add($export)

$import = New-Object System.Windows.Forms.Button
$import.Text = 'Import encrypted...'
$import.Location = New-Object System.Drawing.Point(330, 498)
$import.Size = New-Object System.Drawing.Size(178, 34)
$import.Anchor = 'Bottom,Left'
$form.Controls.Add($import)

$odbc32 = New-Object System.Windows.Forms.Button
$odbc32.Text = 'ODBC 32-bit'
$odbc32.Location = New-Object System.Drawing.Point(530, 498)
$odbc32.Size = New-Object System.Drawing.Size(120, 34)
$odbc32.Anchor = 'Bottom,Left'
$form.Controls.Add($odbc32)

$odbc64 = New-Object System.Windows.Forms.Button
$odbc64.Text = 'ODBC 64-bit'
$odbc64.Location = New-Object System.Drawing.Point(660, 498)
$odbc64.Size = New-Object System.Drawing.Size(120, 34)
$odbc64.Anchor = 'Bottom,Left'
$odbc64.Enabled = [System.Environment]::Is64BitOperatingSystem
$form.Controls.Add($odbc64)

$odbc32.Add_Click({
    try {
        $exe = if ([Environment]::Is64BitOperatingSystem) {
            Join-Path $env:windir 'SysWOW64\odbcad32.exe'
        } else { Join-Path $env:windir 'System32\odbcad32.exe' }
        Start-Process -FilePath $exe
    } catch { Show-Error -Message $_.Exception.Message }
})
$odbc64.Add_Click({
    try {
        $directory = if ([Environment]::Is64BitProcess) { 'System32' } else { 'Sysnative' }
        Start-Process -FilePath (Join-Path $env:windir "$directory\odbcad32.exe")
    } catch { Show-Error -Message $_.Exception.Message }
})

$status = New-Object System.Windows.Forms.Label
$status.Location = New-Object System.Drawing.Point(22, 549)
$status.Size = New-Object System.Drawing.Size(905, 43)
$status.Anchor = 'Bottom,Left,Right'
$status.Text = 'Ready. Drivers and File DSNs are not bundled. Use an elevated session to import System DSNs.'
$form.Controls.Add($status)

function Refresh-OdbcGrid {
    $snapshot = Get-OdbcSnapshot
    $rows = @(Get-DsnRows -Snapshot $snapshot)
    $grid.Rows.Clear()
    foreach ($row in $rows) {
        [void]$grid.Rows.Add([object[]]@(
            $row.Scope, $row.Platform, $row.Name, $row.Driver, $row.Credential))
    }
    $num32 = @($rows | Where-Object { $_.Scope -eq 'System' -and $_.Platform -eq '32-bit' }).Count
    $num64 = @($rows | Where-Object { $_.Scope -eq 'System' -and $_.Platform -eq '64-bit' }).Count
    $numUser = @($rows | Where-Object { $_.Scope -eq 'User' }).Count
    $status.Text = "Found $($rows.Count) DSNs: $num64 x64 System, $num32 x86 System, $numUser User. Run as admin for System DSN imports."
}

$refresh.Add_Click({
    try { Refresh-OdbcGrid } catch { Show-Error -Message $_.Exception.Message }
})

$export.Add_Click({
    $save = New-Object System.Windows.Forms.SaveFileDialog
    $save.Title = 'Save encrypted ODBC backup'
    $save.Filter = 'ODBC encrypted backup (*.odbcpack)|*.odbcpack'
    $save.DefaultExt = 'odbcpack'
    $save.AddExtension = $true
    $save.FileName = 'ODBC-{0}-{1}.odbcpack' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss')
    try {
        if ($save.ShowDialog($form) -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $path = $save.FileName
    } finally { $save.Dispose() }
    $password = Show-BackupPasswordDialog -Mode Export
    if ($null -eq $password) { return }
    try {
        $form.UseWaitCursor = $true
        $snapshot = Get-OdbcSnapshot
        Protect-OdbcBackup -Snapshot $snapshot -Password $password -Path $path
        $count = @(Get-DsnRows -Snapshot $snapshot).Count
        $status.Text = "Exported $count DSNs to $path"
        [void][System.Windows.Forms.MessageBox]::Show(
            $form, "Encrypted backup saved.`r`n`r`n$path`r`n`r`n$count DSNs included.`r`nKeep the password safe. ODBC drivers are not included.",
            'ODBC export completed', [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        Show-Error -Message $_.Exception.Message
    } finally {
        $password = $null
        $form.UseWaitCursor = $false
    }
})

$import.Add_Click({
    $open = New-Object System.Windows.Forms.OpenFileDialog
    $open.Title = 'Choose encrypted ODBC backup'
    $open.Filter = 'ODBC encrypted backup (*.odbcpack)|*.odbcpack'
    try {
        if ($open.ShowDialog($form) -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $path = $open.FileName
    } finally { $open.Dispose() }
    $password = Show-BackupPasswordDialog -Mode Import
    if ($null -eq $password) { return }
    try {
        $form.UseWaitCursor = $true
        $snapshot = Unprotect-OdbcBackup -Password $password -Path $path
        Assert-OdbcImportTarget -Snapshot $snapshot
        $importRows = @(Get-DsnRows -Snapshot $snapshot)
        $systemSections = @($snapshot.Sections | Where-Object { $_.Scope -eq 'System' -and $null -ne $_.Node })
        if ($systemSections.Count -gt 0 -and -not (Test-IsAdministrator)) {
            throw 'Administrator rights required to restore System DSNs. Reopen PowerShell as administrator using the same Windows account.'
        }
        if ($systemSections | Where-Object { $_.Platform -eq '64-bit' -and -not [Environment]::Is64BitOperatingSystem }) {
            throw 'Cannot restore 64-bit DSNs on 32-bit Windows.'
        }
        $missing = @(Get-MissingDrivers -Snapshot $snapshot)
        $driverNotice = if ($missing.Count -gt 0) {
            "`r`n`r`nPOSSIBLY MISSING ODBC DRIVERS ($($missing.Count)):`r`n" +
                (($missing | Select-Object -First 8) -join "`r`n") +
                $(if ($missing.Count -gt 8) { "`r`n..." } else { '' })
        } else { '' }
        $question = "Restore $($importRows.Count) DSNs from $($snapshot.Computer) / $($snapshot.Account)?" +
            "`r`n`r`nExisting matching DSNs will be overwritten; unrelated DSNs remain." +
            "`r`nA password-encrypted safety backup of current DSNs will be created before import." +
            "`r`nDrivers must already be installed. Protected/driver-managed passwords may need re-entry." +
            $driverNotice + "`r`n`r`nContinue?"
        $form.UseWaitCursor = $false
        $answer = [System.Windows.Forms.MessageBox]::Show(
            $form, $question, 'Confirm ODBC import',
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        $form.UseWaitCursor = $true
        $before = Get-OdbcSnapshot
        $backupFolder = [Environment]::GetFolderPath('MyDocuments')
        if ([string]::IsNullOrWhiteSpace($backupFolder)) { $backupFolder = $env:USERPROFILE }
        $backupPath = Join-Path $backupFolder ('ODBC-before-import-{0}-{1}-{2}.odbcpack' -f
            $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'), [Guid]::NewGuid().ToString('N'))
        Save-VerifiedOdbcBackup -Snapshot $before -Password $password -Path $backupPath
        Import-OdbcSnapshot -Snapshot $snapshot
        Refresh-OdbcGrid
        $status.Text = "Import done. Safety backup: $backupPath"
        [void][System.Windows.Forms.MessageBox]::Show(
            $form, "Import completed for $($importRows.Count) DSNs.`r`n`r`nBefore-import backup (same password):`r`n$backupPath`r`n`r`nVerify driver availability and test database connections.",
            'ODBC import completed', [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        Show-Error -Message ("Import stopped: " + $_.Exception.Message +
            "`r`n`r`nIf a failure occurred while writing registry keys, the encrypted pre-import backup can help restore the prior settings.")
    } finally {
        $form.UseWaitCursor = $false
        $password = $null
    }
})

try { Refresh-OdbcGrid } catch { Show-Error -Message $_.Exception.Message }
[void]$form.ShowDialog()
$form.Dispose()
