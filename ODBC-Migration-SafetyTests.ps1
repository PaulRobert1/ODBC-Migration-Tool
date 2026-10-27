param([string]$ScriptPath=(Join-Path $PSScriptRoot 'ODBC-Migration-GUI.ps1'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($ScriptPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Source parse failed'}
$defs=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)
. ([scriptblock]::Create(($defs | ForEach-Object {$_.Extent.Text}) -join "`n"))
$script:Magic=[Text.Encoding]::ASCII.GetBytes('ODBCPACK-V1');$script:KdfRounds=200000
$script:passed=0;$script:failed=0
function Check($name,[scriptblock]$code){try{& $code;$script:passed++;Write-Output ('[PASS] '+$name)}catch{$script:failed++;Write-Output ('[FAIL] '+$name+' : '+$_.Exception.Message)}}
function Assert($ok,$reason){if(-not $ok){throw $reason}}
function New-Snapshot {
 $json='{"Format":"ODBCPACK-V1","Sections":[{"Scope":"User","Platform":"Shared","Node":{"Name":"ODBC.INI","Values":[],"Subkeys":[{"Name":"Existing","Values":[{"Name":"Marker","Kind":"String","Data":"replacement"}],"Subkeys":[]},{"Name":"Later","Values":[],"Subkeys":[]}]}}]}'
 return ($json | ConvertFrom-Json)
}
$id=[guid]::NewGuid().ToString('N');$script:RegPath='Software\ODBCMigrationSelfTest\'+$id
$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryView]::Registry64)
$dir=Join-Path $env:TEMP ('odbc-safety-'+$id);[void][IO.Directory]::CreateDirectory($dir)
$password='SyntheticOnly-'+$id
try {
 $cases=@(
  @{Name='later invalid child path';Edit={param($s) $s.Sections[0].Node.Subkeys[1].Name='invalid\path'}},
  @{Name='later invalid value kind';Edit={param($s) $s.Sections[0].Node.Subkeys[1].Values=@([pscustomobject]@{Name='Value';Kind='Invalid';Data='FAKE_SECRET_NOT_FOR_ERRORS'})}},
  @{Name='later invalid DWORD';Edit={param($s) $s.Sections[0].Node.Subkeys[1].Values=@([pscustomobject]@{Name='Value';Kind='DWord';Data='FAKE_SECRET_NOT_FOR_ERRORS'})}},
  @{Name='later overflowing QWORD';Edit={param($s) $s.Sections[0].Node.Subkeys[1].Values=@([pscustomobject]@{Name='Value';Kind='QWord';Data='9223372036854775808'})}},
  @{Name='later invalid binary';Edit={param($s) $s.Sections[0].Node.Subkeys[1].Values=@([pscustomobject]@{Name='Value';Kind='Binary';Data='invalid!'})}},
  @{Name='duplicate child names';Edit={param($s) $s.Sections[0].Node.Subkeys[1].Name='existing'}},
  @{Name='duplicate value names';Edit={param($s) $s.Sections[0].Node.Subkeys[1].Values=@([pscustomobject]@{Name='x';Kind='String';Data='a'},[pscustomobject]@{Name='X';Kind='String';Data='b'})}},
  @{Name='null subkey';Edit={param($s) $s.Sections[0].Node.Subkeys+=@($null)}},
  @{Name='null values array';Edit={param($s) $s.Sections[0].Node.Subkeys[1].Values=$null}},
  @{Name='invalid MULTI_SZ element';Edit={param($s) $s.Sections[0].Node.Subkeys[1].Values=@([pscustomobject]@{Name='x';Kind='MultiString';Data=@('a',42)})}},
  @{Name='later invalid section';Edit={param($s) $s.Sections+=@([pscustomobject]@{Scope='Invalid';Platform='Shared';Node=$s.Sections[0].Node})}},
  @{Name='array-valued later user platform';Edit={param($s) $s.Sections+=@([pscustomobject]@{Scope='User';Platform=@('Shared','Shared');Node=$s.Sections[0].Node})}},
  @{Name='duplicate sections';Edit={param($s) $s.Sections+=@($s.Sections[0])}}
 )
 foreach($case in $cases){
  Check ($case.Name+' rejected before any writes') {
   $base.DeleteSubKeyTree($script:RegPath,$false)
   $root=$base.CreateSubKey($script:RegPath);$key=$root.CreateSubKey('Existing');$key.SetValue('Marker','original');$key.SetValue('Keep','original');$key.Dispose();$root.Dispose()
   $s=New-Snapshot;& $case.Edit $s
   $rejected=$false;$message=''
   try{Import-OdbcSnapshot -Snapshot $s}catch{$rejected=$true;$message=$_.Exception.Message}
   $root=$base.OpenSubKey($script:RegPath);$key=$root.OpenSubKey('Existing')
   try{$unchanged=$key.GetValue('Marker') -ceq 'original' -and $key.GetValue('Keep') -ceq 'original' -and $root.SubKeyCount -eq 1}finally{$key.Dispose();$root.Dispose()}
   Assert $rejected 'Malformed payload accepted'
   Assert $unchanged 'Registry changed before rejection'
   Assert (-not $message.Contains('FAKE_SECRET_NOT_FOR_ERRORS')) 'Validation disclosed synthetic data'
  }
 }
 Check 'Authenticated malformed tree rejected on decryption' {
  $s=New-Snapshot;$s.Sections[0].Node.Subkeys[1].Name='invalid\path';$path=Join-Path $dir 'invalid.odbcpack'
  Protect-OdbcBackup -Snapshot $s -Password $password -Path $path
  $rejected=$false;try{$null=Unprotect-OdbcBackup -Password $password -Path $path}catch{$rejected=$true}
  Assert $rejected 'Malformed tree returned by decryption'
 }
 Check 'Failed export preserves an existing valid backup' {
  $path=Join-Path $dir 'existing.odbcpack';$s=New-Snapshot
  Protect-OdbcBackup -Snapshot $s -Password $password -Path $path
  $before=[IO.File]::ReadAllBytes($path)
  # Fault injection is limited to the final filesystem commit call; real
  # encryption, temporary-file write, preceding deletion and cleanup still run.
  # Windows administrator ACL tests did not reliably prevent rename here.
  $source=(Get-Command Protect-OdbcBackup).ScriptBlock.ToString()
  $pattern='\[System\.IO\.File\]::(?:Move|Replace)\([^\r\n]*\)'
  Assert ([regex]::Matches($source,$pattern).Count -gt 0) 'Cannot locate filesystem commit boundary'
  $faulted=[regex]::Replace($source,$pattern,"throw 'Injected final file commit failure'")
  $rejected=$false
  try {& ([scriptblock]::Create($faulted)) -Snapshot $s -Password $password -Path $path}catch{$rejected=$true}
  Assert $rejected 'Fault injection did not stop export'
  Assert ([IO.File]::Exists($path)) 'Previous backup was deleted'
  Assert ([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -ceq [Convert]::ToBase64String($before)) 'Previous backup changed'
  $null=Unprotect-OdbcBackup -Password $password -Path $path
 }
 Check 'Depth33 registry tree remains compatible with the existing pack format' {
  $s=New-Snapshot;$leaf=[pscustomobject]@{Name='Leaf';Values=@();Subkeys=@()}
  for($i=0;$i -lt 33;$i++){$leaf=[pscustomobject]@{Name=('N'+$i);Values=@();Subkeys=@($leaf)}}
  $leaf.Name='ODBC.INI';$s.Sections[0].Node=$leaf;$path=Join-Path $dir 'deep.odbcpack'
  Protect-OdbcBackup -Snapshot $s -Password $password -Path $path
  $v=Unprotect-OdbcBackup -Password $password -Path $path
  Assert ((ConvertTo-Json -InputObject $s -Depth 100 -Compress) -ceq (ConvertTo-Json -InputObject $v -Depth 100 -Compress)) 'Deep compatible tree changed'
 }
 Check 'Successful export replaces an existing pack and remains readable' {
  $path=Join-Path $dir 'overwrite.odbcpack';$s=New-Snapshot
  Protect-OdbcBackup -Snapshot $s -Password $password -Path $path
  $s.Sections[0].Node.Subkeys[0].Values[0].Data='updated'
  Protect-OdbcBackup -Snapshot $s -Password $password -Path $path
  $v=Unprotect-OdbcBackup -Password $password -Path $path
  Assert ($v.Sections[0].Node.Subkeys[0].Values[0].Data -ceq 'updated') 'Replacement pack did not contain updated state'
 }
 Check 'Verified pre-import backup reopens with captured state' {
  $path=Join-Path $dir 'verified.odbcpack';$s=New-Snapshot
  Save-VerifiedOdbcBackup -Snapshot $s -Password $password -Path $path
  $v=Unprotect-OdbcBackup -Password $password -Path $path
  Assert ($v.Sections[0].Node.Subkeys[0].Values[0].Data -ceq 'replacement') 'Captured backup mismatch'
 }
 foreach($fault in @('corrupt','different')) {
  Check ($fault+' safety backup blocks subsequent import') {
   $base.DeleteSubKeyTree($script:RegPath,$false)
   $root=$base.CreateSubKey($script:RegPath);$k=$root.CreateSubKey('Existing');$k.SetValue('Marker','original');$k.Dispose();$root.Dispose()
   $s=New-Snapshot;$path=Join-Path $dir ($fault+'.odbcpack')
   $script:realProtect=(Get-Command Protect-OdbcBackup).ScriptBlock
   $script:backupFault=$fault
   try {
    function script:Protect-OdbcBackup {
     param($Snapshot,[string]$Password,[string]$Path)
     if($script:backupFault -eq 'corrupt'){[IO.File]::WriteAllBytes($Path,[byte[]]@(1,2,3));return}
     $different=New-Snapshot;$different.Sections[0].Node.Subkeys[0].Values[0].Data='incorrect-capture'
     & $script:realProtect -Snapshot $different -Password $Password -Path $Path
    }
    $rejected=$false
    try {Save-VerifiedOdbcBackup -Snapshot $s -Password $password -Path $path;Import-OdbcSnapshot -Snapshot $s}catch{$rejected=$true}
   } finally {Set-Item -Path Function:\script:Protect-OdbcBackup -Value $script:realProtect}
   Assert ([IO.File]::Exists($path)) 'Backup fault was not exercised'
   Assert $rejected 'Bad safety backup accepted'
   $k=$base.OpenSubKey($script:RegPath+'\Existing');try{Assert ($k.GetValue('Marker') -ceq 'original') 'Import ran despite backup verification failure'}finally{$k.Dispose()}
  }
 }
} finally {
 $base.DeleteSubKeyTree($script:RegPath,$false);$base.Dispose()
 Remove-Item -LiteralPath $dir -Recurse -Force
}
Write-Output ('RESULT: '+$passed+' PASS; '+$failed+' FAIL')
if($failed){exit 1}
