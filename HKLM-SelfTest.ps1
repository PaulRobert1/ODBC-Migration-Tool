param([string]$ScriptPath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($ScriptPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Source parse failed'}
$defs=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)
. ([scriptblock]::Create(($defs | ForEach-Object {$_.Extent.Text}) -join "`n"))
$script:Magic=[Text.Encoding]::ASCII.GetBytes('ODBCPACK-V1');$script:KdfRounds=200000
$script:RegPath='SOFTWARE\ODBC\ODBC.INI'
if(-not (Test-IsAdministrator)){throw 'Test requires administrative HKLM access'}
$id=[guid]::NewGuid().ToString('N');$name='Codex_ODBC_'+$id;$keep=$name+'_Keep'
$pack=Join-Path $env:TEMP ($name+'.odbcpack');$password='SyntheticOnly-'+$id
$passed=0;$failed=0;$states=@();$sections=@()
function Check([bool]$ok,[string]$label){if($ok){$script:passed++;Write-Output ('[PASS] '+$label)}else{$script:failed++;Write-Output ('[FAIL] '+$label)}}
function Canon($node){ConvertTo-Json -InputObject $node -Depth 100 -Compress}
function Get-Unrelated($root){
 $tree=Read-RegistryTree -Key $root -Name 'ODBC.INI'
 $tree.Subkeys=@($tree.Subkeys | Where-Object {$_.Name -notin @($name,$keep)})
 $idx=Get-NodeChild -Node $tree -Name 'ODBC Data Sources'
 if($null -ne $idx){$idx.Values=@($idx.Values | Where-Object {$_.Name -notin @($name,$keep)})}
 return (Canon $tree)
}
Write-Output ('Machine='+$env:COMPUTERNAME+'; PowerShell='+$PSVersionTable.PSVersion+'; Process64='+[Environment]::Is64BitProcess)
try {
 foreach($platform in @('32-bit','64-bit')){
  $base=Get-RegistryBase -Scope System -Platform $platform
  $existing=$base.OpenSubKey($script:RegPath);$rootWasPresent=$null -ne $existing;if($existing){$existing.Dispose()}
  $root=$base.CreateSubKey($script:RegPath)
  $index=$root.OpenSubKey('ODBC Data Sources');$indexWasPresent=$null -ne $index;if($index){$index.Dispose()}
  foreach($n in @($name,$keep)){$k=$root.OpenSubKey($n);if($k){$k.Dispose();throw 'Unexpected unique test name collision'}}
  $index=$root.CreateSubKey('ODBC Data Sources')
  foreach($n in @($name,$keep)){if($index.GetValueNames() -contains $n){throw 'Unexpected unique index collision'}}
  $state=[pscustomobject]@{Platform=$platform;Base=$base;Root=$root;Index=$index;RootWasPresent=$rootWasPresent;IndexWasPresent=$indexWasPresent;Before=(Get-Unrelated $root);Expected=$null}
  $states+= $state
  $k=$root.CreateSubKey($name)
  try {
   $k.SetValue('', '', [Microsoft.Win32.RegistryValueKind]::String)
   $k.SetValue('Server','invalid.example',[Microsoft.Win32.RegistryValueKind]::String)
   $k.SetValue('PWD','FAKE_ONLY_'+$platform,[Microsoft.Win32.RegistryValueKind]::String)
   $k.SetValue('ViewMarker',$platform,[Microsoft.Win32.RegistryValueKind]::String)
   $k.SetValue('Expanded','%TEMP%\synthetic',[Microsoft.Win32.RegistryValueKind]::ExpandString)
   $k.SetValue('Items',[string[]]@('First','Second'),[Microsoft.Win32.RegistryValueKind]::MultiString)
   $k.SetValue('DWord',[int]-1,[Microsoft.Win32.RegistryValueKind]::DWord)
   $k.SetValue('QWord',[long]::MaxValue,[Microsoft.Win32.RegistryValueKind]::QWord)
   $k.SetValue('Binary',[byte[]]@(0,1,127,255),[Microsoft.Win32.RegistryValueKind]::Binary)
   $child=$k.CreateSubKey('Nested');try{$child.SetValue('Value','nested')}finally{$child.Dispose()}
   $empty=$k.CreateSubKey('Empty');$empty.Dispose()
   $state.Expected=Read-RegistryTree -Key $k -Name $name
  } finally {$k.Dispose()}
  $index.SetValue($name,'Synthetic Missing Driver '+$platform)
  $k=$root.CreateSubKey($keep);try{$k.SetValue('Marker','keep-me')}finally{$k.Dispose()}
  $index.SetValue($keep,'Synthetic Keep Driver')
  $sections+= [pscustomobject]@{Scope='System';Platform=$platform;Node=[pscustomobject]@{Name='ODBC.INI';Values=@();Subkeys=@($state.Expected,[pscustomobject]@{Name='ODBC Data Sources';Values=@([pscustomobject]@{Name=$name;Kind='String';Data=('Synthetic Missing Driver '+$platform)});Subkeys=@()})}}
 }
 $snapshot=[pscustomobject]@{Format='ODBCPACK-V1';Computer='SYNTHETIC';Account='SYNTHETIC';Sections=$sections}
 Protect-OdbcBackup -Snapshot $snapshot -Password $password -Path $pack
 $loaded=Unprotect-OdbcBackup -Password $password -Path $pack
 Check ((Canon $snapshot) -ceq (Canon $loaded)) 'Encrypted synthetic HKLM backup reopens with identical payload'
 foreach($s in $states){$s.Root.DeleteSubKeyTree($name);$s.Index.DeleteValue($name)}
 Import-OdbcSnapshot -Snapshot $loaded
 foreach($s in $states){
  $k=$s.Root.OpenSubKey($name);try{$actual=Read-RegistryTree -Key $k -Name $name}finally{$k.Dispose()}
  Check ((Canon $actual) -ceq (Canon $s.Expected)) ($s.Platform+' exact registry type/data round trip including stored fake PWD')
  Check ($s.Index.GetValue($name) -ceq ('Synthetic Missing Driver '+$s.Platform)) ($s.Platform+' DSN index restored')
  $k=$s.Root.OpenSubKey($name,$true);try{$k.SetValue('Obsolete','remove-me')}finally{$k.Dispose()}
 }
 Import-OdbcSnapshot -Snapshot $loaded
 foreach($s in $states){
  $k=$s.Root.OpenSubKey($name);try{$actual=Read-RegistryTree -Key $k -Name $name}finally{$k.Dispose()}
  Check ((Canon $actual) -ceq (Canon $s.Expected)) ($s.Platform+' replacement removes obsolete attributes')
  $k=$s.Root.OpenSubKey($keep);try{$kept=$k.GetValue('Marker') -ceq 'keep-me'}finally{$k.Dispose()}
  Check ($kept -and $s.Index.GetValue($keep) -ceq 'Synthetic Keep Driver') ($s.Platform+' unrelated synthetic DSN and index preserved')
  Check ((Get-Unrelated $s.Root) -ceq $s.Before) ($s.Platform+' pre-existing ODBC registry tree unchanged')
 }
 Check ((Canon $states[0].Expected) -cne (Canon $states[1].Expected)) 'Same DSN name has distinct x86/x64 payloads'
} catch {$failed++;Write-Output ('[FAIL] Test aborted: '+$_.Exception.GetType().FullName);Write-Output $_.ScriptStackTrace}
finally {
 foreach($s in $states){
  try {
   foreach($n in @($name,$keep)){$s.Root.DeleteSubKeyTree($n,$false);$s.Index.DeleteValue($n,$false)}
   Check ((Get-Unrelated $s.Root) -ceq $s.Before) ($s.Platform+' cleanup preserves pre-existing data')
   $emptyIndex=($s.Index.ValueCount -eq 0 -and $s.Index.SubKeyCount -eq 0);$s.Index.Dispose()
   if(-not $s.IndexWasPresent -and $emptyIndex){$s.Root.DeleteSubKeyTree('ODBC Data Sources',$false)}
   $emptyRoot=($s.Root.ValueCount -eq 0 -and $s.Root.SubKeyCount -eq 0);$s.Root.Dispose()
   if(-not $s.RootWasPresent -and $emptyRoot){$s.Base.DeleteSubKeyTree($script:RegPath,$false)}
   $s.Base.Dispose()
  }catch{$failed++;Write-Output ('[FAIL] Cleanup requires attention for '+$s.Platform)}
 }
 if(Test-Path -LiteralPath $pack){Remove-Item -LiteralPath $pack -Force}
}
Write-Output ('RESULT: '+$passed+' PASS; '+$failed+' FAIL')
if($failed){exit 1}
