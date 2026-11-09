# ==========================================================
# Script      : Fix-MailEnableAppPool.ps1
# Description : Diagnoses and fixes HTTP 503 (AppOffline) on the MailEnable web
#               services (WebAdmin :8383, WebMail, ActiveSync) caused by an
#               invalid IME_ADMIN identity on the MailEnable IIS app pools.
#               Diagnose mode is the default and changes nothing; -Fix sets a
#               new random password on IME_ADMIN and on every app pool that
#               runs as it. The fix is skipped automatically if a service,
#               scheduled task or other IIS setting also uses the account.
# Team        : Tech Support L3
# Author      : Ar.hosseini
# Version     : 1.0.0
# Usage       : Fix-MailEnableAppPool.ps1 [-Fix] [-AccountName <name>]
#               [-TestUrl <url>] [-TestTimeoutSec <sec>] [-Help] [-Version]
#               e.g. powershell -ExecutionPolicy Bypass -File .\Fix-MailEnableAppPool.ps1 -Fix
# Options     : (none)           Diagnose only, nothing is changed (default)
#               -Fix             Apply the fix
#               -AccountName     App pool identity to check (default: IME_ADMIN)
#               -TestUrl         URL for the post-fix HTTP test
#                                (default: auto-detected from the :8383 binding)
#               -TestTimeoutSec  HTTP test timeout in seconds (default: 180)
#               -Help            Show usage
#               -Version         Show script version
# Requires    : Administrator, Windows PowerShell 5.1, IIS with the
#               WebAdministration module, appcmd.exe, wevtutil.exe;
#               runs locally on the MailEnable server
# Exit codes  : 0 OK (healthy or fixed), 1 error (including a blocked or
#               failed fix), 2 usage, 3 dependency, 4 permission,
#               5 problem detected in diagnose mode (run again with -Fix)
# Files       : C:\LogBackup\<Log>_<timestamp>.evtx      event log backups (-Fix)
#               %windir%\System32\inetsrv\backup\BeforeMEFix_<timestamp>
#                                                         IIS config backup (-Fix)
# ==========================================================

param(
  [switch]$Fix,
  [string]$AccountName = 'IME_ADMIN',
  [string]$TestUrl = '',
  [int]$TestTimeoutSec = 180,
  [switch]$Help,
  [switch]$Version
)

# ----------------------------------------------------------
# Constants
# ----------------------------------------------------------
$ScriptName    = 'Fix-MailEnableAppPool.ps1'
$ScriptVersion = '1.0.0'

$EXIT_OK         = 0
$EXIT_ERROR      = 1
$EXIT_USAGE      = 2
$EXIT_DEPENDENCY = 3
$EXIT_PERMISSION = 4
$EXIT_DETECTED   = 5

$LogBackupDir = 'C:\LogBackup'
$LogMaxBytes  = 209715200   # 200 MB
$WasIdentityEventIds = 5021, 5057, 5059   # identity invalid / pool disabled

# ----------------------------------------------------------
# Helper functions
# ----------------------------------------------------------
function Show-Usage {
@"
Usage: $ScriptName [-Fix] [-AccountName <name>] [-TestUrl <url>] [-TestTimeoutSec <sec>] [-Help] [-Version]

  (no option)      Diagnose only, nothing is changed (default)
  -Fix             Reset the account password and update every app pool that uses it
  -AccountName     App pool identity to check (default: IME_ADMIN)
  -TestUrl         URL for the post-fix HTTP test (default: from the :8383 binding)
  -TestTimeoutSec  HTTP test timeout in seconds (default: 180)
  -Help            Show this help
  -Version         Show script version

Examples:
  powershell -ExecutionPolicy Bypass -File .\$ScriptName
  powershell -ExecutionPolicy Bypass -File .\$ScriptName -Fix
"@
}

function Section([string]$Title) { Write-Host "`n=== $Title ===" -ForegroundColor Cyan }
function Fail([string]$Message)  { Write-Host $Message -ForegroundColor Red }

# Validates a password with a local BATCH logon (type 4), exactly what IIS/WAS
# uses for an app pool identity. Does not depend on the Server service.
function Test-Pwd([string]$Password) {
  if ([string]::IsNullOrEmpty($Password)) { return $false }
  $token = [IntPtr]::Zero
  if ([Win32.Logon]::LogonUser($AccountName, '.', $Password, 4, 0, [ref]$token)) {
    [void][Win32.Logon]::CloseHandle($token)
    return $true
  }
  $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  Write-Warning ("Logon test failed: Win32 error {0} - {1}" -f $err, (New-Object ComponentModel.Win32Exception $err).Message)
  return $false
}

# Returns $true if the local account is locked out.
function Get-Locked {
  try {
    $u = [ADSI]"WinNT://./$AccountName,user"
    return ([bool]$u.IsAccountLocked.Value) -or ([bool]($u.UserFlags.Value -band 0x10))
  } catch { return $false }
}

# Clears the lockout flag on the local account.
function Unlock-Account {
  $u = [ADSI]"WinNT://./$AccountName,user"
  try { $u.IsAccountLocked = $false; $u.SetInfo() } catch { }
  $u = [ADSI]"WinNT://./$AccountName,user"
  if ($u.UserFlags.Value -band 0x10) { $u.UserFlags = $u.UserFlags.Value -bxor 0x10; $u.SetInfo() }
}

# ----------------------------------------------------------
# Argument handling
# ----------------------------------------------------------
if ($Help)    { Show-Usage; exit $EXIT_OK }
if ($Version) { "$ScriptName $ScriptVersion"; exit $EXIT_OK }
if ($TestTimeoutSec -lt 1 -or [string]::IsNullOrWhiteSpace($AccountName)) {
  Fail 'Invalid parameter value.'
  Show-Usage
  exit $EXIT_USAGE
}

# ----------------------------------------------------------
# Permission check
# ----------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Fail 'This script must be run as Administrator.'
  exit $EXIT_PERMISSION
}

# ----------------------------------------------------------
# Dependency check
# ----------------------------------------------------------
$appcmd  = "$env:windir\system32\inetsrv\appcmd.exe"
$cfgPath = "$env:windir\System32\inetsrv\config\applicationHost.config"

$missing = @()
if (-not (Get-Module -ListAvailable -Name WebAdministration))    { $missing += 'WebAdministration module' }
if (-not (Test-Path $appcmd))                                      { $missing += 'appcmd.exe' }
if (-not (Get-Command wevtutil.exe -ErrorAction SilentlyContinue)) { $missing += 'wevtutil.exe' }
if ($missing.Count -gt 0) {
  Fail "Missing dependencies: $($missing -join ', ')"
  exit $EXIT_DEPENDENCY
}

# ----------------------------------------------------------
# Main
# ----------------------------------------------------------
$ErrorActionPreference = 'Stop'
try {
  Import-Module WebAdministration
  Add-Type -AssemblyName System.Web
  if (-not ('Win32.Logon' -as [type])) {
    Add-Type -Namespace Win32 -Name Logon -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool LogonUser(string user, string domain, string pass, int type, int provider, out IntPtr token);
[DllImport("kernel32.dll")]
public static extern bool CloseHandle(IntPtr h);
'@
  }

  $stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
  $blockers = New-Object System.Collections.Generic.List[string]

  Write-Host "Server: $env:COMPUTERNAME   Mode: $(if ($Fix) {'FIX'} else {'DIAGNOSE ONLY'})   Version: $ScriptVersion" -ForegroundColor Yellow

  # --- 1. Event logs ---------------------------------------
  # A full log in Retain mode silently drops new events (incl. WAS errors).
  Section 'Event logs'
  foreach ($log in 'System', 'Application') {
    $l = Get-WinEvent -ListLog $log
    "{0,-12} Mode={1,-9} Full={2}" -f $log, $l.LogMode, $l.IsLogFull
    if ($l.LogMode -ne 'Circular' -and $Fix) {
      New-Item -ItemType Directory $LogBackupDir -Force | Out-Null
      $bk = Join-Path $LogBackupDir "${log}_$stamp.evtx"
      wevtutil epl $log $bk
      if ($LASTEXITCODE -ne 0) { Write-Warning "Backup of $log failed; its settings were NOT changed."; continue }
      wevtutil sl $log /rt:false /ab:false /ms:$LogMaxBytes
      "  -> backed up to $bk and switched to Circular (200 MB)"
    }
  }

  # --- 2. Account ------------------------------------------
  Section "Account $AccountName"
  $user = Get-LocalUser -Name $AccountName -ErrorAction SilentlyContinue
  if (-not $user) { Fail "Local account $AccountName not found."; exit $EXIT_ERROR }
  "Enabled={0}  PasswordLastSet={1}  LastLogon={2}" -f $user.Enabled, $user.PasswordLastSet, $user.LastLogon
  if (-not $user.Enabled) { $blockers.Add("Account $AccountName is disabled") }

  $locked = Get-Locked
  "LockedOut=$locked"
  if ($locked) {
    Write-Host '  Account is LOCKED OUT. Old passwords will not be tested (each wrong try extends the lockout).' -ForegroundColor Yellow
    Write-Host '  With -Fix the account gets a new password and is unlocked.' -ForegroundColor Yellow
  }
  (net accounts | Select-String 'Lockout threshold|Lockout duration') | ForEach-Object { "  $($_.Line.Trim())" }

  # --- 3. App pools ----------------------------------------
  # Find every pool running as the account and test its stored password.
  Section "App pools running as $AccountName"
  $pools = @(Get-ChildItem IIS:\AppPools | Where-Object {
    (Get-ItemProperty "IIS:\AppPools\$($_.Name)").processModel.userName -eq $AccountName
  })
  if ($pools.Count -eq 0) { Fail "No app pool runs as $AccountName."; exit $EXIT_ERROR }

  $invalid = @()
  foreach ($pl in $pools) {
    $state = (Get-WebAppPoolState $pl.Name).Value
    if ($locked) {
      "{0,-24} State={1,-8} StoredPasswordValid=UNKNOWN (account locked)" -f $pl.Name, $state
      $invalid += $pl.Name
      continue
    }
    $pw = (& $appcmd list apppool "$($pl.Name)" /text:processModel.password) -join ''
    $ok = Test-Pwd $pw
    "{0,-24} State={1,-8} StoredPasswordValid={2}" -f $pl.Name, $state, $ok
    if (-not $ok) { $invalid += $pl.Name }
  }
  Remove-Variable pw -ErrorAction SilentlyContinue

  # --- 4. Other dependencies -------------------------------
  # Anything else using the password would break after a reset -> blocker.
  Section 'Other things that depend on the account password'
  Get-CimInstance Win32_Service | Where-Object { $_.StartName -match [regex]::Escape($AccountName) } |
    ForEach-Object { $blockers.Add("Service '$($_.Name)' runs as $($_.StartName)") }
  Get-ScheduledTask | Where-Object { $_.Principal.UserId -match [regex]::Escape($AccountName) } |
    ForEach-Object { $blockers.Add("Scheduled task '$($_.TaskPath)$($_.TaskName)' runs as $AccountName") }

  $cfgLines = @(Select-String -Path $cfgPath -Pattern $AccountName -SimpleMatch)
  if ($cfgLines.Count -gt $pools.Count) {
    $blockers.Add("applicationHost.config mentions $AccountName $($cfgLines.Count) times, but only $($pools.Count) app pools use it")
    $cfgLines | ForEach-Object { "  line $($_.LineNumber): " + ($_.Line.Trim() -replace 'password="[^"]*"', 'password="***"') }
  }
  if ($blockers.Count -eq 0) { 'None found.' }
  else { $blockers | ForEach-Object { Fail "  BLOCKER: $_" } }

  # --- 5. Recent WAS errors --------------------------------
  Section 'WAS identity errors in the last 24h (5021/5057/5059)'
  $ev = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WAS'; Id=$WasIdentityEventIds; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue)
  if ($ev.Count -eq 0) { 'None recorded (if the System log was full/Retain, errors could not be written).' }
  else { $ev | Select-Object -First 5 | ForEach-Object { "{0}  Id={1}  {2}" -f $_.TimeCreated, $_.Id, ($_.Message -split "`n")[0] } }

  # --- 6. Decision -----------------------------------------
  Section 'Result'
  if ($invalid.Count -eq 0) {
    Write-Host 'All stored passwords are valid. The 503 on this server is NOT caused by the pool identity.' -ForegroundColor Green
    exit $EXIT_OK
  }
  Fail "Invalid identity password in: $($invalid -join ', ')"
  if (-not $Fix) {
    Write-Host 'Diagnosis matches. Run again with -Fix to apply the fix.' -ForegroundColor Yellow
    exit $EXIT_DETECTED
  }
  if ($blockers.Count -gt 0) { Fail 'Fix NOT applied because of the blockers listed above.'; exit $EXIT_ERROR }

  # --- 7. Fix ----------------------------------------------
  Section 'Applying fix'
  $fixTime = Get-Date
  $bkName  = "BeforeMEFix_$stamp"
  & $appcmd add backup $bkName | Out-Null
  "IIS config backup created: $bkName  (restore: appcmd restore backup $bkName)"

  $p = [System.Web.Security.Membership]::GeneratePassword(24, 4)
  try {
    # Stop pools first so no logon attempt with the old password can re-lock the account.
    foreach ($pl in $pools) {
      if ((Get-WebAppPoolState $pl.Name).Value -ne 'Stopped') { Stop-WebAppPool $pl.Name }
    }
    'Pools stopped.'

    Set-LocalUser -Name $AccountName -Password (ConvertTo-SecureString $p -AsPlainText -Force)
    'Account password reset.'
    if (Get-Locked) {
      Unlock-Account
      Start-Sleep 2
      if (Get-Locked) { throw "Account is still locked after the unlock attempt. Wait for the lockout duration (see 'net accounts') and run -Fix again." }
      'Account unlocked.'
    }
    if (-not (Test-Pwd $p)) { throw 'New password did not validate against the account (see warning above).' }
    'New password validated.'

    foreach ($pl in $pools) {
      Set-ItemProperty "IIS:\AppPools\$($pl.Name)" -Name processModel -Value @{identityType=3; userName=$AccountName; password=$p}
      Start-WebAppPool $pl.Name
      "  $($pl.Name): identity updated, pool started"
    }
  }
  finally { Remove-Variable p -ErrorAction SilentlyContinue }   # never keep the password in memory

  # --- 8. Verification -------------------------------------
  Section 'Verification'
  if (-not $TestUrl) {
    $b = Get-WebBinding -Port 8383 | Select-Object -First 1
    if ($b) {
      $ip = $b.bindingInformation.Split(':')[0]
      if (-not $ip -or $ip -eq '*') { $ip = '127.0.0.1' }
      $TestUrl = "$($b.protocol)://${ip}:8383/"
    }
  }
  if ($TestUrl) {
    # The first request after an update may time out while ASP.NET compiles; that is not a failure.
    "Requesting $TestUrl (timeout ${TestTimeoutSec}s)..."
    try   { $r = Invoke-WebRequest $TestUrl -UseBasicParsing -TimeoutSec $TestTimeoutSec; "  => HTTP $($r.StatusCode)" }
    catch { "  => $($_.Exception.Message)" }
  } else { 'No binding on port 8383 found; skipping HTTP test (use -TestUrl).' }

  Start-Sleep 3
  foreach ($pl in $pools) { "{0,-24} State={1}" -f $pl.Name, (Get-WebAppPoolState $pl.Name).Value }

  $new = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WAS'; Id=$WasIdentityEventIds; StartTime=$fixTime} -ErrorAction SilentlyContinue)
  if ($new.Count -gt 0) {
    Fail 'WAS still reports identity errors after the fix. Check the System event log.'
    exit $EXIT_ERROR
  }
  Write-Host 'No new WAS identity errors. Identity fix applied successfully.' -ForegroundColor Green
  exit $EXIT_OK
}
catch {
  Fail "ERROR: $($_.Exception.Message)"
  exit $EXIT_ERROR
}
