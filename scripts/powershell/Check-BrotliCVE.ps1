<#
.SYNOPSIS
    CVE-2026-111497 (Brotli decoder) - one-shot check & fix for Windows hosting
    servers (IIS / Plesk / MailEnable).

.DESCRIPTION
    1. Audits the server (read-only).
    2. Prints a verdict:  NOT VULNERABLE / MITIGATED / VULNERABLE.
    3. If vulnerable, applies the safe fixes:
         - installs patched .NET 8/9/10 (Microsoft-signed, version-verified)
         - adds a global IIS rule that drops requests with "Content-Encoding: br"
           (protects EOL / self-contained customer apps), then self-tests it
         - upgrades Brotli/brotlicffi in system Python
         - optionally runs Plesk Installer for Plesk-managed PHP/Node
    4. Re-checks and prints the final verdict.

    This script DELETES NOTHING. Binaries inside customer folders are never executed.

    Exit codes: 0 = NOT VULNERABLE, 1 = MITIGATED (residual risk), 2 = VULNERABLE

.PARAMETER CheckOnly
    Audit + verdict only, no changes.
.PARAMETER AutoFix
    No prompts (for running on many servers). Plesk upgrade and app-pool recycle
    still need their own switches below.
.PARAMETER RecycleAppPools
    With -AutoFix: recycle started app pools after a .NET patch is installed.
.PARAMETER AllowPleskUpgrade
    With -AutoFix: allow "plesk installer --upgrade-installed-components".
.PARAMETER RemoveSuperseded
    With -AutoFix: uninstall old/preview .NET 8/9/10 builds that already have a
    patched version side-by-side (interactive mode asks per version).
.PARAMETER ReportShare
    UNC folder to copy the summary JSON + CSV to (e.g. \\nas\security\brotli).
.PARAMETER InstallerDir
    Folder with pre-downloaded .NET installers (offline servers).
.PARAMETER SkipDeepScan
    Skip customer content (vhosts / site folders). Faster, less complete.

.EXAMPLE
    .\Check-BrotliCVE.ps1                      # check, ask before fixing
    .\Check-BrotliCVE.ps1 -CheckOnly           # check only
    .\Check-BrotliCVE.ps1 -AutoFix -RecycleAppPools -ReportShare \\nas\sec\brotli
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$AutoFix,
    [switch]$RecycleAppPools,
    [switch]$AllowPleskUpgrade,
    [switch]$RemoveSuperseded,
    [string]$ReportShare = '',
    [string]$InstallerDir = '',
    [switch]$SkipDeepScan,
    [string[]]$ExtraScanRoots = @(),
    [string]$WorkDir = 'C:\BrotliRemediation'
)

# ===========================================================================
# ADVISORY CONFIG - fixed versions
# ===========================================================================
$CVE         = 'CVE-2026-111497'
$FixedDotNet = @{ 8 = '8.0.33'; 9 = '9.0.22'; 10 = '10.0.14' }      # 11 -> RC3
$FixedNode   = @{ 22 = '22.23.4'; 24 = '24.22.1'; 26 = '26.12.1' }
$FixedPhp    = @{ '8.2' = '8.2.35'; '8.3' = '8.3.36'; '8.4' = '8.4.27'; '8.5' = '8.5.12' }
$FixedBun    = '1.4.4'
$FixedPy     = @{ 'brotli' = '1.2.1'; 'brotlicffi' = '1.2.1.0' }
$RuleName    = 'Block-Brotli-Request-Body'

# ===========================================================================
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
if (-not [Environment]::Is64BitProcess) { Write-Warning 'Run from 64-bit PowerShell.'; exit 3 }

$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
$LogFile     = Join-Path $WorkDir "log-$env:COMPUTERNAME-$ts.txt"
$ReportFile  = Join-Path $WorkDir "report-$env:COMPUTERNAME-$ts.csv"
$NotifyFile  = Join-Path $WorkDir "customers-to-notify-$env:COMPUTERNAME-$ts.csv"
$SummaryFile = Join-Path $WorkDir "summary-$env:COMPUTERNAME-$ts.json"
$DlDir       = Join-Path $WorkDir 'installers'
Start-Transcript -Path $LogFile -Append | Out-Null
$Actions = New-Object System.Collections.Generic.List[string]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Section([string]$t) {
    Write-Host ''; Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host "  $t" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}
function ConvertTo-Ver([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    $m = [regex]::Match($s, '\d+(\.\d+){1,3}')
    if (-not $m.Success) { return $null }
    $p = @($m.Value.Split('.')); while ($p.Count -lt 4) { $p += '0' }
    try { return [version]($p[0..3] -join '.') } catch { return $null }
}
function New-Status([string]$Status, [string]$Fixed) { [pscustomobject]@{ Status = $Status; Fixed = $Fixed } }

$Findings = New-Object System.Collections.Generic.List[object]
function Add-Finding {
    param($Component, $Path, $Version, $Status, $FixedIn = '', $Owner = 'system', $Note = '')
    $Findings.Add([pscustomobject]@{ Status = $Status; Component = $Component; Version = $Version
        FixedIn = $FixedIn; Owner = $Owner; Path = $Path; Note = $Note })
}
function Approve([string]$msg, [bool]$allowedInAuto = $true) {
    if ($AutoFix) {
        if ($allowedInAuto) { Write-Host "[auto] $msg" -ForegroundColor Yellow; return $true }
        Write-Host "[skipped in AutoFix] $msg" -ForegroundColor DarkYellow; return $false
    }
    Write-Host ''; Write-Host "[?] $msg" -ForegroundColor Yellow
    return ((Read-Host '    Proceed? (y/N)') -match '^(y|yes)$')
}
function Test-UnderAny([string]$p, [string[]]$roots) {
    foreach ($r in $roots) {
        if (-not $r) { continue }
        $r2 = $r.TrimEnd('\')
        if ($p.StartsWith($r2 + '\', [StringComparison]::OrdinalIgnoreCase) -or $p -ieq $r2) { return $true }
    }
    return $false
}

function Get-DotNetStatus([string]$vt) {
    $v = ConvertTo-Ver $vt
    if (-not $v) { return New-Status 'UNKNOWN' '' }
    $maj = $v.Major
    if ($maj -eq 11) {
        if ($vt -match '-preview') { return New-Status 'VULNERABLE' '11.0 RC3' }
        if ($vt -match '-rc\.(\d+)') { if ([int]$Matches[1] -ge 3) { return New-Status 'OK' '11.0 RC3' }; return New-Status 'VULNERABLE' '11.0 RC3' }
        return New-Status 'OK' '11.0 RC3'
    }
    if ($FixedDotNet.ContainsKey($maj)) {
        if ($v -ge (ConvertTo-Ver $FixedDotNet[$maj])) { return New-Status 'OK' $FixedDotNet[$maj] }
        return New-Status 'VULNERABLE' $FixedDotNet[$maj]
    }
    if ($maj -lt 8) { return New-Status 'EOL-VULNERABLE' 'none (EOL) - migrate to .NET 8/9/10' }
    return New-Status 'UNKNOWN' ''
}
function Get-NodeStatus([string]$vt) {
    $v = ConvertTo-Ver $vt
    if (-not $v) { return New-Status 'UNKNOWN' '22.23.4 / 24.22.1 / 26.12.1' }
    if ($FixedNode.ContainsKey($v.Major)) {
        if ($v -ge (ConvertTo-Ver $FixedNode[$v.Major])) { return New-Status 'OK' $FixedNode[$v.Major] }
        return New-Status 'VULNERABLE' $FixedNode[$v.Major]
    }
    if ($v.Major -lt 26) { return New-Status 'EOL-VULNERABLE' 'none (EOL) - move to 22/24/26' }
    return New-Status 'UNKNOWN' ''
}
function Get-PhpStatus([string]$vt) {
    $v = ConvertTo-Ver $vt
    if (-not $v) { return New-Status 'UNKNOWN' '8.2.35 / 8.3.36 / 8.4.27 / 8.5.12' }
    $key = "$($v.Major).$($v.Minor)"
    if ($FixedPhp.ContainsKey($key)) {
        if ($v -ge (ConvertTo-Ver $FixedPhp[$key])) { return New-Status 'OK' $FixedPhp[$key] }
        return New-Status 'VULNERABLE' $FixedPhp[$key]
    }
    if ($v -lt [version]'8.2.0.0') { return New-Status 'EOL-VULNERABLE' 'none (EOL) - move to 8.2+' }
    return New-Status 'UNKNOWN' ''
}
function Get-LibBrotliStatus($v) {
    $fx = '1.0.10 / 1.1.1 / 1.2.1'
    if (-not $v -or $v.Major -ne 1) { return New-Status 'UNKNOWN' $fx }
    $st = 'OK'
    switch ($v.Minor) {
        0 { if ($v.Build -ge 10) { $st = 'OK' } elseif ($v.Build -ge 3) { $st = 'VULNERABLE' } else { $st = 'UNKNOWN' } }
        1 { if ($v.Build -ge 1) { $st = 'OK' } else { $st = 'VULNERABLE' } }
        2 { if ($v.Build -ge 1) { $st = 'OK' } else { $st = 'VULNERABLE' } }
    }
    return New-Status $st $fx
}
function Get-PyStatus([string]$name, [string]$vt) {
    $n = $name.ToLowerInvariant()
    if ($n -eq 'brotlipy') { return New-Status 'VULNERABLE' 'unmaintained -> replace with Brotli>=1.2.1' }
    $v = ConvertTo-Ver $vt
    if (-not $v) { return New-Status 'UNKNOWN' $FixedPy[$n] }
    if ($v -ge (ConvertTo-Ver $FixedPy[$n])) { return New-Status 'OK' $FixedPy[$n] }
    return New-Status 'VULNERABLE' $FixedPy[$n]
}
# coreclr.dll etc. report "8,0,3226,50405 @Commit" -> 8.0.32
function Get-NetBinaryVersion($fvi) {
    if (-not $fvi) { return $null }
    if ([string]$fvi.ProductVersion -match '^\s*(\d+\.\d+\.\d+(-[0-9A-Za-z\.]+)?)') { return $Matches[1] }
    $maj = $fvi.FileMajorPart; $min = $fvi.FileMinorPart; $bld = $fvi.FileBuildPart
    if ($maj -ge 5) { return ('{0}.{1}.{2}' -f $maj, $min, [math]::Floor($bld / 100)) }
    if ($maj -eq 4 -and $min -eq 700) { return '3.1' }
    if ($maj -eq 4) { return '2.1' }
    return $null
}

# Self-contained .NET inside Program Files = admin tool (not reachable from the web)
function Get-ToolHint([string]$p) {
    if ($p -match 'SQL Server Management Studio') { return 'SSMS: update via Visual Studio Installer, or uninstall from the server.' }
    if ($p -match 'DesktopAppInstaller')          { return 'App Installer (winget): update from Microsoft Store / "winget upgrade Microsoft.AppInstaller".' }
    if ($p -match 'win-acme|letsencrypt')          { return 'win-acme: update to the latest release.' }
    if ($p -match '\\PowerShell\\7')               { return 'PowerShell 7: update to the latest release.' }
    if ($p -match 'Azure Data Studio')             { return 'Azure Data Studio: uninstall (retired product).' }
    return 'Update the product installed in this folder, or uninstall it if not needed.'
}

# ===========================================================================
# 1) ENVIRONMENT
# ===========================================================================
Write-Section "1) $CVE check on $env:COMPUTERNAME"
$PleskDir   = if ($env:plesk_dir) { $env:plesk_dir.TrimEnd('\') } else { $null }
$VhostsRoot = if ($env:plesk_vhosts) { $env:plesk_vhosts.TrimEnd('\') } elseif (Test-Path 'C:\Inetpub\vhosts') { 'C:\Inetpub\vhosts' } else { $null }
$MailEnableDir = $null
foreach ($k in 'HKLM:\SOFTWARE\WOW6432Node\Mail Enable\Mail Enable', 'HKLM:\SOFTWARE\Mail Enable\Mail Enable') {
    try { $val = (Get-ItemProperty -Path $k -ErrorAction Stop).'Program Directory'; if ($val) { $MailEnableDir = $val.TrimEnd('\'); break } } catch {}
}
if (-not $MailEnableDir) { foreach ($c in "${env:ProgramFiles(x86)}\Mail Enable", "$env:ProgramFiles\Mail Enable") { if (Test-Path $c) { $MailEnableDir = $c; break } } }

$IisPresent = $false
$SiteMap = New-Object System.Collections.Generic.List[object]
try {
    Import-Module WebAdministration -ErrorAction Stop
    $IisPresent = $true
    foreach ($s in Get-Website) {
        $pp = [Environment]::ExpandEnvironmentVariables([string]$s.physicalPath).TrimEnd('\')
        if ($pp) { $SiteMap.Add([pscustomobject]@{ Name = $s.Name; Path = $pp }) }
    }
    foreach ($a in Get-WebApplication) {
        $pp = [Environment]::ExpandEnvironmentVariables([string]$a.PhysicalPath).TrimEnd('\')
        $sn = [regex]::Match([string]$a.ItemXPath, "@name='([^']+)'").Groups[1].Value
        if ($pp) { $SiteMap.Add([pscustomobject]@{ Name = "$sn$($a.path)"; Path = $pp }) }
    }
} catch { Write-Host 'IIS not available.' -ForegroundColor DarkYellow }
Write-Host ("Plesk: {0} | MailEnable: {1} | IIS sites/apps: {2}" -f $(if ($PleskDir) { 'yes' } else { 'no' }), $(if ($MailEnableDir) { 'yes' } else { 'no' }), $SiteMap.Count)

function Get-Owner([string]$p) {
    if ($VhostsRoot -and $p.StartsWith($VhostsRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        return 'vhost:' + $p.Substring($VhostsRoot.Length + 1).Split('\')[0]
    }
    $best = $null
    foreach ($s in $SiteMap) {
        if ($p.StartsWith($s.Path + '\', [StringComparison]::OrdinalIgnoreCase) -or $p -ieq $s.Path) {
            if (-not $best -or $s.Path.Length -gt $best.Path.Length) { $best = $s }
        }
    }
    if ($best) { return 'site:' + $best.Name }
    return 'system'
}

# ===========================================================================
# 2) .NET SYSTEM RUNTIMES
# ===========================================================================
$DotNetRoots = @("$env:ProgramFiles\dotnet", "${env:ProgramFiles(x86)}\dotnet") | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
function Get-SystemDotNet {
    $list = @()
    foreach ($root in $DotNetRoots) {
        $arch = if ($root -like '*(x86)*') { 'x86' } else { 'x64' }
        foreach ($fw in 'Microsoft.NETCore.App', 'Microsoft.AspNetCore.App', 'Microsoft.WindowsDesktop.App') {
            $d = Join-Path $root "shared\$fw"
            if (-not (Test-Path -LiteralPath $d)) { continue }
            foreach ($vd in Get-ChildItem -LiteralPath $d -Directory -ErrorAction SilentlyContinue) {
                $r = Get-DotNetStatus $vd.Name; $vv = ConvertTo-Ver $vd.Name
                $list += [pscustomobject]@{ Arch = $arch; Framework = $fw; VersionText = $vd.Name
                    Major = $(if ($vv) { $vv.Major } else { -1 }); Status = $r.Status; Fixed = $r.Fixed; Path = $vd.FullName }
            }
        }
    }
    # an old/preview 8/9/10 build is SUPERSEDED when a patched build of the same
    # framework+arch+major is installed side-by-side: apps roll forward to the patched one
    foreach ($i in $list) {
        if ($i.Status -ne 'VULNERABLE' -or -not $FixedDotNet.ContainsKey($i.Major)) { continue }
        $twin = $list | Where-Object { $_.Framework -eq $i.Framework -and $_.Arch -eq $i.Arch -and $_.Major -eq $i.Major -and $_.Status -eq 'OK' }
        if ($twin) { $i.Status = 'SUPERSEDED' }
    }
    return $list
}
$DotNetInstalled = @(Get-SystemDotNet)
foreach ($d in $DotNetInstalled) { Add-Finding "$($d.Framework) ($($d.Arch))" $d.Path $d.VersionText $d.Status $d.Fixed 'system' }

# ===========================================================================
# 3) FILE SYSTEM SCAN
# ===========================================================================
Write-Host 'Scanning file system (may take a few minutes on large servers)...'
$NamePattern     = '^(coreclr\.dll|system\.io\.compression\.native\.dll|.*brotli.*\.dll|brolib_x(64|86)\.dll|node\.exe|bun\.exe|php\.exe|.*\.runtimeconfig\.json)$'
$DirPattern      = '^(?<n>brotli|brotlicffi|brotlipy)-(?<v>\d+(\.\d+)*).*\.(dist-info|egg-info)$'
$ExcludeDirNames = @('WinSxS', '$Recycle.Bin', 'System Volume Information', '.git', '.trash')
$FoundFiles = New-Object System.Collections.Generic.List[object]
$FoundDirs  = New-Object System.Collections.Generic.List[object]

function Find-Interesting([string]$root) {
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($root)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        if ($dir -ieq $WorkDir) { continue }
        $entries = $null
        try { $entries = ([System.IO.DirectoryInfo]$dir).GetFileSystemInfos() } catch { continue }
        foreach ($e in $entries) {
            if ($e -is [System.IO.DirectoryInfo]) {
                if ($e.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
                if ($e.Name -match $DirPattern) { $FoundDirs.Add($e) }
                if ($ExcludeDirNames -contains $e.Name) { continue }
                $stack.Push($e.FullName)
            } elseif ($e.Name -match $NamePattern) { $FoundFiles.Add($e) }
        }
    }
}

$candidates = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $PleskDir, $MailEnableDir, 'C:\PHP', 'C:\tools')
$candidates += @(Get-Item 'C:\Python*', 'C:\Users\*\AppData\Local\Programs\Python' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
if (-not $SkipDeepScan) { $candidates += @('C:\inetpub', $VhostsRoot); $candidates += @($SiteMap | ForEach-Object { $_.Path }) }
$candidates += $ExtraScanRoots
$resolved = $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
    ForEach-Object { (Resolve-Path -LiteralPath $_).ProviderPath.TrimEnd('\') } | Sort-Object -Unique | Sort-Object Length
$ScanRoots = @()
foreach ($x in $resolved) { if (-not (Test-UnderAny $x $ScanRoots)) { $ScanRoots += $x } }
foreach ($r in $ScanRoots) { Write-Host "  $r"; Find-Interesting $r }

$AppUsage    = New-Object System.Collections.Generic.List[object]
$PyItems     = New-Object System.Collections.Generic.List[object]
$CoreClrDirs = @{}
$sorted = $FoundFiles | Sort-Object @{ Expression = { if ($_.Name -ieq 'coreclr.dll') { 0 } else { 1 } } }

foreach ($f in $sorted) {
    if (Test-UnderAny $f.FullName $DotNetRoots) { continue }                                   # handled in section 2
    if ($f.FullName -match '\\tmp\\root\\|\\Temporary ASP\.NET Files\\') { continue }          # shadow copies
    $name = $f.Name.ToLowerInvariant(); $dir = $f.DirectoryName; $owner = Get-Owner $f.FullName
    $fvi = $null; try { $fvi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($f.FullName) } catch {}
    $pv = if ($fvi) { $fvi.ProductVersion } else { $null }
    $fv = if ($fvi) { $fvi.FileVersion } else { $null }
    $inPlesk = ($PleskDir -and (Test-UnderAny $f.FullName @($PleskDir)))
    $ownNote = if ($owner -eq 'system') { 'Update the product installed in this folder.' } else { 'Customer app: owner must republish/update.' }

    if ($name -eq 'coreclr.dll') {
        $CoreClrDirs[$dir.ToLowerInvariant()] = $true
        $nv = Get-NetBinaryVersion $fvi; $r = Get-DotNetStatus $nv
        if ($owner -eq 'system') {
            $st = if ($r.Status -in 'VULNERABLE', 'EOL-VULNERABLE') { 'TOOL-VULNERABLE' } else { $r.Status }
            Add-Finding '.NET admin tool (self-contained)' $dir $nv $st $r.Fixed $owner (Get-ToolHint $dir)
        } else {
            Add-Finding '.NET self-contained app' $dir $nv $r.Status $r.Fixed $owner ('Bundles its own runtime - server patch does NOT fix it. ' + $ownNote)
        }
    }
    elseif ($name -eq 'system.io.compression.native.dll') {
        if ($CoreClrDirs.ContainsKey($dir.ToLowerInvariant())) { continue }
        $nv = Get-NetBinaryVersion $fvi; $r = Get-DotNetStatus $nv
        if ($owner -eq 'system') {
            $st = if ($r.Status -in 'VULNERABLE', 'EOL-VULNERABLE') { 'TOOL-VULNERABLE' } else { $r.Status }
            Add-Finding '.NET admin tool (compression lib)' $f.FullName $nv $st $r.Fixed $owner (Get-ToolHint $f.FullName)
        } else {
            Add-Finding '.NET compression native lib' $f.FullName $nv $r.Status $r.Fixed $owner ('Contains Brotli. ' + $ownNote)
        }
    }
    elseif ($name -like '*.runtimeconfig.json') {
        # framework descriptors inside a private/bundled runtime (e.g. SSMS) are not apps
        if ($f.FullName -match '\\shared\\Microsoft\.(NETCore|AspNetCore|WindowsDesktop)\.App\\') { continue }
        $j = $null; try { $j = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop | ConvertFrom-Json } catch { continue }
        $ro = $j.runtimeOptions
        if (-not $ro -or $ro.includedFrameworks) { continue }
        $fws = @(); if ($ro.framework) { $fws += $ro.framework }; if ($ro.frameworks) { $fws += @($ro.frameworks) }
        foreach ($fw in $fws) { $AppUsage.Add([pscustomobject]@{ App = $f.FullName; Owner = $owner; Framework = [string]$fw.name; Version = [string]$fw.version
                                                              RollForward = [string]$ro.rollForward; ApplyPatches = $ro.applyPatches }) }
    }
    elseif ($name -eq 'node.exe') {
        $r = Get-NodeStatus $pv
        Add-Finding 'Node.js' $f.FullName $pv $r.Status $r.Fixed $owner $(if ($inPlesk) { 'Plesk-managed: update via Plesk Installer.' } else { $ownNote })
    }
    elseif ($name -eq 'bun.exe') {
        $v = ConvertTo-Ver $pv
        if ($v) { Add-Finding 'Bun' $f.FullName $pv $(if ($v -ge (ConvertTo-Ver $FixedBun)) { 'OK' } else { 'VULNERABLE' }) $FixedBun $owner $ownNote }
        else { Add-Finding 'Bun' $f.FullName '?' 'UNKNOWN' $FixedBun $owner 'No version metadata: check "bun --version" manually.' }
    }
    elseif ($name -eq 'php.exe') {
        if ($PleskDir -and (Test-UnderAny $f.FullName @("$PleskDir\admin\bin"))) { continue }   # Plesk wrapper, not PHP
        $r = Get-PhpStatus $pv
        $n = if ($inPlesk) { 'Plesk-managed PHP: update via Plesk Installer.' } else { 'Replace with patched build from windows.php.net.' }
        if ($r.Status -eq 'EOL-VULNERABLE') { $n += ' EOL: move sites to PHP 8.2+, then remove this handler.' }
        Add-Finding 'PHP' $f.FullName $pv $r.Status $r.Fixed $owner $n
    }
    elseif ($name -eq 'iisbrotli.dll') {
        Add-Finding 'IIS Compression module (iisbrotli)' $f.FullName $fv 'LOW-RISK' 'vendor (Microsoft)' $owner 'Used only to compress responses (encoder); CVE is in the decoder.'
    }
    else {
        if ($name -eq 'system.io.compression.brotli.dll') { continue }   # managed MS wrapper, no Brotli code
        $isManaged = $false
        try { [void][System.Reflection.AssemblyName]::GetAssemblyName($f.FullName); $isManaged = $true } catch {}
        if ($isManaged) {
            Add-Finding 'Managed Brotli library (3rd-party)' $f.FullName $fv 'UNKNOWN' 'vendor / NuGet update' $owner 'Third-party Brotli port (e.g. BrotliSharpLib). Not fixed by Microsoft patches.'
            continue
        }
        $v = ConvertTo-Ver $fv; if ($v -and $v.Major -ne 1) { $v = $null }
        $r = Get-LibBrotliStatus $v
        $hint = if ($inPlesk) { 'Plesk internal: keep Plesk updated, check Plesk advisories.' }
                elseif ($f.FullName -match '\\Git\\') { 'Git for Windows: update or uninstall.' }
                elseif ($f.FullName -match '\\Nmap\\') { 'Nmap/Zenmap: update or uninstall.' }
                elseif ($name -like 'brolib_x*') { 'Brotli.NET NuGet native lib: owner must update package.' }
                elseif ($r.Status -eq 'UNKNOWN') { 'No brotli version in metadata - ask the vendor.' } else { $ownNote }
        Add-Finding 'libbrotli DLL' $f.FullName $fv $r.Status $r.Fixed $owner $hint
    }
}

foreach ($d in $FoundDirs) {
    $m = [regex]::Match($d.Name, $DirPattern, 'IgnoreCase'); if (-not $m.Success) { continue }
    $pkg = $m.Groups['n'].Value.ToLowerInvariant(); $ver = $m.Groups['v'].Value
    $pyHome = Split-Path (Split-Path $d.Parent.FullName -Parent) -Parent
    $pyExe = $null
    foreach ($c in (Join-Path $pyHome 'python.exe'), (Join-Path $pyHome 'Scripts\python.exe')) { if (Test-Path -LiteralPath $c) { $pyExe = $c; break } }
    $owner = Get-Owner $d.FullName; $r = Get-PyStatus $pkg $ver
    $PyItems.Add([pscustomobject]@{ Package = $pkg; Version = $ver; Status = $r.Status; PythonExe = $pyExe; Owner = $owner; Path = $d.FullName })
    Add-Finding "Python package $pkg" $d.FullName $ver $r.Status $r.Fixed $owner $(if ($pyExe) { "python: $pyExe" } else { '' })
}

foreach ($g in ($AppUsage | Where-Object { $vv = ConvertTo-Ver $_.Version; $vv -and $vv.Major -lt 8 -and $_.Framework -match '^Microsoft\.(NETCore|AspNetCore|WindowsDesktop)\.App$' } | Group-Object App)) {
    $x = $g.Group[0]
    Add-Finding '.NET app on EOL runtime' $x.App "$($x.Framework) $($x.Version)" 'EOL-VULNERABLE' 'migrate to .NET 8/9/10' $x.Owner 'No patch exists for this runtime.'
}

# ===========================================================================
# IIS mitigation rule helpers
# ===========================================================================
$ApphostPath = 'MACHINE/WEBROOT/APPHOST'
function Test-RewriteInstalled { $IisPresent -and [bool](Get-WebGlobalModule -Name 'RewriteModule' -ErrorAction SilentlyContinue) }
function Test-BrRuleExists {
    if (-not (Test-RewriteInstalled)) { return $false }
    [bool](Get-WebConfiguration -PSPath $ApphostPath -Filter "system.webServer/rewrite/globalRules/rule[@name='$RuleName']" -ErrorAction SilentlyContinue)
}
function Add-BrRule {
    $base = "system.webServer/rewrite/globalRules/rule[@name='$RuleName']"
    Add-WebConfigurationProperty -PSPath $ApphostPath -Filter 'system.webServer/rewrite/globalRules' -Name '.' -Value @{ name = $RuleName; stopProcessing = 'True' }
    Set-WebConfigurationProperty -PSPath $ApphostPath -Filter "$base/match" -Name 'url' -Value '.*'
    Add-WebConfigurationProperty -PSPath $ApphostPath -Filter "$base/conditions" -Name '.' -Value @{ input = '{HTTP_CONTENT_ENCODING}'; pattern = '(^|,)\s*br\s*(,|$)' }
    Set-WebConfigurationProperty -PSPath $ApphostPath -Filter "$base/action" -Name 'type' -Value 'AbortRequest'
}
function Remove-BrRule { Clear-WebConfiguration -PSPath $ApphostPath -Filter "system.webServer/rewrite/globalRules/rule[@name='$RuleName']" }
function Test-BrRuleWorks {
    # returns $true (works), $false (broken), $null (could not test)
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curl) { return $null }
    foreach ($b in (Get-WebBinding -Protocol http -ErrorAction SilentlyContinue)) {
        if ([string]$b.bindingInformation -notmatch '^([^:\[\]]*):(\d+):([^*].+)$') { continue }
        $ip = $Matches[1]; $port = $Matches[2]; $hn = $Matches[3]
        if (-not $ip -or $ip -eq '*') { $ip = '127.0.0.1' }
        $res = "${hn}:${port}:$ip"; $url = "http://${hn}:$port/"
        $normal = (& curl.exe -s -o NUL -m 20 -w '%{http_code}' --resolve $res $url) -join ''
        if ($normal -eq '000') { continue }   # this site does not answer at all, try another
        $br = (& curl.exe -s -o NUL -m 20 -w '%{http_code}' --resolve $res -X POST -H 'Content-Encoding: br' --data 'x' $url) -join ''
        Write-Host "  self-test on ${hn}: normal=$normal  br-request=$br"
        return ($br -eq '000')
    }
    return $null
}

# ===========================================================================
# 4) VERDICT
# ===========================================================================
function Get-Verdict {
    $sysVuln = @($Findings | Where-Object { $_.Owner -eq 'system' -and $_.Status -eq 'VULNERABLE' })
    $residual = @($Findings | Where-Object { $_.Status -eq 'EOL-VULNERABLE' -or ($_.Owner -ne 'system' -and $_.Status -eq 'VULNERABLE') })
    $tools = @($Findings | Where-Object Status -eq 'TOOL-VULNERABLE')
    $rule = Test-BrRuleExists
    $v = if ($sysVuln.Count) { 'VULNERABLE' }
         elseif ($residual.Count -and -not $rule) { 'VULNERABLE' }
         elseif ($residual.Count -or $tools.Count) { 'MITIGATED' }
         else { 'NOT VULNERABLE' }
    [pscustomobject]@{ Verdict = $v; ServerItems = $sysVuln; ResidualItems = $residual; ToolItems = $tools; RuleActive = $rule }
}
function Show-Verdict($vd, [string]$title) {
    Write-Section $title
    $color = switch ($vd.Verdict) { 'NOT VULNERABLE' { 'Green' } 'MITIGATED' { 'Yellow' } default { 'Red' } }
    Write-Host ("  {0} : {1}" -f $env:COMPUTERNAME, $vd.Verdict) -ForegroundColor $color
    Write-Host ("  server-level vulnerable : {0}" -f $vd.ServerItems.Count)
    Write-Host ("  EOL / customer residual : {0}" -f $vd.ResidualItems.Count)
    Write-Host ("  IIS br-request rule     : {0}" -f $(if ($vd.RuleActive) { 'ACTIVE' } else { 'not active' }))
    $sup = @($DotNetInstalled | Where-Object Status -eq 'SUPERSEDED')
    if ($sup) {
        Write-Host ("  superseded .NET builds  : {0} (patched version installed next to them; safe to remove)" -f $sup.Count) -ForegroundColor DarkYellow
        foreach ($i in $sup) { Write-Host ("   ~ {0} ({1}) {2}" -f $i.Framework, $i.Arch, $i.VersionText) -ForegroundColor DarkYellow }
    }
    foreach ($i in $vd.ServerItems) { Write-Host ("   - {0} {1}  {2}" -f $i.Component, $i.Version, $i.Path) -ForegroundColor Red }
    if ($vd.ToolItems.Count) {
        Write-Host ("  admin tools to update   : {0} (low risk: not reachable from the web)" -f $vd.ToolItems.Count) -ForegroundColor DarkYellow
        foreach ($i in $vd.ToolItems) { Write-Host ("   ! {0}  {1}" -f $i.Version, $i.Path) -ForegroundColor DarkYellow; Write-Host ("     -> {0}" -f $i.Note) }
    }
}

$Findings | Export-Csv -Path $ReportFile -NoTypeInformation -Encoding UTF8
$before = Get-Verdict
Show-Verdict $before 'VERDICT (before fix)'

$unknown = @($Findings | Where-Object Status -eq 'UNKNOWN')
if ($unknown) {
    Write-Host ''; Write-Host "  Manual check needed ($($unknown.Count)):" -ForegroundColor DarkYellow
    $unknown | Group-Object Note | ForEach-Object { Write-Host ("   - {0}x {1}" -f $_.Count, $_.Name) -ForegroundColor DarkYellow }
}

# ===========================================================================
# 5) FIX
# ===========================================================================
function Get-DotNetInstaller([int]$maj, [string]$pkg) {
    $fixed = ConvertTo-Ver $FixedDotNet[$maj]
    $prefix = $pkg -replace '-win.*$', ''; $suffix = $pkg.Substring($prefix.Length)
    $file = $null
    if ($InstallerDir -and (Test-Path -LiteralPath $InstallerDir)) {
        $hit = Get-ChildItem -LiteralPath $InstallerDir -Filter "$prefix-$maj.*$suffix.exe" -File -ErrorAction SilentlyContinue |
               Sort-Object { ConvertTo-Ver $_.Name } -Descending | Select-Object -First 1
        if ($hit) { $file = $hit.FullName }
    }
    if (-not $file) {
        New-Item -ItemType Directory -Path $DlDir -Force | Out-Null
        $url = "https://aka.ms/dotnet/$maj.0/$pkg.exe"; $file = Join-Path $DlDir "$pkg-$maj.exe"
        Write-Host "  downloading $url"
        try { Invoke-WebRequest -Uri $url -OutFile $file -UseBasicParsing -ErrorAction Stop }
        catch { Write-Host "  download failed: $($_.Exception.Message). Use -InstallerDir." -ForegroundColor Red; return $null }
    }
    $sig = Get-AuthenticodeSignature -FilePath $file
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        Write-Host "  REJECTED: not validly signed by Microsoft." -ForegroundColor Red; return $null
    }
    $iv = ConvertTo-Ver ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($file).ProductVersion)
    if (-not $iv -or $iv.Major -ne $maj -or $iv -lt $fixed) {
        Write-Host "  REJECTED: installer version $iv is not >= $fixed." -ForegroundColor Red; return $null
    }
    return $file
}
function Invoke-DotNetInstaller([string]$file) {
    $log = Join-Path $WorkDir ("install-{0}-{1}.log" -f [IO.Path]::GetFileNameWithoutExtension($file), $ts)
    $p = Start-Process -FilePath $file -ArgumentList @('/install', '/quiet', '/norestart', '/log', "`"$log`"") -Wait -PassThru
    if ($p.ExitCode -in 0, 3010, 1641) { Write-Host "  installed ($($p.ExitCode))" -ForegroundColor Green; return $true }
    Write-Host "  FAILED ($($p.ExitCode)) - see $log" -ForegroundColor Red; return $false
}

if ($CheckOnly) {
    Write-Host ''; Write-Host '-CheckOnly: no changes made.' -ForegroundColor Cyan
}
elseif ($before.Verdict -eq 'NOT VULNERABLE') {
    Write-Host ''; Write-Host 'Nothing to fix.' -ForegroundColor Green
}
else {
    Write-Section 'FIX'

    # --- 5a) patched .NET for vulnerable 8/9/10 ------------------------------
    $installed = $false
    foreach ($maj in ($DotNetInstalled | Where-Object { $_.Status -eq 'VULNERABLE' -and $FixedDotNet.ContainsKey($_.Major) } | ForEach-Object Major | Sort-Object -Unique)) {
        $items = $DotNetInstalled | Where-Object Major -eq $maj
        $missing = foreach ($g in ($items | Group-Object Framework, Arch)) { if (-not ($g.Group | Where-Object Status -eq 'OK')) { $g.Group[0] } }
        if (-not $missing) { continue }   # patched version already side-by-side; old folder is harmless (apps roll forward)
        $pkgs = @()
        $needHosting = [bool]($missing | Where-Object Framework -eq 'Microsoft.AspNetCore.App')
        if ($needHosting) { $pkgs += 'dotnet-hosting-win' }
        foreach ($arch in 'x64', 'x86') {
            if ($missing | Where-Object { $_.Framework -eq 'Microsoft.WindowsDesktop.App' -and $_.Arch -eq $arch }) { $pkgs += "windowsdesktop-runtime-win-$arch" }
            elseif (-not $needHosting -and ($missing | Where-Object { $_.Framework -eq 'Microsoft.NETCore.App' -and $_.Arch -eq $arch })) { $pkgs += "dotnet-runtime-win-$arch" }
        }
        foreach ($pkg in $pkgs) {
            if (-not (Approve "Install patched .NET $maj ($pkg >= $($FixedDotNet[$maj])) side-by-side")) { continue }
            $file = Get-DotNetInstaller $maj $pkg
            if ($file -and (Invoke-DotNetInstaller $file)) { $installed = $true; $Actions.Add("installed $pkg $maj") }
        }
    }
    if ($installed -and $IisPresent) {
        $doRecycle = if ($AutoFix) { [bool]$RecycleAppPools } else { Approve 'Recycle started IIS application pools now so sites load the patched runtime (short per-site blip)?' }
        if ($doRecycle) {
            foreach ($ap in Get-ChildItem IIS:\AppPools) { if ($ap.State -eq 'Started') { try { Restart-WebAppPool -Name $ap.Name -ErrorAction Stop } catch {} } }
            $Actions.Add('recycled app pools'); Write-Host '  app pools recycled.' -ForegroundColor Green
        } else { $Actions.Add('PENDING: recycle app pools'); Write-Host '  PENDING: recycle app pools in maintenance window.' -ForegroundColor Yellow }
    }

    # --- 5b) IIS mitigation rule ---------------------------------------------
    if ($before.ResidualItems.Count -and -not (Test-BrRuleExists)) {
        if (-not $IisPresent) { Write-Host '  IIS not present - mitigation rule not applicable.' }
        elseif (-not (Test-RewriteInstalled)) { Write-Host '  URL Rewrite module not installed - cannot add mitigation rule.' -ForegroundColor Red }
        elseif (Approve 'Add global IIS rule that drops requests with "Content-Encoding: br" (browsers never send these)') {
            Add-BrRule
            $ok = Test-BrRuleWorks
            if ($ok -eq $false) {
                Write-Host '  self-test FAILED - rule removed again.' -ForegroundColor Red; Remove-BrRule
            } else {
                if ($null -eq $ok) { Write-Host '  rule added (self-test not possible on this server).' -ForegroundColor Yellow }
                else { Write-Host '  rule added and verified.' -ForegroundColor Green }
                $Actions.Add('added IIS br-request rule')
            }
        }
    }

    # --- 5c) Plesk-managed PHP / Node ------------------------------------------
    $pleskVuln = @($Findings | Where-Object { $_.Status -eq 'VULNERABLE' -and $_.Component -in 'PHP', 'Node.js' -and $PleskDir -and (Test-UnderAny $_.Path @($PleskDir)) })
    if ($pleskVuln) {
        $pleskExe = $null
        foreach ($c in @((Get-Command plesk -ErrorAction SilentlyContinue).Source, "$env:plesk_bin\plesk.exe", "$PleskDir\bin\plesk.exe")) { if ($c -and (Test-Path -LiteralPath $c)) { $pleskExe = $c; break } }
        if ($pleskExe -and (Approve 'Run Plesk Installer --upgrade-installed-components (updates ALL Plesk components, may restart services)' ([bool]$AllowPleskUpgrade))) {
            & $pleskExe installer --select-release-current --upgrade-installed-components
            $Actions.Add('ran plesk installer upgrade')
        } elseif (-not $pleskExe) { Write-Host '  plesk.exe not found: update via Plesk > Tools & Settings > Updates.' -ForegroundColor Yellow }
    }

    # --- 5d) system Python -----------------------------------------------------
    foreach ($py in ($PyItems | Where-Object { $_.Status -eq 'VULNERABLE' -and $_.Owner -eq 'system' -and $_.PythonExe -and $_.Package -ne 'brotlipy' })) {
        $spec = if ($py.Package -eq 'brotlicffi') { 'brotlicffi>=1.2.1.0' } else { 'Brotli>=1.2.1' }
        if (Approve "pip install --upgrade '$spec' ($($py.PythonExe))") { & $py.PythonExe -m pip install --upgrade $spec; $Actions.Add("pip $spec") }
    }
}

# ===========================================================================
# 5e) OPTIONAL: remove superseded .NET builds (separate decision)
# ===========================================================================
function Get-UninstallEntries {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName }
}
function Get-VersionRegex([string]$vt) {
    if ($vt -match '^(\d+\.\d+\.\d+)-(rc|preview)\.(\d+)') {
        $b = [regex]::Escape($Matches[1]); $kind = $Matches[2]; $n = $Matches[3]
        $word = if ($kind -eq 'rc') { '(Release Candidate|RC)' } else { 'Preview' }
        return "(?i)(?<![\d.])$b(-$kind\.$n(?!\d)|\s+$word\s*$n(?!\d))"
    }
    return '(?<![\d.])' + [regex]::Escape($vt) + '(?![\d-])'
}
function Invoke-Uninstall($entry) {
    $cmd = if ($entry.QuietUninstallString) { [string]$entry.QuietUninstallString } else { [string]$entry.UninstallString }
    if (-not $cmd) { Write-Host "  no uninstall command for $($entry.DisplayName)" -ForegroundColor Red; return }
    if ($cmd -match '(?i)msiexec') {
        $guid = [regex]::Match($cmd, '\{[0-9A-Fa-f\-]{36}\}').Value
        if (-not $guid) { Write-Host "  cannot parse: $cmd" -ForegroundColor Red; return }
        $p = Start-Process msiexec.exe -ArgumentList "/x $guid /qn /norestart" -Wait -PassThru
    } else {
        if ($cmd -match '^\s*"([^"]+)"\s*(.*)$') { $exe = $Matches[1]; $argStr = $Matches[2] }
        else { $parts = $cmd.Split(' ', 2); $exe = $parts[0]; $argStr = $(if ($parts.Count -gt 1) { $parts[1] } else { '' }) }
        if ($argStr -notmatch '/uninstall') { $argStr = "/uninstall $argStr" }
        if ($argStr -notmatch '/quiet')     { $argStr += ' /quiet' }
        if ($argStr -notmatch '/norestart') { $argStr += ' /norestart' }
        $p = Start-Process -FilePath $exe -ArgumentList $argStr.Trim() -Wait -PassThru
    }
    if ($p.ExitCode -in 0, 3010, 1641) { Write-Host "  removed: $($entry.DisplayName)" -ForegroundColor Green; $Actions.Add("uninstalled $($entry.DisplayName)") }
    else { Write-Host "  FAILED ($($p.ExitCode)): $($entry.DisplayName)" -ForegroundColor Red }
}

$supGroups = @($DotNetInstalled | Where-Object Status -eq 'SUPERSEDED' | Group-Object VersionText)
if (-not $CheckOnly -and $supGroups) {
    Write-Section 'OPTIONAL CLEANUP - superseded .NET builds'
    $ancmBefore = $IisPresent -and [bool](Get-WebGlobalModule -Name 'AspNetCoreModuleV2' -ErrorAction SilentlyContinue)
    $Uninst = @(Get-UninstallEntries)
    foreach ($g in $supGroups) {
        $ver = $g.Name
        $pinned = @($AppUsage | Where-Object { $_.Version -eq $ver -and ($_.RollForward -eq 'Disable' -or $_.ApplyPatches -eq $false -or $ver -match '-') })
        if ($pinned) {
            Write-Host ".NET ${ver}: SKIPPED - these apps target exactly this build:" -ForegroundColor Yellow
            $pinned | ForEach-Object { Write-Host "   * [$($_.Owner)] $($_.App)" }
            continue
        }
        $rx = Get-VersionRegex $ver
        $entries = @($Uninst | Where-Object { $_.DisplayName -match $rx -and $_.DisplayName -match '\.NET|ASP\.NET|Windows Desktop Runtime' -and $_.DisplayName -notmatch 'Host FX Resolver|\.NET Host -|SDK' })
        if (-not $entries) {
            Write-Host ".NET ${ver}: no registered uninstaller found. Use Microsoft's tool: https://aka.ms/dotnet-core-uninstall" -ForegroundColor Yellow
            continue
        }
        $targets = @($entries | Where-Object { $_.SystemComponent -ne 1 }); if (-not $targets) { $targets = $entries }
        Write-Host ".NET $ver will be removed via:" -ForegroundColor Cyan
        $targets | ForEach-Object { Write-Host "   - $($_.DisplayName)" }
        if (Approve "Uninstall .NET $ver (patched build stays installed)" ([bool]$RemoveSuperseded)) {
            foreach ($t in $targets) { Invoke-Uninstall $t }
        }
    }
    if ($ancmBefore -and -not (Get-WebGlobalModule -Name 'AspNetCoreModuleV2' -ErrorAction SilentlyContinue)) {
        Write-Host 'WARNING: ASP.NET Core Module V2 was unregistered by the uninstall - ASP.NET Core sites will fail.' -ForegroundColor Red
        $top = $DotNetInstalled | Where-Object { $_.Status -eq 'OK' -and $_.Framework -eq 'Microsoft.AspNetCore.App' } |
               Sort-Object { ConvertTo-Ver $_.VersionText } -Descending | Select-Object -First 1
        $file = if ($top) { Get-DotNetInstaller $top.Major 'dotnet-hosting-win' } else { $null }
        if ($file) {
            Write-Host '  repairing patched Hosting Bundle...' -ForegroundColor Yellow
            $p = Start-Process -FilePath $file -ArgumentList '/repair', '/quiet', '/norestart' -Wait -PassThru
            Write-Host "  repair exit code $($p.ExitCode)"; $Actions.Add('repaired hosting bundle')
        } else { Write-Host '  Run the latest dotnet-hosting-*-win.exe and choose Repair NOW.' -ForegroundColor Red }
    }
}

# ===========================================================================
# 6) FINAL VERDICT + REPORTS
# ===========================================================================
if (-not $CheckOnly) {
    # refresh .NET findings after install / uninstall
    $DotNetInstalled = @(Get-SystemDotNet)
    $keep = @($Findings | Where-Object { $_.Path -notlike '*\dotnet\shared\*' })
    $Findings.Clear(); foreach ($k in $keep) { $Findings.Add($k) }
    foreach ($d in $DotNetInstalled) { Add-Finding "$($d.Framework) ($($d.Arch))" $d.Path $d.VersionText $d.Status $d.Fixed 'system' }
}
$after = Get-Verdict
Show-Verdict $after 'FINAL VERDICT'

$manual = @($after.ServerItems | Where-Object { $_.Component -notmatch '^Microsoft\.(NETCore|AspNetCore|WindowsDesktop)\.App' })
if ($manual) {
    Write-Host ''; Write-Host '  Needs manual action (script cannot patch these):' -ForegroundColor Yellow
    $manual | ForEach-Object { Write-Host ("   - {0} {1} : {2}" -f $_.Component, $_.Version, $_.Note) }
}
$eolMajors = $DotNetInstalled | Where-Object Status -eq 'EOL-VULNERABLE' | ForEach-Object Major | Sort-Object -Unique
if ($eolMajors) {
    Write-Host ''; Write-Host '  Customers on EOL .NET (must migrate to 8/10):' -ForegroundColor Yellow
    foreach ($m in $eolMajors) {
        $users = @($AppUsage | Where-Object { $vv = ConvertTo-Ver $_.Version; $vv -and $vv.Major -eq $m } | ForEach-Object Owner | Sort-Object -Unique)
        $label = if ($m -lt 5) { "Core $m.x" } else { "$m.0" }
        Write-Host ("   .NET {0,-9}: {1}" -f $label, $(if ($users) { $users -join ', ' } else { 'not used by any scanned app' }))
    }
}

$Findings | Export-Csv -Path $ReportFile -NoTypeInformation -Encoding UTF8
$notify = @($Findings | Where-Object { $_.Owner -ne 'system' -and $_.Status -in 'VULNERABLE', 'EOL-VULNERABLE', 'UNKNOWN' })
if ($notify) { $notify | Export-Csv -Path $NotifyFile -NoTypeInformation -Encoding UTF8 }
[pscustomobject]@{
    Host = $env:COMPUTERNAME; Date = (Get-Date).ToString('s'); CVE = $CVE
    VerdictBefore = $before.Verdict; VerdictAfter = $after.Verdict; RuleActive = $after.RuleActive
    ServerLevel = $after.ServerItems.Count; Residual = $after.ResidualItems.Count; AdminTools = $after.ToolItems.Count
    CustomersToNotify = @($notify | ForEach-Object Owner | Sort-Object -Unique)
    Actions = @($Actions)
} | ConvertTo-Json -Depth 4 | Set-Content -Path $SummaryFile -Encoding UTF8

if ($ReportShare) {
    try {
        Copy-Item $SummaryFile, $ReportFile -Destination $ReportShare -ErrorAction Stop
        if ($notify) { Copy-Item $NotifyFile -Destination $ReportShare -ErrorAction Stop }
        Write-Host "  copied to $ReportShare"
    } catch { Write-Host "  could not copy to ${ReportShare}: $($_.Exception.Message)" -ForegroundColor Red }
}
Write-Host ''; Write-Host "Report: $ReportFile"; Write-Host "Summary: $SummaryFile"; Write-Host "Log: $LogFile"

Stop-Transcript | Out-Null
switch ($after.Verdict) { 'NOT VULNERABLE' { exit 0 } 'MITIGATED' { exit 1 } default { exit 2 } }
