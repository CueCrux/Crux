# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# provision-windows-gui-runner.ps1 — bootstrap a GUI-capable GitHub Actions
# runner (the `[self-hosted, windows-gui]` labels) for the desktop shell's
# Windows smoke lane in `.github/workflows/desktop-shell.yml`.
#
# Run ONCE inside the guest, elevated. Idempotent: re-running only patches what
# is missing. See `docs/self-hosted-runner.md` for the operator runbook and for
# how the host-side VM is built.
#
# WHY THIS SCRIPT EXISTS, AND WHY IT IS NOT THE LINUX ONE WITH DIFFERENT PATHS:
#
#   A Tauri/WebView2 window cannot be created without a desktop. That rules out
#   two configurations that otherwise look fine:
#
#     1. Server Core. There is no `explorer.exe` at all, and Core CANNOT be
#        converted to Desktop Experience — that switch was removed after Server
#        2012 R2. It is a reinstall. Install image index 2 ("... Desktop
#        Experience"), not index 1.
#     2. A runner running as a Windows *service*, or as a scheduled task
#        registered with `Register-ScheduledTask -User/-Password` (which forces
#        LogonType=Password). Both land in Session 0, which has no desktop.
#        The runner must be a scheduled task with LogonType=Interactive under an
#        autologon user, so it executes in console session 1.
#
#   The preflight step in the workflow asserts both and points back here.
#
# Usage (elevated, in the guest):
#   powershell -ExecutionPolicy Bypass -File scripts\provision-windows-gui-runner.ps1 `
#       -RunnerToken <registration-token> -AutologonPassword <password>
#
# Get a registration token with:
#   gh api -X POST orgs/CueCrux/actions/runners/registration-token -q .token

[CmdletBinding()]
param(
    # Org-level runner registration token. Omit to provision the desktop and
    # toolchain only, skipping runner registration.
    [string] $RunnerToken,

    # Password for the autologon account. Required unless -SkipAutologon.
    # NOTE: Windows autologon stores this in cleartext at
    # HKLM:\...\Winlogon\DefaultPassword. That is inherent to autologon, not a
    # choice this script makes. Only use a throwaway lab account on an isolated
    # network.
    [string] $AutologonPassword,

    [string] $RunnerUser    = "$env:COMPUTERNAME\Administrator",
    [string] $RunnerName    = "runner-$($env:COMPUTERNAME.ToLower())-gui",
    [string] $RunnerLabels  = 'windows-gui,desktop-gui,interactive',
    [string] $GitHubUrl     = 'https://github.com/CueCrux',
    [string] $RunnerVersion = '2.336.0',
    [string] $RunnerDir     = 'C:\actions-runner',
    [switch] $SkipAutologon
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Log  ($m) { Write-Host "[provision] $m" -ForegroundColor Cyan }
function Ok   ($m) { Write-Host "[ ok ] $m"      -ForegroundColor Green }
function Warn ($m) { Write-Host "[warn] $m"      -ForegroundColor Yellow }
function Die  ($m) { Write-Host "[FAIL] $m"      -ForegroundColor Red; exit 1 }

# --------------------------------------------------------------------------
# 0. refuse to run anywhere a GUI cannot exist
# --------------------------------------------------------------------------
$installType = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').InstallationType
Log "InstallationType = $installType"
if ($installType -eq 'Server Core' -or -not (Test-Path 'C:\Windows\explorer.exe')) {
    Die @'
This image is Server Core (no explorer.exe). Server Core cannot be converted to
Desktop Experience — it is a reinstall. Rebuild the VM from install image
INDEX 2 ("Windows Server 20xx ... Desktop Experience"); index 1 is Core.
See docs/self-hosted-runner.md.
'@
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Die 'This script must run elevated.'
}
Ok 'Desktop Experience image, running elevated'

# --------------------------------------------------------------------------
# 1. autologon, so a console session exists for the runner to live in
# --------------------------------------------------------------------------
if ($SkipAutologon) { Warn 'skipping autologon (-SkipAutologon)' }
elseif (-not $AutologonPassword) { Die '-AutologonPassword is required unless -SkipAutologon is given.' }
else {
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $user = $RunnerUser.Split('\')[-1]
    Set-ItemProperty $wl -Name AutoAdminLogon    -Value '1'                -Type String
    Set-ItemProperty $wl -Name DefaultUserName   -Value $user              -Type String
    Set-ItemProperty $wl -Name DefaultDomainName -Value $env:COMPUTERNAME   -Type String
    Set-ItemProperty $wl -Name DefaultPassword   -Value $AutologonPassword  -Type String
    # An unattend AutoLogon grants a fixed LogonCount and then stops; remove it
    # so the box keeps logging itself in across every future reboot.
    Remove-ItemProperty $wl -Name AutoLogonCount -ErrorAction SilentlyContinue
    Ok "autologon enabled for $user (unlimited)"
}

# --------------------------------------------------------------------------
# 2. never lock, blank, or sleep — a lock screen breaks GUI tests and
#    screenshots just as thoroughly as having no desktop at all
# --------------------------------------------------------------------------
$pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
if (-not (Test-Path $pol)) { New-Item $pol -Force | Out-Null }
Set-ItemProperty $pol -Name DisableLockWorkstation -Value 1 -Type DWord
Set-ItemProperty $pol -Name InactivityTimeoutSecs  -Value 0 -Type DWord
$per = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
if (-not (Test-Path $per)) { New-Item $per -Force | Out-Null }
Set-ItemProperty $per -Name NoLockScreen -Value 1 -Type DWord
foreach ($t in 'monitor-timeout-ac', 'standby-timeout-ac', 'hibernate-timeout-ac') {
    powercfg /change $t 0 | Out-Null
}
Ok 'lock screen, screensaver, and sleep disabled'

# --------------------------------------------------------------------------
# 3. suppress server-shell dialogs that steal focus mid-test
# --------------------------------------------------------------------------
$sm = 'HKLM:\SOFTWARE\Microsoft\ServerManager'
if (Test-Path $sm) { Set-ItemProperty $sm -Name DoNotOpenServerManagerAtLogon -Value 1 -Type DWord }
try { Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Server Manager\' -TaskName 'ServerManager' -ErrorAction Stop | Out-Null } catch {}
foreach ($p in @(
    'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
    'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile'
)) {
    if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
    # A firewall prompt in an automated run is a hang, not a test result.
    Set-ItemProperty $p -Name DisableNotifications -Value 1 -Type DWord
}
Ok 'Server Manager and firewall notification popups suppressed'

# --------------------------------------------------------------------------
# 4. pre-assert the daemon's firewall rules
#    This asserts RULE STATE. It does not test prompt behaviour — that remains a
#    one-off human observation on a clean box.
# --------------------------------------------------------------------------
foreach ($r in @(@{ n = 'Crux corecruxd HTTP 14800'; p = 14800 }, @{ n = 'Crux corecruxd gRPC 14801'; p = 14801 })) {
    Remove-NetFirewallRule -DisplayName $r.n -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName $r.n -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort $r.p -Profile Any | Out-Null
}
Ok 'firewall rules pre-added for 14800/14801'

# --------------------------------------------------------------------------
# 5. build prerequisites
# --------------------------------------------------------------------------
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name LongPathsEnabled -Value 1 -Type DWord
# Real-time scanning of target/ dominates Rust build time on a CI box.
foreach ($p in @($RunnerDir, "$env:USERPROFILE\.cargo", "$env:USERPROFILE\.rustup")) {
    Add-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue
}
foreach ($e in 'cargo.exe', 'rustc.exe', 'link.exe', 'cl.exe', 'corecruxd.exe', 'Crux.exe') {
    Add-MpPreference -ExclusionProcess $e -ErrorAction SilentlyContinue
}
Ok 'long paths enabled, Defender exclusions added'

# WebView2: Server images ship an old inbox runtime. The evergreen bootstrapper
# upgrades it in place and is a no-op when already current.
$wvKeys = @(
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
    'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
)
$before = $null; foreach ($k in $wvKeys) { if (-not $before) { $before = (Get-ItemProperty $k -ErrorAction SilentlyContinue).pv } }
Log "WebView2 before: $(if ($before) { $before } else { 'absent' })"
$wvExe = Join-Path $env:TEMP 'MicrosoftEdgeWebview2Setup.exe'
Invoke-WebRequest 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' -OutFile $wvExe -UseBasicParsing
Start-Process $wvExe -ArgumentList '/silent', '/install' -Wait
$after = $null; foreach ($k in $wvKeys) { if (-not $after) { $after = (Get-ItemProperty $k -ErrorAction SilentlyContinue).pv } }
if (-not $after) { Die 'WebView2 runtime still absent after install' }
Ok "WebView2 runtime: $after"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Log 'installing Git for Windows'
    $rel = Invoke-RestMethod 'https://api.github.com/repos/git-for-windows/git/releases/latest' -UseBasicParsing
    $asset = $rel.assets | Where-Object { $_.name -match '^Git-[\d.]+-64-bit\.exe$' } | Select-Object -First 1
    $gitExe = Join-Path $env:TEMP $asset.name
    Invoke-WebRequest $asset.browser_download_url -OutFile $gitExe -UseBasicParsing
    Start-Process $gitExe -ArgumentList '/VERYSILENT', '/NORESTART', '/NOCANCEL', '/SP-', '/SUPPRESSMSGBOXES' -Wait
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
}
if (Get-Command git -ErrorAction SilentlyContinue) {
    git config --system core.longpaths true 2>&1 | Out-Null
    Ok "git: $(git --version)"
} else { Die 'git is still not on PATH' }

$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$haveVc = $false
if (Test-Path $vswhere) {
    $haveVc = [bool](& $vswhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
}
if (-not $haveVc) {
    Log 'installing Visual Studio Build Tools 2022 (VCTools) — 10-20 min'
    $vsExe = Join-Path $env:TEMP 'vs_BuildTools.exe'
    Invoke-WebRequest 'https://aka.ms/vs/17/release/vs_BuildTools.exe' -OutFile $vsExe -UseBasicParsing
    $p = Start-Process $vsExe -Wait -PassThru -ArgumentList @(
        '--quiet', '--wait', '--norestart', '--nocache',
        '--add', 'Microsoft.VisualStudio.Workload.VCTools', '--includeRecommended'
    )
    Log "vs_BuildTools exit: $($p.ExitCode)"   # 0 = ok, 3010 = ok + reboot queued
}
$link = Get-ChildItem 'C:\Program Files*\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64\link.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $link) { Die 'MSVC link.exe not found after installing Build Tools' }
Ok "MSVC: $($link.FullName)"

$cargoBin = "$env:USERPROFILE\.cargo\bin"
if (-not (Test-Path "$cargoBin\rustup.exe")) {
    Log 'installing rustup (stable-x86_64-pc-windows-msvc)'
    $ruExe = Join-Path $env:TEMP 'rustup-init.exe'
    Invoke-WebRequest 'https://win.rustup.rs/x86_64' -OutFile $ruExe -UseBasicParsing
    Start-Process $ruExe -ArgumentList '-y', '--default-toolchain', 'stable-x86_64-pc-windows-msvc', '--profile', 'default' -Wait
}
$env:Path = "$cargoBin;$env:Path"
Ok "rustc: $(& "$cargoBin\rustc.exe" --version)"

# Same constraint the Linux jobs use, so the lanes cannot drift apart.
if (-not (Test-Path "$cargoBin\cargo-tauri.exe")) {
    Log 'cargo install tauri-cli --version "^2.0" --locked'
    & "$cargoBin\cargo.exe" install tauri-cli --version '^2.0' --locked
}
if (-not (Test-Path "$cargoBin\cargo-tauri.exe")) { Die 'cargo-tauri missing after install' }
Ok "cargo-tauri: $(& "$cargoBin\cargo.exe" tauri --version)"

# --------------------------------------------------------------------------
# 6. the runner itself — interactive, NOT a service
# --------------------------------------------------------------------------
if (-not $RunnerToken) {
    Warn 'no -RunnerToken given; desktop and toolchain are ready but no runner was registered'
    Ok 'provisioning complete (toolchain only)'
    exit 0
}

if (-not (Test-Path (Join-Path $RunnerDir 'config.cmd'))) {
    New-Item -ItemType Directory -Path $RunnerDir -Force | Out-Null
    $zip = Join-Path $RunnerDir "actions-runner-win-x64-$RunnerVersion.zip"
    Log "downloading runner $RunnerVersion"
    Invoke-WebRequest "https://github.com/actions/runner/releases/download/v$RunnerVersion/actions-runner-win-x64-$RunnerVersion.zip" `
        -OutFile $zip -UseBasicParsing
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($zip, $RunnerDir)
    Remove-Item $zip -Force
    Ok 'runner unpacked'
}

# A pre-existing service install is the exact failure mode to remove: it runs in
# Session 0, so every GUI assertion in the workflow would fail there.
$svc = Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'actions\.runner' }
if ($svc) {
    Warn "removing runner service $($svc.Name) — a service has no desktop"
    Push-Location $RunnerDir; & .\svc.cmd uninstall; Pop-Location
}

Push-Location $RunnerDir
& .\config.cmd --url $GitHubUrl --token $RunnerToken --name $RunnerName --labels $RunnerLabels `
    --work '_work' --runnergroup 'Default' --unattended --replace
Pop-Location
if (-not (Test-Path (Join-Path $RunnerDir '.runner'))) { Die 'runner registration failed (no .runner written)' }
Ok "registered as $RunnerName [$RunnerLabels]"

# LogonType=Interactive is the load-bearing setting. It requires the user to be
# logged on (autologon guarantees that) and stores no credential, unlike the
# -User/-Password parameter set which forces LogonType=Password -> Session 0.
$taskName = 'crux-actions-runner-interactive'
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
$action    = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c `"$RunnerDir\run.cmd`"" -WorkingDirectory $RunnerDir
$trigger   = New-ScheduledTaskTrigger -AtLogOn -User $RunnerUser
$principal = New-ScheduledTaskPrincipal -UserId $RunnerUser -LogonType Interactive -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
                -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew `
                -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings `
    -Description 'GitHub Actions runner in interactive console session 1 (GUI-capable). NOT a service: Session 0 has no desktop and WebView2 cannot create a window there.' | Out-Null
Start-ScheduledTask -TaskName $taskName
Ok "scheduled task '$taskName' registered (AtLogOn, LogonType=Interactive)"

# --------------------------------------------------------------------------
# 7. verify the runner really landed in the interactive session
# --------------------------------------------------------------------------
$listener = $null
for ($i = 0; $i -lt 12; $i++) {
    Start-Sleep -Seconds 5
    $listener = Get-Process Runner.Listener -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($listener) { break }
}
if (-not $listener) { Die "Runner.Listener never started; check $RunnerDir\_diag" }

$explorerSession = (Get-Process explorer -ErrorAction SilentlyContinue | Select-Object -First 1).SessionId
Log "Runner.Listener session = $($listener.SessionId); explorer session = $explorerSession"
if ($listener.SessionId -eq 0) {
    Die 'Runner.Listener is in Session 0 — it has no desktop. Check that the task principal LogonType is Interactive and that autologon actually logged the user in.'
}
Ok "runner is live in interactive session $($listener.SessionId)"
Ok 'provisioning complete'
