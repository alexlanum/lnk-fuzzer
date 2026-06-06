# provision_node.ps1 — prepare a fresh Windows 11 box for Jackalope LNK fuzzing.
# Run elevated:  Set-ExecutionPolicy Bypass -Scope Process -Force; .\provision_node.ps1
# Each block is annotated with the failure mode it prevents.

$ErrorActionPreference = 'Stop'
$FuzzRoot = 'C:\fuzz'   # corpus, findings, harness, fuzzer all live here

# ── 1. Defender: exclude the fuzz tree (and ideally disable real-time) ─────────
# WHY: Defender scans every process the harness spawns (huge throughput tax) AND
# it will QUARANTINE the malicious .lnk files your fuzzer generates as crashes —
# i.e. it deletes your findings out from under you. Without this you lose the
# very artifacts you're hunting for.
Add-MpPreference -ExclusionPath $FuzzRoot
Add-MpPreference -ExclusionProcess 'lnk_fuzzer.exe','harness.exe'
Set-MpPreference -DisableRealtimeMonitoring $true   # box is isolated/dedicated to fuzzing

# ── 2. Windows Error Reporting: kill the UI, KEEP the dumps ────────────────────
# WHY: when shell32 faults, default Windows pops a modal "app has stopped working"
# dialog. That dialog BLOCKS the faulting worker forever until someone clicks it —
# silently freezing 1/Nth of your cores and stalling the campaign. We suppress the
# UI but still write FULL-memory dumps so you have something to analyze in WinDbg.
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Force | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' DontShowUI 1 -Type DWord
$ld = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
New-Item -Path $ld -Force | Out-Null
Set-ItemProperty $ld DumpFolder  "$FuzzRoot\dumps" -Type ExpandString
Set-ItemProperty $ld DumpType    2 -Type DWord          # 2 = full memory dump
Set-ItemProperty $ld DumpCount   200 -Type DWord
New-Item -ItemType Directory -Force -Path "$FuzzRoot\dumps" | Out-Null
# Stop the interactive WER service so nothing escalates to a prompt.
sc.exe config WerSvc start= disabled | Out-Null

# ── 3. Disable hard error / fault popups at the OS level ───────────────────────
# WHY: belt-and-suspenders for #2 — stops "critical error" message boxes that also
# block a process on a faulting thread.
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Windows' ErrorMode 2 -Type DWord

# ── 4. Power plan: maximum performance, never sleep ────────────────────────────
# WHY: the default balanced plan down-clocks idle-looking cores and can sleep the
# box. Fuzzing must hold all cores at full clock 24/7; sleep/display-off can also
# pause USB/console sessions you rely on.
powercfg /setactive SCHEME_MIN                 # High performance
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
powercfg /change monitor-timeout-ac 0
powercfg /hibernate off

# ── 5. Freeze Windows Update ───────────────────────────────────────────────────
# WHY (critical for your n-day strategy): an auto-reboot wipes in-memory fuzzer
# state mid-run, AND patching changes shell32.dll — destroying the exact build you
# pinned for CVE rediscovery. You decide when (if ever) this box updates.
sc.exe config wuauserv start= disabled | Out-Null
Stop-Service wuauserv -Force -ErrorAction SilentlyContinue

# ── 6. Trim background CPU/disk contention ─────────────────────────────────────
# WHY: indexing/prefetch compete with workers for cores and NVMe bandwidth on a
# box whose only job is to fuzz.
sc.exe config SysMain start= disabled | Out-Null
sc.exe config WSearch start= disabled | Out-Null

# ── 7. (LATER, distributed only) open the Jackalope server port ────────────────
# WHY: only when you add a 2nd box with -server <ip>:8000. Skipped for single box.
# New-NetFirewallRule -DisplayName 'Jackalope' -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow

Write-Host "Provisioned. Reboot once, then start fuzzing from $FuzzRoot." -ForegroundColor Green
