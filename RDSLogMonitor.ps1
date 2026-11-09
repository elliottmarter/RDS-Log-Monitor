#Requires -Version 5.1
<#
.SYNOPSIS
    RDS Log Monitor - central monitor for Remote Desktop Services event logs across many servers.

.DESCRIPTION
    Run it on a Domain Controller (or any domain-joined management server).
      1. It lists the Windows Servers in Active Directory. "Detect RDS roles" asks each server
         which Remote Desktop roles it has and ticks the RDS servers for you.
      2. Start Logging opens a background reader for each ticked server. Each reader watches that
         server's RDS event logs remotely and sends new events back.
      3. All events go into one grid and one CSV file with columns for Time, Server, Level, Issue,
         User, Session, Event ID, Log, Provider and Message.
         Errors, critical events and audit failures show in bold red. Warnings show in red too
         unless you untick "Warnings are issues".

    Logs read on each server:
      * Every Admin/Operational log named TerminalServices*, RemoteDesktopServices*, RemoteApp*, Rdms*
        (Session Host, Gateway, Broker, Licensing, RdpCoreTS, Printers ...)
      * Optional: User Profile Service and FSLogix logs
      * Optional: System and Application logs, filtered to RDS providers (TermService, TermDD ...)
      * Optional: Security log, filtered to RDP logons/failures (4624/4625 type 10),
        reconnect/disconnect (4778/4779) and NPS grant/deny for RD Gateway (6272/6273)

    Requirements on the monitored servers:
      * Firewall: "Remote Event Log Management" inbound rules enabled (RPC). Role detection uses
        WinRM, which is on by default on Windows Server, with a DCOM fallback.
      * The account running this app must be an administrator on the servers, or a member of their
        "Event Log Readers" group (that group can read the Security log too).

.PARAMETER Probe
    Console test: connect to one server, list the logs it would watch, and show the last hour of
    events with the parsed User field. No window opens.

.EXAMPLE
    .\RDSLogMonitor.ps1
.EXAMPLE
    .\RDSLogMonitor.ps1 -Probe RDSH01.contoso.local
#>
[CmdletBinding()]
param([string]$Probe)

# ==========================================================================================
#  Code shared by the GUI, the background readers and -Probe
# ==========================================================================================
$script:CommonCode = @'
$KW_AUDIT_FAILURE = [long]0x10000000000000
$KW_AUDIT_SUCCESS = [long]0x20000000000000

function Get-InnerException($ErrorRecord) {
    $ex = $ErrorRecord.Exception
    while ($ex -is [System.Management.Automation.MethodInvocationException] -and $ex.InnerException) { $ex = $ex.InnerException }
    return $ex
}

function New-Source([string]$LogName, [string]$Kind) {
    [pscustomobject]@{
        LogName   = $LogName
        Short     = ($LogName -replace '^Microsoft-Windows-', '' -replace '^TerminalServices-', 'TS-' -replace '^RemoteDesktopServices-', 'RDS-')
        Kind      = $Kind          # Full | Filtered | Security
        LastId    = [long]0
        Initial   = $false
        HistoryMs = [long]0
        Failed    = $false
        LastError = $null
    }
}

# Finds the RDS logs on one server
function Get-ServerSources($Session, $Opt) {
    $list  = New-Object System.Collections.Generic.List[object]
    $names = @($Session.GetLogNames())
    $want  = @($names | Where-Object { $_ -match $Opt.RdsLogRegex -and $_ -notmatch $Opt.RdsLogExclude } | Sort-Object)
    if ($Opt.IncludeRelated) { $want += @($names | Where-Object { $_ -match $Opt.RelatedLogRegex } | Sort-Object) }
    foreach ($n in $want) {
        try { $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($n, $Session) } catch { continue }
        if ($cfg.LogType -ne 'Administrative' -and $cfg.LogType -ne 'Operational') { continue }   # skip Analytic/Debug
        if (-not $cfg.IsEnabled) { continue }
        $list.Add((New-Source $n 'Full'))
    }
    if ($Opt.IncludeSysApp)   { $list.Add((New-Source 'System' 'Filtered')); $list.Add((New-Source 'Application' 'Filtered')) }
    if ($Opt.IncludeSecurity) { $list.Add((New-Source 'Security' 'Security')) }
    return ,$list
}

function Get-LatestRecordId($Session, [string]$LogName) {
    $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($LogName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, '*')
    $q.Session = $Session
    $q.ReverseDirection = $true
    $r = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
    try {
        $e = $r.ReadEvent()
        if ($null -eq $e) { return [long]0 }
        $id = [long]$e.RecordId; $e.Dispose(); return $id
    } finally { $r.Dispose() }
}

function Get-SourceXPath($Source) {
    if ($Source.Initial) { $cond = "TimeCreated[timediff(@SystemTime) <= $($Source.HistoryMs)]" }
    else                 { $cond = "EventRecordID > $($Source.LastId)" }
    if ($Source.Kind -eq 'Security') {
        return "*[(System[(EventID=4624 or EventID=4625) and $cond] and EventData[Data[@Name='LogonType']='10'])" +
               " or System[(EventID=4778 or EventID=4779 or EventID=6272 or EventID=6273) and $cond]]"
    }
    return "*[System[$cond]]"
}

# Pulls User / Session out of the event's data fields
function Get-EventFields($Ev) {
    if (-not $global:RdsMonSidCache) { $global:RdsMonSidCache = @{} }
    $d = @{}
    try {
        $x = [xml]$Ev.ToXml()
        foreach ($n in $x.SelectNodes("//*[local-name()='EventData' or local-name()='UserData']//*[not(*)]")) {
            $k = $n.LocalName
            if ($k -eq 'Data') { $k = $n.GetAttribute('Name'); if (-not $k) { continue } }
            if (-not $d.ContainsKey($k)) { $d[$k] = $n.InnerText.Trim() }
        }
    } catch { }
    $pick = {
        param([string[]]$Keys)
        foreach ($k in $Keys) { $v = $d[$k]; if ($v -and $v -ne '-' -and $v -ne 'NULL SID' -and $v -ne '%%1793') { return $v } }
        return ''
    }

    $user = & $pick @('TargetUserName', 'AccountName', 'SubjectUserName', 'User', 'UserName', 'TargetUser')
    $dom  = ''
    if ($user -and $user -notmatch '[\\@]') { $dom = & $pick @('TargetDomainName', 'AccountDomain', 'SubjectDomainName', 'Domain', 'DomainName') }

    if ($Ev.Id -eq 1149 -and $d['Param1']) {      # RemoteConnectionManager: user authenticated
        $user = $d['Param1']; $dom = $d['Param2']
    }
    if ($user -and $dom) { $user = "$dom\$user" }

    if (-not $user -and $Ev.UserId -and @('S-1-5-18', 'S-1-5-19', 'S-1-5-20') -notcontains $Ev.UserId.Value) {
        $sid = $Ev.UserId.Value
        if (-not $global:RdsMonSidCache.ContainsKey($sid)) {
            try { $global:RdsMonSidCache[$sid] = $Ev.UserId.Translate([System.Security.Principal.NTAccount]).Value }
            catch { $global:RdsMonSidCache[$sid] = $sid }
        }
        $user = $global:RdsMonSidCache[$sid]
    }
    @{
        User    = $user
        Session = (& $pick @('SessionID', 'SessionId', 'Session', 'SessionName'))
    }
}

function Convert-Event($Ev, $Source, [string]$Server) {
    $level = 4; if ($null -ne $Ev.Level) { $level = [int]$Ev.Level }
    $kw = [long]0; if ($null -ne $Ev.Keywords) { $kw = [long]$Ev.Keywords }
    $sev = 'Info'
    switch ($level) {
        1 { $label = 'CRITICAL'; $sev = 'Error' }
        2 { $label = 'ERROR';    $sev = 'Error' }
        3 { $label = 'WARNING';  $sev = 'Warning' }
        5 { $label = 'VERBOSE' }
        default {
            if     ($kw -band $KW_AUDIT_FAILURE) { $label = 'AUDITFAIL'; $sev = 'Error' }
            elseif ($kw -band $KW_AUDIT_SUCCESS) { $label = 'AUDIT-OK' }
            else                                 { $label = 'INFO' }
        }
    }
    $msg = $null
    try { $msg = $Ev.FormatDescription() } catch { }
    if ([string]::IsNullOrWhiteSpace($msg)) {
        $data = ''
        try { $data = (@($Ev.Properties | ForEach-Object { "$($_.Value)" }) -join '; ') } catch { }
        $msg = if ($data) { "(no message text) Data: $data" } else { '(no message text)' }
    }
    $msg = ($msg -replace '\s*[\r\n]+\s*', ' | ').Trim().TrimEnd('|', ' ')
    $f = Get-EventFields $Ev
    [pscustomobject]@{
        Type     = 'Event'
        Time     = $(if ($Ev.TimeCreated) { [datetime]$Ev.TimeCreated } else { Get-Date })
        Server   = $Server
        Level    = $label
        Sev      = $sev
        User     = $f.User
        Session  = $f.Session
        EventId  = [int]$Ev.Id
        Log      = $Source.Short
        Provider = [string]$Ev.ProviderName
        Message  = $msg
        RecordId = [long]$Ev.RecordId
    }
}

# Reads new events for one source into $Into; moves the source's position forward
function Read-SourceEvents($Session, $Source, $Into, $Opt, [string]$Server) {
    $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($Source.LogName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, (Get-SourceXPath $Source))
    $q.Session = $Session
    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
    $n = 0
    try {
        while ($n -lt $Opt.MaxPerPoll -and $null -ne ($ev = $reader.ReadEvent())) {
            $n++
            try {
                $Source.LastId = [long]$ev.RecordId
                if ($Source.Kind -eq 'Filtered' -and $ev.ProviderName -notmatch $Opt.ProviderRegex) { continue }
                $Into.Add((Convert-Event $ev $Source $Server))
            } finally { $ev.Dispose() }
        }
    } finally { $reader.Dispose() }
    $Source.Initial = $false
    return $n
}
'@
. ([scriptblock]::Create($script:CommonCode))

# Background reader: one per server. Runs until $Control.Stop is set.
$script:WorkerCode = 'param($Server, $Opt, $Queue, $Control)' + "`n" + $script:CommonCode + "`n" + @'
function Send-Monitor([string]$Text, [bool]$IsError = $false) {
    $Queue.Enqueue([pscustomobject]@{ Type = 'Monitor'; Time = (Get-Date); Server = $Server; Message = $Text; IsError = $IsError })
}
function Send-Status([string]$Text, [string]$Kind = 'Info') {
    $Queue.Enqueue([pscustomobject]@{ Type = 'Status'; Server = $Server; Text = $Text; Kind = $Kind })
}
function Wait-Ms([int]$Ms) {
    $end = (Get-Date).AddMilliseconds($Ms)
    while (-not $Control.Stop -and (Get-Date) -lt $end) { Start-Sleep -Milliseconds 250 }
}
$connRegex = 'RPC server|network path|unavailable|timed out|timeout|endpoint|not accessible|no longer available|network name'

$session = $null; $sources = $null; $online = $false; $lastErr = $null; $tick = 0
while (-not $Control.Stop) {
    if (-not $sources) {
        try {
            Send-Status 'Connecting...'
            $session = New-Object System.Diagnostics.Eventing.Reader.EventLogSession($Server)
            $sources = Get-ServerSources $session $Opt
            foreach ($s in $sources) {
                try { $s.LastId = Get-LatestRecordId $session $s.LogName }
                catch {
                    $ex = Get-InnerException $_
                    if ($ex.Message -match $connRegex) { throw }
                    $s.Failed = $true
                    Send-Monitor "Cannot read '$($s.LogName)': $($ex.Message)" $true
                }
                $s.Initial = ($Opt.HistoryMs -gt 0); $s.HistoryMs = $Opt.HistoryMs
            }
            $ok = @($sources | Where-Object { -not $_.Failed }).Count
            Send-Monitor "Connected - watching $ok log(s)."
            Send-Status "Connected ($ok logs)" 'Ok'
            $online = $true; $lastErr = $null
        } catch {
            $msg = (Get-InnerException $_).Message
            if ($msg -ne $lastErr) { Send-Monitor "Cannot connect: $msg (retrying every 60 s)" $true; $lastErr = $msg }
            Send-Status "Unreachable - retrying" 'Error'
            $sources = $null
            if ($session) { try { $session.Dispose() } catch { } ; $session = $null }
            Wait-Ms 60000
            continue
        }
    }

    $tick++
    $batch = New-Object System.Collections.Generic.List[object]
    $lost = $null
    foreach ($s in $sources) {
        if ($Control.Stop) { break }
        if ($s.Failed) { continue }
        try {
            $n = Read-SourceEvents $session $s $batch $Opt $Server
            $s.LastError = $null
            if ($n -eq 0 -and ($tick % 30) -eq 0) {
                if ((Get-LatestRecordId $session $s.LogName) -lt $s.LastId) {
                    Send-Monitor "'$($s.LogName)' was cleared - reading from the start of the log."
                    $s.LastId = 0
                }
            }
        } catch {
            $ex = Get-InnerException $_
            if ($ex.Message -match $connRegex) { $lost = $ex.Message; break }
            elseif ($ex -is [UnauthorizedAccessException]) { $s.Failed = $true; Send-Monitor "Access denied reading '$($s.LogName)' - log skipped." $true }
            elseif ($ex -is [System.Diagnostics.Eventing.Reader.EventLogNotFoundException]) { $s.Failed = $true; Send-Monitor "Log '$($s.LogName)' no longer exists - skipped." $true }
            elseif ($s.LastError -ne $ex.Message) { $s.LastError = $ex.Message; Send-Monitor "Error reading '$($s.LogName)': $($ex.Message)" $true }
        }
    }
    if ($Control.Stop) { break }
    foreach ($e in ($batch | Sort-Object Time, RecordId)) { $Queue.Enqueue($e) }

    if ($lost) {
        if ($online) { Send-Monitor "Connection lost: $lost (retrying every 30 s)" $true; Send-Status 'Connection lost - retrying' 'Error' }
        $online = $false
        Wait-Ms 30000
        continue
    }
    if (-not $online) { Send-Monitor 'Connection restored.'; Send-Status 'Connected' 'Ok'; $online = $true }
    Wait-Ms $Opt.PollMs
}
if ($session) { try { $session.Dispose() } catch { } }
'@

# Asks a server which Remote Desktop roles it has (WinRM, then DCOM)
$script:RoleCode = @'
param($Server, $Queue)
$features = $null; $err = $null
try {
    $features = Get-CimInstance -ComputerName $Server -ClassName Win32_ServerFeature -OperationTimeoutSec 20 -ErrorAction Stop
} catch {
    try {
        $cs = New-CimSession -ComputerName $Server -SessionOption (New-CimSessionOption -Protocol Dcom) -OperationTimeoutSec 20 -ErrorAction Stop
        try { $features = Get-CimInstance -CimSession $cs -ClassName Win32_ServerFeature -ErrorAction Stop } finally { Remove-CimSession $cs }
    } catch { $err = $_.Exception.Message }
}
$roles = @()
foreach ($f in @($features)) {
    switch -Regex ($f.Name) {
        'Remote Desktop Session Host'      { $roles += 'Session Host' }
        'Remote Desktop Gateway'           { $roles += 'Gateway' }
        'Remote Desktop Connection Broker' { $roles += 'Broker' }
        'Remote Desktop Licensing'         { $roles += 'Licensing' }
        'Remote Desktop Web Access'        { $roles += 'Web Access' }
    }
}
$Queue.Enqueue([pscustomobject]@{ Type = 'Roles'; Server = $Server; Roles = (@($roles | Select-Object -Unique) -join ', '); Error = $err })
'@

# ==========================================================================================
#  Settings
# ==========================================================================================
$script:Opt = @{
    RdsLogRegex     = 'TerminalServices|RemoteDesktopServices|RemoteApp and Desktop|Remote-Desktop|Rdms|TSGateway'
    RdsLogExclude   = 'RDPClient|ClientActiveXCore|ClientUSBDevices'
    RelatedLogRegex = '^(Microsoft-Windows-User Profile Service/Operational|Microsoft-FSLogix-Apps/(Admin|Operational))$'
    ProviderRegex   = 'TermService|TermDD|TerminalServices|Terminal Services|RemoteDesktop|Remote Desktop|Rdms|TSGateway|TS Gateway|TermServLicensing|TScPubRPC|Tssdis|RDPDR|rdpbus|RDPNP|RdpCoreTS|RemoteApp|User Profiles? Service|User Profiles General|FSLogix'
    MaxPerPoll      = 2000
    IncludeRelated  = $true
    IncludeSysApp   = $true
    IncludeSecurity = $true
    HistoryMs       = [long]0
    PollMs          = 5000
}
$script:CsvColumns = 'Time', 'Server', 'Level', 'Issue', 'User', 'SessionId', 'EventId', 'Log', 'Provider', 'Message'

# ==========================================================================================
#  -Probe: console test against one server
# ==========================================================================================
if ($Probe) {
    $session = New-Object System.Diagnostics.Eventing.Reader.EventLogSession($Probe)
    try { $sources = Get-ServerSources $session $script:Opt } catch { Write-Warning "Cannot connect to ${Probe}: $((Get-InnerException $_).Message)"; return }
    "Logs watched on ${Probe}:"
    foreach ($s in $sources) {
        $state = try { "latest record $(Get-LatestRecordId $session $s.LogName)" } catch { "UNREADABLE: $((Get-InnerException $_).Message)" }
        '  {0,-75} {1}' -f $s.LogName, $state
    }
    ''
    'Last hour of events (up to 15 per log, with parsed fields):'
    $all = New-Object System.Collections.Generic.List[object]
    $probeOpt = $script:Opt.Clone(); $probeOpt.MaxPerPoll = 15
    foreach ($s in $sources) { $s.Initial = $true; $s.HistoryMs = 3600000; try { [void](Read-SourceEvents $session $s $all $probeOpt $Probe) } catch { } }
    $all | Sort-Object Time | Format-Table Time, Level, User, Session, EventId, Log, @{ n = 'Message'; e = { $_.Message.Substring(0, [Math]::Min(70, $_.Message.Length)) } } -AutoSize
    return
}

# ==========================================================================================
#  STA (Windows Forms dialogs need it)
# ==========================================================================================
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$PSCommandPath`""
    return
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$script:SettingsPath = Join-Path $env:APPDATA 'RDSLogMonitor\settings.json'
$script:Settings = $null
try { if (Test-Path $script:SettingsPath) { $script:Settings = Get-Content $script:SettingsPath -Raw | ConvertFrom-Json } } catch { }

$script:Run        = $null        # current run: Pool, Workers, Queue, Control
$script:Retiring   = New-Object System.Collections.Generic.List[object]
$script:RoleQueue  = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
$script:RoleJobs   = New-Object System.Collections.Generic.List[object]
$script:RolePool   = $null
$script:ServerRows = @{}
$script:CsvPending = New-Object System.Collections.Generic.List[string]
$script:CsvPath    = $null
$script:CsvWarned  = $false
$script:EventCount = 0
$script:IssueCount = 0
$script:MaxGridRows = 20000

$clrRed     = [System.Drawing.Color]::FromArgb(200, 0, 0)
$clrRedBack = [System.Drawing.Color]::FromArgb(255, 228, 228)
$clrOrange  = [System.Drawing.Color]::FromArgb(190, 100, 0)
$clrText    = [System.Drawing.Color]::FromArgb(30, 30, 30)
$clrApp     = [System.Drawing.Color]::FromArgb(40, 90, 160)
$clrGreen   = [System.Drawing.Color]::FromArgb(0, 130, 0)
$clrGrey    = [System.Drawing.Color]::FromArgb(120, 120, 120)
$fontUi     = New-Object System.Drawing.Font('Segoe UI', 9)
$fontBold   = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)

function New-Ctl([string]$Type, [hashtable]$Props) {
    $c = New-Object "System.Windows.Forms.$Type"
    foreach ($k in $Props.Keys) { $c.$k = $Props[$k] }
    return $c
}
function Add-Col($Grid, [string]$Name, [string]$Header, [int]$Width, [string]$Prop = $null, [string]$Format = $null) {
    $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $c.Name = $Name; $c.HeaderText = $Header; $c.Width = $Width; $c.ReadOnly = $true
    if ($Prop) { $c.DataPropertyName = $Prop }
    if ($Format) { $c.DefaultCellStyle.Format = $Format }
    [void]$Grid.Columns.Add($c)
    return $c
}
function Set-DoubleBuffered($Ctl) {
    $Ctl.GetType().GetProperty('DoubleBuffered', [Reflection.BindingFlags]'NonPublic,Instance').SetValue($Ctl, $true, $null)
}

# ==========================================================================================
#  Form layout
# ==========================================================================================
$form = New-Ctl Form @{ Text = "RDS Log Monitor (central) - $env:COMPUTERNAME"; Size = '1500,850'; MinimumSize = '1000,550'; StartPosition = 'CenterScreen'; Font = $fontUi }

# --- top panel ---
$top = New-Ctl Panel @{ Dock = 'Top'; Height = 108 }
$top.Width = $form.ClientSize.Width    # anchors are measured from this width, so it must match the form
$lblFile   = New-Ctl Label   @{ Text = 'CSV file:'; Location = '10,13'; AutoSize = $true }
$txtFile   = New-Ctl TextBox @{ Location = '70,10'; Width = 1190; Anchor = 'Top,Left,Right' }
$btnBrowse = New-Ctl Button  @{ Text = 'Browse...'; Location = '1268,8'; Width = 90; Anchor = 'Top,Right' }
$btnExcel  = New-Ctl Button  @{ Text = 'Open in Excel'; Location = '1364,8'; Width = 110; Anchor = 'Top,Right' }

$btnStart = New-Ctl Button @{ Text = 'Start Logging'; Size = '120,30'; Location = '10,40'; BackColor = [System.Drawing.Color]::FromArgb(220, 245, 220) }
$btnStop  = New-Ctl Button @{ Text = 'Stop Logging'; Size = '120,30'; Location = '138,40'; Enabled = $false }
$btnClear = New-Ctl Button @{ Text = 'Clear Grid'; Size = '90,30'; Location = '266,40' }
$chkIssuesOnly = New-Ctl CheckBox @{ Text = 'Issues only'; Location = '372,46'; AutoSize = $true }
$chkWarn   = New-Ctl CheckBox @{ Text = 'Warnings are issues'; Location = '466,46'; AutoSize = $true; Checked = $true }
$chkScroll = New-Ctl CheckBox @{ Text = 'Auto-scroll'; Location = '610,46'; AutoSize = $true; Checked = $true }
$lblHist   = New-Ctl Label @{ Text = 'Include last (mins):'; Location = '706,47'; AutoSize = $true }
$numHist   = New-Ctl NumericUpDown @{ Location = '820,44'; Width = 60; Minimum = 0; Maximum = 10080; Value = 0 }
$lblPoll   = New-Ctl Label @{ Text = 'Poll every (s):'; Location = '892,47'; AutoSize = $true }
$numPoll   = New-Ctl NumericUpDown @{ Location = '978,44'; Width = 50; Minimum = 2; Maximum = 600; Value = 5 }

$lblInc     = New-Ctl Label    @{ Text = 'Also read:'; Location = '10,82'; AutoSize = $true }
$chkRelated = New-Ctl CheckBox @{ Text = 'User Profile / FSLogix logs'; Location = '80,80'; AutoSize = $true; Checked = $true }
$chkSysApp  = New-Ctl CheckBox @{ Text = 'System + Application (RDS providers)'; Location = '268,80'; AutoSize = $true; Checked = $true }
$chkSec     = New-Ctl CheckBox @{ Text = 'Security (RDP logons, failed logons, Gateway auth)'; Location = '512,80'; AutoSize = $true; Checked = $true }
$lblFind    = New-Ctl Label    @{ Text = 'Find in grid:'; Location = '1090,47'; AutoSize = $true; Anchor = 'Top,Right' }
$txtFind    = New-Ctl TextBox  @{ Location = '1170,44'; Width = 200; Anchor = 'Top,Right' }
$btnClrFlt  = New-Ctl Button   @{ Text = 'Clear filters'; Location = '1378,42'; Size = '96,26'; Anchor = 'Top,Right' }
$top.Controls.AddRange(@($lblFile, $txtFile, $btnBrowse, $btnExcel, $btnStart, $btnStop, $btnClear, $chkIssuesOnly, $chkWarn, $chkScroll,
                         $lblHist, $numHist, $lblPoll, $numPoll, $lblInc, $chkRelated, $chkSysApp, $chkSec, $lblFind, $txtFind, $btnClrFlt))

# --- split: servers (left) / events (right) ---
$split = New-Ctl SplitContainer @{ Dock = 'Fill'; FixedPanel = 'Panel1' }

$srvTools = New-Ctl Panel @{ Dock = 'Top'; Height = 66 }
$lblSrv     = New-Ctl Label  @{ Text = 'Servers'; Location = '4,8'; AutoSize = $true; Font = $fontBold }
$btnAd      = New-Ctl Button @{ Text = 'Reload from AD'; Location = '62,3'; Size = '110,26' }
$btnDetect  = New-Ctl Button @{ Text = 'Detect RDS roles'; Location = '176,3'; Size = '115,26' }
$btnAll     = New-Ctl Button @{ Text = 'All'; Location = '295,3'; Size = '40,26' }
$btnNone    = New-Ctl Button @{ Text = 'None'; Location = '338,3'; Size = '46,26' }
$btnRdsOnly = New-Ctl Button @{ Text = 'RDS only'; Location = '387,3'; Size = '66,26' }
$txtSrvFilter = New-Ctl TextBox @{ Location = '4,36'; Width = 220 }
$txtAdd       = New-Ctl TextBox @{ Location = '232,36'; Width = 160 }
$btnAdd       = New-Ctl Button  @{ Text = 'Add'; Location = '396,34'; Size = '57,26' }
$tip = New-Object System.Windows.Forms.ToolTip
$tip.SetToolTip($txtSrvFilter, 'Filter the server list')
$tip.SetToolTip($txtAdd, 'Add a server by name (for servers not found in AD)')
$tip.SetToolTip($btnDetect, 'Ask each listed server which Remote Desktop roles it has, and tick the RDS servers')
$tip.SetToolTip($btnRdsOnly, 'Tick only servers with a detected Remote Desktop role')
$srvTools.Controls.AddRange(@($lblSrv, $btnAd, $btnDetect, $btnAll, $btnNone, $btnRdsOnly, $txtSrvFilter, $txtAdd, $btnAdd))

$gridSrv = New-Ctl DataGridView @{ Dock = 'Fill'; AllowUserToAddRows = $false; AllowUserToDeleteRows = $false; RowHeadersVisible = $false
                                   SelectionMode = 'FullRowSelect'; BackgroundColor = [System.Drawing.Color]::White; BorderStyle = 'None' }
$colMon = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$colMon.Name = 'Monitor'; $colMon.HeaderText = ''; $colMon.Width = 28
[void]$gridSrv.Columns.Add($colMon)
[void](Add-Col $gridSrv 'Server' 'Server' 175)
[void](Add-Col $gridSrv 'Roles' 'RDS roles' 120)
[void](Add-Col $gridSrv 'Status' 'Status' 150)
[void](Add-Col $gridSrv 'Events' 'Events' 50)
[void](Add-Col $gridSrv 'Issues' 'Issues' 45)
[void](Add-Col $gridSrv 'LastEvent' 'Last event' 120)
[void](Add-Col $gridSrv 'OS' 'Operating system' 190)
[void](Add-Col $gridSrv 'LastLogon' 'AD last logon' 90)
[void](Add-Col $gridSrv 'OU' 'OU' 260)
# kept as hidden data: used by role detection, RDS only, the filter box and saved settings
foreach ($n in 'Roles', 'OS', 'LastLogon', 'OU') { $gridSrv.Columns[$n].Visible = $false }
$split.Panel1.Controls.Add($gridSrv)
$split.Panel1.Controls.Add($srvTools)

# events grid, bound to a DataTable
$script:Table = New-Object System.Data.DataTable 'Events'
foreach ($c in @(@('Time', [datetime]), @('Server', [string]), @('Level', [string]), @('Issue', [string]), @('User', [string]),
                 @('Session', [string]), @('EventId', [int]), @('Log', [string]), @('Provider', [string]), @('Message', [string]), @('Sev', [string]))) {
    [void]$script:Table.Columns.Add($c[0], $c[1])
}
$script:Binding = New-Object System.Windows.Forms.BindingSource
$script:Binding.DataSource = $script:Table.DefaultView

$gridEv = New-Ctl DataGridView @{ Dock = 'Fill'; AllowUserToAddRows = $false; AllowUserToDeleteRows = $false; ReadOnly = $true; RowHeadersVisible = $false
                                  SelectionMode = 'FullRowSelect'; AutoGenerateColumns = $false; BackgroundColor = [System.Drawing.Color]::White; BorderStyle = 'None' }
$gridEv.RowTemplate.Height = 20
Set-DoubleBuffered $gridEv
[void](Add-Col $gridEv 'Time' 'Time' 130 'Time' 'yyyy-MM-dd HH:mm:ss')
[void](Add-Col $gridEv 'Server' 'Server' 120 'Server')
[void](Add-Col $gridEv 'Level' 'Level' 75 'Level')
[void](Add-Col $gridEv 'User' 'User' 150 'User')
[void](Add-Col $gridEv 'Session' 'Session' 75 'Session')
[void](Add-Col $gridEv 'EventId' 'Event ID' 80 'EventId')
[void](Add-Col $gridEv 'Log' 'Log' 210 'Log')
[void](Add-Col $gridEv 'Provider' 'Provider' 140 'Provider')
$colMsg = Add-Col $gridEv 'Message' 'Message' 900 'Message'
foreach ($c in $gridEv.Columns) {
    $c.SortMode = 'Programmatic'                                              # header click sorts; the filter button opens the filter
    $c.HeaderCell.Style.Padding = New-Object System.Windows.Forms.Padding(0, 0, 18, 0)   # room for the filter button
}
$gridEv.DataSource = $script:Binding
$script:ColFilters = @{}    # column -> @{ Values = HashSet[string] or $null; Text = '' }
$brushFltOn  = New-Object System.Drawing.SolidBrush($clrApp)
$brushFltOff = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
$penFlt      = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(150, 150, 150))
$split.Panel2.Controls.Add($gridEv)

$menu = New-Object System.Windows.Forms.ContextMenuStrip
[void]$menu.Items.Add('Show full details', $null, { Show-EventDetails })
[void]$menu.Items.Add('Copy selected rows', $null, { $d = $gridEv.GetClipboardContent(); if ($d) { [System.Windows.Forms.Clipboard]::SetDataObject($d) } })
$gridEv.ContextMenuStrip = $menu
$gridEv.ClipboardCopyMode = 'EnableWithAutoHeaderText'

# --- status bar ---
$status   = New-Object System.Windows.Forms.StatusStrip
$stState  = New-Object System.Windows.Forms.ToolStripStatusLabel
$stCounts = New-Object System.Windows.Forms.ToolStripStatusLabel
$stCsv    = New-Object System.Windows.Forms.ToolStripStatusLabel
$stCsv.Spring = $true; $stCsv.TextAlign = 'MiddleRight'
[void]$status.Items.AddRange(@($stState, $stCounts, $stCsv))

$form.Controls.Add($split); $form.Controls.Add($top); $form.Controls.Add($status)
$split.BringToFront()

$uiTimer = New-Object System.Windows.Forms.Timer
$uiTimer.Interval = 500

# ==========================================================================================
#  Servers
# ==========================================================================================
function Add-ServerRow([string]$Name, [string]$OS = '', [string]$OU = '', [string]$LastLogon = '', [bool]$Checked = $false) {
    $key = $Name.ToLowerInvariant()
    if ($script:ServerRows.ContainsKey($key)) { return $script:ServerRows[$key] }
    $i = $gridSrv.Rows.Add([object[]]@($Checked, $Name, '', '', 0, 0, '', $OS, $LastLogon, $OU))
    $row = $gridSrv.Rows[$i]
    $script:ServerRows[$key] = $row
    return $row
}

function Get-AdServers {
    $ds = [adsisearcher]'(&(objectCategory=computer)(operatingSystem=*Server*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    $ds.PageSize = 1000
    foreach ($p in 'name', 'dnshostname', 'operatingsystem', 'distinguishedname', 'lastlogontimestamp') { [void]$ds.PropertiesToLoad.Add($p) }
    $res = $ds.FindAll()
    try {
        foreach ($r in $res) {
            $p = $r.Properties
            $name = if ($p['dnshostname'].Count) { [string]$p['dnshostname'][0] } else { [string]$p['name'][0] }
            $dn = [string]$p['distinguishedname'][0]
            $ll = ''
            if ($p['lastlogontimestamp'].Count) { $ll = [DateTime]::FromFileTime([long]$p['lastlogontimestamp'][0]).ToString('yyyy-MM-dd') }
            [pscustomobject]@{ Name = $name; OS = [string]$p['operatingsystem'][0]; OU = ($dn -replace '^CN=[^,]+,', ''); LastLogon = $ll }
        }
    } finally { $res.Dispose() }
}

function Import-AdServers {
    $form.Cursor = 'WaitCursor'
    $saved = @()
    if ($script:Settings -and $script:Settings.Servers) { $saved = @($script:Settings.Servers | ForEach-Object { $_.ToLowerInvariant() }) }
    try {
        $list = @(Get-AdServers | Sort-Object Name)
        foreach ($s in $list) {
            $row = Add-ServerRow $s.Name $s.OS $s.OU $s.LastLogon ($saved -contains $s.Name.ToLowerInvariant())
            $row.Cells['OS'].Value = $s.OS; $row.Cells['OU'].Value = $s.OU; $row.Cells['LastLogon'].Value = $s.LastLogon
        }
        Write-Monitor '' "Loaded $($list.Count) server(s) from Active Directory."
    } catch {
        Write-Monitor '' "Could not read servers from Active Directory: $((Get-InnerException $_).Message). Add servers by name instead." $true
    }
    # servers added by hand last time
    if ($script:Settings -and $script:Settings.ManualServers) {
        foreach ($m in $script:Settings.ManualServers) { [void](Add-ServerRow $m '' '(added manually)' '' ($saved -contains $m.ToLowerInvariant())) }
    }
    if ($script:Settings -and $script:Settings.Roles) {
        foreach ($p in $script:Settings.Roles.PSObject.Properties) {
            $k = $p.Name.ToLowerInvariant(); if ($script:ServerRows.ContainsKey($k)) { $script:ServerRows[$k].Cells['Roles'].Value = $p.Value }
        }
    }
    $form.Cursor = 'Default'
    Update-ServerFilter
}

function Update-ServerFilter {
    $f = $txtSrvFilter.Text.Trim()
    $gridSrv.CurrentCell = $null
    foreach ($row in $gridSrv.Rows) {
        $row.Visible = (-not $f) -or ("$($row.Cells['Server'].Value) $($row.Cells['Roles'].Value) $($row.Cells['OS'].Value) $($row.Cells['OU'].Value)" -like "*$f*")
    }
}

function Get-CheckedServers { @($gridSrv.Rows | Where-Object { $_.Cells['Monitor'].Value -eq $true } | ForEach-Object { [string]$_.Cells['Server'].Value }) }

function Set-ServerStatus([string]$Server, [string]$Text, [string]$Kind) {
    $row = $script:ServerRows[$Server.ToLowerInvariant()]; if (-not $row) { return }
    $cell = $row.Cells['Status']; $cell.Value = $Text
    $cell.Style.ForeColor = switch ($Kind) { 'Ok' { $clrGreen } 'Error' { $clrRed } default { $clrText } }
}

function Start-RoleDetection {
    $names = @($gridSrv.Rows | Where-Object { $_.Visible } | ForEach-Object { [string]$_.Cells['Server'].Value })
    if ($names.Count -eq 0) { return }
    if (-not $script:RolePool) {
        $script:RolePool = [RunspaceFactory]::CreateRunspacePool(1, 16); $script:RolePool.Open()
    }
    foreach ($n in $names) {
        $script:ServerRows[$n.ToLowerInvariant()].Cells['Roles'].Value = 'checking...'
        if (-not $script:Run) { Set-ServerStatus $n 'Checking RDS roles...' 'Info' }
        $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:RolePool
        [void]$ps.AddScript($script:RoleCode).AddArgument($n).AddArgument($script:RoleQueue)
        $script:RoleJobs.Add([pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
    }
    $btnDetect.Enabled = $false; $btnDetect.Text = "Checking $($names.Count)..."
}

# ==========================================================================================
#  CSV
# ==========================================================================================
function ConvertTo-CsvField($Value) {
    $s = if ($Value -is [datetime]) { $Value.ToString('yyyy-MM-dd HH:mm:ss') } else { [string]$Value }
    if ($s -match '^[=+\-@\t\r]' -and $s -ne '-') { $s = "'" + $s }          # stop Excel treating log text as a formula
    if ($s -match '[",\r\n]') { $s = '"' + ($s -replace '"', '""') + '"' }
    return $s
}

function Add-CsvRow([object[]]$Values) {
    if (-not $script:CsvPath) { return }
    $script:CsvPending.Add((($Values | ForEach-Object { ConvertTo-CsvField $_ }) -join ','))
}

# Appends pending rows. If the file is locked (e.g. open in Excel) rows wait and are retried.
function Save-CsvPending {
    if (-not $script:CsvPath -or $script:CsvPending.Count -eq 0) { return }
    try {
        $fs = New-Object System.IO.FileStream($script:CsvPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        try {
            if ($fs.Length -eq 0) { $bom = [byte[]](0xEF, 0xBB, 0xBF); $fs.Write($bom, 0, 3) }
            $sw = New-Object System.IO.StreamWriter($fs, (New-Object System.Text.UTF8Encoding($false)))
            if ($fs.Length -le 3) { $sw.WriteLine(($script:CsvColumns -join ',')) }
            foreach ($l in $script:CsvPending) { $sw.WriteLine($l) }
            $sw.Flush()
        } finally { $fs.Dispose() }
        $script:CsvPending.Clear()
        if ($script:CsvWarned) { $script:CsvWarned = $false; Write-Monitor '' 'CSV file is writable again - buffered rows saved.' }
    } catch {
        if (-not $script:CsvWarned) {
            $script:CsvWarned = $true
            Write-Monitor '' "Cannot write to the CSV file (is it open in Excel?). Rows are kept in memory and saved when it is free. Use 'Open in Excel' to view a copy instead." $true
        }
    }
}

# ==========================================================================================
#  Events grid
# ==========================================================================================
function Add-GridRow($Time, $Server, $Level, $User, $Session, $EventId, $Log, $Provider, $Message, $Sev, $Issue) {
    [void]$script:Table.Rows.Add([object[]]@($Time, $Server, $Level, $Issue, $User, $Session, $EventId, $Log, $Provider, $Message, $Sev))
}

# Message from the monitor itself (connect/disconnect/errors): grid + CSV
function Write-Monitor([string]$Server, [string]$Text, [bool]$IsError = $false) {
    $now = Get-Date
    $sev = if ($IsError) { 'MonitorError' } else { 'Monitor' }
    $issue = if ($IsError) { 'Yes' } else { 'No' }
    Add-CsvRow @($now, $Server, 'MONITOR', $issue, '', '', '', 'RDS Log Monitor', '', $Text)
    $script:Binding.RaiseListChangedEvents = $true
    Add-GridRow $now $Server 'MONITOR' '' '' ([DBNull]::Value) 'RDS Log Monitor' '' $Text $sev $issue
    Complete-GridUpdate
}

function Complete-GridUpdate {
    while ($script:Table.Rows.Count -gt $script:MaxGridRows) {
        for ($i = 0; $i -lt 2000 -and $script:Table.Rows.Count -gt 0; $i++) { $script:Table.Rows.RemoveAt(0) }
    }
    if ($chkScroll.Checked -and $gridEv.RowCount -gt 0) {
        # newest rows are at the bottom, or at the top when sorted descending
        $target = if ($script:Binding.Sort -match 'DESC$') { 0 } else { $gridEv.RowCount - 1 }
        try { $gridEv.FirstDisplayedScrollingRowIndex = $target } catch { }
    }
}

function ConvertTo-LikeText([string]$Text) { $Text -replace "'", "''" -replace '([\[\]\*%])', '[$1]' }

# Text shown in a column's filter list (Time is grouped by day)
function Get-FilterValue($Row, [string]$Col) {
    $v = $Row.Item($Col)
    if ($null -eq $v -or $v -is [DBNull]) { return '' }
    if ($v -is [datetime]) { return $v.ToString('yyyy-MM-dd') }
    return [string]$v
}

function Get-ColumnFilterExpr([string]$Name, $F) {
    $parts = @()
    $str = "ISNULL(CONVERT([$Name], 'System.String'), '')"
    if ($null -ne $F.Values) {
        if ($F.Values.Count -eq 0) { $parts += "[Sev] = '~nothing~'" }
        elseif ($Name -eq 'Time') {
            $inv = [Globalization.CultureInfo]::InvariantCulture
            $days = foreach ($d in $F.Values) {
                $day = [datetime]::ParseExact($d, 'yyyy-MM-dd', $inv)
                "([Time] >= #{0}# AND [Time] < #{1}#)" -f $day.ToString('MM/dd/yyyy', $inv), $day.AddDays(1).ToString('MM/dd/yyyy', $inv)
            }
            $parts += '(' + ($days -join ' OR ') + ')'
        } else {
            $parts += "$str IN (" + (($F.Values | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ',') + ')'
        }
    }
    if ($F.Text) { $parts += "$str LIKE '*$(ConvertTo-LikeText $F.Text)*'" }
    return ($parts -join ' AND ')
}

function Update-GridFilter {
    $parts = New-Object System.Collections.Generic.List[string]
    $f = $txtFind.Text.Trim()
    if ($f) {
        $parts.Add(("(Server LIKE '*{0}*' OR User LIKE '*{0}*' OR Level LIKE '*{0}*' OR Log LIKE '*{0}*' OR Provider LIKE '*{0}*' OR Message LIKE '*{0}*' OR CONVERT(EventId, 'System.String') LIKE '*{0}*')" -f (ConvertTo-LikeText $f)))
    }
    foreach ($k in @($script:ColFilters.Keys)) { $parts.Add('(' + (Get-ColumnFilterExpr $k $script:ColFilters[$k]) + ')') }
    try { $script:Table.DefaultView.RowFilter = ($parts -join ' AND ') }
    catch {
        $script:ColFilters.Clear(); $script:Table.DefaultView.RowFilter = ''
        [void][System.Windows.Forms.MessageBox]::Show("That filter could not be applied and was cleared:`n$((Get-InnerException $_).Message)", 'RDS Log Monitor', 'OK', 'Warning')
    }
    $gridEv.Invalidate()
    Update-Status
}

# --- Excel-style column filter popup ---
function Update-FilterList {
    $F = $script:Flt
    $F.Filling = $true
    $F.List.BeginUpdate(); $F.List.Items.Clear(); $F.Shown.Clear()
    $t = $F.Text.Text
    foreach ($v in $F.Values) {
        if ($t -and $v.IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        $F.Shown.Add($v)
        [void]$F.List.Items.Add($(if ($v -eq '') { '(Blanks)' } else { $v }), $F.State[$v])
    }
    $F.List.EndUpdate()
    $F.All.Checked = (@($F.Shown | Where-Object { -not $F.State[$_] }).Count -eq 0)
    $F.Filling = $false
}

function Show-ColumnFilter([int]$ColIndex) {
    $col  = $gridEv.Columns[$ColIndex]
    $name = $col.DataPropertyName
    $cur  = $script:ColFilters[$name]

    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($r in $script:Table.Rows) { [void]$set.Add((Get-FilterValue $r $name)); if ($set.Count -ge 2000) { break } }
    $values = if ($name -eq 'Time') { @($set | Sort-Object -Descending) }
              elseif ($name -eq 'EventId') { @($set | Sort-Object { if ($_ -eq '') { -1 } else { [int]$_ } }) }
              else { @($set | Sort-Object) }
    $state = New-Object 'System.Collections.Generic.Dictionary[string,bool]'
    foreach ($v in $values) { $state[$v] = (-not $cur -or $null -eq $cur.Values -or $cur.Values.Contains($v)) }

    $dlg = New-Ctl Form @{ Text = "Filter: $($col.HeaderText)"; FormBorderStyle = 'SizableToolWindow'; ClientSize = '290,384'; MinimumSize = '240,260'
                           StartPosition = 'Manual'; Font = $fontUi; ShowInTaskbar = $false }
    $rect = $gridEv.GetCellDisplayRectangle($ColIndex, -1, $false)
    $pt   = $gridEv.PointToScreen((New-Object System.Drawing.Point([Math]::Max(0, $rect.Right - 290), $rect.Bottom)))
    $wa   = [System.Windows.Forms.Screen]::FromControl($gridEv).WorkingArea
    $dlg.Location = New-Object System.Drawing.Point([Math]::Max($wa.Left, [Math]::Min($pt.X, $wa.Right - $dlg.Width)), [Math]::Min($pt.Y, $wa.Bottom - $dlg.Height))

    $lbl  = New-Ctl Label @{ Text = 'Contains:'; Location = '10,11'; AutoSize = $true }
    $txt  = New-Ctl TextBox @{ Location = '72,8'; Width = 208; Anchor = 'Top,Left,Right' }
    $all  = New-Ctl CheckBox @{ Text = '(Select all)'; Location = '12,38'; AutoSize = $true }
    $lst  = New-Ctl CheckedListBox @{ Location = '10,60'; Size = '270,276'; Anchor = 'Top,Bottom,Left,Right'; CheckOnClick = $true; IntegralHeight = $false; HorizontalScrollbar = $true }
    $ok   = New-Ctl Button @{ Text = 'OK'; Location = '10,348'; Size = '70,26'; Anchor = 'Bottom,Left'; DialogResult = 'OK' }
    $clr  = New-Ctl Button @{ Text = 'Clear filter'; Location = '86,348'; Size = '90,26'; Anchor = 'Bottom,Left'; DialogResult = 'Abort' }
    $can  = New-Ctl Button @{ Text = 'Cancel'; Location = '210,348'; Size = '70,26'; Anchor = 'Bottom,Right'; DialogResult = 'Cancel' }
    $dlg.Controls.AddRange(@($lbl, $txt, $all, $lst, $ok, $clr, $can))
    $dlg.AcceptButton = $ok; $dlg.CancelButton = $can
    $tip.SetToolTip($txt, 'Show only rows where this column contains the text. Also narrows the list below.')
    if ($set.Count -ge 2000) { $tip.SetToolTip($lst, 'Showing the first 2000 distinct values - use Contains to narrow it down.') }
    if ($cur) { $txt.Text = $cur.Text }

    $script:Flt = @{ Values = $values; State = $state; Shown = (New-Object System.Collections.Generic.List[string]); List = $lst; Text = $txt; All = $all; Filling = $false }
    $lst.Add_ItemCheck({
        param($s, $e)
        if ($script:Flt.Filling) { return }
        $script:Flt.State[$script:Flt.Shown[$e.Index]] = ($e.NewValue -eq 'Checked')
        $script:Flt.Filling = $true
        $script:Flt.All.Checked = (@($script:Flt.Shown | Where-Object { -not $script:Flt.State[$_] }).Count -eq 0)
        $script:Flt.Filling = $false
    })
    $all.Add_CheckedChanged({
        if ($script:Flt.Filling) { return }
        foreach ($v in $script:Flt.Shown) { $script:Flt.State[$v] = $script:Flt.All.Checked }
        Update-FilterList
    })
    $txt.Add_TextChanged({ Update-FilterList })
    Update-FilterList

    $result = $dlg.ShowDialog($form)
    if ($result -eq 'OK') {
        $text = $txt.Text.Trim()
        $sel = New-Object 'System.Collections.Generic.HashSet[string]'
        $allSel = $true
        foreach ($v in $values) { if ($state[$v]) { [void]$sel.Add($v) } else { $allSel = $false } }
        if ($allSel -and -not $text) { $script:ColFilters.Remove($name) }
        else { $script:ColFilters[$name] = @{ Values = $(if ($allSel) { $null } else { $sel }); Text = $text } }
        Update-GridFilter
    } elseif ($result -eq 'Abort') {
        $script:ColFilters.Remove($name)
        Update-GridFilter
    }
    $dlg.Dispose()
}

function Show-EventDetails {
    $r = $gridEv.CurrentRow; if (-not $r -or -not $r.DataBoundItem) { return }
    $d = $r.DataBoundItem.Row
    $text = "Time:     {0:yyyy-MM-dd HH:mm:ss}`r`nServer:   {1}`r`nLevel:    {2}`r`nUser:     {3}`r`nSession:  {4}`r`nEvent ID: {5}`r`nLog:      {6}`r`nProvider: {7}`r`n`r`n{8}" -f `
        $d.Item('Time'), $d.Item('Server'), $d.Item('Level'), $d.Item('User'), $d.Item('Session'), $d.Item('EventId'), $d.Item('Log'), $d.Item('Provider'), ($d.Item('Message') -replace ' \| ', "`r`n")
    $dlg = New-Ctl Form @{ Text = 'Event details'; Size = '760,520'; StartPosition = 'CenterParent'; Font = $fontUi }
    $tb = New-Ctl TextBox @{ Multiline = $true; ReadOnly = $true; Dock = 'Fill'; ScrollBars = 'Both'; Text = $text; Font = (New-Object System.Drawing.Font('Consolas', 9)); BackColor = [System.Drawing.Color]::White }
    $dlg.Controls.Add($tb); [void]$dlg.ShowDialog($form); $dlg.Dispose()
}

# ==========================================================================================
#  Start / stop
# ==========================================================================================
function Update-Status {
    if ($script:Run) { $stState.Text = '  LOGGING  '; $stState.BackColor = [System.Drawing.Color]::FromArgb(200, 240, 200) }
    else             { $stState.Text = '  STOPPED  '; $stState.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230) }
    $n = if ($script:Run) { $script:Run.Workers.Count } else { 0 }
    $stCounts.Text = "Servers: $n    Events: $($script:EventCount)    Issues: $($script:IssueCount)"
    if ($script:Table.DefaultView.RowFilter) { $stCounts.Text += "    Showing $($script:Table.DefaultView.Count) of $($script:Table.Rows.Count) rows (filtered)" }
    $stCounts.ForeColor = if ($script:IssueCount -gt 0) { $clrRed } else { $clrText }
    $stCsv.Text = if ($script:CsvPath) {
        if ($script:CsvPending.Count -gt 0) { "CSV: $($script:CsvPath)  ($($script:CsvPending.Count) rows waiting - file locked)" } else { "CSV: $($script:CsvPath)" }
    } else { '' }
}

function Set-RunningUi([bool]$Running) {
    $btnStart.Enabled = -not $Running; $btnStop.Enabled = $Running
    foreach ($c in @($txtFile, $btnBrowse, $btnAd, $btnAll, $btnNone, $btnRdsOnly, $btnAdd, $txtAdd, $numHist, $chkRelated, $chkSysApp, $chkSec)) { $c.Enabled = -not $Running }
    $gridSrv.Columns['Monitor'].ReadOnly = $Running
}

function Save-Settings {
    try {
        $roles = @{}
        foreach ($row in $gridSrv.Rows) { $v = [string]$row.Cells['Roles'].Value; if ($v -and $v -ne 'checking...') { $roles[[string]$row.Cells['Server'].Value] = $v } }
        $manual = @($gridSrv.Rows | Where-Object { $_.Cells['OU'].Value -eq '(added manually)' } | ForEach-Object { [string]$_.Cells['Server'].Value })
        $obj = [ordered]@{
            CsvPath = $txtFile.Text; Servers = @(Get-CheckedServers); ManualServers = $manual; Roles = $roles
            IssuesOnly = $chkIssuesOnly.Checked; WarningsAreIssues = $chkWarn.Checked; PollSeconds = [int]$numPoll.Value
            Related = $chkRelated.Checked; SysApp = $chkSysApp.Checked; Security = $chkSec.Checked
        }
        $dir = Split-Path $script:SettingsPath -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $obj | ConvertTo-Json -Depth 4 | Set-Content -Path $script:SettingsPath -Encoding UTF8
    } catch { }
}

function Start-Monitoring {
    $servers = Get-CheckedServers
    if ($servers.Count -eq 0) { [void][System.Windows.Forms.MessageBox]::Show('Tick at least one server to monitor.', 'RDS Log Monitor', 'OK', 'Warning'); return }
    $path = $txtFile.Text.Trim()
    if (-not $path) { [void][System.Windows.Forms.MessageBox]::Show('Choose a CSV file first.', 'RDS Log Monitor', 'OK', 'Warning'); return }
    # An existing CSV with different columns (e.g. from an older version) gets a new file instead of mixed rows
    $renamed = $null
    try {
        if ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length -gt 0) {
            $header = (Get-Content -LiteralPath $path -TotalCount 1 -Encoding UTF8).TrimStart([char]0xFEFF)
            if ($header -ne ($script:CsvColumns -join ',')) {
                $renamed = $path
                $path = Join-Path (Split-Path $path -Parent) ('{0}_{1:HHmmss}.csv' -f [IO.Path]::GetFileNameWithoutExtension($path), (Get-Date))
                $txtFile.Text = $path
            }
        }
    } catch { }
    try {
        $dir = Split-Path -Path $path -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $fs = New-Object System.IO.FileStream($path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read); $fs.Dispose()
    } catch {
        [void][System.Windows.Forms.MessageBox]::Show("Cannot write to the CSV file:`n$path`n`n$((Get-InnerException $_).Message)`n`nIf it is open in Excel, close it or pick another file.", 'RDS Log Monitor', 'OK', 'Error')
        return
    }
    $script:CsvPath = $path
    if ($renamed) { Write-Monitor '' "$renamed has different columns (from an older version), so this run is saved to $path instead." }
    Save-Settings

    $opt = $script:Opt.Clone()
    $opt.IncludeRelated = $chkRelated.Checked; $opt.IncludeSysApp = $chkSysApp.Checked; $opt.IncludeSecurity = $chkSec.Checked
    $opt.HistoryMs = [long]$numHist.Value * 60000
    $opt.PollMs = [int]$numPoll.Value * 1000

    $run = [pscustomobject]@{
        Queue   = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
        Control = [hashtable]::Synchronized(@{ Stop = $false })
        Pool    = [RunspaceFactory]::CreateRunspacePool(1, $servers.Count + 1)
        Workers = New-Object System.Collections.Generic.List[object]
    }
    $run.Pool.Open()
    foreach ($s in $servers) {
        $ps = [PowerShell]::Create(); $ps.RunspacePool = $run.Pool
        [void]$ps.AddScript($script:WorkerCode).AddArgument($s).AddArgument($opt).AddArgument($run.Queue).AddArgument($run.Control)
        $run.Workers.Add([pscustomobject]@{ Server = $s; PS = $ps; Handle = $ps.BeginInvoke() })
        $row = $script:ServerRows[$s.ToLowerInvariant()]
        $row.Cells['Events'].Value = 0; $row.Cells['Issues'].Value = 0
        Set-ServerStatus $s 'Starting...' 'Info'
    }
    $script:Run = $run
    Set-RunningUi $true
    $extra = @(); if ($opt.HistoryMs -gt 0) { $extra += "including the last $($numHist.Value) minute(s)" }
    Write-Monitor '' ("Logging started by $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME. Monitoring $($servers.Count) server(s): $($servers -join ', ') $($extra -join ' ')").Trim()
    Update-Status
}

function Stop-Monitoring {
    if (-not $script:Run) { return }
    $script:Run.Control.Stop = $true
    Receive-Queue            # take anything already read
    foreach ($w in $script:Run.Workers) { $script:Retiring.Add($w); Set-ServerStatus $w.Server 'Stopped' 'Info' }
    $script:Retiring.Add([pscustomobject]@{ Server = ''; PS = $null; Handle = $null; Pool = $script:Run.Pool })
    $script:Run = $null
    Write-Monitor '' 'Logging stopped.'
    Save-CsvPending
    Set-RunningUi $false
    Update-Status
}

# Moves results from the background readers into the grid and CSV
function Receive-Queue {
    $item = $null
    $warnIssue = $chkWarn.Checked; $issuesOnly = $chkIssuesOnly.Checked
    $added = 0
    $script:Binding.RaiseListChangedEvents = $false
    try {
        if ($script:Run) {
            $q = $script:Run.Queue
            while ($added -lt 3000 -and $q.TryDequeue([ref]$item)) {
                switch ($item.Type) {
                    'Event' {
                        $isIssue = ($item.Sev -eq 'Error') -or ($warnIssue -and $item.Sev -eq 'Warning')
                        if ($issuesOnly -and -not $isIssue) { continue }
                        $issue = if ($isIssue) { 'Yes' } else { 'No' }
                        $script:EventCount++; if ($isIssue) { $script:IssueCount++ }
                        Add-CsvRow @($item.Time, $item.Server, $item.Level, $issue, $item.User, $item.Session, $item.EventId, $item.Log, $item.Provider, $item.Message)
                        Add-GridRow $item.Time $item.Server $item.Level $item.User $item.Session $item.EventId $item.Log $item.Provider $item.Message $item.Sev $issue
                        $row = $script:ServerRows[$item.Server.ToLowerInvariant()]
                        if ($row) {
                            $row.Cells['Events'].Value = [int]$row.Cells['Events'].Value + 1
                            if ($isIssue) { $row.Cells['Issues'].Value = [int]$row.Cells['Issues'].Value + 1; $row.Cells['Issues'].Style.ForeColor = $clrRed }
                            $row.Cells['LastEvent'].Value = $item.Time.ToString('yyyy-MM-dd HH:mm:ss')
                        }
                        $added++
                    }
                    'Monitor' {
                        $sev = if ($item.IsError) { 'MonitorError' } else { 'Monitor' }
                        $issue = if ($item.IsError) { 'Yes' } else { 'No' }
                        Add-CsvRow @($item.Time, $item.Server, 'MONITOR', $issue, '', '', '', 'RDS Log Monitor', '', $item.Message)
                        Add-GridRow $item.Time $item.Server 'MONITOR' '' '' ([DBNull]::Value) 'RDS Log Monitor' '' $item.Message $sev $issue
                        $added++
                    }
                    'Status' { Set-ServerStatus $item.Server $item.Text $item.Kind }
                }
            }
        }
    } finally {
        $script:Binding.RaiseListChangedEvents = $true
        if ($added -gt 0) { $script:Binding.ResetBindings($false); Complete-GridUpdate }
    }

    while ($script:RoleQueue.TryDequeue([ref]$item)) {
        $row = $script:ServerRows[$item.Server.ToLowerInvariant()]; if (-not $row) { continue }
        if ($item.Error) {
            $row.Cells['Roles'].Value = 'unknown'
            if (-not $script:Run) { Set-ServerStatus $item.Server 'Role check failed' 'Info'; $row.Cells['Status'].ToolTipText = $item.Error }
        } elseif ($item.Roles) {
            $row.Cells['Roles'].Value = $item.Roles
            if (-not $script:Run) { Set-ServerStatus $item.Server "RDS: $($item.Roles)" 'Ok' }
            if (-not $script:Run) { $row.Cells['Monitor'].Value = $true }
        } else {
            $row.Cells['Roles'].Value = 'none'
            if (-not $script:Run) { Set-ServerStatus $item.Server 'No RDS roles' 'Info' }
        }
    }
}

function Remove-FinishedJobs {
    for ($i = $script:Retiring.Count - 1; $i -ge 0; $i--) {
        $w = $script:Retiring[$i]
        if ($w.PS) {
            if ($w.Handle.IsCompleted) { $w.PS.Dispose(); $script:Retiring.RemoveAt($i) }
        } elseif ($w.Pool) {
            if (@($script:Retiring | Where-Object { $_.PS -and $_.PS.RunspacePool -eq $w.Pool }).Count -eq 0) { $w.Pool.Dispose(); $script:Retiring.RemoveAt($i) }
        }
    }
    if ($script:RoleJobs.Count -gt 0) {
        for ($i = $script:RoleJobs.Count - 1; $i -ge 0; $i--) {
            if ($script:RoleJobs[$i].Handle.IsCompleted) { $script:RoleJobs[$i].PS.Dispose(); $script:RoleJobs.RemoveAt($i) }
        }
        if ($script:RoleJobs.Count -eq 0) { $btnDetect.Enabled = $true; $btnDetect.Text = 'Detect RDS roles'; Save-Settings }
        else { $btnDetect.Text = "Checking $($script:RoleJobs.Count)..." }
    }
}

# ==========================================================================================
#  Event handlers
# ==========================================================================================
$btnBrowse.Add_Click({
    $dlg = New-Ctl SaveFileDialog @{ Title = 'CSV file'; Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'; OverwritePrompt = $false; DefaultExt = 'csv' }
    try { $dlg.InitialDirectory = Split-Path $txtFile.Text -Parent; $dlg.FileName = Split-Path $txtFile.Text -Leaf } catch { }
    if ($dlg.ShowDialog($form) -eq 'OK') { $txtFile.Text = $dlg.FileName }
})
$btnExcel.Add_Click({
    Save-CsvPending
    $src = $txtFile.Text.Trim()
    if (-not (Test-Path -LiteralPath $src)) { [void][System.Windows.Forms.MessageBox]::Show('The CSV file does not exist yet.', 'RDS Log Monitor', 'OK', 'Information'); return }
    # Open a copy so Excel never locks the live file
    $copy = Join-Path $env:TEMP ('RDSMonitor_snapshot_{0:yyyyMMdd_HHmmss}.csv' -f (Get-Date))
    try { Copy-Item -LiteralPath $src -Destination $copy -ErrorAction Stop; Start-Process $copy }
    catch { [void][System.Windows.Forms.MessageBox]::Show("Could not open a copy: $($_.Exception.Message)", 'RDS Log Monitor', 'OK', 'Error') }
})
$btnStart.Add_Click({ Start-Monitoring })
$btnStop.Add_Click({ Stop-Monitoring })
$btnClear.Add_Click({ $script:Table.Clear() })
$btnAd.Add_Click({ Import-AdServers })
$btnDetect.Add_Click({ Start-RoleDetection })
$btnAll.Add_Click({ foreach ($r in $gridSrv.Rows) { if ($r.Visible) { $r.Cells['Monitor'].Value = $true } } })
$btnNone.Add_Click({ foreach ($r in $gridSrv.Rows) { $r.Cells['Monitor'].Value = $false } })
$btnRdsOnly.Add_Click({ foreach ($r in $gridSrv.Rows) { $v = [string]$r.Cells['Roles'].Value; $r.Cells['Monitor'].Value = ($v -and $v -notin 'none', 'unknown', 'checking...') } })
$addServer = {
    $n = $txtAdd.Text.Trim()
    if (-not $n) { return }
    $row = Add-ServerRow $n '' '(added manually)' '' $true
    $row.Cells['Monitor'].Value = $true
    $txtAdd.Text = ''
}
$btnAdd.Add_Click($addServer)
$txtAdd.Add_KeyDown({ param($s, $e) if ($e.KeyCode -eq 'Enter') { & $addServer; $e.SuppressKeyPress = $true } })
$txtSrvFilter.Add_TextChanged({ Update-ServerFilter })
$txtFind.Add_TextChanged({ Update-GridFilter })
$btnClrFlt.Add_Click({ $script:ColFilters.Clear(); $txtFind.Text = ''; Update-GridFilter })

# Filter button in each column header
$gridEv.Add_CellPainting({
    param($s, $e)
    if ($e.RowIndex -ne -1 -or $e.ColumnIndex -lt 0) { return }
    $e.Paint($e.CellBounds, [System.Windows.Forms.DataGridViewPaintParts]::All)
    $active = $script:ColFilters.ContainsKey($gridEv.Columns[$e.ColumnIndex].DataPropertyName)
    $b = $e.CellBounds
    $r = New-Object System.Drawing.Rectangle(($b.Right - 18), ($b.Top + [int](($b.Height - 14) / 2)), 14, 14)
    $e.Graphics.FillRectangle($(if ($active) { $brushFltOn } else { $brushFltOff }), $r)
    $e.Graphics.DrawRectangle($penFlt, $r)
    $cx = $r.X + 7; $cy = $r.Y + 5
    $tri = [System.Drawing.Point[]]@((New-Object System.Drawing.Point(($cx - 4), $cy)), (New-Object System.Drawing.Point(($cx + 4), $cy)), (New-Object System.Drawing.Point($cx, ($cy + 4))))
    $e.Graphics.FillPolygon($(if ($active) { [System.Drawing.Brushes]::White } else { [System.Drawing.Brushes]::DimGray }), $tri)
    $e.Handled = $true
})

# Header click: filter button opens the filter, anywhere else sorts
$gridEv.Add_ColumnHeaderMouseClick({
    param($s, $e)
    if ($e.Button -ne 'Left') { return }
    $col = $gridEv.Columns[$e.ColumnIndex]
    if ($e.X -ge $col.Width - 20) { Show-ColumnFilter $e.ColumnIndex; return }
    $dir = if ($col.HeaderCell.SortGlyphDirection -eq 'Ascending') { 'Descending' } else { 'Ascending' }
    foreach ($c in $gridEv.Columns) { $c.HeaderCell.SortGlyphDirection = 'None' }
    $script:Binding.Sort = $col.DataPropertyName + $(if ($dir -eq 'Ascending') { ' ASC' } else { ' DESC' })
    $col.HeaderCell.SortGlyphDirection = $dir
})
$gridSrv.Add_CurrentCellDirtyStateChanged({ if ($gridSrv.IsCurrentCellDirty) { [void]$gridSrv.CommitEdit('CurrentCellChange') } })
$gridEv.Add_CellDoubleClick({ param($s, $e) if ($e.RowIndex -ge 0) { Show-EventDetails } })

# Row colours: issues red, warnings red/orange, monitor messages blue
$gridEv.Add_CellFormatting({
    param($s, $e)
    if ($e.RowIndex -lt 0) { return }
    $drv = $gridEv.Rows[$e.RowIndex].DataBoundItem
    if (-not $drv) { return }
    switch ([string]$drv.Row.Item('Sev')) {
        'Error'        { $e.CellStyle.ForeColor = $clrRed; $e.CellStyle.BackColor = $clrRedBack; $e.CellStyle.Font = $fontBold }
        'MonitorError' { $e.CellStyle.ForeColor = $clrRed; $e.CellStyle.BackColor = $clrRedBack; $e.CellStyle.Font = $fontBold }
        'Warning'      { if ($chkWarn.Checked) { $e.CellStyle.ForeColor = $clrRed } else { $e.CellStyle.ForeColor = $clrOrange } }
        'Monitor'      { $e.CellStyle.ForeColor = $clrApp }
    }
})
$chkWarn.Add_CheckedChanged({ $gridEv.Invalidate() })

$uiTimer.Add_Tick({
    try {
        Receive-Queue
        Save-CsvPending
        Remove-FinishedJobs
        Update-Status
    } catch { }
})

$form.Add_Shown({
    if ($script:Settings) {
        if ($script:Settings.CsvPath) { $txtFile.Text = $script:Settings.CsvPath }
        if ($null -ne $script:Settings.IssuesOnly) { $chkIssuesOnly.Checked = [bool]$script:Settings.IssuesOnly }
        if ($null -ne $script:Settings.WarningsAreIssues) { $chkWarn.Checked = [bool]$script:Settings.WarningsAreIssues }
        if ($script:Settings.PollSeconds) { $numPoll.Value = [Math]::Max(2, [int]$script:Settings.PollSeconds) }
        if ($null -ne $script:Settings.Related) { $chkRelated.Checked = [bool]$script:Settings.Related }
        if ($null -ne $script:Settings.SysApp) { $chkSysApp.Checked = [bool]$script:Settings.SysApp }
        if ($null -ne $script:Settings.Security) { $chkSec.Checked = [bool]$script:Settings.Security }
    }
    if (-not $txtFile.Text) { $txtFile.Text = Join-Path "$env:SystemDrive\RDSMonitor" ('RDSMonitor_{0:yyyyMMdd}.csv' -f (Get-Date)) }
    $split.SplitterDistance = 470
    Set-RunningUi $false
    Update-Status
    $uiTimer.Start()
    Import-AdServers
    Write-Monitor '' 'Tick the servers to monitor (or click Detect RDS roles), choose a CSV file and press Start Logging.'
})

$form.Add_FormClosing({
    Stop-Monitoring
    Save-CsvPending
    Save-Settings
    $uiTimer.Stop()
})

[void]$form.ShowDialog()

# Give background readers a moment to finish, then leave
$deadline = (Get-Date).AddSeconds(5)
while ($script:Retiring.Count -gt 0 -and (Get-Date) -lt $deadline) { Remove-FinishedJobs; Start-Sleep -Milliseconds 200 }
if ($script:RolePool) { try { $script:RolePool.Dispose() } catch { } }
$form.Dispose()
