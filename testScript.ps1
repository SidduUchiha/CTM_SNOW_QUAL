param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ControlMArgs
)

$ErrorActionPreference = "Stop"

# ============================================================
# PATHS — everything is relative to where this script lives.
#
# Expected folder layout (create these once):
#
#   <ProjectRoot>\
#       config\config.json      <- settings (this script reads it)
#       scripts\testScript.ps1  <- this file
#       logs\                   <- text logs + raw JSON captures
#       data\                   <- CSV audit trail + dedup state file
# ============================================================

$ScriptDir  = $PSScriptRoot
$ProjectDir = Split-Path -Path $ScriptDir -Parent

$ConfigDir  = Join-Path $ProjectDir "config"
$LogDir     = Join-Path $ProjectDir "logs"
$DataDir    = Join-Path $ProjectDir "data"

$ConfigPath = Join-Path $ConfigDir "config.json"

$RunTimestamp = Get-Date -Format "yyyyMMdd_HHmmss_fff"
$RunId        = "$RunTimestamp`_$PID"

$CsvLogFile        = Join-Path $DataDir "controlm_servicenow_trace.csv"
$IncidentStateFile = Join-Path $DataDir "incident_state.json"
$TextLogFile       = Join-Path $LogDir "controlm_servicenow_run_$RunId.log"
$RawLogFile        = Join-Path $LogDir "controlm_raw_$RunId.json"

# ============================================================
# SETUP
# ============================================================

foreach ($dir in @($ConfigDir, $LogDir, $DataDir)) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Bypass self-signed certificate on CTM AAPI / internal HTTPS, PowerShell 5.1
[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$scriptStart = Get-Date

# ============================================================
# SCRIPT STATE VARIABLES
# ============================================================

$Config             = $null
$alert              = $null
$serviceNowPayload  = $null
$serviceNowResponse = $null

$jobName        = ""
$memName        = ""
$alertId        = ""
$dataCenter     = ""
$orderId        = ""
$severity       = ""
$status         = ""
$message        = ""
$runAs          = ""
$application    = ""
$subApplication = ""
$hostId         = ""
$alertType      = ""
$sendTimeRaw    = ""
$sendTime       = ""
$ticketNumber   = ""
$runCounter     = ""

$correlationId  = ""
$matchType      = "NONE"
$incidentNumber = ""
$incidentSysId  = ""

$ctmWritebackStatus = "SKIPPED"
$ctmWritebackError  = ""

# ============================================================
# FUNCTIONS
# ============================================================

function Write-StepLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )

    $line = "[{0}] [{1}] [PID:{2}] {3}" -f `
        (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"),
        $Level,
        $PID,
        $Message

    Add-Content -Path $TextLogFile -Value $line -Encoding UTF8
}

function Convert-ToJsonSafe {
    param(
        $Object,
        [int]$Depth = 20
    )

    try {
        return ($Object | ConvertTo-Json -Depth $Depth -Compress)
    }
    catch {
        return "JSON conversion failed: $($_.Exception.Message)"
    }
}

function Get-ExceptionDetails {
    param(
        [Parameter(Mandatory)]
        $ErrorRecord
    )

    $details = New-Object System.Text.StringBuilder

    [void]$details.AppendLine("Exception message:")
    [void]$details.AppendLine($ErrorRecord.Exception.Message)
    [void]$details.AppendLine("")

    [void]$details.AppendLine("Full error:")
    [void]$details.AppendLine(($ErrorRecord | Out-String))
    [void]$details.AppendLine("")

    try {
        if ($ErrorRecord.Exception.Response -ne $null) {
            $response = $ErrorRecord.Exception.Response

            [void]$details.AppendLine("HTTP response:")

            try {
                [void]$details.AppendLine("StatusCode: $([int]$response.StatusCode)")
                [void]$details.AppendLine("StatusDescription: $($response.StatusDescription)")
            }
            catch { }

            try {
                $stream = $response.GetResponseStream()
                if ($stream -ne $null) {
                    $reader = New-Object System.IO.StreamReader($stream)
                    $responseBody = $reader.ReadToEnd()
                    [void]$details.AppendLine("Response body:")
                    [void]$details.AppendLine($responseBody)
                }
            }
            catch { }
        }
    }
    catch { }

    return $details.ToString()
}

function Get-ScriptConfig {
    param([string]$Path)

    if (!(Test-Path $Path)) {
        throw "Config file not found at $Path. Copy config.json into the config folder and fill in real values."
    }

    try {
        $raw = Get-Content -Path $Path -Raw -Encoding UTF8
        $cfg = $raw | ConvertFrom-Json
    }
    catch {
        throw "Failed to parse config file '$Path'. Error: $($_.Exception.Message)"
    }

    return $cfg
}

function Assert-Config {
    param($Config)

    Write-StepLog "Validating required configuration."

    if ([string]::IsNullOrWhiteSpace($Config.ServiceNow.Instance) -or $Config.ServiceNow.Instance -like "*YOUR_INSTANCE*") {
        throw "config.json: ServiceNow.Instance is not configured."
    }

    if ([string]::IsNullOrWhiteSpace($Config.ServiceNow.User) -or $Config.ServiceNow.User -like "*YOUR_SNOW_USERNAME*") {
        throw "config.json: ServiceNow.User is not configured."
    }

    if ([string]::IsNullOrWhiteSpace($Config.ServiceNow.Password) -or $Config.ServiceNow.Password -like "*YOUR_SNOW_PASSWORD*") {
        throw "config.json: ServiceNow.Password is not configured."
    }

    if ([string]::IsNullOrWhiteSpace($Config.ControlM.AapiEndpoint)) {
        throw "config.json: ControlM.AapiEndpoint is not configured."
    }

    if ([string]::IsNullOrWhiteSpace($Config.ControlM.AapiToken) -or $Config.ControlM.AapiToken -like "*YOUR_CTM_AAPI_TOKEN*") {
        throw "config.json: ControlM.AapiToken is not configured."
    }

    if ($Config.Smtp.Enabled) {
        if ([string]::IsNullOrWhiteSpace($Config.Smtp.Server)) {
            throw "config.json: Smtp.Enabled is true, but Smtp.Server is not configured."
        }

        if ([string]::IsNullOrWhiteSpace($Config.Smtp.MailFrom)) {
            throw "config.json: Smtp.Enabled is true, but Smtp.MailFrom is not configured."
        }

        if ([string]::IsNullOrWhiteSpace($Config.Smtp.MailTo)) {
            throw "config.json: Smtp.Enabled is true, but Smtp.MailTo is not configured."
        }
    }

    if ([string]::IsNullOrWhiteSpace($Config.ReminderFilter.RequiredSubstring)) {
        throw "config.json: ReminderFilter.RequiredSubstring is not configured."
    }

    Write-StepLog "Configuration validation completed."
}

function Parse-ControlMAlertArgs {
    param(
        [string[]]$ArgsList
    )

    Write-StepLog "Parsing Control-M alert arguments. Argument count: $($ArgsList.Count)"

    $parsed = [ordered]@{}
    $currentKey = $null
    $currentValueParts = New-Object System.Collections.Generic.List[string]

    foreach ($item in $ArgsList) {
        if ($item -match '^[A-Za-z0-9_]+:$') {
            if ($null -ne $currentKey) {
                $parsed[$currentKey] = ($currentValueParts -join " ").Trim()
            }

            $currentKey = $item.TrimEnd(":")
            $currentValueParts.Clear()
        }
        else {
            if ($null -ne $currentKey) {
                $currentValueParts.Add($item)
            }
        }
    }

    if ($null -ne $currentKey) {
        $parsed[$currentKey] = ($currentValueParts -join " ").Trim()
    }

    Write-StepLog "Parsed Control-M alert fields: $($parsed.Keys -join ', ')"

    return $parsed
}

function Convert-ControlMTime {
    param(
        [string]$ControlMTime
    )

    if ([string]::IsNullOrWhiteSpace($ControlMTime)) {
        return ""
    }

    try {
        $dt = [datetime]::ParseExact(
            $ControlMTime,
            "yyyyMMddHHmmss",
            [System.Globalization.CultureInfo]::InvariantCulture
        )

        return $dt.ToString("yyyy-MM-dd HH:mm:ss")
    }
    catch {
        return $ControlMTime
    }
}

function Get-AlertValue {
    param(
        [System.Collections.IDictionary]$Alert,
        [string]$Name,
        [string]$Default = ""
    )

    if ($null -ne $Alert -and $Alert.Contains($Name)) {
        return [string]$Alert[$Name]
    }

    return $Default
}

function Get-SeverityMapping {
    param([string]$Severity)

    switch ($Severity.ToUpper()) {
        'V' { return @{ Impact = "1"; Urgency = "1"; Text = "Very Urgent" } }
        'U' { return @{ Impact = "2"; Urgency = "2"; Text = "Urgent"      } }
        'R' { return @{ Impact = "3"; Urgency = "3"; Text = "Regular"     } }
        default { return @{ Impact = "3"; Urgency = "3"; Text = "Unknown" } }
    }
}

function Test-IsActionableAlert {
    # Decides whether this alert is a real job failure or a reminder /
    # gateway / custom "on do action" notification that should NOT create
    # a ServiceNow incident. Rule: the message must contain the configured
    # substring (default "ended not ok"). Empty or unrelated messages are
    # treated as non-actionable.
    param(
        [string]$Message,
        [string]$RequiredSubstring
    )

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return $false
    }

    return $Message.ToLower().Contains($RequiredSubstring.ToLower())
}

function Get-CorrelationId {
    # Key used to detect "is this the same failure occurrence as before".
    # Deliberately EXCLUDES alert_id, because Control-M assigns a new
    # alert_id every time — including on operator re-runs — which would
    # make every alert look unique. Includes the calendar date (from
    # send_time) instead of relying on order_id resetting on its own,
    # since a fresh day's run of the same job is a new occurrence, not a
    # continuation of a previous day's failure.
    param(
        [string]$DataCenter,
        [string]$JobName,
        [string]$OrderId,
        [string]$SendTimeRaw
    )

    $dc  = if ([string]::IsNullOrWhiteSpace($DataCenter)) { "UNKNOWN_DC" } else { $DataCenter }
    $job = if ([string]::IsNullOrWhiteSpace($JobName)) { "UNKNOWN_JOB" } else { $JobName }
    $ord = if ([string]::IsNullOrWhiteSpace($OrderId)) { "UNKNOWN_ORDER" } else { $OrderId }

    $datePart = $null

    if (![string]::IsNullOrWhiteSpace($SendTimeRaw)) {
        try {
            $dt = [datetime]::ParseExact(
                $SendTimeRaw,
                "yyyyMMddHHmmss",
                [System.Globalization.CultureInfo]::InvariantCulture
            )
            $datePart = $dt.ToString("yyyyMMdd")
        }
        catch {
            $datePart = $null
        }
    }

    if ($null -eq $datePart) {
        $datePart = (Get-Date).ToString("yyyyMMdd")
    }

    return "ControlM-$dc-$job-$ord-$datePart"
}

function Get-ServiceNowAuthHeader {
    param($Config)

    $pair   = "$($Config.ServiceNow.User):$($Config.ServiceNow.Password)"
    $base64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))

    return @{
        "Authorization" = "Basic $base64"
        "Accept"        = "application/json"
        "Content-Type"  = "application/json"
    }
}

function New-ServiceNowPayload {
    param(
        [System.Collections.IDictionary]$Alert,
        [string]$CorrelationId,
        $Config
    )

    Write-StepLog "Building ServiceNow incident payload."

    $jobName        = Get-AlertValue $Alert "job_name"
    $memName        = Get-AlertValue $Alert "memname"
    $alertId        = Get-AlertValue $Alert "alert_id"
    $orderId        = Get-AlertValue $Alert "order_id"
    $severity       = Get-AlertValue $Alert "severity"
    $status         = Get-AlertValue $Alert "status"
    $message        = Get-AlertValue $Alert "message"
    $dataCenter     = Get-AlertValue $Alert "data_center"
    $application    = Get-AlertValue $Alert "application"
    $subApplication = Get-AlertValue $Alert "sub_application"
    $hostId         = Get-AlertValue $Alert "host_id"
    $runAs          = Get-AlertValue $Alert "run_as"
    $alertType      = Get-AlertValue $Alert "alert_type"
    $sendTime       = Get-AlertValue $Alert "send_time"
    $runCounter     = Get-AlertValue $Alert "run_counter"

    $sendTimeReadable = Convert-ControlMTime $sendTime
    $sev              = Get-SeverityMapping -Severity $severity

    $descriptionText = @"
Control M job $jobName $message on $dataCenter

Other Details:
Sub Application : $subApplication
Application     : $application
Run Counter     : $runCounter
Order ID        : $orderId
Alert ID        : $alertId
Host ID         : $hostId
Severity        : $severity - $($sev.Text)
Mem Name        : $memName
Run As          : $runAs
Alert Type      : $alertType
Send Time       : $sendTimeReadable
Status          : $status
"@

    $payload = [ordered]@{
        short_description          = "Batch Failure - $jobName $orderId"
        description                = $descriptionText.Trim()
        assignment_group           = $Config.ServiceNow.AssignmentGroup
        cmdb_ci                    = $jobName
        impact                     = $sev.Impact
        urgency                    = $sev.Urgency
        category                   = "batch"
        subcategory                = "Control-M"
        contact_type               = "event"
        correlation_id             = $CorrelationId

        u_controlm_alert_id        = $alertId
        u_controlm_order_id        = $orderId
        u_controlm_job_name        = $jobName
        u_controlm_memname         = $memName
        u_controlm_data_center     = $dataCenter
        u_controlm_application     = $application
        u_controlm_sub_application = $subApplication
        u_controlm_host            = $hostId
        u_controlm_severity        = $severity
        u_controlm_severity_text   = $sev.Text
        u_controlm_status          = $status
        u_controlm_message         = $message
        u_controlm_run_counter     = $runCounter
        u_controlm_run_as          = $runAs
        u_controlm_alert_type      = $alertType
        u_controlm_send_time       = $sendTimeReadable
    }

    Write-StepLog "ServiceNow payload built. correlation_id=$CorrelationId"

    return $payload
}

function Invoke-ServiceNowCreateIncident {
    param(
        [System.Collections.IDictionary]$Payload,
        $Config
    )

    $uri = "$($Config.ServiceNow.Instance)$($Config.ServiceNow.Table)"

    Write-StepLog "Calling ServiceNow incident API (create): $uri"

    $headers = Get-ServiceNowAuthHeader -Config $Config
    $body    = $Payload | ConvertTo-Json -Depth 10

    Write-StepLog "ServiceNow request payload created. Payload JSON length: $($body.Length)"

    try {
        $response = Invoke-RestMethod `
            -Method     Post `
            -Uri        $uri `
            -Headers    $headers `
            -Body       $body `
            -TimeoutSec $Config.ServiceNow.TimeoutSec

        if ($null -eq $response.result) {
            throw "ServiceNow response did not contain expected 'result' object."
        }

        Write-StepLog "ServiceNow incident created. number=$($response.result.number), sys_id=$($response.result.sys_id)"

        return [ordered]@{
            number         = $response.result.number
            sys_id         = $response.result.sys_id
            correlation_id = $response.result.correlation_id
            state          = $response.result.state
            created_on     = $response.result.sys_created_on
        }
    }
    catch {
        Write-StepLog "ServiceNow incident creation failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Update-ServiceNowWorkNotes {
    # Adds a work note to an existing incident instead of creating a
    # duplicate. Used when the correlation_id matches a previously
    # created incident that is still tracked in the local state file.
    param(
        [string]$SysId,
        [string]$Note,
        $Config
    )

    $uri = "$($Config.ServiceNow.Instance)$($Config.ServiceNow.Table)/$SysId"

    Write-StepLog "Calling ServiceNow incident API (work notes update): $uri"

    $headers = Get-ServiceNowAuthHeader -Config $Config
    $body    = @{ work_notes = $Note } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod `
            -Method     Patch `
            -Uri        $uri `
            -Headers    $headers `
            -Body       $body `
            -TimeoutSec $Config.ServiceNow.TimeoutSec

        Write-StepLog "ServiceNow work notes updated successfully for sys_id=$SysId"

        return $response
    }
    catch {
        Write-StepLog "ServiceNow work notes update failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Update-ControlMAlert {
    param(
        [Parameter(Mandatory)]
        [string]$AlertId,

        [Parameter(Mandatory)]
        [string]$IncidentNumber,

        $Config
    )

    Write-StepLog "Preparing Control-M alert write-back. alert_id=$AlertId, incident=$IncidentNumber"

    try {
        $alertIdInt = [int]$AlertId
    }
    catch {
        throw "Control-M alert_id '$AlertId' is not numeric. Cannot update Control-M alert."
    }

    $headers = @{
        "x-api-key"    = $Config.ControlM.AapiToken
        "Content-Type" = "application/json"
        "Accept"       = "application/json"
    }

    $body = @{
        alertIds = @($alertIdInt)
        urgency  = "Normal"
        comment  = "ServiceNow incident: $IncidentNumber"
    } | ConvertTo-Json -Depth 5

    $uri = "$($Config.ControlM.AapiEndpoint)/run/alerts/status/$alertIdInt"

    Write-StepLog "Calling Control-M AAPI alert status endpoint: $uri"

    try {
        $response = Invoke-RestMethod `
            -Uri        $uri `
            -Method     Post `
            -Headers    $headers `
            -Body       $body `
            -TimeoutSec $Config.ControlM.TimeoutSec

        Write-StepLog "Control-M alert updated successfully. alert_id=$AlertId, incident=$IncidentNumber"

        return $response
    }
    catch {
        Write-StepLog "Control-M alert write-back failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

# ---- Duplicate-detection state file (JSON) --------------------------

function Get-IncidentState {
    param([string]$Path)

    if (!(Test-Path $Path)) {
        return [ordered]@{}
    }

    try {
        $raw = Get-Content -Path $Path -Raw -Encoding UTF8

        if ([string]::IsNullOrWhiteSpace($raw)) {
            return [ordered]@{}
        }

        $obj = $raw | ConvertFrom-Json

        $ht = [ordered]@{}

        if ($null -ne $obj) {
            foreach ($prop in $obj.PSObject.Properties) {
                $ht[$prop.Name] = $prop.Value
            }
        }

        return $ht
    }
    catch {
        Write-StepLog "Failed to read/parse incident state file. Starting with empty state. Error: $($_.Exception.Message)" "WARN"
        return [ordered]@{}
    }
}

function Save-IncidentState {
    param(
        [string]$Path,
        $State
    )

    $State | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
}

function Remove-OldStateEntries {
    # Keeps the dedup state file small. This file only needs to answer
    # "have we seen this failure recently", so anything older than the
    # configured window is safe to drop. This does NOT touch the CSV
    # audit trail, which is meant to keep every record forever.
    param(
        $State,
        [int]$MaxAgeDays
    )

    $cutoff = (Get-Date).AddDays(-1 * $MaxAgeDays)
    $keysToRemove = New-Object System.Collections.Generic.List[string]

    foreach ($key in @($State.Keys)) {
        $entry = $State[$key]
        $lastUpdatedStr = $entry.last_updated
        $lastUpdated = Get-Date

        $parsed = [datetime]::MinValue
        if ([datetime]::TryParse($lastUpdatedStr, [ref]$parsed)) {
            $lastUpdated = $parsed
        }
        else {
            # Can't parse the timestamp — treat as old so it gets cleaned up.
            $lastUpdated = [datetime]::MinValue
        }

        if ($lastUpdated -lt $cutoff) {
            $keysToRemove.Add($key)
        }
    }

    foreach ($key in $keysToRemove) {
        $State.Remove($key)
    }

    if ($keysToRemove.Count -gt 0) {
        Write-StepLog "Pruned $($keysToRemove.Count) stale entr(y/ies) from incident state file."
    }

    return $State
}

function Invoke-WithStateLock {
    # Everything that reads-then-writes the dedup state file (and the
    # ServiceNow create/update call that depends on that read) happens
    # inside this lock. This matters because Control-M can fire more than
    # one alert at nearly the same time — without a lock, two script
    # instances could both check "no existing incident" at once and both
    # create one.
    param(
        [scriptblock]$Action,
        [int]$TimeoutMs = 30000
    )

    $mutex = New-Object System.Threading.Mutex($false, "Global\ControlM_ServiceNow_State_Lock")
    $lockTaken = $false

    try {
        $lockTaken = $mutex.WaitOne($TimeoutMs)

        if (-not $lockTaken) {
            throw "Could not acquire the incident-state lock within $TimeoutMs ms."
        }

        return & $Action
    }
    finally {
        if ($lockTaken) {
            $mutex.ReleaseMutex()
        }

        $mutex.Dispose()
    }
}

# ---- CSV audit trail --------------------------------------------------

function Add-CsvLog {
    param(
        [string]$Path,
        [pscustomobject]$Row
    )

    Write-StepLog "Writing CSV trace row to $Path"

    $mutexName = "Global\ControlM_ServiceNow_Csv_Log"
    $mutex     = New-Object System.Threading.Mutex($false, $mutexName)
    $lockTaken = $false

    try {
        $lockTaken = $mutex.WaitOne(30000)

        if (-not $lockTaken) {
            throw "Could not get CSV log file lock after 30 seconds."
        }

        if (Test-Path $Path) {
            $Row | Export-Csv -Path $Path -NoTypeInformation -Append -Encoding UTF8
        }
        else {
            $Row | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        }

        Write-StepLog "CSV trace row written successfully."
    }
    finally {
        if ($lockTaken) {
            $mutex.ReleaseMutex()
        }

        $mutex.Dispose()
    }
}

function New-CsvRow {
    param(
        [string]$Status,
        [string]$ErrorMessage = ""
    )

    $nowLocal = Get-Date

    return [pscustomobject]@{
        trace_time_local           = $nowLocal.ToString("yyyy-MM-dd HH:mm:ss.fff")
        trace_time_utc             = $nowLocal.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff")
        status                     = $Status
        match_type                 = $matchType
        correlation_id             = $correlationId

        call_type                  = if ($alert) { Get-AlertValue $alert "call_type" } else { "" }
        alert_id                   = $alertId
        data_center                = $dataCenter
        memname                    = $memName
        order_id                   = $orderId
        severity                   = $severity
        controlm_status            = $status
        send_time_raw              = $sendTimeRaw
        send_time                  = $sendTime
        message                    = $message
        run_as                     = $runAs
        sub_application            = $subApplication
        application                = $application
        job_name                   = $jobName
        host_id                    = $hostId
        alert_type                 = $alertType
        ticket_number              = $ticketNumber
        run_counter                = $runCounter

        servicenow_incident_number = $incidentNumber
        servicenow_sys_id          = $incidentSysId
        servicenow_response_json   = Convert-ToJsonSafe $serviceNowResponse 20
        servicenow_payload_json    = Convert-ToJsonSafe $serviceNowPayload 20

        ctm_writeback_status       = $ctmWritebackStatus
        ctm_writeback_error        = $ctmWritebackError

        raw_arg_count              = if ($ControlMArgs) { $ControlMArgs.Count } else { 0 }
        raw_args                   = if ($ControlMArgs) { $ControlMArgs -join " " } else { "" }
        parsed_alert_json          = Convert-ToJsonSafe $alert 20
        raw_log_file               = $RawLogFile
        text_log_file              = $TextLogFile

        error_message              = $ErrorMessage
    }
}

function Send-FailureEmail {
    param(
        [string]$ErrorMessage,
        [string]$ErrorDetails,
        $Config
    )

    if (-not $Config.Smtp.Enabled) {
        Write-StepLog "SMTP failure email disabled. Skipping email."
        return
    }

    Write-StepLog "Sending failure email to $($Config.Smtp.MailTo)"

    $body = @"
Control-M ServiceNow Integration Script Failed.

Time:
$(Get-Date -Format o)

Server:
$env:COMPUTERNAME

User:
$env:USERNAME

PID:
$PID

Script:
$PSCommandPath

Raw command line:
$([Environment]::CommandLine)

Raw args:
$($ControlMArgs -join " ")

Text log file:
$TextLogFile

Raw log file:
$RawLogFile

CSV log file:
$CsvLogFile

Error message:
$ErrorMessage

Error details:
$ErrorDetails
"@

    try {
        $mailParams = @{
            SmtpServer = $Config.Smtp.Server
            Port       = $Config.Smtp.Port
            From       = $Config.Smtp.MailFrom
            To         = $Config.Smtp.MailTo
            Subject    = $Config.Smtp.Subject
            Body       = $body
        }

        if ($Config.Smtp.UseSsl) {
            $mailParams.UseSsl = $true
        }

        if (![string]::IsNullOrWhiteSpace($Config.Smtp.Username) -and
            ![string]::IsNullOrWhiteSpace($Config.Smtp.Password)) {

            $securePassword = ConvertTo-SecureString $Config.Smtp.Password -AsPlainText -Force
            $credential     = New-Object System.Management.Automation.PSCredential($Config.Smtp.Username, $securePassword)

            $mailParams.Credential = $credential
        }

        Send-MailMessage @mailParams

        Write-StepLog "Failure email sent successfully."
    }
    catch {
        Write-StepLog "Failed to send SMTP failure email: $($_.Exception.Message)" "ERROR"

        $emailFailureFile = Join-Path $LogDir ("email_failure_{0}_{1}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss_fff"), $PID)
        "Failed to send SMTP failure email: $($_.Exception.Message)" | Out-File -FilePath $emailFailureFile -Encoding UTF8
    }
}

# ============================================================
# MAIN
# ============================================================

try {
    Write-StepLog "============================================================"
    Write-StepLog "Control-M ServiceNow integration script started."
    Write-StepLog "Script path: $PSCommandPath"
    Write-StepLog "Command line: $([Environment]::CommandLine)"
    Write-StepLog "Computer: $env:COMPUTERNAME"
    Write-StepLog "User: $env:USERNAME"
    Write-StepLog "PID: $PID"
    Write-StepLog "Config file: $ConfigPath"
    Write-StepLog "Log directory: $LogDir"
    Write-StepLog "Data directory: $DataDir"
    Write-StepLog "Raw argument count: $($ControlMArgs.Count)"
    Write-StepLog "Raw arguments: $($ControlMArgs -join ' ')"

    $Config = Get-ScriptConfig -Path $ConfigPath
    Assert-Config -Config $Config

    # ── Step 1: Parse Control-M alert arguments ──────────────
    Write-StepLog "Step 1 started: Parse Control-M alert arguments."

    $alert = Parse-ControlMAlertArgs -ArgsList $ControlMArgs

    $jobName        = Get-AlertValue $alert "job_name"
    $memName        = Get-AlertValue $alert "memname"
    $alertId        = Get-AlertValue $alert "alert_id"
    $dataCenter     = Get-AlertValue $alert "data_center"
    $orderId        = Get-AlertValue $alert "order_id"
    $severity       = Get-AlertValue $alert "severity"
    $status         = Get-AlertValue $alert "status"
    $message        = Get-AlertValue $alert "message"
    $runAs          = Get-AlertValue $alert "run_as"
    $application    = Get-AlertValue $alert "application"
    $subApplication = Get-AlertValue $alert "sub_application"
    $hostId         = Get-AlertValue $alert "host_id"
    $alertType      = Get-AlertValue $alert "alert_type"
    $sendTimeRaw    = Get-AlertValue $alert "send_time"
    $sendTime       = Convert-ControlMTime $sendTimeRaw
    $ticketNumber   = Get-AlertValue $alert "ticket_number"
    $runCounter     = Get-AlertValue $alert "run_counter"

    Write-StepLog "Parsed alert summary: alert_id=$alertId, data_center=$dataCenter, job_name=$jobName, order_id=$orderId, severity=$severity, status=$status"

    if ([string]::IsNullOrWhiteSpace($alertId)) {
        throw "Required field alert_id is missing from Control-M arguments."
    }

    if ([string]::IsNullOrWhiteSpace($jobName)) {
        throw "Required field job_name is missing from Control-M arguments."
    }

    # Save raw JSON capture
    Write-StepLog "Writing raw JSON capture to $RawLogFile"

    $rawCapture = [ordered]@{
        timestamp_local = $scriptStart.ToString("yyyy-MM-dd HH:mm:ss.fff")
        timestamp_utc   = $scriptStart.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff")
        computer        = $env:COMPUTERNAME
        user            = $env:USERNAME
        pid             = $PID
        script_path     = $PSCommandPath
        command_line    = [Environment]::CommandLine
        arg_count       = $ControlMArgs.Count
        raw_args        = $ControlMArgs
        parsed_alert    = $alert
        text_log_file   = $TextLogFile
        csv_log_file    = $CsvLogFile
    }

    $rawCapture | ConvertTo-Json -Depth 20 | Out-File -FilePath $RawLogFile -Encoding UTF8

    Write-StepLog "Step 1 completed."

    # ── Step 2: Reminder / non-actionable filter ─────────────
    Write-StepLog "Step 2 started: Check whether alert is actionable."

    $isActionable = Test-IsActionableAlert -Message $message -RequiredSubstring $Config.ReminderFilter.RequiredSubstring

    if (-not $isActionable) {
        Write-StepLog "Alert is non-actionable (message did not contain '$($Config.ReminderFilter.RequiredSubstring)'). Skipping ServiceNow and Control-M write-back." "WARN"

        $matchType = "NONE"
        $csvRow = New-CsvRow -Status "SKIPPED_NON_ACTIONABLE"
        Add-CsvLog -Path $CsvLogFile -Row $csvRow

        Write-StepLog "Step 2 completed. Alert skipped."
        Write-StepLog "============================================================"

        exit 0
    }

    Write-StepLog "Step 2 completed. Alert is actionable, continuing."

    # ── Step 3: Correlation ID + duplicate check + ServiceNow ─
    Write-StepLog "Step 3 started: Correlation check and ServiceNow incident create/update."

    $correlationId = Get-CorrelationId -DataCenter $dataCenter -JobName $jobName -OrderId $orderId -SendTimeRaw $sendTimeRaw
    Write-StepLog "Computed correlation_id=$correlationId"

    Invoke-WithStateLock -Action {

        $state = Get-IncidentState -Path $IncidentStateFile
        $state = Remove-OldStateEntries -State $state -MaxAgeDays $Config.StateFile.PruneAfterDays

        if ($state.Contains($correlationId)) {

            # ---- Duplicate: update work notes on the existing incident ----
            $existing = $state[$correlationId]

            $script:matchType      = "DUPLICATE_UPDATED"
            $script:incidentNumber = $existing.incident_number
            $script:incidentSysId  = $existing.sys_id

            Write-StepLog "Correlation match found. Existing incident=$($existing.incident_number). Updating work notes instead of creating a new incident."

            $note = "Control-M job '$jobName' (order $orderId) failed again on $dataCenter. Run counter: $runCounter. Alert ID: $alertId. Message: $message"

            $script:serviceNowResponse = Update-ServiceNowWorkNotes -SysId $existing.sys_id -Note $note -Config $Config

            $existing.last_run_counter = $runCounter
            $existing.last_updated     = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            $state[$correlationId]     = $existing
        }
        else {

            # ---- New occurrence: create a fresh incident ----
            $script:matchType = "NEW_INCIDENT"

            $script:serviceNowPayload  = New-ServiceNowPayload -Alert $alert -CorrelationId $correlationId -Config $Config
            $script:serviceNowResponse = Invoke-ServiceNowCreateIncident -Payload $script:serviceNowPayload -Config $Config

            $script:incidentNumber = $script:serviceNowResponse["number"]
            $script:incidentSysId  = $script:serviceNowResponse["sys_id"]

            if ([string]::IsNullOrWhiteSpace($script:incidentNumber)) {
                throw "ServiceNow incident creation returned empty incident number."
            }

            $nowStr = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

            $state[$correlationId] = [ordered]@{
                incident_number  = $script:incidentNumber
                sys_id           = $script:incidentSysId
                job_name         = $jobName
                order_id         = $orderId
                data_center      = $dataCenter
                last_run_counter = $runCounter
                first_created    = $nowStr
                last_updated     = $nowStr
            }
        }

        Save-IncidentState -Path $IncidentStateFile -State $state
    }

    Write-StepLog "Step 3 completed. match_type=$matchType, incident=$incidentNumber"

    # ── Step 4: Write incident number back to CTM Alert Window ──
    Write-StepLog "Step 4 started: Update Control-M alert with ServiceNow incident number."

    $ctmWritebackStatus = "SKIPPED"
    $ctmWritebackError  = ""

    if (![string]::IsNullOrWhiteSpace($alertId) -and
        ![string]::IsNullOrWhiteSpace($incidentNumber) -and
        ![string]::IsNullOrWhiteSpace($Config.ControlM.AapiToken)) {

        try {
            Update-ControlMAlert -AlertId $alertId -IncidentNumber $incidentNumber -Config $Config | Out-Null
            $ctmWritebackStatus = "SUCCESS"
            Write-StepLog "Step 4 completed. Control-M write-back successful."
        }
        catch {
            $ctmWritebackStatus = "FAILED"
            $ctmWritebackError  = $_.Exception.Message

            Write-StepLog "Step 4 failed but incident was already created/updated. Error: $ctmWritebackError" "ERROR"
            Write-StepLog "Continuing because ServiceNow incident exists: $incidentNumber" "WARN"
        }
    }
    else {
        Write-StepLog "Step 4 skipped. Missing alert_id, incident number, or AAPI token." "WARN"
    }

    # ── Step 5: Write trace CSV ──────────────────────────────
    Write-StepLog "Step 5 started: Write CSV trace log."

    $csvRow = New-CsvRow -Status "SUCCESS"
    Add-CsvLog -Path $CsvLogFile -Row $csvRow

    Write-StepLog "Step 5 completed."

    $duration = New-TimeSpan -Start $scriptStart -End (Get-Date)

    Write-StepLog "Script completed successfully."
    Write-StepLog "Match type: $matchType"
    Write-StepLog "Incident number: $incidentNumber"
    Write-StepLog "Control-M write-back status: $ctmWritebackStatus"
    Write-StepLog "Duration seconds: $([math]::Round($duration.TotalSeconds, 3))"
    Write-StepLog "============================================================"

    exit 0
}
catch {
    $errorMessage = $_.Exception.Message
    $errorDetails = Get-ExceptionDetails -ErrorRecord $_

    try {
        Write-StepLog "Script failed: $errorMessage" "ERROR"
        Write-StepLog $errorDetails "ERROR"
    }
    catch { }

    # Try to write failure details to raw JSON file
    try {
        $failureCapture = [ordered]@{
            timestamp_local = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
            timestamp_utc   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff")
            computer        = $env:COMPUTERNAME
            user            = $env:USERNAME
            pid             = $PID
            script_path     = $PSCommandPath
            command_line    = [Environment]::CommandLine
            arg_count       = if ($ControlMArgs) { $ControlMArgs.Count } else { 0 }
            raw_args        = $ControlMArgs
            parsed_alert    = $alert
            correlation_id  = $correlationId
            match_type      = $matchType
            incident_number = $incidentNumber
            incident_sys_id = $incidentSysId
            ctm_writeback_status = $ctmWritebackStatus
            ctm_writeback_error  = $ctmWritebackError
            error_message   = $errorMessage
            error_details   = $errorDetails
            text_log_file   = $TextLogFile
            csv_log_file    = $CsvLogFile
        }

        $failureCapture | ConvertTo-Json -Depth 20 | Out-File -FilePath $RawLogFile -Encoding UTF8
    }
    catch { }

    # Try to write failure row to CSV
    try {
        $csvRow = New-CsvRow -Status "FAILED" -ErrorMessage $errorMessage
        Add-CsvLog -Path $CsvLogFile -Row $csvRow
    }
    catch { }

    # Send SMTP failure alert
    try {
        if ($null -ne $Config) {
            Send-FailureEmail -ErrorMessage $errorMessage -ErrorDetails $errorDetails -Config $Config
        }
    }
    catch { }

    try {
        $duration = New-TimeSpan -Start $scriptStart -End (Get-Date)
        Write-StepLog "Script ended with failure."
        Write-StepLog "Duration seconds: $([math]::Round($duration.TotalSeconds, 3))"
        Write-StepLog "============================================================"
    }
    catch { }

    exit 1
}
