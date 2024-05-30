Function New-LogicMonitorDashboardWidget {
    <#
        .DESCRIPTION
            Clone an existing LogicMonitor dashboard.
        .NOTES
            Author: Mike Hashemi
            V2024.05.08.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER SourceDashboardId
            Mandatory parameter. Represents the ID of the dashboard to copy.
        .PARAMETER TargetDashboardName
            Represents the desired name for the cloned dashboard. Either this parameter or -Properties (including a name) is required.
        .PARAMETER Properties
            Represents the a customer PS object containing the desired properties (including a name) for the cloned dashboard. Either this parameter or -TargetDashboardName is required.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> $properties = [PsCustomObject]@{name = 'Dashboard Clone'; groupId = 123}
            PS C:\> Add-LogicMonitorDashboard -AccessId <access Id> -AccessKey <access key> -AccountName <account name> -Properties $properties -SourceDashboardId 456

            In this example, the function will clone the dashboard with ID 456, naming the new dashboard "Dashboard Clone" and placing it into the dashboard group with ID 123. Limited logging output is sent only to the host.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [SecureString]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory)]
        [Id]$SourceDashboardId,

        [String]$TargetDashboardName,

        [PSCustomObject]$Properties,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    # Initialize variables.
    $httpVerb = "POST" # Define what HTTP operation will the script run.
    $resourcePath = "/dashboard/dashboards/{0}/clone" -f $SourceDashboardId
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    #region Logging
    # Setup parameters for splatting.
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') {
        If ($EventLogSource -and (-NOT $LogPath)) {
            $loggingParams = @{
                Verbose        = $true
                EventLogSource = $EventLogSource
            }
        } ElseIf ($LogPath -and (-NOT $EventLogSource)) {
            $loggingParams = @{
                Verbose = $true
                LogPath = $LogPath
            }
        } Else {
            $loggingParams = @{
                Verbose = $true
            }
        }
    } Else {
        If ($EventLogSource -and (-NOT $LogPath)) {
            $loggingParams = @{
                EventLogSource = $EventLogSource
            }
        } ElseIf ($LogPath -and (-NOT $EventLogSource)) {
            $loggingParams = @{
                LogPath = $LogPath
            }
        } Else {
            $loggingParams = @{}
        }
    }
    #endregion Logging

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand); If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    #endregion Setup

    #region Set body
    If (-NOT $Properties) {
        If (-NOT $TargetDashboardName) {
            $message = ("{0}: A name or a property object is required. To prevent errors, {1} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand); Out-PsLogging @loggingParams -MessageType Error -Message $message

            Return "Error"
        } Else {
            $data = (@{
                    name = $TargetDashboardName
                } | ConvertTo-Json -Depth 5)
        }
    } Else {
        $data = $Properties | ConvertTo-Json -Depth 5
    }
    #endregion Set body

    #region Execute REST query
    # Construct the query URL.
    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"

    $message = ("{0}: Connecting to: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $url); If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

    #region Auth and headers
    # Get current time in milliseconds.
    $epoch = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End (Get-Date).ToUniversalTime()).TotalMilliseconds)
    $requestVars = $httpVerb + $epoch + $data + $resourcePath
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
    $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
    $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
    $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

    $headers = @{
        "Authorization" = "LMv1 $AccessId`:$signature`:$epoch"
        "Content-Type"  = "application/json"
        "X-Version"     = 3
    }
    #endregion Auth and headers

    Try {
        $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -Body $data -ErrorAction Stop
    }
    Catch {
        If ($_.Exception.Message -match '429') {
            $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message); Out-PsLogging @loggingParams -MessageType Warning -Message $message

            Start-Sleep -Seconds 60
        }
        Else {
            # Left the body out of the error message, because the body can be really long and it is annoying to have to scroll up to see the error message.
            $errormsg = Try { ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage) } Catch { $error[1].Exception.Message }
            $errorcode = Try { ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode) } Catch { "none" }
            $message = ("{0}: Unexpected error cloning the dashboard. To prevent errors, the cmdlet will exit. If present, the following details were returned:`r`n
                Error message: {1}`r
                Error code: {2}`r
                Invoke-Request: {3}`r
                Headers: {4}" -f
                ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $errormsg, $errorcode, $_.Exception.Message, ($headers | Out-String)
            ); Out-PsLogging @loggingParams -MessageType Error -Message $message
        }

        Return "Error"
    }

    #region Output
    If ($response.id) {
        $message = ("{0}: Successfully cloned the dashboard." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss")); If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    } Else {
        $message = ("{0}: Unexpected error cloning the desired dashboard. To prevent errors, {1} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand); Out-PsLogging @loggingParams -MessageType Error -Message $message

        Return "Error"
    }

    Return $response
    #endregion Output
} #2024.05.08.0