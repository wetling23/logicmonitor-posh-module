Function Remove-LogicMonitorDashboardGroup {
    <#
        .DESCRIPTION
            Accepts a dashboard group ID, or name and deletes the object in LogicMonitor.
        .NOTES
            Author: Mike Hashemi
            V2023.05.23.0
            V2023.08.23.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Id
            Represents the dashboard ID of a desired dashboard.
        .PARAMETER Name
            Represents the dashboard name of a desired dashboard.
        .PARAMETER AllowNonEmptyGroup
            When included, the cmdlet will delete the requested dashboard group(s) and any sub-groups/dashboards contained within.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorDashboardGroup -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 45 -Verbose

            Deletes the dashboard group with Id 45 if it is empty. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorDashboardGroup -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Name "10.0.0.1"

            Deletes the dashboard with name 10.0.0.1. If more than one dashboard is returned, the function will exit.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorDashboardGroup -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DisplayName "server1.domain.local"

            Deletes the dashboard with display name "server1.domain.local".
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [SecureString]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'Default')]
        [Int[]]$Id,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [String]$Name,

        [Parameter(Mandatory, ParameterSetName = 'StringFilter')]
        [String]$Filter,

        [Switch]$AllowNonEmptyGroup,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    #region Initialize variables
    $httpVerb = 'DELETE'
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    If ($AllowNonEmptyGroup) {
        $queryParams = '?allowNonEmptyGroup=true'
    } Else { $queryParams = $null }

    $commandParams = @{
        AccountName = $AccountName
        AccessId    = $AccessId
        AccessKey   = $AccessKey
    }
    #endregion Initialize variables

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

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    #endregion Setup

    # Update $resourcePath to filter for a specific dashboard, when a dashboard ID, name, or displayName is provided by the user.
    If ($PsCmdlet.ParameterSetName -eq "NameFilter") {
        $message = ("{0}: Attempting to retrieve the ID of dashboard group, '{1}'." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Name)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        $dashboardGroup = Get-LogicMonitorDashboardGroup @commandParams -Name $Name @loggingParams

        If ($dashboardGroup.id) {
            [Int[]]$Id = $dashboardGroup.id
            $message = ("{0}: Retrieved {1} dashboard group(s)." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Id.Count)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
        }
        Else {
            $message = ("{0}: No dashboard group was returned when searching for {1}. To prevent errors, {2} will exit." `
                    -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Name, $MyInvocation.MyCommand)
            Out-PsLogging @loggingParams -MessageType Error -Message $message

            Return "Error"
        }
    } ElseIf ($PsCmdlet.ParameterSetName -eq "StringFilter") {
        $message = ("{0}: Attempting to retrieve the ID(s) of dashboard groups matching the filter, '{1}'." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $($Filter -replace 'filter='))
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        $dashboardGroup = Get-LogicMonitorDashboardGroup @commandParams -Filter $Filter @loggingParams

        If ($dashboardGroup.id) {
            [Int[]]$Id = $dashboardGroup.id
            $message = ("{0}: Retrieved {1} dashboard group(s)." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Id.Count)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
        } Else {
            $message = ("{0}: No dashboard group was returned when searching for {1}. To prevent errors, {2} will exit." `
                    -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Name, $MyInvocation.MyCommand)
            Out-PsLogging @loggingParams -MessageType Error -Message $message

            Return "Error"
        }
    }

    Foreach ($dashboardGroup in $Id) {
        $resourcePath = "/dashboard/groups/$dashboardGroup"

        #region Auth and headers
        # Get current time in milliseconds.
        $epoch = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End (Get-Date).ToUniversalTime()).TotalMilliseconds)
        $requestVars = $httpVerb + $epoch + $resourcePath
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

        # Construct the query URL.
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

        $message = ("{0}: Connecting to: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $url)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        $stopLoop = $false
        Do {
            Try {
                $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop

                $stopLoop = $True
            } Catch {
                If ($_.Exception.Message -match '429') {
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                    Out-PsLogging @loggingParams -MessageType Warning -Message $message

                    Start-Sleep -Seconds 60
                } Else {
                    $message = ("{0}: Unexpected error deleting the dashboard group. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
                Error message: {2}`r
                Error code: {3}`r
                Invoke-Request: {4}`r
                Headers: {5}`r
                Body: {6}" -f
                ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage),
                ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
                    )
                    Out-PsLogging @loggingParams -MessageType Error -Message $message

                    Return "Error"
                }
            }
        } While ($stopLoop -eq $false)

        ("{0}: Deleted:`r`n{1}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), ($response | Out-String).Trim())
    }
} #2023.08.23.0