Function Get-LogicMonitorAlert {
    <#
        .DESCRIPTION
            Retrieves Alert objects from LogicMonitor.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 16 January 2017
                - Initial release.
            V1.0.0.2 date: 10 February 2017
                - Updated procedure order.
            V1.0.0.3 date: 23 April 2018
                - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
                - Updated logging setup.
            V1.0.0.4 date: 14 March 2019
                - Added support for rate-limited re-try.
            V1.0.0.5 date: 10 April 2019
                - Updated filtering.
            V1.0.0.6 date: 23 August 2019
            V1.0.0.7 date: 26 August 2019
            V1.0.0.8 date: 18 October 2019
            V1.0.0.9 date: 4 December 2019
            V1.0.0.10 date: 23 July 2020
            v1.0.0.11 date: 25 September 2020
            v1.0.0.12 date: 25 October 2021
            V1.0.0.13 date: 26 October 2021
            V1.0.0.14 date: 1 November 2021
            V1.0.0.15 date: 3 November 2021
            V1.0.0.16 date: 16 August 2022
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Represents the subdomain of the LogicMonitor customer.
        .PARAMETER StartDate
            Represents the beginning of the time range, for which alerts will be retireved. If no value is provided (but an end date is provided), minus one day (-1) is used. If no start/end date is provided, up to the previous five years is used.
        .PARAMETER EndDate
            Represents the end of the time range, for which alerts will be retireved. If no value is provided (but an end date is provided), the current date is used. If no start/end date is provided, up to the previous five years is used.
        .PARAMETER All
            Depricated parameter. When included, the cmdlet returns all open alerts, up to the LogicMonitor API limit (10000 as of 10 April 2019).
        .PARAMETER Filter
            Represents a hashtable of filterable alert properties and the value, for which to filter. Valid values are:
                'id', 'type', 'acked', 'rule', 'chain', 'severity', 'cleared', 'sdted', 'monitorObjectName', 'monitorObjectGroups', 'resourceTemplateName', 'instanceName', 'dataPointName'
            Invalid keys in the hashtable are removed before the query is run.
        .PARAMETER BatchSize
            Default value is 1000. Represents the number of alerts to request from LogicMonitor.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID <access ID> -AccessKey <access key> -AccountName <account name> -BlockLogging -Verbose

            In this example, the cmdlet gets all alerts (up to the API maximum) going back as far as five years (or the maximum duration of available alerts). Verbose output is sent to the session host only.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID <access ID> -AccessKey <access key> -AccountName <account name> -Filter 'filter=severity:2,cleared:"false"' -StartDate (Get-Date -Month 1 -Day 1)

            In this example, the cmdlet gets all open alerts (up to the API maximum) at the warning threshold, beginning on January 1 and ending on the current date. Limited logging output is sent to the session host only.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID <access ID> -AccessKey <access key> -AccountName <account name> -Filter "filter=severity:2,cleared:`"false`"" -EndDate (Get-Date).AddHours(-1) -Verbose -LogPath C:\Temp\log.txt

            In this example, the cmdlet gets all open alerts (up to the API maximum) at the warning threshold, beginning one day ago and ending one hour ago. Verbose logging output is sent to the session host and C:\Temp\log.txt.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID <access ID> -AccessKey <access key> -AccountName <account name> -Filter "filter=type:`"websiteAlert`",cleared:`"false`",startEpoch>:$(([DateTimeOffset](Get-Date).AddMinutes(-90)).ToUnixTimeSeconds())"

            In this example, the cmdlet gets all open alerts (up to the API maximum), beginning on or after the 90 minutes ago. Limited logging output is sent to the session host only.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [securestring]$AccessKey,

        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Filter')]
        [datetime]$StartDate,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Filter')]
        [datetime]$EndDate,

        [Parameter(ParameterSetName = 'AllAlerts')]
        [switch]$All,

        [string]$Filter,

        [int]$BatchSize = 1000,

        [boolean]$BlockStdErr = $false,

        [string]$EventLogSource,

        [string]$LogPath
    )

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    #region Setup
    #region Initilize variables
    $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    $batchCount = 0 # Counter so we know how many times we have looped through the request.
    [boolean]$firstLoopDone = $false # Will change to true, once the function determines how many times it needs to loop, to retrieve all alerts.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $resourcePath = "/alert/alerts" # Define the resourcePath.
    $alerts = [System.Collections.Generic.List[PSObject]]::new() # Create a collection to hold the alerts.
    $response = $null
    [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    #endregion Initilize variables

    $message = ("{0}: Operating in the {1} parameter set." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $PsCmdlet.ParameterSetName)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    #region Parsing dates
    If ($Filter -and ($Filter -match 'startEpoch|endEpoch')) {
        # Nothing to do, we will use the user-provided epochs for filtering.
        $message = ("{0}: Using the start and end epochs specified in the Filter parameter." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
    }
    ElseIf (-NOT($StartDate) -and -NOT($EndDate)) {
        $message = ("{0}: No start or end epoch specified, defaulting to the past five years (or as far back as the alerts go)." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        [decimal]$StartDate = ([DateTimeOffset](Get-Date).AddYears(-5)).ToUnixTimeSeconds()
        [decimal]$EndDate = ([DateTimeOffset](Get-Date)).ToUnixTimeSeconds()
        $Filter += "startEpoch>:`"$StartDate`",endEpoch<:`"$EndDate`""
    }
    ElseIf ($StartDate -and -NOT($EndDate)) {
        $message = ("{0}: End epoch not specified, defaulting to the current time." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        [decimal]$StartDate = ([DateTimeOffset]$StartDate).ToUnixTimeSeconds()
        [decimal]$EndDate = ([DateTimeOffset](Get-Date)).ToUnixTimeSeconds()
        $Filter += "startEpoch>:`"$StartDate`",endEpoch<:`"$EndDate`""
    }
    ElseIf (-NOT($StartDate -and $EndDate)) {
        $message = ("{0}: Start epoch not specified, defaulting to the past day." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        [decimal]$StartDate = ([DateTimeOffset](Get-Date).AddDays(-1)).ToUnixTimeSeconds()
        [decimal]$EndDate = ([DateTimeOffset]$EndDate).ToUnixTimeSeconds()
        $Filter += "startEpoch>:`"$StartDate`",endEpoch<:`"$EndDate`""
    }
    ElseIf ($StartDate -and $EndDate) {
        [decimal]$StartDate = ([DateTimeOffset]$StartDate).ToUnixTimeSeconds()
        [decimal]$EndDate = ([DateTimeOffset]$EndDate).ToUnixTimeSeconds()
        $Filter += "startEpoch>:`"$StartDate`",endEpoch<:`"$EndDate`""
    }
    ElseIf ($PsCmdlet.ParameterSetName -eq "AllAlerts") {
        $message = ("{0}: Attempting to get as many alerts as possible." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        # Same action as "no date" but left here for backwards compatibility. Defaulting to all alerts in the last five years (or as far back as the alerts go).
        [decimal]$StartDate = ([DateTimeOffset](Get-Date).AddYears(-5)).ToUnixTimeSeconds()
        [decimal]$EndDate = ([DateTimeOffset](Get-Date)).ToUnixTimeSeconds()
        $Filter += "startEpoch>:`"$StartDate`",endEpoch<:`"$EndDate`""
    }

    If ($StartDate -or $EndDate) {
        $message = ("{0}: Start date: {1} and end date: {2}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $StartDate, $EndDate)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
    }
    #endregion Parsing dates

    If ($Filter) {
        $message = ("{0}: Converting special characters to URL encoding." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        Switch ($Filter) {
            { $_.Contains('&') } { $Filter = $Filter.Replace('&', "%26") }
            { $_.Contains('#') } { $Filter = $Filter.Replace('#', "%23") }
            { $_.Contains(')') } { $Filter = $Filter.Replace(')', "%29") }
            { $_.Contains('(') } { $Filter = $Filter.Replace('(', "%28") }
            { $_.Contains('/') } { $Filter = $Filter.Replace('/', "%2F") }
            { $_.Contains('*') } { $Filter = $Filter.Replace('*', "%2A") }
            { $_.Contains(' ') } { $Filter = $Filter.Replace(' ', "%20") }
            { $_.Contains('|') } { $Filter = $Filter.Replace('|', "%7C") }
            { $_.Contains('$') } { $Filter = $Filter.Replace('$', "%24") }
            { $_.Contains('\') } { $Filter = $Filter.Replace('\', "%5C") }
            { $_.Contains('_') } { $Filter = $Filter.Replace('_', "%5F") }
            { $_.Contains(',') } { $Filter = $Filter.Replace(',', "%2C") }
            { $_.Contains('"') } { $Filter = $Filter.Replace('"', "%22") }
            { $_.Contains('<') } { $Filter = $Filter.Replace('<', "%3C") }
            { $_.Contains('>') } { $Filter = $Filter.Replace('>', "%3E") }
            { $_.Contains(':') } { $Filter = $Filter.Replace(':', "%3A") }

        }

        $Filter = $Filter -replace "^filter="
    }
    #endregion Setup

    #region Main
    While (($response.Count -ge 1) -or ($firstLoopDone -eq $false)) {
        $message = ("{0}: The request loop has run {1} times." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $batchCount)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $queryParams = "?filter=$Filter&sort=startEpoch&offset=$offset&size=$BatchSize"

        # Construct the query URL.
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

        # Build header.
        If ($firstLoopDone -eq $false) {
            $message = ("{0}: Building request header." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            # Get current time in milliseconds
            $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

            # Concatenate Request Details
            $requestVars = $httpVerb + $epoch + $resourcePath

            # Construct Signature
            $hmac = New-Object System.Security.Cryptography.HMACSHA256
            $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
            $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
            $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
            $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

            # Construct Headers
            $headers = @{
                "Authorization" = "LMv1 $accessId`:$signature`:$epoch"
                "Content-Type"  = "application/json"
                "X-Version"     = 2
            }
        }

        # Make the API request.
        $message = ("{0}: Executing the REST query." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $stopLoop = $false
        Do {
            Try {
                $response = [System.Collections.Generic.List[PSObject]]@((Invoke-RestMethod -Uri $url -Method $httpverb -Header $headers -ErrorAction Stop).items)

                $stopLoop = $True
            }
            Catch {
                If ($_.Exception.Message -match '429') {
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }

                    Start-Sleep -Seconds 60
                }
                Else {
                    $message = ("{0}: Unexpected error getting alerts. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
                        Error message: {2}`r
                        Error code: {3}`r
                        Invoke-Request: {4}`r
                        Headers: {5}`r
                        Body: {6}" -f
                        ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage),
                        ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
                    )
                    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                    Return "Error"
                }
            }
        }
        While ($stopLoop -eq $false)

        $alerts.AddRange($response)

        $message = ("{0}: Executed REST query. There are {1} entries in `$alerts." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $alerts.id.Count)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $offset += $BatchSize
        $firstLoopDone = $true
        $batchCount++
    }
    #endregion Main

    Return $alerts
} #1.0.0.16