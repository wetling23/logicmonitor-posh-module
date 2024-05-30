Function Get-LogicMonitorAlert {
    <#
        .DESCRIPTION
            Retrieves Alert objects from LogicMonitor.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 16 January 2017
                - Initial release.
            V2022.10.24.0
            V2022.11.01.0
            V2022.11.03.0
            V2022.11.03.1
            V2022.11.03.2
            V2023.05.22.0
            V2023.06.10.0
            V2023.08.27.0
            V2024.05.30.0
            V2024.05.30.1
            V2024.05.30.2
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Cleared
            Represents the desired clear state.
        .PARAMETER All
            When included, the cmdlet will get all alerts started in the past one hour (minus any filtered out by -Cleared).
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
            PS C:\> Get-LogicMonitorAlert -AccessID $accessId -AccessKey $accessKey -AccountName <account name> -Verbose

            In this example, the cmdlet will get all alerts (up to the maximum), as far back as five years (or the maximum data-retention limit).
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID $accessId -AccessKey $accessKey -AccountName <account name> -StartDate (Get-Date -Month 1 -Day 1) -Verbose

            In this example, the cmdlet will get all alerts beginning after the start of the current month.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID $accessId -AccessKey $accessKey -AccountName <account name> -EndDate (Get-Date).AddHours(-1) -Verbose

            In this example, the cmdlet will get all alerts that ended before one hour ago.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID $accessId -AccessKey $accessKey -AccountName <account name> -Filter 'severity<"3",sdted:"false",cleared:"",startEpoch<:"1667495125"' -Verbose

            In this example, the cmdlet will get all open alerts, which started before November 3, 2022 5:05:25 PM (GMT) and that are a higher severity than "3" and are not in SDT.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID $accessId -AccessKey $accessKey -AccountName <account name> -Filter 'filter=severity:2,cleared:"false"' -Verbose

            In this example, the cmdlet will get all open alerts with severity "2", as far bas as five years (or the maximum data-retention limit).
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID $accessId -AccessKey $accessKey -AccountName <account name> -Filter 'severity<"3",sdted:"false",cleared:"false",startEpoch>:"1667494500",startEpoch<:"1667495125"' -Verbose

            In this example, the cmdlet will get all open alerts that began between November 3, 2022 4:55:00 PM (GMT) and November 3, 2022 5:05:25 PM (GMT).
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID $accessId -AccessKey $accessKey -AccountName <account name> -Filter ('filter=type:"websiteAlert",cleared:"false",startEpoch>:"{0}"' -f $(([DateTimeOffset](Get-Date).AddMinutes(-90)).ToUnixTimeSeconds())) -Verbose

            In this example, the cmdlet will get all open website alerts, that started before 90 minutes ago.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName <account name> -Cleared All -Verbose

            In this example, the cmdlet will get all alerts (up to the maximum), as far back as five years (or the maximum data-retention limit).
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName <account name> -Cleared No -Verbose

            In this example, the cmdlet will get all alerts (up to the maximum), as far back as five years (or the maximum data-retention limit).
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName <account name> -Filter "startEpoch>:$((Get-Date).AddHours(-1))"

            In this example, the cmdlet will get
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName <account name> -Filter "endEpoch:>$((Get-Date).AddDays(-10)),type:`"dataSourceAlert`""

            In this example, the cmdlet will get all DataSource alerts that have cleared in the past 10 days. Limited logging will be send only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName <account name> -Filter "startEpoch>:$((Get-Date -Month 1 -Day 1)),sdted:`"true`""

            In this example, the cmdlet will get all alerts currently in SDT that also started in the past 1 month, 1 day. Limited logging will be send only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName <account name> -Filter "startEpoch>:$((Get-Date).AddDays(-1)),severity<:`"2`""

            In this example, the cmdlet will get all alerts that started in the past one day, that are also at least warning severity (2 == warning, 3 == error, 4 == error). Limited logging will be send only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName <account name> -Filter "severity<`"3`",sdted:`"false`""

            In this example, the cmdlet will get all alerts with severity greater than error (2 == warning, 3 == error, 4 == error) and that are also currently in SDT. Limited logging will be send only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName <account name> -Filter "dataPointName:`"IdleMinutes`""

            In this example, the cmdlet will get all alerts for the datapoint called "IdleMinutes". Limited logging will be send only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName <account name> -Filter "id:`"DS10742262`""

            In this example, the cmdlet will get all alerts for ID DS10742262. Limited logging will be send only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName <account name> -Filter "monitorObjectName:`"server1`""

            In this example, the cmdlet will get all alserts for the monitored object called "server1". Limited logging will be send only to the host.
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllAlerts')]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [SecureString]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(ParameterSetName = 'AllAlerts')]
        [ValidateSet('All', 'Yes', 'No')]
        [String]$Cleared = 'All',

        [Parameter(ParameterSetName = 'AllAlerts')]
        [Switch]$All,

        [Parameter(ParameterSetName = 'Filter')]
        [String]$Filter,

        [Int]$BatchSize = 1000,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    #region Initilize variables
    $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $resourcePath = "/alert/alerts" # Define the resourcePath.
    $alerts = [System.Collections.Generic.List[PSObject]]::new() # Create a collection to hold the alerts.
    $filterList = [System.Collections.Generic.List[PSObject]]::new()
    $response = $null
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    #endregion Initilize variables

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

    $message = ("{0}: Beginning {1}." -f ([DateTime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand); If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

    $message = ("{0}: Operating in the {1} parameter set." -f ([DateTime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $PsCmdlet.ParameterSetName); If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    #endregion Setup

    If ($PsCmdlet.ParameterSetName -eq 'AllAlerts') {
        $message = ("{0}: Preparing to look for alerts between {1} and {2} (local time)." -f ([DateTime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), (Get-Date).AddYears(-5), (Get-Date)); If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        $filterList.Add("startEpoch>:`"$(([DateTimeOffset](Get-Date).AddYears(-1)).ToUnixTimeSeconds())`"")
        $filterList.Add("startEpoch<:`"$(([DateTimeOffset](Get-Date)).ToUnixTimeSeconds())`"")

        Switch ($Cleared) {
            'All' {
                $filterList.Add('cleared:"*"')
            }
            'Yes' {
                $filterList.Add("cleared:true")
            }
            'No' {
                $filterList.Remove($($filterList | Where-Object { $_ -match 'endEpoch.*' }))
                $filterList.Add("cleared:`"`"")
                $filterList.Add("startEpoch<:`"{0}`"" -f ([DateTimeOffset](Get-Date)).ToUnixTimeSeconds()) # Replacing endDate, because it will be 0 for open alerts
            }
        }
    }

    #region Validate comparison operators
    If (($filterList) -and ($filterList -match ':<')) {
        $toReplace = $filterList -match ':<'
        $null = $filterList.Remove($toReplace)

        $filterList.Add($($toReplace -replace ':<', '<:'))

        $message = ("{0}: The filter contains an invalid comparison operator, `":<`". Replaced the invalid value with `"<:`"." -f ([DateTime]::Now).ToString("yyyy-MM-dd`THH:mm:ss")); Out-PsLogging @loggingParams -MessageType Warning -Message $message
    }
    #endregion Validate comparison operators

    $message = ("{0}: Initial filter: {1}." -f ([DateTime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $(If ($filterList) { ($filterList -join ',') } Else { (($Filter.TrimStart(',')) -replace "^filter=") })); If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

    #region Set filter into encoded string
    If ($filterList) {
        $filterString = $filterList -join ','
    } ElseIf ($Filter) {
        # If the filter includes cleared:false or cleared:"false", make sure to remove "endEpoch" and its value.
        $filterString = [System.Net.WebUtility]::UrlEncode($(If ($Filter -match '(cleared:"false"|cleared:false|cleared:"")') { ((($Filter -replace 'startEpoch') -replace ',,', ',') -replace '(cleared:["]false["]|cleared:false)', 'cleared:""').TrimEnd(',').TrimStart(',') -replace "^filter=" } Else { $Filter.TrimStart(',') -replace "^filter=" }))
    }

    $message = ("{0}: Encoded filter: {1}." -f ([DateTime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $filterString); If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    #endregion Set filter into encoded string

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

    #region Get alerts
    $stopLoop = $false
    Do {
        $params = @{
            Method      = $httpVerb
            ErrorAction = 'Stop'
            Header      = $headers
            Uri         = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$(If ($filterString) { "?filter=$filterString&offset=$offset&size=$BatchSize&sort=startEpoch" } Else { "?offset=$offset&size=$BatchSize&sort=startEpoch" })"
        }

        $message = ("{0}: Connecting to: {1}." -f ([DateTime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $params.Uri); If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        Try {
            $response = Invoke-RestMethod @params

            $stopLoop = $true
        } Catch {
            If ($_.Exception.Message -match '429') {
                $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([DateTime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message); Out-PsLogging @loggingParams -MessageType Warning -Message $message

                Start-Sleep -Seconds 60
            } Else {
                $message = ("{0}: Unexpected error getting alerts. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
                Error message: {2}`r
                Error code: {3}`r
                Invoke-Request: {4}`r
                Headers: {5}`r
                Body: {6}" -f
                ([DateTime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $(Try { ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage) } Catch { '' }),
                    $(Try { ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode) } Catch { '' }), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
                ); Out-PsLogging @loggingParams -MessageType Error -Message $message

                Return "Error"
            }
        }

        If ($response) {
            Foreach ($item in $response.items) { $alerts.Add($item) }

            $message = ("{0}: Retrieved {1} items so far." -f ([DateTime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $alerts.id.Count); If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
        }

        If (($response.total -match '-') -or ($response.total -gt $alerts.id.Count)) {
            $offset += $BatchSize
            $stopLoop = $false
        } ElseIf ($response.total -eq 0) {
            $message = ("{0}: Zero alerts returned." -f ([DateTime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $alerts.id.Count); If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
        } Else {
            $message = ("{0}: No further alerts to retrieve." -f ([DateTime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $alerts.id.Count); If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
        }
    } Until (($stopLoop -eq $true) -or ($response.total -eq $alerts.id.Count))
    #endregion Get alerts

    #region Output
    $message = ("{0}: Returning {1} alerts." -f ([DateTime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $alerts.id.Count); If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

    Return $alerts
    #endregion Output
} #2024.05.30.0