Function Get-LogicMonitorRawData {
    <#
        .DESCRIPTION
            Retrieves raw data values from via the LogicMonitor REST API, for the requested DataSource, datapoint, and duration (from the specified device).

            Note that a maximum of 500 raw data entries are returned. As of 10 March 2020, there is no way to request more than 500 entries.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 11 March 2020
                - Initial release
            V1.0.0.1 date: 12 March 2020
            V1.0.0.2 date: 23 July 2020
            V2023.04.28.0
            V2023.08.23.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            LogicMonitor REST API access Id.
        .PARAMETER AccessKey
            LogicMonitor REST API access key.
        .PARAMETER AccountName
            LogicMonitor portal account name.
        .PARAMETER Id
            Represents the LogicMonitor device ID of the desired device.
        .PARAMETER DisplayName
            Represents the display name of the desired device.
        .PARAMETER DataSourceName
            Represents the name (not display name) of the desired DataSource.
        .PARAMETER DataPointName
            Represents the name of the desired datapoint. When included, the cmdlet will return raw data only for this datapoint. When not included, data from all datapoints will be returned. The maximum number of lines is 500 lines.
        .PARAMETER Range
            Represents the time range, for which the command will query the API.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorRawData -AccessId <access Id> -AccessKey <access key> -AccountName company -Id 234 -DataSourceName Winif- -Range Yesterday -LogFile C:\temp\log.log

            In this example, the command connects to the API and returns the raw data for all instances of Winif- from yesterday. Limited logging is sent to C:\temp\log.log.
        .EXAMPLE
            PS C:\> Get-LogicMonitorRawData -AccessId <access Id> -AccessKey <access key> -AccountName company -Id 234 -DataSourceName wincpu -Range All -Verbose

            In this example, the command connects to the API and returns the raw data for all instances of wincpu (up to 500 lines). Verbose logging is sent to the console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [SecureString]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'IdFilter')]
        [Int64]$Id,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [String]$DisplayName,

        [Parameter(Mandatory)]
        [String]$DataSourceName,

        [String]$DataPointName,

        [Parameter(Mandatory)]
        [ValidateSet('Yesterday', 'Last24', 'Last7', 'Last30', 'All')]
        [String]$Range,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    #region Initialize variables
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $resourcePath = "/device/devices"
    $queryParams = $null
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

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

    Switch ($PsCmdlet.ParameterSetName) {
        "IdFilter" {
            $device = Get-LogicMonitorDevice @commandParams -Id $Id
        }
        "NameFilter" {
            $device = Get-LogicMonitorDevice @commandParams -Name $DisplayName
        }
    }

    If ($device.id) {
        $message = ("{0}: Found a device matching ID {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $device.id)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        $resourcePath += "/$($device.Id)/instances"

        $message = ("{0}: Updated resource path to {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    }
    Else {
        $message = ("{0}: Unable to identify the desired device in LogicMonitor. To prevent errors, {1} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
        Out-PsLogging @loggingParams -MessageType Error -Message $message

        Return "Error"
    }

    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"
    $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

    # Concatenate Request Details
    $requestVars = $httpVerb + $epoch + $resourcePath

    # Construct Signature
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
    $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
    $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
    $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

    # Create the web client object and add headers.
    $headers = @{
        "Authorization" = "LMv1 $AccessId`:$signature`:$epoch"
        "Content-Type"  = "application/json"
        "X-Version"     = 3
    }

    $message = ("{0}: Attempting to get the list of DataSources on {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Id)
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

    Try {
        $appliedDataSources = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop
    }
    Catch {
        If ($_.Exception.Message -match '429') {
            $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
            Out-PsLogging @loggingParams -MessageType Warning -Message $message

            Start-Sleep -Seconds 60
        }
        Else {
            $message = ("{0}: Unexpected error getting applied DataSources. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
                Error message: {2}`r
                Error code: {3}`r
                Invoke-Request: {4}`r
                Headers: {5}`r
                Body: {6}" -f
                [datetime]::Now, $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage),
                ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
            )
            Out-PsLogging @loggingParams -MessageType Error -Message $message

            Return "Error"
        }
    }

    If (-NOT($appliedDataSources) -or $appliedDataSources -eq "Error") {
        $message = ("{0}: No Datasources were returned for {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $device.displayName)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        Return "Error"
    }

    $message = ("{0}: Filtering for monitored instances of {1} on {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $DataSourceName, $device.displayName)
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

    $instances = $appliedDataSources.items | Where-Object { ($_.name -match $DataSourceName) -and ($_.stopMonitoring -eq $false) }

    $instances | ForEach-Object {
        $instance = $_
        If ($instance.displayName) { $out = $instance.displayName } Else { $out = $DataSourceName } # Not every DS has instances. In that case, just use the DS name for the instance name later on.

        $message = ("{0}: Attempting to get value data for the `"{1}`" instance." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $out)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        $message = ("{0}: Calculating the start and end dates for {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Range)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        # Math, so we can get values for the correct time range. Using "TotalSeconds" because that is what the LM API requires, even though the datapoint time stamps use TotalMilliseconds.
        Switch ($Range) {
            { $_ -eq 'Yesterday' } {
                $start = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end ([DateTime]::Today.AddDays(-2).AddHours(00))).TotalSeconds)
                $end = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end ([DateTime]::Today.AddDays(-1).AddHours(23).AddMinutes(59).AddSeconds(59))).TotalSeconds)
            }
            { $_ -eq 'Last24Hour' } {
                $start = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end ([DateTime]::Now.AddDays(-1))).TotalSeconds)
                $end = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end ([DateTime]::Now)).TotalSeconds)
            }
            { $_ -eq 'Last7Day' } {
                $start = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end ([DateTime]::Now.AddDays(-7))).TotalSeconds)
                $end = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end ([DateTime]::Now)).TotalSeconds)
            }
            { $_ -eq 'Last30Day' } {
                $start = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end ([DateTime]::Now.AddDays(-1))).TotalSeconds)
                $end = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end ([DateTime]::Now)).TotalSeconds)
            }
            { $_ -eq 'All' } {
                $start = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end ([DateTime]::Now.AddDays(-365))).TotalSeconds)
                $end = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end ([DateTime]::Now)).TotalSeconds)
            }
        }

        $message = ("{0}: The range is from {1} ({2}) to {3} ({4}) in {5}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $start, `
            ([datetime]'1/1/1970').AddSeconds($start), $end, `
            ([datetime]'1/1/1970').AddSeconds($end), $([System.TimeZoneInfo]::FindSystemTimeZoneById((Get-WmiObject -Class win32_timezone).StandardName)).Id)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        # This is where we start getting datapoint values
        $queryParams = "?start=$start&end=$end&size=1000"
        $resourcePath = "/device/devices/$($device.id)/devicedatasources/$($instance.deviceDataSourceId)/instances/$($instance.id)/data"
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"
        $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

        # Concatenate Request Details
        $requestVars = $httpVerb + $epoch + $resourcePath

        # Construct Signature
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
        $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
        $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
        $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

        # Create the web client object and add headers.
        $headers = @{
            "Authorization" = "LMv1 $AccessId`:$signature`:$epoch"
            "Content-Type"  = "application/json"
            "X-Version"     = 3
        }

        $message = ("{0}: Attempting to query for datapoints." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        Try {
            [array]$datapoints = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop
        }
        Catch {
            $message = ("{0}: Unexpected error getting datapoints. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
                Error message: {2}`r
                Error code: {3}`r
                Invoke-Request: {4}`r
                Headers: {5}`r
                Body: {6}" -f
                [datetime]::Now, $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage),
                ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
            )
            Out-PsLogging @loggingParams -MessageType Error -Message $message

            Return "Error"
        }

        $message = ("{0}: There were {1} datapoint values returned." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $datapoints.values.Count)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        If ($DataPointName) {
            $message = ("{0}: Filtering out data from the unwanted datapoints (keeping data for {1})." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $DataPointName)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $index = [array]::indexOf($datapoints.datapoints, $DataPointName)

            # The time stamp is in the time zone of the device that ran the query.
            $valueObject = for ($i = 0; $i -lt $datapoints.values.Count; $i++) {
                [pscustomobject]@{
                    $DataPointName = $datapoints.values[$i][$index]
                    time           = ([datetime]'1/1/1970').AddMilliSeconds($datapoints.time[$i])
                    datasourceName = $DataSourceName
                    instanceName   = $out
                    device         = $device.displayName
                }
            }
        }
        Else {
            # Grab the data point names.
            $dpNames = $datapoints.dataPoints

            $valueObject = for ($i = 0; $i -lt $datapoints.values.Count; $i++) {
                # Grab data at index $i, split data points into N strings
                $collectionValues = -split $datapoints.values[$i]
                $time = $datapoints.time[$i]

                # Create a hashtable to hold the properties
                $properties = [ordered]@{ }

                for ($n = 0; $n -lt $dpNames.Count; $n++) {
                    # Grab data point N and associated with data point name N
                    $properties[$dpNames[$n]] = $collectionValues[$n]
                }

                # Add values to hashtable, not in the data from LM.
                $properties['time'] = ([datetime]'1/1/1970').AddMilliSeconds($time)
                $properties['datasourceName'] = $DataSourceName
                $properties['instanceName'] = $out
                $properties['device'] = $device.displayName

                # Output object.
                [pscustomobject]$properties
            }
        }

        $valueObject
    }
} #2023.08.23.0