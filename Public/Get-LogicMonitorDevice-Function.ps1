﻿Function Get-LogicMonitorDevice {
    <#
        .DESCRIPTION
            Returns a list of LogicMonitor-monitored devices and all of their properties. By default, the function returns all devices. 
            If a device ID, device name (IP or DNS name), or device display name is provided, the function will return properties for 
            the specified device.
        .NOTES
            Author: Mike Hashemi
            V1 date: 21 November 2016
            V1.0.0.17 date: 23 August 2019
            V1.0.0.18 date: 26 August 2019
            V1.0.0.19 date: 18 October 2019
            V1.0.0.20 date: 4 December 2019
            V1.0.0.21 date: 10 December 2019
            V1.0.0.22 date: 23 July 2020
            V1.0.0.23 date: 1 September 2020
            V1.0.0.24 date: 2 September 2020
            V1.0.0.25 date: 25 November 2020
            V1.0.1.26 date: 1 December 2020
            V1.0.0.27 date: 30 July 2021
            V2022.03.18.0
            V2022.03.18.1
            V2023.02.27.0
            V2023.06.05.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Id
            Represents deviceId of the desired device.
        .PARAMETER DisplayName
            Represents display name of the desired device.
        .PARAMETER Name
            Represents IP address or FQDN of the desired device.
        .PARAMETER Filter
            Represents a string matching the API's filter format. This parameter can be used to filter for devices matching certain criteria (e.g. "Microsoft Windows Server 2012 R2 Standard" appears in systemProperties).

            See https://www.logicmonitor.com/support/rest-api-developers-guide/v1/devices/get-devices#Example-Request-5--GET-all-devices-that-have-a-spe
        .PARAMETER BatchSize
            Default value is 1000. Represents the number of devices to request from LogicMonitor, in a single batch.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Verbose

            In this example, the function will search for all monitored devices and will return their properties. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6

            In this example, the function will search for the monitored device with "6" in the ID property and will return its properties.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DisplayName server1

            In this example, the function will search for the monitored device with "server1" in the displayName property and will return its properties.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Name 10.1.1.1

            In this example, the function will search for the monitored device with "10.1.1.1" in the name property and will return its properties.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Name server1.domain.local

            In this example, the function will search for the monitored device with "server1.domain.local" (the FQDN) in the name property and will return its properties.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Filter 'filter=systemProperties.value:"Microsoft Windows Server 2012 R2 Standard"'

            In this example, the function will search for monitored devices with "Microsoft Windows Server 2012 R2 Standard" as a value in one of the system properties. Other valid property lists include customProperties and inheritedPropreties.
            Note that the quotes around the value are required.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Filter 'filter=hostGroupIds~12345'

            In this example, the function will search for monitored devices with "12345" in the list of host-group IDs. Note that the quotes around the value are required.
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllDevices')]
    [alias('Get-LogicMonitorDevices')]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [SecureString]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'IDFilter')]
        [Alias("DeviceId")]
        [Int]$Id,

        [Parameter(Mandatory, ParameterSetName = 'DisplayNameFilter')]
        [Alias("DeviceDisplayName")]
        [string]$DisplayName,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [Alias("DeviceName")]
        [String]$Name,

        [Parameter(Mandatory, ParameterSetName = 'StringFilter')]
        [String]$Filter,

        [Int]$BatchSize = 1000,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    #region Initialize variables
    $devices = [System.Collections.Generic.List[PSObject]]::New() # Primary collection to be filled with Invoke-RestMethod response.
    $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $resourcePath = "/device/devices" # Define the resourcePath, based on the type of query you are doing.
    $queryParams = $null
    $pattern1 = '[^a-zA-Z\d\s]' # Match any non-alpha numeric or white space character.
    $pattern2 = '(?:>:|<:|:|>|<|!:|:|~|!~|@)(?:")(.*?)(?:")' # Allow us to replace characters in the filter. We will leave some of the characters alone, since they are used by the API in certain spots. For example, ":" means equal between the property name and value but should be replaced in the value portion of the pair.
    $regex = [Regex]::new($pattern2)
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
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

    $message = ("{0}: Operating in the {1} parameter set." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $PsCmdlet.ParameterSetName)
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    #endregion Setup

    #region Update filter/resourcePath
    Switch ($PsCmdlet.ParameterSetName) {
        "StringFilter" {
            $message = ("{0}: URL encoding special characters in the filter." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $Filter = [regex]::Replace(
                $Filter,
                '(?<=[:|><~]").*?(?=")',
                {
                    param($m)
                    [Uri]::EscapeDataString($m.Value)
                }
            )

            $message = ("{0}: After parsing, the filter is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Filter)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
        }
        "IDFilter" {
            # Update $resourcePath to filter for a specific device, when a device ID is provided by the user.
            $resourcePath += "/$Id"

            $message = ("{0}: Updated resource path to {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
        }
    }
    #endregion Update filter/resourcePath

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

    #region Execute REST query
    Do {
        Switch ($PsCmdlet.ParameterSetName) {
            "StringFilter" {
                $queryParams = "?$Filter&offset=$offset&size=$BatchSize&sort=id"
            }
            "DisplayNameFilter" {
                $queryParams = "?filter=displayName:`"$DisplayName`"&offset=$offset&size=$BatchSize&sort=id"
            }
            "NameFilter" {
                $queryParams = "?filter=name:`"$Name`"&offset=$offset&size=$BatchSize&sort=id"
            }
            "AllDevices" {
                $queryParams = "?offset=$offset&size=$BatchSize&sort=id"
            }
        }

        $message = ("{0}: Updated `$queryParams variable in {1}. The value is {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $($PsCmdlet.ParameterSetName), $queryParams)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

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
                } ElseIf ($_.ErrorDetails -match 'invalid filter') {
                    $message = ("{0}: LogicMonitor returned `"invalid filter`". Please validate the value of the -Filter parameter and try again." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                    Out-PsLogging @loggingParams -MessageType Error -Message $message

                    Return "Error"
                } Else {
                    $message = ("{0}: Unexpected error getting devices. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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

        If ($response.items.Count -gt 0) {
            $message = ("{0}: Retrieved {1} devices of {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $response.items.Count, $response.total)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            Foreach ($item in $response.items) {
                $devices.Add($item)
            }

            If (($response.items.Count -eq 1) -or ($response.total -and ($response.total -eq $devices.id.Count))) {
                $message = ("{0}: Retrieved all devices." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                $stopLoop = $true
            } Else {
                # Increment offset, to grab the next batch of devices.
                $message = ("{0}: Incrementing the search offset by {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $BatchSize)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                $offset += $BatchSize
                $stopLoop = $false
            }
        } ElseIf ($response.id) {
            $devices = $response
            $stopLoop = $true
        } Else {
            $message = ("{0}: The `$response variable is empty." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $stopLoop = $true
        }

        $message = ("{0}: There are {1} devices in `$devices." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $devices.id.Count)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    } Until ($stopLoop -eq $true)
    #endregion Execute REST query

    #region Output
    Return $devices
    #endregion Output
} #2023.06.05.0