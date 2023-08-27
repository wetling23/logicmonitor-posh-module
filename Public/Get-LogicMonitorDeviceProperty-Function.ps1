Function Get-LogicMonitorDeviceProperty {
    <#
        .DESCRIPTION
            Retrieves all properties (inherited and not) from a selected device.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 08 March 2017
                - Initial release.
            V1.0.0.1 date: 13 March 2017
                - Added OutputType paramater to Confirm-OutputPathAvailability call.
            V1.0.0.2 date: 3 May 2017
                - Removed code from writing to file and added Event Log support.
                - Updated code for verbose logging.
                - Changed Add-EventLogSource failure behavior to just block logging (instead of quitting the function).
            V1.0.0.3 date: 21 June 2017
                - Updated logging to reduce chatter.
            V1.0.0.4 date: 2 July 2017
                - Added $EventLogSource to Get-LogicMonitorDevices call.
            V1.0.0.5 date: 23 April 2018
                - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
                - Replaced ! with -NOT.
            V1.0.0.6 date: 14 March 2019
                - Added support for rate-limited re-try.
            V1.0.0.7 date: 18 March 2019
                - Updated alias publishing method.
            V1.0.0.8 date: 23 August 2019
            V1.0.0.9 date: 26 August 2019
            V1.0.0.10 date: 18 October 2019
            V1.0.0.11 date: 4 Denver 2019
            V1.0.0.12 date: 23 July 2020
            V2023.04.28.0
            V2023.08.24.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Id
            Represents ID of the desired device.
        .PARAMETER DisplayName
            Represents display name of the desired device.
        .PARAMETER DeviceName
            Represents IP address or FQDN of the desired device.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDeviceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Verbose

            In this example, the function will search for all monitored devices and will return their properties. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDeviceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6

            In this example, the function will search for the monitored device with "6" in the ID property and will return its properties.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDeviceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DisplayName server1

            In this example, the function will search for the monitored device with "server1" in the displayName property and will return its properties.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDeviceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceName 10.1.1.1

            In this example, the function will search for the monitored device with "10.1.1.1" in the name property and will return its properties.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDeviceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceName server1.domain.local

            In this example, the function will search for the monitored device with "server1.domain.local" (the FQDN) in the name property and will return its properties.
    #>
    [CmdletBinding(DefaultParameterSetName = 'IDFilter')]
    [alias('Get-LogicMonitorDeviceProperties')]
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

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [Alias("DeviceDisplayName")]
        [String]$DisplayName,

        [Parameter(Mandatory, ParameterSetName = 'IPFilter')]
        [Alias("DeviceName")]
        [String]$Name,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    #region Initialize variables
    $deviceProps = [System.Collections.Generic.List[PSObject]]::new() # Create a collection to hold the EventSources.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $resourcePath = "/device/devices" # Define the resourcePath, based on the type of device you're searching for.
    $queryParams = $null
    $batchSize = 1000
    $offset = 0
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
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

    $message = ("{0}: Operating in the {1} parameter set." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $PsCmdlet.ParameterSetName)
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    #endregion Setup

    # Update $resourcePath to filter for a specific device.
    Switch ($PsCmdlet.ParameterSetName) {
        "NameFilter" {
            $device = Get-LogicMonitorDevice @commandParams -DisplayName $DisplayName @loggingParams

            $id = $device.Id
        }
        "IPFilter" {
            $device = Get-LogicMonitorDevice @commandParams -Name $Name @loggingParams

            If ($device.count -gt 1) {
                $message = ("{0}: Too many devices returned when searching for {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Name)
                Out-PsLogging @loggingParams -MessageType Error -Message $message

                Return "Error"
            }
            Else {
                $id = $device.id
            }
        }
    }

    $resourcePath += "/$Id/properties"

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

    Do {
        $queryParams = "?offset=$offset&size=$batchSize&sort=id"

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
                    $message = ("{0}: Unexpected error getting device properties. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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
            $message = ("{0}: Retrieved {1} properties of {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $response.items.Count, $response.total)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            Foreach ($item in $response.items) {
                $deviceProps.Add($item)
            }

            If (($response.items.Count -eq 1) -or ($response.total -and ($response.total -eq $deviceProps.id.Count))) {
                $message = ("{0}: Retrieved all properties." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                $stopLoop = $true
            } Else {
                # Increment offset, to grab the next batch of devices.
                $message = ("{0}: Incrementing the search offset by {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $batchSize)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                $offset += $batchSize
                $stopLoop = $false
            }
        } ElseIf ($response.id) {
            $deviceProps = $response
            $stopLoop = $true
        } Else {
            $message = ("{0}: The `$response variable is empty." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $stopLoop = $true
        }

        $message = ("{0}: There are {1} properties in `$deviceProps." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $deviceProps.id.Count)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    } Until ($stopLoop -eq $true)

    Return $deviceProps
} #2023.08.24.0