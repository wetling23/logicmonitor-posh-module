Function Remove-LogicMonitorDeviceProperty {
    <#
        .DESCRIPTION
            Accepts a device ID, display name, or device IP/DNS name, and one or more property names, then deletes the property(ies).
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 2 February 2017
                - Initial release.
            V1.0.0.1 date: 10 February 2017
                - Updated procedure order.
            V1.0.0.2 date: 3 May 2017
                - Removed code from writing to file and added Event Log support.
                - Updated code for verbose logging.
                - Changed Add-EventLogSource failure behavior to just block logging (instead of quitting the function).
            V1.0.0.3 date: 21 June 2017
                - Updated logging to reduce chatter.
                - Added missing parameters to the in-line help.
            V1.0.0.4 date: 23 April 2018
                - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
                - Replaced ! with -NOT.
            V1.0.0.5 date: 14 March 2019
                - Added support for rate-limited re-try.
                - Updated whitespace.
            V1.0.0.6 date: 18 March 2019
                - Updated alias publishing method.
            V1.0.0.7 date: 23 August 2019
            V1.0.0.8 date: 26 August 2019
            V1.0.0.9 date: 18 October 2019
            V1.0.0.10 date: 4 December 2019
            V1.0.0.11 date: 11 December 2019
            V1.0.0.12 date: 23 July 2020
            V2023.05.02.0
            V2023.05.22.0
            V2023.08.23.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Represents the subdomain of the LogicMonitor customer. Default value is "synoptek".
        .PARAMETER Id
            Represents the device ID of a monitored device.
        .PARAMETER Displayname
            Represents the display name of the device to be monitored. This name must be unique in your LogicMonitor account.
        .PARAMETER Name
            Represents the IP address or DNS name of the device to be monitored. This IP/name must be unique on the monitoring collector.
        .PARAMETER PropertyName
            Mandatory parameter. Represents the name of the target property. Note that LogicMonitor properties are case sensitive.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorDeviceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 45 -PropertyName Location -Verbose

            In this example, the function will remove the Location property for the device with "45" in the ID property. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorDeviceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Name "10.0.0.1" -PropertyName Location

            In this example, the function will remove the Location property for the device with "10.0.0.1" in the name property.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorDeviceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Displayname "server1 - Customer" -PropertyName Location,AssignedTeam

            In this example, the function will remove the Location and AssignedTeam properties for the device with "server1 - Customer" in the display name property.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [Securestring]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'Default')]
        [Alias('DeviceId')]
        [Int]$Id,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [Alias('DeviceDisplayName')]
        [String]$DisplayName,

        [Parameter(Mandatory, ParameterSetName = 'IPFilter')]
        [Alias('DeviceName')]
        [String]$Name,

        [Parameter(Mandatory)]
        [Alias('PropertyNames')]
        [String[]]$PropertyName,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    #region Initialize variables
    $httpVerb = 'DELETE'
    $queryParams = $null
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
    #endregion Setup

    # For each property, append the name to the $resourcePath.
    Foreach ($property in $PropertyName) {
        # Update $resourcePath to filter for a specific device, when a device ID, name, or displayName is provided by the user.
        Switch ($PsCmdlet.ParameterSetName) {
            Default {
                $resourcePath = "/device/devices/$Id/properties"
            }
            'NameFilter' {
                $message = ("{0}: Attempting to retrieve the device ID of {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Displayname)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                If ($Id -eq $null) {
                    $device = Get-LogicMonitorDevice @commandParams -Displayname $Displayname @loggingParams
                }

                If ($device.id) {
                    $Id = $device.id
                    $resourcePath = "/device/devices/$Id/properties"
                }
                Else {
                    $message = ("{0}: No device was returned when searching for {1}. To prevent errors, {2} will exit." `
                            -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $DisplayName, $MyInvocation.MyCommand)
                    Out-PsLogging @loggingParams -MessageType Error -Message $message

                    Return "Error"
                }
            }
            'IPFilter' {
                $message = ("{0}: Attempting to retrieve the device ID of {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Name)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                If ($Id -eq $null) {
                    $device = Get-LogicMonitorDevices @commandParams -Name $Name @loggingParams
                }

                If ($device.count -gt 1) {
                    $message = ("{0}: More than one device with the name {1} were detected (specifically {2}). To prevent errors, {3} will exit." `
                            -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Name, $device.count, $MyInvocation.MyCommand)
                    Out-PsLogging @loggingParams -MessageType Error -Message $message

                    Return "Error"
                }
                ElseIf ($device.id) {
                    $Id = $device.id
                    $resourcePath = "/device/devices/$Id/properties"
                }
                Else {
                    $message = ("{0}: No device was returned when searching for {1}. To prevent errors, {2} will exit." `
                            -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Name, $MyInvocation.MyCommand)
                    Out-PsLogging @loggingParams -MessageType Error -Message $message

                    Return "Error"
                }
            }
        }

        $resourcePath += "/$property"

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
                    $message = ("{0}: Unexpected error deleting the device property. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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
    }

    Return "Success"
} #2023.08.23.0