Function Add-LogicMonitorDevice {
    <#
        .DESCRIPTION
            Adds a monitored device to LogicMonitor. Note that the name (IP or DNS name) must be unique to the collector monitoring the device
            and that the display name must be unique to LogicMonitor. Returns a success or failure string.
        .NOTES
            Author: Mike Hashemi
            V1 date: 24 January 2017
            V1.0.0.1 date: 31 January 2017
                - Added support for the hostGroupIds property.
            V1.0.0.2 date: 31 January 2017
                - Updated error output color.
                - Streamlined header creation (slightly).
            V1.0.0.3 date: 31 January 2017
                - Added $logPath output to host.
            V1.0.0.4 date: 31 January 2017
                - Added additional logging.
            V1.0.0.5 date: 2 February 2017
                - Updated logging.
                - Added support for multiple host group IDs.
                - Added support for the device description field.
            V1.0.0.6 date: 2 February 2017
                - Updated logging.
            V1.0.0.7 date: 10 February 2017
                - Updated procedure order.
            V1.0.0.8 date: 3 May 2017
                - Removed code from writing to file and added Event Log support.
                - Updated code for verbose logging.
                - Changed Add-EventLogSource failure behavior to just block logging (instead of quitting the function).
            V1.0.0.9 date: 21 June 2017
                - Updated logging to reduce chatter.
            V1.0.0.10 date: 19 July 2017
                - Updated handing the $data variable.
            V1.0.0.11 date: 23 April 2018
                - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
                - Replaced ! with -NOT.
            V1.0.0.12 date: 13 March 2019
                - Updated whitespace.
            V1.0.1.0 date: 15 August 2019
            V1.0.1.1 date: 23 August 2019
            V1.0.1.2 date: 26 August 2019
            V1.0.1.3 date: 18 October 2019
            V1.0.1.4 date: 4 December 2019
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER DeviceDisplayName
            Mandatory parameter. Represents the display name of the device to be monitored. This name must be unique in your LogicMonitor account.
        .PARAMETER DeviceName
            Mandatory parameter. Represents the IP address or DNS name of the device to be monitored. This IP/name must be unique on the monitoring collector.
        .PARAMETER PreferredCollectorID
            Mandatory parameter. Represents the collector ID of the collector which will monitor the device.
        .PARAMETER HostGroupID
            Mandatory parameter. Represents the ID number of the group, into which the monitored device will be placed.
        .PARAMETER Description
            Represents the device description.
        .PARAMETER PropertyNames
            Mandatory parameter. Represents the name(s) of the target property. Note that LogicMonitor properties are case sensitive.
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> $table = @{
                        name = '10.1.1.2'
                        displayName = 'server1'
                        preferredCollectorId = '10'
                    }
            PS C:\> Add-LogicMonitorDevice -AccessId <access Id> -AccessKey <access key> -AccountName <account name> -Properties $table -Verbose

            In this example, the function will create a new device with the following properties:
                - Name: 10.1.1.2
                - Display name: server1
                - Preferred collector ID: 10
            Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> $table = @{
                        name = '10.1.1.2'
                        displayName = 'server1'
                        preferredCollectorId = '10'
                        customProperties = @(
                            @{
                                name = 'testProperty'
                                value = 'someValue'
                            }
                        )
                    }
            PS C:\> Add-LogicMonitorDevice -AccessId <access Id> -AccessKey <access key> -AccountName <account name> -Properties $table

            In this example, the function will create a new device with the following properties:
                - Name: 10.1.1.2
                - Display name: server1
                - Preferred collector ID: 10
                - Custom property name: testProperty
                - Custom property value: someValue
            Verbose output is sent to the host.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [securestring]$AccessKey,

        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory)]
        [hashtable]$Properties,

        [string]$EventLogSource,

        [string]$LogPath
    )

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    # Initialize variables.
    $httpVerb = "POST" # Define what HTTP operation will the script run.
    $resourcePath = "/device/devices"
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    # Checking for the required properties
    If (-NOT($Properties.ContainsKey('name'))) {
        $message = ("{0}: No group name provided. Please update the provided properties and re-submit the request.")
        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

        Return "Error"
    }
    If (-NOT($Properties.ContainsKey('displayName'))) {
        $message = ("{0}: No display name provided. Please update the provided properties and re-submit the request.")
        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

        Return "Error"
    }
    If (-NOT($Properties.ContainsKey('preferredCollectorId'))) {
        $message = ("{0}: No preferred collector ID provided. Please update the provided properties and re-submit the request.")
        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

        Return "Error"
    }

    $data = ($Properties | ConvertTo-Json)

    # Construct the query URL.
    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"

    # Get current time in milliseconds
    $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

    # Concatenate Request Details
    $requestVars = $httpVerb + $epoch + $data + $resourcePath

    # Construct Signature
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes(([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey)))))
    $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
    $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
    $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

    # Construct Headers
    $headers = @{
        "Authorization" = "LMv1 $accessId`:$signature`:$epoch"
        "Content-Type"  = "application/json"
        "X-Version"     = 2
    }

    # Make Request
    $message = ("{0}: Executing the REST query ({1})." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $url)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    Try {
        $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -Body $data -ErrorAction Stop
    }
    Catch {
        If ($_.Exception.Message -match '429') {
            $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
            If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }

            Start-Sleep -Seconds 60
        }
        Else {
            $message = ("{0}: Unexpected error adding device called `"{1}`". To prevent errors, {2} will exit. If present, the following details were returned:`r`n
                Error message: {3}`r
                Error code: {4}`r
                Invoke-Request: {5}`r
                Headers: {6}`r
                Body: {7}" -f
                ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Properties.Name, $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage),
                ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
            )
            If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }
        }

        Return "Error"
    }

    $response
} #1.0.1.4