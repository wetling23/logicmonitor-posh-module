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
        .LINK
            
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
            Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .PARAMETER LogPath
            Path where the function should store its log. When omitted, output will be sent to the shell.
        .EXAMPLE
            PS C:\> Add-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceDisplayName device1 -DeviceName 10.0.0.0 -PreferredCollectorID 459 -HostGroupID 379 -PropertyNames location -PropertyValues Denver

            In this example, the function will create a new device with the following properties:
                - IP: 10.0.0.0
                - Display name: device1
                - Preferred collector: 459
                - Host group: 379
                - Location: Denver
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        $AccessId,
        
        [Parameter(Mandatory = $True)]
        $AccessKey,

        [Parameter(Mandatory = $True)]
        $AccountName,

        [Parameter(Mandatory = $True)]
        [string]$DeviceDisplayName,

        [Parameter(Mandatory = $True)]
        [string]$DeviceName,

        [Parameter(Mandatory = $True)]
        [int]$PreferredCollectorID,

        [Parameter(Mandatory = $True)]
        [string]$HostGroupID,

        [string]$Description,

        [string[]]$PropertyNames,

        [string[]]$PropertyValues,

        [string]$EventLogSource = 'LogicMonitorPowershellModule',

        [switch]$BlockLogging
    )

    If (-NOT($BlockLogging)) {
        $return = Add-EventLogSource -EventLogSource $EventLogSource

        If ($return -ne "Success") {
            $message = ("{0}: Unable to add event source ({1}). No logging will be performed." -f (Get-Date -Format s), $EventLogSource)
            Write-Host $message -ForegroundColor Yellow;

            $BlockLogging = $True
        }
    }

    $message = ("{0}: Beginning {1}." -f (Get-Date -Format s), $MyInvocation.MyCommand)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

    # Initialize variables.
    [int]$index = 0
    $propertyData = ""
    $data = ""
    $httpVerb = "POST" # Define what HTTP operation will the script run.
    $resourcePath = "/device/devices"
    $requiredProperties = "`"name`":`"$DeviceName`",`"displayName`":`"$DeviceDisplayName`",`"preferredCollectorId`":$PreferredCollectorID,`"hostGroupIds`":`"$HostGroupID`""
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    If ($Description) {
        $message = ("{0}: Appending `"description`" to the list of properties." -f (Get-Date -Format s))
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

        $requiredProperties += ",`"description`":`"$Description`""
    }

    # For each property, assign the name and value to $propertyData...
    Foreach ($property in $PropertyNames) {    
        $message = ("{0}: Updating/adding property: {1} with a value of {2}." -f (Get-Date -Format s), $property, $($PropertyValues[$index]))
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

        $propertyData += "{`"name`":`"$property`",`"value`":`"$($PropertyValues[$index])`"},"
        $index++
    }

    #...trim the trailing comma...
    $propertyData = $propertyData.TrimEnd(",")

    #...and assign the entire string to the $data variable.
    If ($propertyData) {
        $data = "{$requiredProperties,`"customProperties`":[$propertyData]}"
    }
    Else {
        $data = "{$requiredProperties}"
    }

    $message = ("{0}: The value of `$data, is: {1}." -f (Get-Date -Format s), $data)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

    # Construct the query URL.
    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"

    # Get current time in milliseconds
    $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

    # Concatenate Request Details
    $requestVars = $httpVerb + $epoch + $data + $resourcePath

    # Construct Signature
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($accessKey)
    $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
    $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
    $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

    # Construct Headers
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "LMv1 $accessId`:$signature`:$epoch")
    $headers.Add("Content-Type", 'application/json')

    # Make Request
    $message = ("{0}: Executing the REST query ({1})." -f (Get-Date -Format s), $url)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

    Try {
        $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -Body $data -ErrorAction Stop
    }
    Catch {
        $message = ("{0}: It appears that the web request failed. Check your credentials and try again. To prevent errors, the Add-LogicMonitorDevice function will exit. The specific error message is: {1}" -f (Get-Date -Format s), $_.Message.Exception)
        If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417}
        write-host "response: $response"
        Return "Failure"
    }

    Switch ($response.status) {
        "200" {
            $message = ("{0}: Successfully added the device in LogicMonitor." -f (Get-Date -Format s))
            If ($BlockLogging) {Write-Host $message -ForegroundColor White} Else {Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

            Return "Success"
        }
        "600" {
            $message = ("{0}: LogicMonitor reported that there is a duplicate device. Verify that the device you are adding has an IP (or DNS) name unique to the preferred collector and a display name unique to LogicMonitor. The specific message was: {1}" `
                    -f (Get-Date -Format s), $response.errmsg)
            If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417}

            Return "Failure (600)"
        }
        Default {
            $message = ("{0}: Unexpected error creating a new device in LogicMonitor. To prevent errors, the Add-LogicMonitorDevice function will exit. The status was: {1} and the error was: `"{2}`"" `
                    -f (Get-Date -Format s), $response.status, $response.errmsg)
            If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417}

            Return "Failure"
        }
    }
}
#1.0.0.12