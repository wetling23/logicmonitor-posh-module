Function Get-LogicMonitorDeviceProperties {
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
.LINK
    
.PARAMETER AccessId
    Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.    
.PARAMETER AccessKey
    Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
.PARAMETER AccountName
    Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
.PARAMETER DeviceId
    Represents deviceId of the desired device.
.PARAMETER DeviceDisplayName
    Represents display name of the desired device.
.PARAMETER DeviceName
    Represents IP address or FQDN of the desired device.
.PARAMETER EventLogSource
    Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
.PARAMETER BlockLogging
    When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
.EXAMPLE
    PS C:\> Get-LogicMonitorDevices -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName>

    In this example, the function will search for all monitored devices and will return their properties.
.EXAMPLE
    PS C:\> Get-LogicMonitorDevices -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceId 6

    In this example, the function will search for the monitored device with "6" in the ID property and will return its properties.
.EXAMPLE
    PS C:\> Get-LogicMonitorDevices -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceDisplayName server1

    In this example, the function will search for the monitored device with "server1" in the displayName property and will return its properties.
.EXAMPLE
    PS C:\> Get-LogicMonitorDevices -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceName 10.1.1.1

    In this example, the function will search for the monitored device with "10.1.1.1" in the name property and will return its properties.
.EXAMPLE
    PS C:\> Get-LogicMonitorDevices -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceName server1.domain.local

    In this example, the function will search for the monitored device with "server1.domain.local" (the FQDN) in the name property and will return its properties.
#>
    [CmdletBinding(DefaultParameterSetName = ’IDFilter’)]
    Param (
        [Parameter(Mandatory = $True)]
        $AccessId,
        [Parameter(Mandatory = $True)]
        $AccessKey,
        [Parameter(Mandatory = $True)]
        $AccountName,
        [Parameter(Mandatory = $True, ParameterSetName = ’IDFilter’)]
        [int]$DeviceId,
        [Parameter(Mandatory = $True, ParameterSetName = ’NameFilter’)]
        [string]$DeviceDisplayName,
        [Parameter(Mandatory = $True, ParameterSetName = ’IPFilter’)]
        [string]$DeviceName,
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
    If ($BlockLogging) {Write-Host $message -ForegroundColor White} Else {Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

    $message = ("{0}: Operating in the {1} parameter set." -f (Get-Date -Format s), $PsCmdlet.ParameterSetName)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

    # Initialize variables.
    $currentBatchNum = 0 # Start at zero and increment in the while loop, so we know how many times we have looped.
    $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    $deviceBatchCount = 1 # Define how many times we need to loop, to get all devices.
    $firstLoopDone = $false # Will change to true, once the function determines how many times it needs to loop, to retrieve all devices.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $props = @{} # Initialize hash table for custom object (created later).
    $resourcePath = "/device/devices" # Define the resourcePath, based on the type of device you're searching for.
    $queryParams = $null
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    $message = ("{0}: The resource path is: {1}." -f (Get-Date -Format s), $resourcePath)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

    # Update $resourcePath to filter for a specific device.
    Switch ($PsCmdlet.ParameterSetName) {
        "NameFilter" {	
            $device = Get-LogicMonitorDevices -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -DeviceDisplayName $DeviceDisplayName -EventLogSource $EventLogSource
            
            $deviceId = $device.id
        }
        "IPFilter" {
            $device = Get-LogicMonitorDevices -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -DeviceName $DeviceName -EventLogSource $EventLogSource
            
            $deviceId = $device.id
        }
    }

    $resourcePath += "/$DeviceId/properties"

    # Construct the query URL.
    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"

    $message = ("{0}: Building request header." -f (Get-Date -Format s))
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

    # Get current time in milliseconds
    $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)
        
    # Concatenate Request Details
    $requestVars = $httpVerb + $epoch + $resourcePath

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
    $message = ("{0}: Executing the REST query." -f (Get-Date -Format s))
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

    Try {
        $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop
    }
    Catch {
        $message = ("{0}: It appears that the web request failed. Check your credentials and try again. To prevent errors, the Get-LogicMonitorDevices function will exit. The specific error message is: {1}" `
                -f (Get-Date -Format s), $_.Message.Exception)
        If ($BlockLogging) {Write-Host $message -ForegroundColor White} Else {Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
        
        Return
    }

    $devices = $response.data.items
	
    Return $devices
} #1.0.0.5