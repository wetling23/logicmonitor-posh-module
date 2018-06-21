Function Add-LogicMonitorDeviceGroup {
    <#
        .DESCRIPTION 

        .NOTES 
            Author: Mike Hashemi
            V1 date: 2 February 2017
                - Initial release.
            V1.0.0.3 date: 10 February 2017
                - Updated procedure order.
            V1.0.0.4 date: 3 May 2017
                - Removed code from writing to file and added Event Log support.
                - Updated code for verbose logging.
                - Changed Add-EventLogSource failure behavior to just block logging (instead of quitting the function).
            V1.0.0.5 date: 21 June 2017
                - Updated logging to reduce chatter.
            V1.0.0.6 date: 23 April 2018
                - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
                - Replaced ! with -NOT.
            V1.0.0.7 date: 21 June 2018
                - Updated white space.
        .LINK
            
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.    
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER GroupDisplayName
            Mandatory parameter. Represents the display name of the device to be monitored. This name must be unique in your LogicMonitor account.
        .PARAMETER GroupName
            Mandatory parameter. Represents the name of the group to be added.
        .PARAMETER ParentGroupID
            Mandatory parameter. Represents the group ID of the group, to which the new group will be subordinate.
        .PARAMETER Description
            Represents the description of the group.
        .PARAMETER DisableAlerting
            Boolean value. Represents the default alerting state for the group.
        .PARAMETER AppliesTo
            Represents the query syntax, to which devices must conform for membership in this group.
        .PARAMETER PropertyNames
            Mandatory parameter. Represents the name(s) of the target property. Note that LogicMonitor properties are case sensitive.
        .PARAMETER PropertyValues
            Mandatory parameter. Represents the value of the target property(ies). Property values must be in the same order as the property names.
        .PARAMETER EventLogSource
            Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> Add-LogicMonitorDeviceGroup

            In this example, the function will create a new device group with the following properties:
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
        [string]$GroupName,

        [Parameter(Mandatory = $True)]
        [string]$ParentGroupID,

        [string]$Description,

        [boolean]$DisableAlerting = $false,

        [string]$AppliesTo,

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
    If ($BlockLogging) {Write-Host $message -ForegroundColor White} Else {Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

    # Initialize variables.
    [int]$index = 0
    $propertyData = ""
    $data = ""
    $httpVerb = "POST" # Define what HTTP operation will the script run.
    $resourcePath = "/device/groups"
    $requiredProperties = "`"name`":`"$GroupName`",`"parentId`":`"$ParentGroupID`""
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols    

    If ($Description) {
        $message = ("{0}: Appending `"description`" to the list of properties." -f (Get-Date -Format s))
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

        $requiredProperties += ",`"description`":`"$Description`""
    }
    If ($AppliesTo) {
        $message = ("{0}: Appending `"appliesTo`" to the list of properties." -f (Get-Date -Format s))
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

        $requiredProperties += ",`"appliesTo`":`"$AppliesTo`""
    }

    $message = ("{0}: Appending `"disableAlerting`" to the list of properties." -f (Get-Date -Format s))
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

    $requiredProperties += ",`"disableAlerting`":`"$DisableAlerting`""

    $message = ("{0}: Finished adding standard properties." -f (Get-Date -Format s))
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

    # For each property, assign the name and value to $propertyData...
    Foreach ($property in $PropertyNames) {    
        $message = ("{0}: Updating/adding property: {1} with a value of {2}." -f (Get-Date -Format s), $property, $($PropertyValues[$index]))
        If ($BlockLogging) {Write-Host $message -ForegroundColor White} Else {Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

        $propertyData += "{`"name`":`"$property`",`"value`":`"$($PropertyValues[$index])`"},"
        
        $index++
    }
    
    #...trim the trailing comma...
    $propertyData = $propertyData.TrimEnd(",")

    #...and assign the entire string to the $data variable.
    If ($PropertyNames) {
        $data = "{$requiredProperties,`"customProperties`":[$propertyData]}"

        $message = ("{0}: There are custom properties. The value of `$data is {1}." -f (Get-Date -Format s), $data)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
    }
    Else {
        $data = "{$requiredProperties}"

        $message = ("{0}: There are no custom properties. The value of `$data is {1}." -f (Get-Date -Format s), $data)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
    }

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
        $message = ("{0}: It appears that the web request failed. Check your credentials and try again. To prevent errors, the Add-LogicMonitorDeviceGroup function will exit. The specific error message is: {1}" -f (Get-Date -Format s), $_.Message.Exception)
        If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417}

        Return "Failure"
    }
    Switch ($response.status) {
        "200" {
            $message = ("{0}: Successfully added the group in LogicMonitor." -f (Get-Date -Format s))
            If ($BlockLogging) {Write-Host $message -ForegroundColor White} Else {Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

            Return "Success"
        }
        "600" {
            $message = ("{0}: LogicMonitor reported that there is a duplicate group. Verify that the group you are adding has a unique name. The specific message was: {1}" `
                    -f (Get-Date -Format s), $response.errmsg)
            If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417}

            Return "Failure (600)"
        }
        Default {
            $message = ("{0}: Unexpected error creating a new group in LogicMonitor. To prevent errors, the Add-LogicMonitorDeviceGroup function will exit. The status was: {1} and the error was: `"{2}`"" `
                    -f (Get-Date -Format s), $response.status, $response.errmsg)
            If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417}

            Return "Failure"
        }
    }
}
#1.0.0.7