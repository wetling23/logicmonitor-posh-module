###Need to update the help in for the "id"/"deviceid" parameter.
Function Update-LogicMonitorDeviceProperties {
    <#
        .DESCRIPTION 
            Accepts a device ID, display name, or device IP/DNS name, and one or more property name/value pairs, then updates the property(ies).
        .NOTES 
            Author: Mike Hashemi
            V1.0.0.0 date: 12 December 2016
            V1.0.0.1 date: 31 January 2017
                - Updated syntax and logging.
                - Improved error handling.
            V1.0.0.2 date: 31 January 2017
                - Updated error output color.
                - Streamlined header creation (slightly).
            V1.0.0.3 date: 31 January 2017
                - Added $logPath output to host.
            V1.0.0.4 date: 31 January 2017
                - Added additional logging.
            V1.0.0.5 date: 10 February 2017
                - Updated procedure order.
            V1.0.0.6 date: 3 May 2017
                - Removed code from writing to file and added Event Log support.
                - Updated code for verbose logging.
                - Changed Add-EventLogSource failure behavior to just block logging (instead of quitting the function).
            V1.0.0.7 date: 21 June 2017
                - Updated logging to reduce chatter.
            V1.0.0.8 date: 12 July 2017
                - Added -EventLogSource to a couple of cmdlet calls.
            V1.0.0.9 date: 1 August 2017
                - Updated inline documentation.
            V1.0.0.10 date: 28 September 2017
                - Replaced ! with -Not.
            V1.0.0.11 date: 23 April 2018
                - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
            V1.0.0.12 date: 11 July 2018
                - Updated white space.
                - Updated in-line help.
        .LINK

        .PARAMETER AccessId
            Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Represents the subdomain of the LogicMonitor customer.
        .PARAMETER DeviceId
            Represents the device ID of a monitored device.
        .PARAMETER DeviceDisplayName
            Represents the device's display name.
        .PARAMETER PropertyName
            Represents the name of the target property. Note that LogicMonitor properties are case sensitive.
        .PARAMETER PropertyValue
            Represents the value of the target property.
        .PARAMETER EventLogSource
            Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> Update-LogicMonitorDeviceProperties -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceId 6 -PropertyNames Location,AssignedTeam -PropertyValues Denver,Finance

            In this example, the function will update the Location and AssignedTeam properties for the device with "6" in the ID property. The location will be set to "Denver" and the assigned team will be "Finance". If the properties are not present, they will be added.
        .EXAMPLE
            PS C:\> Update-LogicMonitorDeviceProperties -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceDisplayName server1 -PropertyNames Location -PropertyValues Denver

            In this example, the function will update the Location property for the device with "server1" in the displayName property. The location will be set to "Denver". If the property is not present, it will be added.
        .EXAMPLE
            PS C:\> Update-LogicMonitorDeviceProperties -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceName 10.0.0.0 -PropertyNames Location -PropertyValues Denver

            In this example, the function will update the Location property for the device with "10.0.0.0" in the name property. The location will be set to "Denver". If the property is not present, it will be added.
        .EXAMPLE
            PS C:\> Update-LogicMonitorDeviceProperties -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceName server1.domain.local -PropertyNames Location -PropertyValues Denver

            In this example, the function will update the Location property for the device with "server1.domain.local" in the name property. The location will be set to "Denver". If the property is not present, it will be added.
    #>
    [CmdletBinding(DefaultParameterSetName = ’Default’)]
    Param (
        [Parameter(Mandatory = $True)]
        [string]$AccessId,

        [Parameter(Mandatory = $True)]
        [string]$AccessKey,

        [Parameter(Mandatory = $True)]
        [string]$AccountName,

        [Parameter(Mandatory = $True, ParameterSetName = ’Default’)]
        [int]$DeviceId,

        [Parameter(Mandatory = $True, ParameterSetName = ’NameFilter’)]
        [string]$DeviceDisplayName,

        [Parameter(Mandatory = $True, ParameterSetName = ’IPFilter’)]
        [string]$DeviceName,

        [Parameter(Mandatory = $True)]
        [string[]]$PropertyNames,

        [Parameter(Mandatory = $True)]
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
    If ($BlockLogging) {Write-Host $message -ForegroundColor White} Else {Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

    # Initialize variables.
    [int]$index = 0
    $propertyData = ""
    $standardProperties = ""
    $data = ""
    $httpVerb = 'PATCH'
    $queryParams = "?patchFields="
    $resourcePath = "/device/devices"
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    # Update $resourcePath to filter for a specific device, when a device ID, name, or displayName is provided by the user.
    Switch ($PsCmdlet.ParameterSetName) {
        Default {
            $resourcePath += "/$DeviceId"
        }
        NameFilter {
            $message = ("{0}: Attempting to retrieve the device ID of {1}." -f (Get-Date -Format s), $DeviceDisplayName)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

            $device = Get-LogicMonitorDevices -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -DeviceDisplayName $DeviceDisplayName -EventLogSource $EventLogSource

            $resourcePath += "/$($device.id)"

            $message = ("{0}: The value of `$resourcePath is {1}." -f (Get-Date -Format s), $resourcePath)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}
        }
        IPFilter {
            $message = ("{0}: Attempting to retrieve the device ID of {1}." -f (Get-Date -Format s), $DeviceName)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

            $device = Get-LogicMonitorDevices -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -DeviceName $DeviceName -EventLogSource $EventLogSource

            If ($device.count -gt 1) {
                $message = ("{0}: More than one device with the name {1} were detected (specifically {2}). To prevent errors, {3} will exit." `
                        -f (Get-Date -Format s), $DeviceName, $device.count, $MyInvocation.MyCommand)
                If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $message -EventId 5417}

                Return "Error"
            }			

            $resourcePath += "/$($device.id)"

            $message = ("{0}: The value of `$resourcePath is {1}." -f (Get-Date -Format s), $resourcePath)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}
        }
    }

    $message = ("{0}: Finished updating `$resourcePath. The value is {1}." -f (Get-Date -Format s), $resourcePath)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}
    
    # For each property, assign the name and value to $propertyData.
    Foreach ($property in $PropertyNames) {    
        Switch ($property) {
            {$_ -in ("name", "displayName", "preferredCollectorId", "hostGroupIds", "description", "disableAlerting", "link", "enableNetflow", "netflowCollectorId")} {
                $queryParams += "$property,"

                $message = ("{0}: Added {1} to `$queryParams. The new value of `$queryParams is: {2}" -f (Get-Date -Format s), $property, $queryParams)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

                $message = ("{0}: Updating/adding standard property: {1} with a value of {2}." -f (Get-Date -Format s), $property, $($PropertyValues[$index]))
                If ($BlockLogging) {Write-Host $message -ForegroundColor White} Else {Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

                $standardProperties += "`"$property`":`"$($PropertyValues[$index])`","

                $index++
            }
            Default {
                $customProps = $True

                $message = ("{0}: Found that there is a custom property present." -f (Get-Date -Format s))
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

                If ($property -like "*pass") {
                    $message = ("{0}: Updating/adding property: {1} with a value of ********." -f (Get-Date -Format s), $property)
                    If ($BlockLogging) {Write-Host $message -ForegroundColor White} Else {Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}
                }
                Else {
                    $message = ("{0}: Updating/adding property: {1} with a value of {2}." -f (Get-Date -Format s), $property, $($PropertyValues[$index]))
                    If ($BlockLogging) {Write-Host $message -ForegroundColor White} Else {Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}
                }

                $propertyData += "{`"name`":`"$property`",`"value`":`"$($PropertyValues[$index])`"},"

                $index++
            }
        }
    }

    If ($customProps -eq $True) {
        $queryParams += "customProperties&opType=replace"
    }
    Else {
        $queryParams.TrimEnd(",")
        $queryParams += "&opType=replace"
    }

    # Trim the trailing comma.
    $propertyData = $propertyData.TrimEnd(",")

    $standardProperties = $standardProperties.TrimEnd(",")

    If (($standardProperties.Length -gt 0) -and ($propertyData.Length -gt 0)) {
        $message = ("{0}: The length of `$standardProperties is {1}." -f (Get-Date -Format s), $standardProperties.Length)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

        # Assign the entire string to the $data variable.
        $data = "{$standardProperties,`"customProperties`":[$propertyData]}"
    }
    ElseIf (($standardProperties.Length -gt 0) -and ($propertyData.Length -le 0)) {
        $data = "{$standardProperties}"
    }
    Else {
        # Assign the entire string to the $data variable.
        $data = "{`"customProperties`":[$propertyData]}"
    }

    $message = ("{0}: Finished updating `$data. The value update is {1}." -f (Get-Date -Format s), $data)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

    # Construct the query URL.
    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

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
    $message = ("{0}: Executing the REST query." -f (Get-Date -Format s))
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

    Try {
        $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -Body $data -ErrorAction Stop
    }
    Catch {
        $message = ("{0}: It appears that the web request failed. Check your credentials and try again. To prevent errors, the {1} function will exit. The specific error message is: {2}" `
                -f (Get-Date -Format s), $MyInvocation.MyCommand, $_.Message.Exception)
        If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $message -EventId 5417}
        
        Return "Error"
    }

    If ($response.status -ne "200") {
        $message = ("{0}: LogicMonitor reported an error (status {1}). The message is: {2}" -f (Get-Date -Format s), $response.status, $response.errmsg)
        If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $message -EventId 5417}
    }

    Return $response
} #1.0.0.12