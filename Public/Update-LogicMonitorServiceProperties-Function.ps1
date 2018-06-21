##Needs some testing (like updating multiple properties)
##Then addition to the lm module and published to the ps gallery.
##Do I want to support the PUT method to update additoinal properties (those not covered by PATCH)?
##Need to update in-line documentation.
Function Update-LogicMonitorServiceProperties {
    <#
.DESCRIPTION 
    Accepts a service ID or name and one or more property name/value pairs, then updates the property(ies), replacing existing values if the property is already defined.
.NOTES 
    Author: Mike Hashemi
    V1.0.0.0 date: 23 February 2017
        - Initial release.
    V1.0.0.1 date: 23 April 2018
        - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
.LINK
    
.PARAMETER AccessId
    Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.    
.PARAMETER AccessKey
    Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
.PARAMETER AccountName
    Represents the subdomain of the LogicMonitor customer.
.PARAMETER Id
    Mandatory parameter. Represents the service ID of a monitored service.
.PARAMETER PropertyName
    Mandatory parameter. Represents the name of the target property. Note that LogicMonitor properties are case sensitive.
.PARAMETER PropertyValue
    Mandatory parameter. Represents the value of the target property.
.PARAMETER EventLogSource
    Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
.PARAMETER BlockLogging
    When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
.EXAMPLE
    PS C:\> Update-LogicMonitorServiceProperties -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -ServiceId 6 -PropertyNames ### -PropertyValues ###

    In this example, the function will update the
.EXAMPLE
    PS C:\> Update-LogicMonitorServiceProperties -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceDisplayName server1 -PropertyNames Location -PropertyValues Denver

    
.EXAMPLE
    PS C:\> Update-LogicMonitorServiceProperties -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceName 10.0.0.0 -PropertyNames Location -PropertyValues Denver

    
.EXAMPLE
    PS C:\> Update-LogicMonitorServiceProperties -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceName server1.domain.local -PropertyNames Location -PropertyValues Denver

    
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
        [int]$ServiceId,
		
        [Parameter(Mandatory = $True, ParameterSetName = ’NameFilter’)]
        [string]$ServiceName,
        
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
    Set-Variable -Name index -Value 0 -Force -Scope Local
    $propertyData = ""
    $standardProperties = ""
    $data = ""
    $httpVerb = 'PATCH'
    $queryParams = "?patchFields="
    $resourcePath = "/service/services"
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    
    # Update $resourcePath to filter for a specific service, when a service ID or service name is provided by the user.
    Switch ($PsCmdlet.ParameterSetName) {
        Default {
            $resourcePath += "/$ServiceId"
        }
        NameFilter {
            $message = ("{0}: Attempting to retrieve the service ID of {1}." -f (Get-Date -Format s), $DeviceDisplayName)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}
			
            $service = Get-LogicMonitorServices -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -ServiceName $DeviceDisplayName -EventLogSource $EventLogSource
            
            $resourcePath += "/$($service.id)"

            $message = ("{0}: The value of `$resourcePath is {1}." -f (Get-Date -Format s), $resourcePath)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}
        }
    }
	
    $message = ("{0}: Finished updating `$resourcePath. The value is {1}." -f (Get-Date -Format s), $resourcePath)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}
    
    # For each property, assign the name and value to $propertyData.
    Foreach ($property in $PropertyNames) {    
        Switch ($property) {
            {$_ -in ("name", "description", "serviceFolderId", "stopMonitoring", "disableAlerting", "individualSmAlertEnable", "individualAlertLevel", `
                        "overallAlertLevel", "pollingInterval", "transition", "globalSmAlertCond", "testLocation", "serviceProperties")} {
				
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
        $queryParams = "$($queryParams.TrimEnd(","))&opType=replace"
    }
	
    # Trim the trailing comma.
    $propertyData = $propertyData.TrimEnd(",")
	
    $standardProperties = $standardProperties.TrimEnd(",")
	
    If (($standardProperties.Length -gt 0) -and ($propertyData.Length -le 0)) {
        $data = "{$standardProperties}"
    }
    Else {
        ##will this section ever be hit? I don't think so, but need to confirm.
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
} #1.0.0.1