Function Update-LogicMonitorDevice {
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
    V1.0.1.0 d
.LINK
    
.PARAMETER AccessId
    Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.    
.PARAMETER AccessKey
    Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
.PARAMETER AccountName
    Represents the subdomain of the LogicMonitor customer. Default value is "synoptek".
.PARAMETER Id
    Mandatory parameter. Represents the device ID of a monitored device.
.PARAMETER CustomProperty
    Switch parameter. Required when the target property is custom. 
.PARAMETER PropertyName
    Mandatory parameter. Represents the name of the target property. Note that LogicMonitor properties are case sensitive.
.PARAMETER PropertyValue
    Mandatory parameter. Represents the value of the target property.
.PARAMETER WriteLog
    Switch parameter. When included (and a log path is defined), the script will send output to a log file and to the screen.
.PARAMETER LogPath
    Path where the function should store its log. When omitted, output will be sent to the shell.
.EXAMPLE
    PS C:\> Update-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceId 6 -PropertyNames Location -PropertyValues Denver

    In this example, the function will update the Location property for the device with "6" in the ID property. The location will be set to "Denver".
.EXAMPLE
    PS C:\> Update-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceDisplayName server1 -PropertyNames Location -PropertyValues Denver

    In this example, the function will update the Location property for the device with "server1" in the displayName property. The location will be set to "Denver".
.EXAMPLE
    PS C:\> Update-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceName 10.0.0.0 -PropertyNames Location -PropertyValues Denver

    In this example, the function will update the Location property for the device with "10.0.0.0" in the name property. The location will be set to "Denver".
.EXAMPLE
    PS C:\> Update-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceName server1.domain.local -PropertyNames Location -PropertyValues Denver

    In this example, the function will update the Location property for the device with "server1.domain.local" in the name property. The location will be set to "Denver".
#>
[CmdletBinding(DefaultParameterSetName='DefaultAdd')]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$AccessId,

        [Parameter(Mandatory=$True)]
        [string]$AccessKey,

        [Parameter(Mandatory=$True)]
        [string]$AccountName,

        [Parameter(Mandatory=$True,ParameterSetName='DefaultAdd')]
        [Parameter(Mandatory=$True,ParameterSetName='DefaultRemove')]
        [int]$DeviceId,

        [Parameter(Mandatory=$True,ParameterSetName='DisplayNameFilterAdd')]
        [Parameter(Mandatory=$True,ParameterSetName='DisplayNameFilterRemove')]
        [string]$DeviceDisplayName,

        [Parameter(Mandatory=$True,ParameterSetName='IPOrNameFilterAdd')]
        [Parameter(Mandatory=$True,ParameterSetName='IPOrNameIPFilterRemove')]
        [string]$DeviceName,

        [Parameter(Mandatory=$True)]
        [string[]]$PropertyNames,

        [Parameter(Mandatory=$True, ParameterSetName='DefaultAdd')]
        [Parameter(Mandatory=$True, ParameterSetName='DisplayNameFilterAdd')]
        [Parameter(Mandatory=$True, ParameterSetName='IPOrNameIPFilterAdd')]
        [string[]]$PropertyValues,

        [Parameter(Mandatory=$True, ParameterSetName='DefaultAdd')]
        [Parameter(Mandatory=$True, ParameterSetName='DisplayNameFilterAdd')]
        [Parameter(Mandatory=$True, ParameterSetName='IPOrNameIPFilterAdd')]
        [switch]$Add,

        [Parameter(Mandatory=$True, ParameterSetName='DefaultRemove')]
        [Parameter(Mandatory=$True, ParameterSetName='DisplayNameFilterRemove')]
        [Parameter(Mandatory=$True, ParameterSetName='IPOrNameIPFilterRemove')]
        [switch]$Remove,

        [switch]$WriteLog,
        [string]$LogPath
    )

    If ($LogPath) {
        $logPath = Confirm-OutputPathAvailability -LogPath $LogPath
        
        Write-Host ("Logging output to {0}" -f $LogPath)
    }

    $message = Write-Output ("{0}: Beginning {1}" -f (Get-Date -Format s), $MyInvocation.MyCommand)
    If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
    
    # Initialize variables.
    [int]$index = 0
    $propertyData = ""
	$standardProperties = ""
    $data = ""
    $httpVerb = 'PATCH'
	$queryParams = "?patchFields="
    $resourcePath = "/device/devices"
    
    # Update $resourcePath to filter for a specific device, when a device ID, name, or displayName is provided by the user.
    Switch ($PsCmdlet.ParameterSetName) {
        {$_ -in ("DefaultAdd", "DefaultRemove")} {
            $resourcePath += "/$DeviceId"
		}
		{$_ -in ("DisplayNameFilterAdd", "DisplayNameFilterRemove")} {
			$message = Write-Verbose ("{0}: Attempting to retrieve the device ID of {1}." -f (Get-Date -Format s), $DeviceDisplayName)
			If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
			
            $device = Get-LogicMonitorDevices -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -DeviceDisplayName $DeviceDisplayName
            
            $resourcePath += "/$($device.id)"

            $message = Write-Verbose ("{0}: The value of `$resourcePath is {1}." -f (Get-Date -Format s), $resourcePath)
			If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
        }
        {$_ -in ("IPOrNameFilterAdd", "IPOrNameIPFilterRemove")} {
			$message = Write-Verbose ("{0}: Attempting to retrieve the device ID of {1}." -f (Get-Date -Format s), $DeviceName)
			If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
			
            $device = Get-LogicMonitorDevices -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -DeviceName $DeviceName

            If ($device.count -gt 1) {
                $message = Write-Output ("{0}: More than one device with the name {1} were detected (specifically {2}). To prevent errors, the Update-LogicMonitorDevices will exit." `
                    -f (Get-Date -Format s), $DeviceName, $device.count)
			    If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}

                Return "Error"
            }			

            $resourcePath += "/$($device.id)"

            $message = Write-Verbose ("{0}: The value of `$resourcePath is {1}." -f (Get-Date -Format s), $resourcePath)
			If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
        }
    }
	
    $message = Write-Verbose ("{0}: Finished updating `$resourcePath. The value is {1}." -f (Get-Date -Format s), $resourcePath)
	If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
    
    If ($Add) {
        # For each property, assign the name and value to $propertyData.
        Foreach ($property in $PropertyNames) {    
		Switch ($property) {
			{$_ -in ("name", "displayName", "preferredCollectorId", "hostGroupIds", "description", "disableAlerting", "link", "enableNetflow", "netflowCollectorId")} {
				$queryParams += "$property,"
	
    			$message = Write-Verbose ("{0}: Added {1} to `$queryParams. The new value of `$queryParams is: {2}" -f (Get-Date -Format s), $property, $queryParams)
				If ($WriteLog -and ($LogPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $LogPath -Append} Else {Write-Host $message}
	
    			$message = Write-Output ("{0}: Updating/adding standard property: {1} with a value of {2}." -f (Get-Date -Format s), $property, $($PropertyValues[$index]))
				If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
	
    			$standardProperties += "`"$property`":`"$($PropertyValues[$index])`","
	    
    			$index++
			}
			Default {
				$customProps = $True
	
    			$message = Write-Verbose ("{0}: Found that there is a custom property present." -f (Get-Date -Format s))
				If ($WriteLog -and ($LogPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $LogPath -Append} Else {Write-Host $message}
	
    	        If ($property -like "*pass") {
					$message = Write-Output ("{0}: Updating/adding property: {1} with a value of ********." -f (Get-Date -Format s), $property)
					If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
				}
				Else {
					$message = Write-Output ("{0}: Updating/adding property: {1} with a value of {2}." -f (Get-Date -Format s), $property, $($PropertyValues[$index]))
					If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
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
	
        If (($standardProperties.Length -gt 0) -and ($propertyData.Length -gt 0)){
		    $message = Write-Verbose ("{0}: The length of `$standardProperties is {1}." -f (Get-Date -Format s), $standardProperties.Length)
		    If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
		
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
	
        $message = Write-Verbose ("{0}: Finished updating `$data. The value updateis {1}." -f (Get-Date -Format s), $data)
	    If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
    
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
	    $headers.Add("Authorization","LMv1 $accessId`:$signature`:$epoch")
	    $headers.Add("Content-Type",'application/json')
    
        # Make Request
        $message = Write-Output ("{0}: Executing the REST query." -f (Get-Date -Format s))
        If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
    
        Try {
            $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -Body $data -ErrorAction Stop
        }
        Catch {
            $message = Write-Output ("{0}: It appears that the web request failed. Check your credentials and try again. To prevent errors, the Update-LogicMonitorDevices function will exit. The specific error message is: {1}" -f (Get-Date -Format s), $_.Message.Exception)
            If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message -ForegroundColor Red; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message -ForegroundColor Red}
        
            Return "Error"
        }
    
        If ($response.status -ne "200") {
            $message = Write-Output ("{0}: LogicMonitor reported an error (status {1}). The message is: {2}" -f (Get-Date -Format s), $response.status, $response.errmsg)
            If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
        }

        Return $response
    }
    ElseIf ($Remove) {
        $message = Write-Verbose ("{0}: The -Remove switch was included." -f (Get-Date -Format s))
    	If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
    
        $httpVerb = 'DELETE'

        Foreach ($propertyName in $propertyNames) {
            $message = Write-Output ("{0}: Preparing to delete property: {1}." -f (Get-Date -Format s), $propertyName)
        	If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}

            $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath/properties/$propertyName"
            
            $message = Write-Verbose ("{0}: The URL is: {1}" -f (Get-Date -Format s), $url)
            If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}

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
	        $headers.Add("Authorization","LMv1 $accessId`:$signature`:$epoch")
	        $headers.Add("Content-Type",'application/json')

            # Make Request
            $message = Write-Output ("{0}: Executing the REST query to delete {1}." -f (Get-Date -Format s), $propertyName)
            If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
        
            $message = Write-Verbose ("{0}: The value of `$httpVerb is: {1}. The value of `$header is: {2}" -f (Get-Date -Format s), $httpVerb, $headers)
            If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}

            Try {
                $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop
            }
            Catch {
                $message = Write-Output ("{0}: It appears that the web request failed. Check your credentials and try again. To prevent errors, the Update-LogicMonitorDevices function will exit. The specific error message is: {1}" -f (Get-Date -Format s), $_.Message.Exception)
                If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message -ForegroundColor Red; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message -ForegroundColor Red}
        
                Return "Error"
            }
        }
    }
}