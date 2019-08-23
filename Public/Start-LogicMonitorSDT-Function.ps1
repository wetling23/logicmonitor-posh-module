# Need to figure out, in what format(s) I can have the user provide start and end dates. Using '06/07/2017' (for example) works, but throws an error.
# The ElseIf for "Start date is provided. Start time is not provided." complains, but I'm not sure why. The lines work when called outside the function.
Function Start-LogicMonitorSDT {
    <#
.DESCRIPTION 
    Starts standard down time (SDT) for a device in LogicMonitor.
.NOTES 
    Author: Mike Hashemi
    V1.0.0.0 date: 19 December 2016
        - Initial release
    V1.0.0.1 date: 3 May 2016
        - Updated logging code.
        - Added to the SynoptekLogicMonitor module.
        - Added usage examples.
    V1.0.0.2 date: 23 April 2018
        - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
        - Replaced ! with -NOT.
    V1.0.0.3 date: 23 August 2019
.LINK
    https://github.com/wetling23/logicmonitor-posh-module
.PARAMETER AccessId
    Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.    
.PARAMETER AccessKey
    Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
.PARAMETER AccountName
    Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
.PARAMETER Id
    Represents the device ID of a monitored device. Accepts pipeline input. Either this or the DisplayName is required.
.PARAMETER DisplayName
    Represents the device display name of a monitored device. Accepts pipeline input. Must be unique in LogicMonitor. Either this or the Id is required.
.PARAMETER StartDate
    Represents the SDT start date. If no value is provided, the current date is used.
.PARAMETER StartTime
    Represents the SDT start time. If no value is provided, the current time is used.
.PARAMETER Duration
    Represents the duration of SDT in the format days, hours, minutes (xxx:xx:xx). If no value is provided, the duration will be one hour.
.PARAMETER Comment
    Default value is "SDT initiated by Start-LogicMonitorSDT". 
.PARAMETER EventLogSource
    Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
.PARAMETER BlockLogging
    When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
.EXAMPLE
    PS C:\> Start-LogicMonitorSDT -AccessId $accessID -AccessKey $accessKey -AccountName $accountname -Id 1

    In this example, SDT will be started for the device with Id "1". The SDT will start immediately and will last one hour.
.EXAMPLE 
    PS C:\> 
.EXAMPLE 

.EXAMPLE 

.EXAMPLE 
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [string]$AccessId,

        [Parameter(Mandatory = $True)]
        [string]$AccessKey,

        [Parameter(Mandatory = $True)]
        [string]$AccountName,

        [Parameter(Mandatory = $True, ParameterSetName = "Id", ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [string]$Id,

        [Parameter(Mandatory = $True, ParameterSetName = "Name", ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [string]$DisplayName,

        [datetime]$StartDate,

        [datetime]$StartTime,

        [string]$Duration = "00:01:00",

        [string]$Comment = "SDT initiated by Start-LogicMonitorSDT",

        [string]$EventLogSource = 'LogicMonitorPowershellModule',

        [switch]$BlockLogging
    )

    Begin {
        #Request Info
        $httpVerb = 'POST'
        $resourcePath = "/sdt/sdts"
        $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

        # Regular expression to validate that the provided SDT duration was formatted correctly.
        $regex = '^\d{1,3}:([01]?[0-9]|2[0-3]):([0-5][0-9])$'
    }
    Process {
        If (-NOT($BlockLogging)) {
            $return = Add-EventLogSource -EventLogSource $EventLogSource
    
            If ($return -ne "Success") {
                $message = ("{0}: Unable to add event source ({1}). No logging will be performed." -f [datetime]::Now, $EventLogSource)
                Write-Warning $message;

                $BlockLogging = $True
            }
        }

        $message = ("{0}: Beginning {1}." -f [datetime]::Now, $MyInvocation.MyCommand)
        If ($BlockLogging) { Write-Host $message -ForegroundColor White } Else { Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

        While ($Duration -notmatch $regex) {
            Write-Output ("The value for duration ({0}) is invalid. Please provide a valid SDT duration." -f $Duration)
            $Duration = Read-Host "Please enter the end duration of SDT (days:hours:minutes (999:23:59))"
        }

        $message = ("{0}: Validating start time/date." -f [datetime]::Now)
        If ($BlockLogging) { Write-Host $message -ForegroundColor White } Else { Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

        If (($StartDate -eq $null) -and ($StartTime -eq $null)) {
            # Neither start time nor end time provided.
            $StartDate = (Get-Date).AddMinutes(1)
        }
        ElseIf (($StartDate -eq $null) -and ($StartTime -ne $null)) {
            # Start date not provided. Start time is provided.
            $StartDate = (Get-Date -Format d)
            [datetime]$StartDate = $StartDate
            $StartDate = $StartDate.Add($StartTime)
        }
        ElseIf (($StartDate -ne $null) -and ($StartTime -eq $null)) {
            # Start date is provided. Start time is not provided.
            $StartTime = (Get-Date -Format HH:mm)
            [datetime]$StartDate = $StartDate
            $StartDate = $StartDate.Add($StartTime)
        }
        Else {
            $StartDate = $StartDate.Add($StartTime)
        }

        # Split the duration into days, hours, and minutes.
        [array]$duration = $duration.Split(":")

        $message = ("{0}: Configuring duration." -f [datetime]::Now)
        If ($BlockLogging) { Write-Host $message -ForegroundColor White } Else { Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

        # Use the start date/time + duration to determine when the end date/time.
        $endDate = $StartDate.AddDays($duration[0])
        $endDate = $endDate.AddHours($duration[1])
        $endDate = $endDate.AddMinutes($duration[2])
    
        $sdtStart = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End ($StartDate).ToUniversalTime()).TotalMilliseconds)
        $sdtEnd = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End ($endDate).ToUniversalTime()).TotalMilliseconds)
		
        While (($Id -eq $null) -and ($DisplayName -eq $null)) {
            $input = Read-Host = "Enter the target device's ID or display name"

            # If the input is only digits, assign to $id, otherwise, assign to $displayName.
            If ($input -match "^[\d\.]+$") { $id = $input } Else { $displayName = $input }
        }

        $message = ("{0}: SDT Start: {1}; SDT End: {2}; Device ID: {3}; Device Display Name: {4}." -f [datetime]::Now, $StartDate, $endDate, $Id, $DisplayName)
        If ($BlockLogging) { Write-Host $message -ForegroundColor White } Else { Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

        If ($id) {
            $data = "{`"sdtType`":1,`"type`":`"DeviceSDT`",`"deviceId`":`"$Id`",`"startDateTime`":$sdtStart,`"endDateTime`":$sdtEnd}"
        }
        Else {
            $data = "{`"sdtType`":1,`"type`":`"DeviceSDT`",`"deviceDisplayName`":`"$DisplayName`",`"startDateTime`":$sdtStart,`"endDateTime`":$sdtEnd,`"comment`":`"$Comment`"}"
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
        $auth = 'LMv1 ' + $accessId + ':' + $signature + ':' + $epoch
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Authorization", $auth)
        $headers.Add("Content-Type", 'application/json')
        
        # Make Request
        $message = ("{0}: Executing the REST query." -f [datetime]::Now)
        If ($BlockLogging) { Write-Host $message -ForegroundColor White } Else { Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

        Try {
            $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -Body $data -ErrorAction Stop
        }
        Catch {
            $message = ("{0}: It appears that the web request failed. Check your credentials and try again. To prevent errors, the {1} function will exit. The specific error message is: {2}" `
                    -f [datetime]::Now, $MyInvocation.MyCommand, $_.Message.Exception)
            If ($BlockLogging) { Write-Error $message } Else { Write-Error $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417 }

            Return "Error"
        }
    }
} #1.0.0.3