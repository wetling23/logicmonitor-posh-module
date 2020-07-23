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
            V1.0.0.4 date: 18 October 2019
            V1.0.0.5 date: 4 December 2019
            V1.0.0.6 date: 23 July 2020
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
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Start-LogicMonitorSDT -AccessId $accessID -AccessKey $accessKey -AccountName $accountname -Id 1 -Verbose

            In this example, SDT will be started for the device with Id "1". The SDT will start immediately and will last one hour. Verbose output is sent to the host.
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

        [boolean]$BlockStdErr = $false,

        [string]$EventLogSource,

        [string]$LogPath
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
        $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        While ($Duration -notmatch $regex) {
            $message = ("{0}: The value for duration ({1}) is invalid. Please provide a valid SDT duration." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Duration)
            $Duration = Read-Host "Please enter the end duration of SDT (days:hours:minutes (999:23:59))"
        }

        $message = ("{0}: Validating start time/date." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

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

        $message = ("{0}: Configuring duration." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

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

        $message = ("{0}: SDT Start: {1}; SDT End: {2}; Device ID: {3}; Device Display Name: {4}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $StartDate, $endDate, $Id, $DisplayName)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

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
        $message = ("{0}: Executing the REST query." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
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
                $message = ("{0}: Unexpected error starting SDT. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
                Error message: {2}`r
                Error code: {3}`r
                Invoke-Request: {4}`r
                Headers: {5}`r
                Body: {6}" -f
                    ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage),
                    ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
                )
                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                Return "Error"
            }
        }

        $response
    }
} #1.0.0.6