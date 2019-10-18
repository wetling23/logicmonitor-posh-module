Function Start-LogicMonitorDeviceSdt {
    <#
        .DESCRIPTION
            Starts standard down time (SDT) for a device in LogicMonitor.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 9 July 2018
                - Initial release.
            V1.0.0.1 date: 11 July 2018
                - Updated code to handle times better.
            V1.0.0.2 date: 12 July 2018
                - Changed the variable cast of $StartTime from [datetime] to [string].
                - Changed references to "LogicMonitorCommentSdt", to "LogicMonitorDeviceSdt".
            V1.0.0.3 date: 11 February 2019
                - Added support for time zones.
                - Updated message output.
            V1.0.0.5 date: 14 March 2019
                - Added support for rate-limited re-try.
            V1.0.0.6 date: 14 March 2019
                - Added support for rate-limited re-try.
            V1.0.0.7 date: 27 March 2019
                - Removed timezone parameter after discussion with LogicMonitor.
            V1.0.0.8 date: 26 August 2019
            V1.0.0.9 date: 17 October 2019
            V1.0.0.10 date: 18 October 2019
            V1.0.0.11 date: 18 October 2019
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
            Represents the text that will show in the notes field of the SDT entry. The text "...SDT initiated via Start-LogicMonitorDeviceSdt." will be appended to the user's comment.
        .PARAMETER EventLogSource
            Default value is "LogicMonitorPowershellModule". Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> Start-LogicMonitorDeviceSdt -AccessId $accessID -AccessKey $accessKey -AccountName <account name> -Id 1

            In this example, SDT will be started for the device with Id "1". The SDT will start immediately and will last one hour.
        .EXAMPLE
            PS C:\> Start-LogicMonitorDeviceSdt -AccessId $accessID -AccessKey $accessKey -AccountName <account name> -Id 1 -StartDate 06/07/2050 -Duration 00:02:00 -Comment "Testing" 

            In this example, SDT will be started for the device with Id "1". The SDT will start on 7 June 2050 (at the time the command was run). The duraction will be two hours and the comment will be "Testing......SDT initiated via Start-LogicMonitorDeviceSdt.".
        .EXAMPLE
            PS C:\> Get-LogicMonitorDevices -AccessId $accessID -AccessKey $accessKey -AccountName <account name> -DeviceId 1 | Start-LogicMonitorDeviceSdt -AccessId $accessID -AccessKey $accessKey -AccountName <account name> -StartDate 06/07/2050 -Duration 00:02:00 -Comment "Testing" 

            In this example, SDT will be started for the device with Id "1". The SDT will start on 7 June 2050 (at the time the command was run). The duraction will be two hours and the comment will be "Testing......SDT initiated via Start-LogicMonitorDeviceSdt.".
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [securestring]$AccessKey,

        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory, ParameterSetName = "Id", ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [string]$Id,

        [Parameter(Mandatory, ParameterSetName = "Name", ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [string]$DisplayName,

        [datetime]$StartDate,

        [ValidateScript( { $_ -match '^([01]\d|2[0-3]):?([0-5]\d)$' })]
        [string]$StartTime,

        [ValidateScript( { $_ -match '^\d{1,3}:([01]?[0-9]|2[0-3]):([0-5][0-9])$' })]
        [string]$Duration = "00:01:00",

        [string]$Comment,

        [string]$EventLogSource = 'LogicMonitorPowershellModule',

        [switch]$BlockLogging
    )

    Begin {
        #Request Info
        $httpVerb = 'POST'
        $resourcePath = "/sdt/sdts"
        [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
        $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
        $comment += "...SDT initiated via Start-LogicMonitorDeviceSdt"
    }
    Process {
        If (-NOT($BlockLogging)) {
            $return = Add-EventLogSource -EventLogSource $EventLogSource

            If ($return -ne "Success") {
                $message = ("{0}: Unable to add event source ({1}). No logging will be performed." -f [datetime]::Now, $EventLogSource)
                Write-Host $message

                $BlockLogging = $True
            }
        }

        $message = ("{0}: Beginning {1}." -f [datetime]::Now, $MyInvocation.MyCommand)
        If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

        $message = ("{0}: Validating start time/date." -f [datetime]::Now)
        If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

        If (-NOT($StartDate) -and -NOT($StartTime)) {
            # Neither start time nor end time provided.

            $message = ("{0}: StartDate and StartTime are null." -f [datetime]::Now)
            If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

            $StartDate = (Get-Date).AddMinutes(1)
        }
        ElseIf (-NOT($StartDate) -and ($StartTime)) {
            # Start date not provided. Start time is provided.
            $message = ("{0}: StartDate is null and StartTime is {1}." -f [datetime]::Now, $StartTime)
            If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

            $StartDate = Get-Date
            $StartDate = $StartDate.Date.Add((New-Timespan -Hour $StartTime.Split(':')[0] -Minute $StartTime.Split(':')[0]))
        }
        ElseIf (($StartDate) -and -NOT($StartTime)) {
            # Start date is provided. Start time is not provided.
            $message = ("{0}: StartDate is {1} and StartTime is null. The object type of StartDate is {2}" -f [datetime]::Now, $StartDate, $StartDate.GetType())
            If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

            $currentTime = (Get-Date).AddMinutes(1)
            $StartDate = $StartDate.Date.Add((New-Timespan -Hour $currentTime.Hour -Minute $currentTime.Minute))
        }
        Else {
            # Start date is provided. Start time is provided.
            $message = ("{0}: StartDate is {1} and StartTime is {2}." -f [datetime]::Now, $StartDate, $StartTime)
            If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

            $StartDate = $StartDate.Date.Add([Timespan]::Parse($StartTime))
        }

        # Split the duration into days, hours, and minutes.
        [array]$duration = $duration.Split(":")

        $message = ("{0}: Configuring duration." -f [datetime]::Now)
        If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

        # Use the start date/time + duration to determine when the end date/time.
        $endDate = $StartDate.AddDays($duration[0])
        $endDate = $endDate.AddHours($duration[1])
        $endDate = $endDate.AddMinutes($duration[2])

        $message = ("{0}: The value of `$endDate is: {1}." -f [datetime]::Now, $endDate)
        If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

        $sdtStart = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End ($StartDate).ToUniversalTime()).TotalMilliseconds)
        $sdtEnd = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End ($endDate).ToUniversalTime()).TotalMilliseconds)

        If ($PsCmdlet.ParameterSetName -eq "id") {
            $message = ("{0}: SDT Start: {1}; SDT End: {2}; Device ID: {3}; Commnet: {4}." -f [datetime]::Now, $StartDate, $endDate, $Id, $Comment)
            If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

            $data = @{
                "type"          = "DeviceSDT"
                "deviceId"      = $Id
                "startDateTime" = $sdtStart
                "endDateTime"   = $sdtEnd
                "comment"       = $Comment
            }
        }
        Else {
            $message = ("{0}: SDT Start: {1}; SDT End: {2}; Device name: {3}; Commnet: {4}." -f [datetime]::Now, $StartDate, $endDate, $DisplayName, $Comment)
            If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

            $data = @{
                "type"              = "DeviceSDT"
                "deviceDisplayName" = $DisplayName
                "startDateTime"     = $sdtStart
                "endDateTime"       = $sdtEnd
                "comment"           = $Comment
            }
        }

        $data = ($data | ConvertTo-Json)

        # Construct the query URL.
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"

        # Get current time in milliseconds
        $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

        # Concatenate Request Details
        $requestVars = $httpVerb + $epoch + $data + $resourcePath

        # Construct Signature
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
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
        $message = ("{0}: Executing the REST query." -f [datetime]::Now)
        If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

        Do {
            Try {
                $response = Invoke-RestMethod -Uri $url -Method $httpverb -Header $headers -Body $data -ErrorAction Stop

                $stopLoop = $True
            }
            Catch {
                If ($_.Exception.Message -match '429') {
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f [datetime]::Now, $MyInvocation.MyCommand, $_.Exception.Message)
                    If ($BlockLogging) { Write-Warning $message } Else { Write-Warning $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Warning -Message $message -EventId 5417 }

                    Start-Sleep -Seconds 60
                }
                Else {
                    $message = ("{0}: Unexpected error starting SDT. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
                        Error message: {2}`r
                        Error code: {3}`r
                        Invoke-Request: {4}`r
                        Headers: {5}`r
                        Body: {6}" -f
                        [datetime]::Now, $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage),
                        ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
                    )
                    If ($BlockLogging) { Write-Error $message } Else { Write-Error $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $message -EventId 5417 }

                    Return $response
                }
            }
        }
        While ($stopLoop -eq $false)

        Return $response
    }
} #1.0.0.11