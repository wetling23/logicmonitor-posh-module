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
            V1.0.0.12 date: 4 December 2019
            V1.0.0.13 date: 23 July 2020
            V1.0.0.14 date: 21 September 2021
            V2023.01.10.0
            V2023.04.28.0
            V2023.05.19.0
            V2023.08.22.0
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
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Start-LogicMonitorDeviceSdt -AccessId $accessID -AccessKey $accessKey -AccountName <account name> -Id 1 -Verbose

            In this example, SDT will be started for the device with Id "1". The SDT will start immediately and will last one hour. Verbose output is sent to the host.
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

        [boolean]$BlockStdErr = $false,

        [string]$EventLogSource,

        [string]$LogPath
    )

    Begin {
        #region Setup
        #region Initialize variables
        $httpVerb = 'POST'
        $resourcePath = "/sdt/sdts"
        [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
        $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
        $comment += "...SDT initiated via Start-LogicMonitorDeviceSdt"
        #endregion Initialize variables

        #region Logging
        # Setup parameters for splatting.
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') {
            If ($EventLogSource -and (-NOT $LogPath)) {
                $loggingParams = @{
                    Verbose        = $true
                    EventLogSource = $EventLogSource
                }
            } ElseIf ($LogPath -and (-NOT $EventLogSource)) {
                $loggingParams = @{
                    Verbose = $true
                    LogPath = $LogPath
                }
            } Else {
                $loggingParams = @{
                    Verbose = $true
                }
            }
        } Else {
            If ($EventLogSource -and (-NOT $LogPath)) {
                $loggingParams = @{
                    EventLogSource = $EventLogSource
                }
            } ElseIf ($LogPath -and (-NOT $EventLogSource)) {
                $loggingParams = @{
                    LogPath = $LogPath
                }
            } Else {
                $loggingParams = @{}
            }
        }
        #endregion Logging

        $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
        #endregion Setup
    }
    Process {
        #region Validate time/date
        $message = ("{0}: Validating start time/date." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        If (-NOT($StartDate) -and -NOT($StartTime)) {
            # Neither start time nor end time provided.

            $message = ("{0}: StartDate and StartTime are null." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $StartDate = (Get-Date).AddMinutes(1)
        }
        ElseIf (-NOT($StartDate) -and ($StartTime)) {
            # Start date not provided. Start time is provided.
            $message = ("{0}: StartDate is null and StartTime is {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $StartTime)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $StartDate = Get-Date
            $StartDate = $StartDate.Date.Add((New-Timespan -Hour $StartTime.Split(':')[0] -Minute $StartTime.Split(':')[0]))
        }
        ElseIf (($StartDate) -and -NOT($StartTime)) {
            # Start date is provided. Start time is not provided.
            $message = ("{0}: StartDate is {1} and StartTime is null. The object type of StartDate is {2}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $StartDate, $StartDate.GetType())
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $currentTime = (Get-Date).AddMinutes(1)
            $StartDate = $StartDate.Date.Add((New-Timespan -Hour $currentTime.Hour -Minute $currentTime.Minute))
        }
        Else {
            # Start date is provided. Start time is provided.
            $message = ("{0}: StartDate is {1} and StartTime is {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $StartDate, $StartTime)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $StartDate = $StartDate.Date.Add([Timespan]::Parse($StartTime))
        }

        # Split the duration into days, hours, and minutes.
        [array]$duration = $duration.Split(":")
        #endregion Validate time/date

        #region Build data
        $message = ("{0}: Configuring duration." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        # Use the start date/time + duration to determine when the end date/time.
        $endDate = $StartDate.AddDays($duration[0])
        $endDate = $endDate.AddHours($duration[1])
        $endDate = $endDate.AddMinutes($duration[2])

        $message = ("{0}: The value of `$endDate is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $endDate)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        $sdtStart = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End ($StartDate).ToUniversalTime()).TotalMilliseconds)
        $sdtEnd = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End ($endDate).ToUniversalTime()).TotalMilliseconds)

        If ($PsCmdlet.ParameterSetName -eq "id") {
            $message = ("{0}: SDT Start: {1}; SDT End: {2}; Device ID: {3}; Comment: {4}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $StartDate, $endDate, $Id, $Comment)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $data = @{
                "type"          = "ResourceSDT"
                "deviceId"      = $Id
                "startDateTime" = $sdtStart
                "endDateTime"   = $sdtEnd
                "comment"       = $Comment
            }
        }
        Else {
            $message = ("{0}: SDT Start: {1}; SDT End: {2}; Device name: {3}; Comment: {4}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $StartDate, $endDate, $DisplayName, $Comment)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $data = @{
                "type"              = "ResourceSDT"
                "deviceDisplayName" = $DisplayName
                "startDateTime"     = $sdtStart
                "endDateTime"       = $sdtEnd
                "comment"           = $Comment
            }
        }
        #endregion Build data

        #region Execute REST query
        $data = $($Properties | ConvertTo-Json -Depth 5)

        #region Auth and headers
        # Get current time in milliseconds.
        $epoch = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End (Get-Date).ToUniversalTime()).TotalMilliseconds)
        $requestVars = $httpVerb + $epoch + $data + $resourcePath
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
        $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
        $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
        $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

        $headers = @{
            "Authorization" = "LMv1 $AccessId`:$signature`:$epoch"
            "Content-Type"  = "application/json"
            "X-Version"     = 3
        }
        #endregion Auth and headers

        # Construct the query URL.
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

        $message = ("{0}: Connecting to: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $url)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        $stopLoop = $false
        Do {
            Try {
                $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -Body $data -ErrorAction Stop

                $stopLoop = $True
            } Catch {
                If ($_.Exception.Message -match '429') {
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                    Out-PsLogging @loggingParams -MessageType Warning -Message $message

                    Start-Sleep -Seconds 60
                } Else {
                    $message = ("{0}: Unexpected error starting SDT. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
                Error message: {2}`r
                Error code: {3}`r
                Invoke-Request: {4}`r
                Headers: {5}`r
                Body: {6}" -f
                ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage),
                ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
                    )
                    Out-PsLogging @loggingParams -MessageType Error -Message $message

                    Return "Error"
                }
            }
        } While ($stopLoop -eq $false)

        If ($response.id) {
            $message = ("{0}: Successfully started SDT." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            Return $response
        } Else {
            $message = ("{0}: Unexpected error starting SDT. To prevent errors, {1} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
            Out-PsLogging @loggingParams -MessageType Error -Message $message

            Return "Error"
        }
        #endregion Execute REST query
    }
} #2023.08.22.0