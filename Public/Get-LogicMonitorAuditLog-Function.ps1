Function Get-LogicMonitorAuditLog {
    <#
        .DESCRIPTION
            Retrieves LogicMonitor audit logs. By default, the last 24 hours of logs are retrieved.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 07 March 2017
                - Initial release.
            V1.0.0.1 date: 13 March 2017
                - Added OutputType parameter to the Confirm-OutputPathAvailability call.
            V1.0.0.2 date: 3 May 2017
                - Removed code from writing to file and added Event Log support.
                - Updated code for verbose logging.
                - Changed Add-EventLogSource failure behavior to just block logging (instead of quitting the function).
            V1.0.0.3 date: 21 June 2017
                - Updated logging to reduce chatter.
            V1.0.0.4 date: 23 April 2018
                - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
                - Replaced ! with -NOT.
            V1.0.0.5 date: 14 March 2019
                - Added support for rate-limited re-try.
                - Updated whitespace.
            V1.0.0.6 date: 18 March 2019
                - Updated alias publishing method.
            V1.0.0.7 date: 23 August 2019
            V1.0.0.8 date: 26 August 2019
            V1.0.0.9 date: 18 October 2019
            V1.0.0.10 date: 4 December 2019
            V1.0.0.11 date: 23 July 2020
            V1.0.0.12 date: 7 February 2021
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER StartDate
            Represents the number of milliseconds from January 1, 1970 to the start date of the audit log filter.
        .PARAMETER EndDate
            Represents the number of milliseconds from January 1, 1970 to the end date of the audit log filter.
        .PARAMETER Filter
            String representation of the desired API filter. See also: https://www.logicmonitor.com/swagger-ui-master/dist/#/Audit%20Logs/getAuditLog
        .PARAMETER BatchSize
            Default value is 1000. Represents the number of alerts to request from LogicMonitor.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAuditLog -AccessID <access ID> -AccessKey <access key> -AccountName <account name> -Verbose

            In this example, the command gets all audit log entries, in batches of 1000, up to the API-imposed query limit. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAuditLog -AccessId <access ID> -AccessKey <access key> -AccountName <account name> -Filter 'username:"*@*",_all~"*server1*",happenedOn>:0' -LogPath C:\Temp\log.txt

            In this example, the command gets all audit log entries, in batches of 1000, up to the API-imposed query limit, where the username has an @ symbole in it, and the content includes "server1". Limited logging output is written to C:\Temp\log.txt
        .EXAMPLE
            PS C:\> Get-LogicMonitorAuditLog -AccessId <access ID> -AccessKey <access key> -AccountName <account name> -Filter 'username:"*@*",_all~"*server1*",happenedOn<:1612705657,happenedOn>:1612619257"'

            In this example, the command gets all audit log entries, in batches of 1000, up to the API-imposed query limit, where the username has an @ symbole in it, and the content includes "server1". The query only returns those entries dated between the indicated dates.
    #>
    [CmdletBinding()]
    [alias('Get-LogicMonitorAuditLogs')]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [securestring]$AccessKey,

        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'DateFilter')]
        $StartDate,

        [Parameter(Mandatory, ParameterSetName = 'DateFilter')]
        $EndDate,

        [Parameter(ParameterSetName = 'StringFilter')]
        [string]$Filter,

        [int]$BatchSize = 1000,

        [boolean]$BlockStdErr = $false,

        [string]$EventLogSource,

        [string]$LogPath
    )

    #region Setup
    #region Initialize variables
    $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    $batchCount = 0 # Counter so we know how many times we have looped through the request
    $loopDone = $false # Switch for knowing when to stop requesting alerts. Will change to $true once $response.data.items.count is a positive number.
    $firstLoopDone = $false
    $max = $false # Used to stop the command when the API-specified query limit is reached.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $resourcePath = "/setting/accesslogs"
    $regex = "^[0-9]*$" # Used later, to confirm that the start and end times are in the correct format.
    [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
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

    Switch ($PsCmdlet.ParameterSetName) {
        "DateFilter" {
            # Verify that $startDate and $endDate were provided correctly. If not provided, set start date as 24 hours before now.
            If ((($StartDate -eq $null) -and ($EndDate -ne $null)) -or (($StartDate -ne $null) -and ($EndDate -eq $null))) {
                #If only StartDate /or/ EndDate are provided.
                $message = ("Both the start and end dates are required. You entered {0} for StartDate and {1} for EndDate. To prevent errors, {2} will exit." -f $StartDate, $EndDate, $MyInvocation.MyCommand)
                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }

                Return
            } ElseIf ((($StartDate -ne $null) -and ($StartDate -notmatch $regex)) -or (($EndDate -ne $null) -and ($EndDate -notmatch $regex))) {
                #If StartDate or EndDate are provided, but are not in the correct format.
                $message = ("StartDate and EndDate must be in the format of milliseconds since January 1, 1970. You entered {0} for StartDate and {1} for EndDate. To prevent errors, {2} will exit." -f $StartDate, $EndDate, $MyInvocation.MyCommand)
                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }

                Return
            } ElseIf (($StartDate -eq $null) -and ($EndDate -eq $null)) {
                #If neither StartDate nor EndDate are provided.
                $message = ("Neither StartDate nor EndDate were provided. Using the last 24-hours.")
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                $startDate = [int][double]::Parse((Get-Date (Get-Date).AddHours(-24) -UFormat "%s"))
                $endDate = [int][double]::Parse((Get-Date -UFormat "%s"))
            }

            $Filter = "filter=happenedOn<:$endDate,happenedOn>:$startDate"
        }
        "StringFilter" {
            If ($Filter.Length -lt 2) {
                $message = ("{0}: Adding `"happenedOn`" to the filter." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                $Filter = "filter=happenedOn%3E%3A%220%22"
            }
            If ($Filter -notmatch 'happenedOn') {
                $message = ("{0}: Adding `"happenedOn`" to the filter." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                $Filter = "$Filter,happenedOn%3E%3A%220%22"
            }

            If (-NOT($Filter -match 'filter\=')) {
                $message = ("{0}: Adding `"filter=`" to the filter." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                $Filter = "filter=$Filter"
            }
        }
    }

    $message = ("{0}: Filter is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Filter)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    # Retrieve log entires.
    While ($loopDone -ne $true) {
        $message = ("{0}: The request loop has run {1} times." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $batchCount)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $queryParams = "?offset=$offset&size=$BatchSize&sort=-happenedOn&$Filter"

        # Construct the query URL.
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

        # Build header.
        If ($firstLoopDone -eq $false) {
            $message = ("{0}: Building request header." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            # Get current time in milliseconds
            $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

            # Concatenate Request Details
            $requestVars = $httpVerb + $epoch + $resourcePath

            # Construct Signature
            $hmac = New-Object System.Security.Cryptography.HMACSHA256
            $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
            $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
            $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
            $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

            # Construct Headers
            $headers = @{
                "Authorization" = "LMv1 $AccessId`:$signature`:$epoch"
                "Content-Type"  = "application/json"
                "X-Version"     = 3
            }

            $firstLoopDone = $true
        }

        # Make Request
        $message = ("{0}: Executing the REST query." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        Do {
            Try {
                $response = Invoke-RestMethod -Uri $url -Method $httpverb -Header $headers -ErrorAction Stop

                $stopLoop = $True
            }
            Catch {
                If ($_.Exception.Message -match '429') {
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }

                    Start-Sleep -Seconds 60
                }
                ElseIf ($_.ErrorDetails.Message -match 'the query limitation of auditLog is 10000') {
                    $message = ("{0}: Reached the query limitation of 10000." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                    $stopLoop = $true
                    $max = $true
                }
                Else {
                    $message = ("{0}: Unexpected error getting audit log entries. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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
        }
        While ($stopLoop -eq $false)

        If ($response.items) {
            $logEntries += $response.items
        }
        ElseIf ($response.total -gt 0) {
            $logEntries = $response
        }

        If ($max -eq $true) {
            $loopDone = $true
        }
        ElseIf ($response.items.Count -eq $BatchSize) {
            # The response was full of log entries (up to the number in $BatchSize), so there are probably more. Increment offset, to grab the next batch of log entries.
            $message = ("{0}: There are more log entries to retrieve. Incrementing offset by {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $BatchSize)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $message = ("{0}: The value of `$response.items.count is {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $($response.items.Count))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $offset += $BatchSize
            $batchCount++
        }
        Else {
            # The number of returned log entries was less than the $BatchSize so we must have run out log entries to retrieve.
            $message = ("{0}: There are no more log entries to retrieve." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $message = ("{0}: The value of `$response.items.count is {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $($response.items.Count))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $loopDone = $true
        }
    }

    Return $logEntries
} #1.0.0.12