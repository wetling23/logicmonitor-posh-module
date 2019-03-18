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
        .PARAMETER BatchSize
            Default value is 1000. Represents the number of alerts to request from LogicMonitor.
        .PARAMETER EventLogSource
            Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAuditLog -AccessID <access ID> -AccessKey <access key> -AccountName <account name>

            In this example, the function gets all audit log events, in batches of 1000.
    #>
    [CmdletBinding()]
    [alias('Get-LogicMonitorAuditLogs')]
    Param (
        [Parameter(Mandatory = $True)]
        $AccessId,

        [Parameter(Mandatory = $True)]
        $AccessKey,

        [Parameter(Mandatory = $True)]
        $AccountName,

        $StartDate,

        $EndDate,

        [int]$BatchSize = 1000,

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
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

    # Initialize variables.
    $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    $batchCount = 0 # Counter so we know how many times we have looped through the request
    $loopDone = $false # Switch for knowing when to stop requesting alerts. Will change to $true once $response.data.items.count is a positive number.
    $firstLoopDone = $false
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $regex = "^[0-9]*$" # Used later, to confirm that the start and end times are in the correct format.
    [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
        
    # Define the resourcePath.
    $resourcePath = "/setting/accesslogs"

    # Verify that $startDate and $endDate were provided correctly. If not provided, set start date as 24 hours before now.
    If ((($StartDate -eq $null) -and ($EndDate -ne $null)) -or (($StartDate -ne $null) -and ($EndDate -eq $null))) {
        #If only StartDate /or/ EndDate are provided.
        $message = ("Both the start and end dates are required. You entered {0} for StartDate and {1} for EndDate. To prevent errors, {2} will exit." -f $StartDate, $EndDate, $MyInvocation.MyCommand)
        If ($BlockLogging) {Write-Host $message -ForegroundColor Yellow} Else {Write-Host $message -ForegroundColor Yellow; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Warning -Message $message -EventId 5417}

        Return
    }
    ElseIf ((($StartDate -ne $null) -and ($StartDate -notmatch $regex)) -or (($EndDate -ne $null) -and ($EndDate -notmatch $regex))) {
        #If StartDate or EndDate are provided, but are not in the correct format.
        $message = ("StartDate and EndDate must be in the format of milliseconds since January 1, 1970. You entered {0} for StartDate and {1} for EndDate. To prevent errors, {2} will exit." -f $StartDate, $EndDate, $MyInvocation.MyCommand)
        If ($BlockLogging) {Write-Host $message -ForegroundColor Yellow} Else {Write-Host $message -ForegroundColor Yellow; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Warning -Message $message -EventId 5417}

        Return
    }
    ElseIf (($StartDate -eq $null) -and ($EndDate -eq $null)) {
        #If neither StartDate nor EndDate are provided.
        $message = ("Neither StartDate nor EndDate were provided. Using the last 24-hours.")
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

        $startDate = [int][double]::Parse((Get-Date (get-date).AddHours(-24) -UFormat "%s"))
        $endDate = [int][double]::Parse((Get-Date -UFormat "%s"))
    }

    # Retrieve log entires.
    While ($loopDone -ne $true) {
        $message = ("{0}: The request loop has run {1} times." -f (Get-Date -Format s), $batchCount)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

        $queryParams = "?offset=$offset&size=$BatchSize&&filter=happenedOn<:$endDate,happenedOn>:$startDate"

        # Construct the query URL.
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

        # Build header.
        If ($firstLoopDone -eq $false) {
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
            $auth = 'LMv1 ' + $accessId + ':' + $signature + ':' + $epoch
            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("Authorization", $auth)
            $headers.Add("Content-Type", 'application/json')

            $firstLoopDone = $true
        }

        # Make Request
        $message = ("{0}: Executing the REST query." -f (Get-Date -Format s))
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

        Do {
            Try {
                $response = Invoke-RestMethod -Uri $url -Method $httpverb -Header $headers -ErrorAction Stop

                $stopLoop = $True
            }
            Catch {
                If ($_.Exception.Message -match '429') {
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f (Get-Date -Format s), $MyInvocation.MyCommand, $_.Exception.Message)
                    If ($BlockLogging) {Write-Host $message -ForegroundColor Yellow} Else {Write-Host $message -ForegroundColor Yellow; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Warning -Message $message -EventId 5417}

                    Start-Sleep -Seconds 60
                }
                Else {
                    $message = ("{0}: Unexpected error getting audit log entries. To prevent errors, {1} will exit. PowerShell returned: {2}" -f (Get-Date -Format s), $MyInvocation.MyCommand, $_.Exception.Message)
                    If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417}

                    Return "Error"
                }
            }
        }
        While ($stopLoop -eq $false)

        $logEntries += $response.data.items

        If ($response.data.items.Count -eq $BatchSize) {
            # The response was full of log entries (up to the number in $BatchSize), so there are probably more. Increment offset, to grab the next batch of log entries.
            $message = ("{0}: There are more log entries to retrieve. Incrementing offset by {1}." -f (Get-Date -Format s), $BatchSize)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

            $message = ("{0}: The value of `$response.data.items.count is {1}." -f (Get-Date -Format s), $($response.data.items.Count))
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

            $offset += $BatchSize
            $batchCount++
        }
        Else {
            # The number of returned log entries was less than the $BatchSize so we must have run out log entries to retrieve.
            $message = ("{0}: There are no more log entries to retrieve." -f (Get-Date -Format s))
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

            $message = ("{0}: The value of `$response.data.items.count is {1}." -f (Get-Date -Format s), $($response.data.items.Count))
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

            $loopDone = $true
        }
    }

    Return $logEntries
} #1.0.0.6