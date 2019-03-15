Function Get-LogicMonitorSdt {
    <#
        .DESCRIPTION
            Retrieves a list of Standard Down Time (SDT) entries from LogicMonitor. The cmdlet allows for the retrieval of a specific SDT entry, all entries, or all entries initiated by a specific user. Uses /sdt/sdts.

            The list of SDT entries are further filterable by type of monitored object.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 9 July 2018
                - Initial release.
            V1.0.0.1 date: 9 July 2018
                - Changed references to "devices", to "SDT entries".
                - Added parameter site assignment to the SdtEntry parameter, so it cannot be used with the SdtId parameter set.
            V1.0.0.2 date: 24 October 2018
                - Fixed bug in ParameterSetName.
            V1.0.0.3 date: 22 January 2019
                - Removed SdtType from the list of mandatory parameters.Function Get-LogicMonitorSdt.
            V1.0.0.4 date: 14 March 2019
                - Added support for rate-limited re-try.
        .LINK

        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Id
            Represents the ID of a specific SDT entry. Accepts pipeline input.
        .PARAMETER AdminName
            Represents the user name of the user who created the SDT entry.
        .PARAMETER SdtType
            Represents the type of SDT entries which to return. Valid values are CollectorSDT, DeviceGroupSDT, DeviceSDT, ServiceCheckpointSDT, ServiceSDT.
        .PARAMETER IsEffective
            When included, only returns SDT entries that are currently active.
        .PARAMETER BatchSize
            Default value is 1000. Represents the number of SDT entries to request from LogicMonitor, in a single batch.
        .PARAMETER EventLogSource
            Default value is "LogicMonitorPowershellModule". Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> Get-LogicMonitorSdt -AccessId $accessID -AccessKey $accessKey -AccountName <account name> -Id A_8

            This example shows how to get the SDT entry with ID "A_8".
        .EXAMPLE
            PS C:\> $allSdts = Get-LogicMonitorSdt -AccessId $accessID -AccessKey $accessKey -AccountName <account name> -Blocklogging

            This example shows how to get all SDT entries and store them in a variable called "allSdts". The command's logging is output only to the host, and not to the event log.
        .EXAMPLE
            PS C:\> Get-LogicMonitorSdt -AccessId $accessID -AccessKey $AccessKey -AccountName <account name> -AdminName <username> -SdtType DeviceGroupSDT

            This example shows how to get all device group SDT entries created by the user in <username>.
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllSdt')]
    Param (
        [Parameter(Mandatory = $True)]
        [string]$AccessId,

        [Parameter(Mandatory = $True)]
        [string]$AccessKey,

        [Parameter(Mandatory = $True)]
        [string]$AccountName,

        [Parameter(Mandatory = $True, ParameterSetName = "Id", ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias("SdtId")]
        [string]$Id,

        [Parameter(Mandatory = $True, ParameterSetName = "AdminName")]
        [string]$AdminName,

        [Parameter(ParameterSetName = "AdminName")]
        [Parameter(ParameterSetName = "Id")]
        [Parameter(ParameterSetName = "AllSdt")]
        [ValidateSet('ServiceSDT', 'CollectorSDT', 'DeviceDataSourceInstanceSDT', 'DeviceBatchJobSDT', 'DeviceClusterAlertDefSDT', 'DeviceDataSourceInstanceGroupSDT', 'DeviceDataSourceSDT', 'DeviceEventSourceSDT', 'DeviceGroupSDT', 'DeviceSDT', 'WebsiteCheckpointSDT', 'WebsiteGroupSDT', 'WebsiteSDT')]
        [string]$SdtType,

        [switch]$IsEffective,

        [int]$BatchSize = 1000,

        [string]$EventLogSource = 'LogicMonitorPowershellModule',

        [switch]$BlockLogging
    )

    Begin {
        # Initialize variables.
        $filter = $null # The script
        $currentBatchNum = 0 # Start at zero and increment in the while loop, so we know how many times we have looped.
        $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
        $sdtBatchCount = 1 # Define how many times we need to loop, to get all SDT entries.
        $firstLoopDone = $false # Will change to true, once the function determines how many times it needs to loop, to retrieve all SDT entries.
        $httpVerb = "GET" # Define what HTTP operation will the script run.
        $resourcePath = "/sdt/sdts" # Define the resourcePath, based on what you're searching for.
        $queryParams = $null
        [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
        $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    }
    Process {
        If (-NOT($BlockLogging)) {
            $return = Add-EventLogSource -EventLogSource $EventLogSource

            If ($return -ne "Success") {
                $message = ("{0}: Unable to add event source ({1}). No logging will be performed." -f (Get-Date -Format s), $EventLogSource)
                Write-Host $message -ForegroundColor Yellow;

                $BlockLogging = $True
            }
        }

        $message = ("{0}: Beginning {1}." -f (Get-Date -Format s), $MyInvocation.MyCommand)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

        # Update $resourcePath to filter for a specific SDT entry, when a SDT ID is provided by the user.
        Switch ($PsCmdlet.ParameterSetName) {
            {$_ -eq "Id"} {
                $resourcePath += "/$Id"

                $message = ("{0}: Updated resource path to {1}." -f (Get-Date -Format s), $resourcePath)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
            }
        }

        # Build the filter, if any of the following conditions are met.
        Switch ($IsEffective, $SdtType) {
            {$_.IsPresent} {
                $filter += "isEffective:`"True`","

                $message = ("{0}: Updating `$filter variable in {1}. The value is {2}." -f (Get-Date -Format s), $($PsCmdlet.ParameterSetName), $queryParams)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

                Continue
            }
            {$_ -in 'ServiceSDT', 'CollectorSDT', 'DeviceDataSourceInstanceSDT', 'DeviceBatchJobSDT', 'DeviceClusterAlertDefSDT', 'DeviceDataSourceInstanceGroupSDT', 'DeviceDataSourceSDT', 'DeviceEventSourceSDT', 'DeviceGroupSDT', 'DeviceSDT', 'WebsiteCheckpointSDT', 'WebsiteGroupSDT', 'WebsiteSDT'} {
                $filter += "type:`"$sdtType`","

                $message = ("{0}: Updating `$filter variable in {1}. The value is {2}." -f (Get-Date -Format s), $($PsCmdlet.ParameterSetName), $queryParams)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

                Continue
            }
        }

        If ($PsCmdlet.ParameterSetName -eq "AdminName") {
            $filter += "admin:`"$AdminName`","

            $message = ("{0}: Updating `$filter variable in {1}. The value is {2}." -f (Get-Date -Format s), $($PsCmdlet.ParameterSetName), $queryParams)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
        }

        If (-NOT([string]::IsNullOrEmpty($filter))) {
            $filter = $filter.TrimEnd(",")
        }

        # Determine how many times "GET" must be run, to return all SDT entries, then loop through "GET" that many times.
        While ($currentBatchNum -lt $sdtBatchCount) {
            Switch ($PsCmdlet.ParameterSetName) {
                {$_ -in ("Id", "AllSdt")} {
                    If ([string]::IsNullOrEmpty($filter)) {
                        $queryParams = "?offset=$offset&size=$BatchSize&sort=id"
                    }
                    Else {
                        $queryParams = "?filter=$filter&offset=$offset&size=$BatchSize&sort=id"
                    }

                    $message = ("{0}: Updated `$queryParams variable in {1}. The value is {2}." -f (Get-Date -Format s), $($PsCmdlet.ParameterSetName), $queryParams)
                    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
                }
                "AdminName" {
                    If ([string]::IsNullOrEmpty($filter)) {
                        $queryParams = "?offset=$offset&size=$BatchSize&sort=id"
                    }
                    Else {
                        $queryParams = "?filter=$filter&offset=$offset&size=$BatchSize&sort=id"
                    }

                    $message = ("{0}: Updating `$queryParams variable in {1}. The value is {2}." -f (Get-Date -Format s), $($PsCmdlet.ParameterSetName), $queryParams)
                    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
                }
            }

            # Construct the query URL.
            $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

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
                $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                $headers.Add("Authorization", "LMv1 $accessId`:$signature`:$epoch")
                $headers.Add("Content-Type", 'application/json')
                $headers.Add("X-Version", 2)
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
                        $message = ("{0}: Unexpected error getting SDTs. To prevent errors, {1} will exit. PowerShell returned: {2}" -f (Get-Date -Format s), $MyInvocation.MyCommand, $_.Exception.Message)
                        If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417}

                        Return "Error"
                    }
                }
            }
            While ($stopLoop -eq $false)

            Switch ($PsCmdlet.ParameterSetName) {
                {$_ -in ("AllSdt", "AdminName")} {
                    $message = ("{0}: Entering switch statement for all-SDT retrieval." -f (Get-Date -Format s))
                    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

                    $sdts += $response.items

                    $message = ("{0}: There are {1} SDT entries in `$sdts." -f (Get-Date -Format s), $($sdts.count))
                    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

                    # The first time through the loop, figure out how many times we need to loop (to get all SDT entries).
                    If ($firstLoopDone -eq $false) {
                        [int]$sdtBatchCount = ((($response.total) / $BatchSize) + 1)

                        $message = ("{0}: {1} will query LogicMonitor {2} times to retrieve all SDT entries. LogicMonitor reports that there are {3} SDT entries." `
                                -f (Get-Date -Format s), $MyInvocation.MyCommand, $sdtBatchCount, $response.total)
                        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

                        $message = ("{0}: Completed the first loop." -f (Get-Date -Format s))
                        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
                    }

                    # Increment offset, to grab the next batch of SDT entries.
                    $message = ("{0}: Incrementing the search offset by {1}" -f (Get-Date -Format s), $BatchSize)
                    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

                    $offset += $BatchSize

                    $message = ("{0}: Retrieving data in batch #{1} (of {2})." -f (Get-Date -Format s), $currentBatchNum, $sdtBatchCount)
                    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

                    # Increment the variable, so we know when we have retrieved all SDT entries.
                    $currentBatchNum++
                }
                "Id" {
                    $message = ("{0}: Entering switch statement for single-SDT retrieval." -f (Get-Date -Format s))
                    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

                    $sdts = $response

                    Return $sdts

                    $message = ("{0}: There are {1} SDT entries in `$sdts." -f (Get-Date -Format s), $($sdts.count))
                    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
                }
            }
        }

        Return $sdts
    }
} #1.0.0.4