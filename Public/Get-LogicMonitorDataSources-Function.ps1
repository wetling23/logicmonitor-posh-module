Function Get-LogicMonitorDataSources {
    <#
        .DESCRIPTION 
            Returns a list of LogicMonitor DataSources. By default, the function returns all datasources. If a DataSource ID or name is provided, the function will 
            return properties for the specified DataSource.
        .NOTES 
            Author: Mike Hashemi
            V1.0.0.0 date: 5 March 2017
                - Initial release.
                - Bug in the AppliesToFilter parameter set. Engaged LogicMonitor for support.
            V1.0.0.2 date: 3 May 2017
                - Removed code from writing to file and added Event Log support.
                - Updated code for verbose logging.
                - Changed Add-EventLogSource failure behavior to just block logging (instead of quitting the function).
            V1.0.0.3 date: 21 June 2017
                - Updated logging to reduce chatter.
            V1.0.0.4 date: 1 August 2017
                - Updated code to support XML output when a DataSource ID is provided.
            V1.0.0.5 date: 18 August 2017
                - Changed the "AppliesTo" query filter.
            V1.0.0.6 date: 23 April 2018
                - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
            V1.0.0.7 date: 15 May 2018
                - Fixed typo in the cmdlet name.
            V1.0.0.8 date: 14 June 2018
                - Updated whitespace.
            V1.0.0.9 date: 21 June 2018
                - Added encoding of &, to UTF-8.
                - Added example.
        .LINK
            https://git.synoptek.com/tools-group/logicmonitor/Synoptek.LogicMonitor.PowershellModule
        .PARAMETER AccessId
            Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER DataSourceId
            Represents the ID of the desired DataSource.
        .PARAMETER XmlOutput
            When included, the function will request XML output from LogicMonitor. The switch is only available when a DataSource ID is specified.
        .PARAMETER DataSourceDisplayName
            Represents the display name of the desired DataSource.
        .PARAMETER DataSourceApplyTo
            Represents the "AppliesTo" filter of the desired DataSource.
        .PARAMETER BatchSize
            Default value is 950. Represents the number of DataSoruces to request from LogicMonitor, in a single batch.
        .PARAMETER EventLogSource
            Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDataSources -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName>

            In this example, the function will search for all monitored devices and will return their properties.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDataSources -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DataSourceId 6

            In this example, the function returns the DataSource with ID '6'.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDataSources -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DataSourceId 6 -XmlOutput

            In this example, the function returns the DataSource with ID '6', in XML format.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDataSources -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DataSourceDisplayName 'Oracle Library Cache'

            In this example, the function returns the DataSource with display name 'Oracle Library Cache'.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDataSources -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DataSourceApplyTo 'system.hostname =~ "255.1.1.1"'

            In this example, the function returns the DataSource with the 'appliesTo' filter 'system.hostname =~ "255.1.1.1"'.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDataSources -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DataSourceApplyTo 'isWindows()&&hasCategory("collector")'

            In this example, the function returns the DataSource with the 'appliesTo' filter 'isWindows()&&hasCategory("collector")'.
    #>
    [CmdletBinding(DefaultParameterSetName = ’AllDataSources’)]
    Param (
        [Parameter(Mandatory = $True)]
        $AccessId,

        [Parameter(Mandatory = $True)]
        $AccessKey,

        [Parameter(Mandatory = $True)]
        $AccountName,

        [Parameter(Mandatory = $True, ParameterSetName = ’IDFilter’)]
        [int]$DataSourceId,

        [Parameter(ParameterSetName = ’IDFilter’)]
        [switch]$XmlOutput,

        [Parameter(Mandatory = $True, ParameterSetName = 'DisplayNameFilter')]
        [string]$DataSourceDisplayName,

        [Parameter(Mandatory = $True, ParameterSetName = 'AppliesToFilter')]
        [string]$DataSourceApplyTo,

        [int]$BatchSize = 950,

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
    If ($BlockLogging) {Write-Host $message -ForegroundColor White} Else {Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

    $message = ("{0}: Operating in the {1} parameter set." -f (Get-Date -Format s), $PsCmdlet.ParameterSetName)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

    # Initialize variables.
    [int]$currentBatchNum = 0 # Start at zero and increment in the while loop, so we know how many times we have looped.
    [int]$offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    [int]$dataSourceBatchCount = 1 # Define how many times we need to loop, to get all DataSource.
    [boolean] $firstLoopDone = $false # Will change to true, once the function determines how many times it needs to loop, to retrieve all DataSources.
    [string]$httpVerb = "GET" # Define what HTTP operation will the script run.
    [string]$resourcePath = "/setting/datasources" # Define the resourcePath.
    $queryParams = $null
    $dataSources = $null
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    $message = ("{0}: The resource path is: {1}." -f (Get-Date -Format s), $resourcePath)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

    # Update $resourcePath to filter for a specific DataSource, when a DataSource ID is provided by the user.
    If ($PsCmdlet.ParameterSetName -eq "IDFilter") {
        $resourcePath += "/$DataSourceId"

        $message = ("{0}: Updated resource path to {1}." -f (Get-Date -Format s), $resourcePath)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
    }

    # Determine how many times "GET" must be run, to return all DataSources, then loop through "GET" that many times.
    While ($currentBatchNum -lt $dataSourceBatchCount) {
        Switch ($PsCmdlet.ParameterSetName) {
            "AllDataSources" {
                $queryParams = "?offset=$offset&size=$BatchSize&sort=id"

                $message = ("{0}: Updating `$queryParams variable in {1}. The value is {2}." -f (Get-Date -Format s), $($PsCmdlet.ParameterSetName), $queryParams)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
            }
            "IDFilter" {
                If ($XmlOutput) {
                    $queryParams = "?format=xml&offset=$offset&size=$BatchSize&sort=id"
                }
                Else {
                    $queryParams = "?offset=$offset&size=$BatchSize&sort=id"
                }

                $message = ("{0}: Updating `$queryParams variable in {1}. The value is {2}." -f (Get-Date -Format s), $($PsCmdlet.ParameterSetName), $queryParams)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
            }
            "DisplayNameFilter" {
                $queryParams = "?filter=displayName:$DataSourceDisplayName&offset=$offset&size=$BatchSize&sort=id"

                $message = ("{0}: Updating `$queryParams variable in {1}. The value is {2}." -f (Get-Date -Format s), $($PsCmdlet.ParameterSetName), $queryParams)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
            }
            "AppliesToFilter" {
                # Need to encode the ampersands in UTF-8, so the API will interpret them correctly.
                If ($DataSourceApplyTo -match '&') {
                    $DataSourceApplyTo = $DataSourceApplyTo.Replace("&", "%26")
                }
                $queryParams = "?filter=appliesTo:$DataSourceApplyTo&offset=$offset&size=$BatchSize&sort=id"

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
        }

        # Make Request
        $message = ("{0}: Executing the REST query." -f (Get-Date -Format s))
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

        Try {
            $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop
        }
        Catch {
            $message = ("{0}: It appears that the web request failed. Check your credentials and try again. To prevent errors, {1} function will exit. The specific error message is: {2}" `
                    -f (Get-Date -Format s), $MyInvocation.MyCommand, $_.Message.Exception)
            If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417}
        
            Return
        }

        Switch ($PsCmdlet.ParameterSetName) {
            "AllDataSources" {
                $message = ("{0}: Entering switch statement for all-DataSource retrieval." -f (Get-Date -Format s))
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

                # If no DataSource ID is provided...
                $dataSources += $response.data.items

                $message = ("{0}: There are {1} DataSources in `$dataSources." -f (Get-Date -Format s), $($dataSources.count))
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

                # The first time through the loop, figure out how many times we need to loop (to get all DataSources).
                If ($firstLoopDone -eq $false) {
                    [int]$dataSourceBatchCount = ((($response.data.total) / $BatchSize) + 1)

                    $message = ("{0}: The function will query LogicMonitor {1} times to retrieve all DataSources. LogicMonitor reports that there are {2} DataSources." `
                            -f (Get-Date -Format s), $dataSourceBatchCount, $response.data.total)
                    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
                }

                # Increment offset, to grab the next batch of DataSources.
                $message = ("{0}: Incrementing the search offset by {1}" -f (Get-Date -Format s), $BatchSize)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

                $offset += $BatchSize

                $message = ("{0}: Retrieving data in batch #{1} (of {2})." -f (Get-Date -Format s), $currentBatchNum, $dataSourceBatchCount)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

                # Increment the variable, so we know when we have retrieved all DataSources.
                $currentBatchNum++
            }
            {$_ -in ("IDFilter", "DisplayNameFilter", "AppliesToFilter")} {
                $message = ("{0}: Entering switch statement for single-DataSource retrieval." -f (Get-Date -Format s))
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

                If ($XmlOutput) {
                    $dataSources = $response
                }
                Else {
                    $dataSources = $response.data ###Should this be $response.data.items? What about just for displaynamefilter and appliestofilter
                }

                $message = ("{0}: There are {1} DataSources in `$dataSources." -f (Get-Date -Format s), $($dataSources.count))
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

                # The first time through the loop, figure out how many times we need to loop (to get all DataSources).
                If ($firstLoopDone -eq $false) {
                    [int]$dataSourceBatchCount = ((($response.data.total) / 250) + 1)

                    $message = ("{0}: The function will query LogicMonitor {1} times to retrieve all DataSources." -f (Get-Date -Format s), $dataSourceBatchCount)
                    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

                    $firstLoopDone = $True

                    $message = ("{0}: Completed the first loop." -f (Get-Date -Format s))
                    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
                }

                $message = ("{0}: Retrieving data in batch #{1} (of {2})." -f (Get-Date -Format s), $currentBatchNum, $dataSourceBatchCount)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

                # Increment the variable, so we know when we have retrieved all DataSources.
                $currentBatchNum++
            }
        }
    }

    Return $dataSources
} #1.0.0.9