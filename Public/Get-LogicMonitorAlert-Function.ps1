Function Get-LogicMonitorAlert {
    <#
        .DESCRIPTION
            Retrieves Alert objects from LogicMonitor.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 16 January 2017
                - Initial release.
            V1.0.0.2 date: 10 February 2017
                - Updated procedure order.
            V1.0.0.3 date: 23 April 2018
                - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
                - Updated logging setup.
            V1.0.0.4 date: 14 March 2019
                - Added support for rate-limited re-try.
            V1.0.0.5 date: 10 April 2019
                - Updated filtering.
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Represents the subdomain of the LogicMonitor customer.
        .PARAMETER All
            When included, the cmdlet returns all open alerts, up to the LogicMonitor API limit (10000 as of 10 April 2019).
        .PARAMETER Filter
            Represents a hashtable of filterable alert properties and the value, for which to filter. Valid values are:
                'id', 'type', 'acked', 'rule', 'chain', 'severity', 'cleared', 'sdted', 'monitorObjectName', 'monitorObjectGroups', 'resourceTemplateName', 'instanceName', 'dataPointName'
            Invalid keys in the hashtable are removed before the query is run.
        .PARAMETER BatchSize
            Default value is 1000. Represents the number of alerts to request from LogicMonitor.
        .PARAMETER EventLogSource
            Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID <access ID> -AccessKey <access key> -AccountName <account name> -All -BlockLogging -Verbose

            In this example, the cmdlet gets all open alerts (up to 10000). Verbose output is sent to the session host only.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID <access ID> -AccessKey <access key> -AccountName <account name> -Filter @{"severity"="2"}

            In this example, the cmdlet gets all open alerts (up to 10000) at the warning threshold. Output is sent to the session host and event log.
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllAlerts')]
    Param (
        [Parameter(Mandatory = $True)]
        $AccessId,

        [Parameter(Mandatory = $True)]
        $AccessKey,

        [Parameter(Mandatory = $True)]
        $AccountName,

        [Parameter(Mandatory = $True, ParameterSetName = 'AllAlerts')]
        [switch]$All,

        [Parameter(Mandatory = $True, ParameterSetName = 'Filter')]
        [hashtable]$Filter,

        [int]$BatchSize = 1000,

        [string]$EventLogSource = 'LogicMonitorPowershellModule',

        [switch]$BlockLogging
    )

    If (-NOT($BlockLogging)) {
        $return = Add-EventLogSource -EventLogSource $EventLogSource

        If ($return -ne "Success") {
            $message = ("{0}: Unable to add event source ({1}). No logging will be performed." -f (Get-Date -Format s), $EventLogSource)
            Write-Verbose $message

            $BlockLogging = $True
        }
    }

    $message = ("{0}: Beginning {1}." -f (Get-Date -Format s), $MyInvocation.MyCommand)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

    # Initialize variables.
    $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    $batchCount = 0 # Counter so we know how many times we have looped through the request
    $firstLoopDone = $false # Will change to true, once the function determines how many times it needs to loop, to retrieve all alerts.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $resourcePath = "/alert/alerts" # Define the resourcePath.
    $hashstr = $null # Filter as a string.
    $alerts = $null
    $response = $null
    [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    Switch ($PsCmdlet.ParameterSetName) {
        "AllAlerts" {
            $message = ("{0}: Operating in the {1} parameter set." -f (Get-Date -Format s), $PsCmdlet.ParameterSetName)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

            While ($response.total -lt 0) {
                $message = ("{0}: The request loop has run {1} times." -f (Get-Date -Format s), $batchCount)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

                $queryParams = "?offset=$offset&size=$BatchSize&sort=id"

                # Construct the query URL.
                $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

                # Build header.
                If ($firstLoopDone -eq $false) {
                    $message = ("{0}: Building request header." -f (Get-Date -Format s))
                    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

                    # Get current time in milliseconds
                    $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

                    # Concatenate Request Details
                    $requestVars = $httpVerb + $epoch + $resourcePath

                    # Construct Signature
                    $hmac = New-Object System.Security.Cryptography.HMACSHA256
                    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($AccessKey)
                    $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
                    $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
                    $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

                    # Construct Headers
                    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                    $headers.Add("Authorization", "LMv1 $AccessId`:$signature`:$epoch")
                    $headers.Add("Content-Type", 'application/json')
                    $headers.Add("X-Version", 2)
                }

                # Make Request
                $message = ("{0}: Executing the REST query." -f (Get-Date -Format s))
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

                Do {
                    Try {
                        $response = Invoke-RestMethod -Uri $url -Method $httpverb -Header $headers -ErrorAction Stop

                        $stopLoop = $True
                    }
                    Catch {
                        If ($_.Exception.Message -match '429') {
                            $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f (Get-Date -Format s), $MyInvocation.MyCommand, $_.Exception.Message)
                            If ($BlockLogging) { Write-Host $message -ForegroundColor Yellow } Else { Write-Host $message -ForegroundColor Yellow; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Warning -Message $message -EventId 5417 }

                            Start-Sleep -Seconds 60
                        }
                        Else {
                            $message = ("{0}: Unexpected error getting alerts. To prevent errors, {1} will exit. PowerShell returned: {2}" -f (Get-Date -Format s), $MyInvocation.MyCommand, $_.Exception.Message)
                            If ($BlockLogging) { Write-Host $message -ForegroundColor Red } Else { Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417 }

                            Return "Error"
                        }
                    }
                }
                While ($stopLoop -eq $false)

                $alerts += $response.items

                $offset += $BatchSize
                $firstLoopDone = $true
                $batchCount++
            }

            Return $alerts
        }
        "Filter" {
            $message = ("{0}: Operating in the {1} parameter set." -f (Get-Date -Format s), $PsCmdlet.ParameterSetName)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

            Foreach ($key in $($Filter.keys)) {
                If ($key -notin 'id', 'type', 'acked', 'rule', 'chain', 'severity', 'cleared', 'sdted', 'monitorObjectName', 'monitorObjectGroups', 'resourceTemplateName', 'instanceName', 'dataPointName') {
                    $message = ("{0}: Unable to filter by {1}, removing the entry." -f (Get-Date -Format s), $key)
                    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

                    $filter.remove($key)
                }
            }

            $message = ("{0}: Converting special characters to URL encoding." -f (Get-Date -Format s))
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

            ($filter.Clone()).keys | ForEach-Object {
                $filter.$_ = ($filter.$_).Replace('"', '%2522')
                $filter.$_ = ($filter.$_).Replace('&', '%26')
                $filter.$_ = ($filter.$_).Replace("`r`n", "`n")
                $filter.$_ = ($filter.$_).Replace('#', '%23')
                $filter.$_ = ($filter.$_).Replace("`n", '%0A')
                $filter.$_ = ($filter.$_).Replace(')', '%29')
                $filter.$_ = ($filter.$_).Replace('(', '%28')
                $filter.$_ = ($filter.$_).Replace('>', '%3E')
                $filter.$_ = ($filter.$_).Replace('<', '%3C')
                $filter.$_ = ($filter.$_).Replace('/', '%2F')
                $filter.$_ = ($filter.$_).Replace(',', '%2C')
                $filter.$_ = ($filter.$_).Replace('*', '%2A')
                $filter.$_ = ($filter.$_).Replace('!', '%21')
                $filter.$_ = ($filter.$_).Replace('=', '%3D')
                $filter.$_ = ($filter.$_).Replace('~', '%7E')
                $filter.$_ = ($filter.$_).Replace(' ', '%20')
                $filter.$_ = ($filter.$_).Replace('|', '%7C')
                $filter.$_ = ($filter.$_).Replace('$', '%24')
                $filter.$_ = ($filter.$_).Replace('\', '%5C')
                $filter.$_ = ($filter.$_).Replace('_', '%5F')
            }

            $message = ("{0}: Converting the filter hashtable to a string." -f (Get-Date -Format s))
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

            foreach ($key in $($filter.keys)) {
                $hashstr += $key + ":" + "`"$($filter[$key])`"" + ","
            }
            $hashstr = $hashstr.trimend(',')

            # Determine how many times "GET" must be run, to return all alerts, then loop through "GET" that many times.
            While ($response.total -lt 0) {
                $message = ("{0}: The request loop has run {1} times." -f (Get-Date -Format s), $batchCount)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

                $queryParams = "?filter=$hashstr&offset=$offset&size=$BatchSize&sort=id"

                $message = ("{0}: Updated `$queryParams variable. The value is {2}." -f (Get-Date -Format s), $($PsCmdlet.ParameterSetName), $queryParams)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                # Construct the query URL.
                $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

                # Build header.
                If ($firstLoopDone -eq $false) {
                    $message = ("{0}: Building request header." -f (Get-Date -Format s))
                    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

                    # Get current time in milliseconds
                    $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

                    # Concatenate Request Details
                    $requestVars = $httpVerb + $epoch + $resourcePath

                    # Construct Signature
                    $hmac = New-Object System.Security.Cryptography.HMACSHA256
                    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($AccessKey)
                    $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
                    $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
                    $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

                    # Construct Headers
                    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                    $headers.Add("Authorization", "LMv1 $AccessId`:$signature`:$epoch")
                    $headers.Add("Content-Type", 'application/json')
                    $headers.Add("X-Version", 2)
                }

                # Make Request
                $message = ("{0}: Executing the REST query." -f (Get-Date -Format s))
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

                Do {
                    Try {
                        $response = Invoke-RestMethod -Uri $url -Method $httpverb -Header $headers -ErrorAction Stop

                        $stopLoop = $True
                    }
                    Catch {
                        If ($_.Exception.Message -match '429') {
                            $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f (Get-Date -Format s), $MyInvocation.MyCommand, $_.Exception.Message)
                            If ($BlockLogging) { Write-Host $message -ForegroundColor Yellow } Else { Write-Host $message -ForegroundColor Yellow; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Warning -Message $message -EventId 5417 }

                            Start-Sleep -Seconds 60
                        }
                        Else {
                            $message = ("{0}: Unexpected error getting alerts. To prevent errors, {1} will exit. PowerShell returned: {2}" -f (Get-Date -Format s), $MyInvocation.MyCommand, $_.Exception.Message)
                            If ($BlockLogging) { Write-Host $message -ForegroundColor Red } Else { Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417 }

                            Return "Error"
                        }
                    }
                }
                While ($stopLoop -eq $false)

                $alerts += $response.items

                $offset += $BatchSize
                $firstLoopDone = $true
                $batchCount++
            }

            Return $alerts
        }
    }
} #1.0.0.5