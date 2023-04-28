Function Get-LogicMonitorEscalationChain {
    <#
        .DESCRIPTION
            Returns a list of LogicMonitor escalation chains. By default, the function returns all escalation chains. 
            If an escalation chain ID or name is provided, the function will return properties for the specified escalation chain.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 29 July 2020
            V2023.04.28.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Id
            Represents the ID of the desired escalation chain.
        .PARAMETER Name
            Represents name of the desired escalation chain.
        .PARAMETER Filter
            Represents a string matching the API's filter format. This parameter can be used to filter for escalation chains matching certain criteria (e.g. "True" appears in enableThrottling property).
        .PARAMETER BatchSize
            Default value is 1000. Represents the number of escalation chains to request from LogicMonitor, in a single batch.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorEscalationChain -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Verbose

            In this example, the function will return all escalation chains. Verbose logging output will be sent to the host only.
        .EXAMPLE
            PS C:\> Get-LogicMonitorEscalationChain -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6

            In this example, the function will return the escalation chain with ID 6. Limited logging output will be sent to the host only.
        .EXAMPLE
            PS C:\> Get-LogicMonitorEscalationChain -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Name default -LogPath C:\Temp\log.txt

            In this example, the function will return the escalation chain with name "default". Limited logging output will be sent to the host and C:\Temp.log.txt.
        .EXAMPLE
            PS C:\> Get-LogicMonitorEscalationChain -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Filter "filter=throttlingPeriod:15" -LogPath C:\Temp\log.txt -Verbose

            In this example, the function will return the escalation chains with the throttlingPeriod is 15. Verbose logging output will be sent to the host and C:\Temp.log.txt.
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllChains')]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [Securestring]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'IDFilter')]
        [Int]$Id,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [String]$Name,

        [Parameter(Mandatory, ParameterSetName = 'StringFilter')]
        [String]$Filter,

        [Int]$BatchSize = 1000,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    #region Initialize variables
    $chains = [System.Collections.Generic.List[PSObject]]::New() # Primary collection to be filled with Invoke-RestMethod response.
    $singleChainCheckDone = $false # Controls when a Do loop exits, if we are getting a single escalation chain.
    $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    $firstLoopDone = $false # Will change to true, once the function determines how many times it needs to loop, to retrieve all escalation chains.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $resourcePath = "/setting/alert/chains" # Define the resourcePath, based on the type of device you're searching for.
    $queryParams = $null
    $pattern1 = '[^a-zA-Z\d\s]' # Match any non-alpha numeric or white space character.
    $pattern2 = '(?:>:|<:|:|>|<|!:|:|~|!~)(?:")(.*?)(?:")(\+)' # Allow us to replace characters in the filter. We will leave some of the characters alone, since they are used by the API in certain spots. For example, ":" means equal between the property name and value but should be replaced in the value portion of the pair.
    $regex = [Regex]::new($pattern2)
    #%2B
    [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    #endregion Initialize variables

    #region Logging splatting
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
    #endregion Logging splatting

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    Out-PsLogging @loggingParams -MessageType First -Message $message
    #endregion Setup

    $message = ("{0}: Operating in the {1} parameter set." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $PsCmdlet.ParameterSetName)
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

    #region Construct parameters
    # Update $resourcePath to filter for a specific device, when a device ID is provided by the user.
    If ($PsCmdlet.ParameterSetName -eq "IDFilter") {
        $resourcePath += "/$Id"

        $message = ("{0}: Updated resource path to {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    }
    #endregion Construct parameters

    #region Get data
    Do {
        Switch ($PsCmdlet.ParameterSetName) {
            { $_ -in ("IDFilter", "AllChains") } {
                $queryParams = "?offset=$offset&size=$BatchSize&sort=id"

                $message = ("{0}: Updated `$queryParams variable in {1}. The value is {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $($PsCmdlet.ParameterSetName), $queryParams)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
            }
            "NameFilter" {
                If ($Name -match $pattern1) {
                    $message = ("{0}: URL encoding special characters in the filter." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                    $regex.Matches($Name) | ForEach-Object {
                        $Name = $Name -replace ([regex]::Escape($_.Groups[1].value)), ([uri]::EscapeDataString($_.Groups[1].value))
                    }

                    # Per LM support (https://www.logicmonitor.com/support/rest-api-developers-guide/v2/rest-api-v2-overview), the + character needs to be double encoded.
                    $Name = $Name.replace('+', '%252B')

                    $message = ("{0}: After parsing, the filter is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Filter)
                    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
                }

                $queryParams = "?filter=name:`"$Name`"&offset=$offset&size=$BatchSize&sort=id"

                $message = ("{0}: Updated `$queryParams variable in {1}. The value is {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $($PsCmdlet.ParameterSetName), $queryParams)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
            }
            "StringFilter" {
                If ($Filter -match $pattern1) {
                    $message = ("{0}: URL encoding special characters in the filter." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                    $regex.Matches($Filter) | ForEach-Object {
                        $Filter = $Filter -replace ([regex]::Escape($_.Groups[1].value)), ([uri]::EscapeDataString($_.Groups[1].value))
                    }

                    $message = ("{0}: After parsing, the filter is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Filter)
                    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
                }

                $queryParams = "?$Filter&offset=$offset&size=$BatchSize&sort=id"
            }
        }

        # Construct the query URL.
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

        If ($firstLoopDone -eq $false) {
            $message = ("{0}: Building request header." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            # Get current time in milliseconds.
            $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

            # Concatenate request details.
            $requestVars = $httpVerb + $epoch + $resourcePath

            # Construct signature.
            $hmac = New-Object System.Security.Cryptography.HMACSHA256
            $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
            $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
            $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
            $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

            # Construct headers.
            $headers = @{
                "Authorization" = "LMv1 $AccessId`:$signature`:$epoch"
                "Content-Type"  = "application/json"
                "X-Version"     = 3
            }
        }

        Switch ($PsCmdlet.ParameterSetName) {
            "AllChains" {
                $message = ("{0}: Entering switch statement for all-esclation chain retrieval." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                $message = ("{0}: Executing the REST query." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                $stopLoop = $false
                Do {
                    Try {
                        $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop

                        $stopLoop = $True
                        $firstLoopDone = $True

                        Foreach ($item in $response.items) {
                            $chains.Add($item)
                        }
                    }
                    Catch {
                        If ($_.Exception.Message -match '429') {
                            $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                            { Out-PsLogging @loggingParams -MessageType Warning -Message $message }

                            Start-Sleep -Seconds 60
                        }
                        Else {
                            $message = ("{0}: Unexpected error getting devices. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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
                }
                While ($stopLoop -eq $false)

                If (($null -ne $response) -and ($chains.id.Count -lt $response.total)) {
                    $message = ("{0}: There are {1} escalation chains in `$chains." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $chains.count)
                    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                    # Increment offset, to grab the next batch of escalation chains.
                    $message = ("{0}: Incrementing the search offset by {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $BatchSize)
                    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                    $offset += $BatchSize
                    $stopLoop = $false
                }
            }
            # If an escalation chain ID or name is provided...
            { $_ -in ("IDFilter", "NameFilter", "StringFilter") } {
                $message = ("{0}: Entering switch statement for single-escalation chain retrieval." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                # Make Request
                $message = ("{0}: Executing the REST query." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                $stopLoop = $false
                Do {
                    Try {
                        $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop

                        $stopLoop = $True
                        $firstLoopDone = $True
                        $singleInstanceCheckDone = $True

                        If ($response.id) {
                            $chains.Add($item)
                        } Else {
                            Foreach ($item in $response.items) {
                                $chains.Add($item)
                            }
                        }
                    }
                    Catch {
                        If ($_.Exception.Message -match '429') {
                            $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                            { Out-PsLogging @loggingParams -MessageType Warning -Message $message }

                            Start-Sleep -Seconds 60
                        }
                        Else {
                            $message = ("{0}: Unexpected error getting device. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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
                }
                While ($stopLoop -eq $false)

                $message = ("{0}: There are {1} escalation chains in `$chains." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $chains.count)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
            }
        }
    }
    Until (($stopLoop -eq $true) -or ($singleInstanceCheckDone))
    #endregion Get data

    $chains
} #2023.04.28.0