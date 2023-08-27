Function Get-LogicMonitorEscalationChain {
    <#
        .DESCRIPTION
            Returns a list of LogicMonitor escalation chains. By default, the function returns all escalation chains. 
            If an escalation chain ID or name is provided, the function will return properties for the specified escalation chain.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 29 July 2020
            V2023.04.28.0
            V2023.08.27.0
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
    $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $resourcePath = "/setting/alert/chains" # Define the resourcePath, based on the type of device you're searching for.
    $queryParams = $null
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
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

    $message = ("{0}: Operating in the {1} parameter set." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $PsCmdlet.ParameterSetName)
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

    #region URL prep
    Switch ($PsCmdlet.ParameterSetName) {
        "NameFilter" {
            $message = ("{0}: URL encoding special characters in the filter." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $Name = [uri]::EscapeDataString($Name)

            # Per LM support (https://www.logicmonitor.com/support/rest-api-developers-guide/v2/rest-api-v2-overview), the + character needs to be double encoded.
            $Name = $Name.replace('%2B', '%252B')

            $filter = "name:`"$Name`""
        }
        "StringFilter" {
            $message = ("{0}: URL encoding special characters in the filter." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $Filter = [regex]::Replace(
                $Filter,
                '(?<=[:|><~]").*?(?=")',
                {
                    param($m)
                    [Uri]::EscapeDataString($m.Value)
                }
            )

            $filter = $filter.Replace('filter=','')
        }
        "IDFilter" {
            $resourcePath += "/$Id"
        }
    }
    #endregion URL prep

    #region Auth and headers
    # Get current time in milliseconds.
    $epoch = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End (Get-Date).ToUniversalTime()).TotalMilliseconds)
    $requestVars = $httpVerb + $epoch + $resourcePath
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

    $stopLoop = $false
    Do {
        If ([string]::IsNullOrEmpty($filter)) {
            $queryParams = "?offset=$offset&size=$BatchSize&sort=id"
        } Else {
            $queryParams = "?filter=$filter&offset=$offset&size=$BatchSize&sort=id"
        }

        # Construct the query URL.
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

        $message = ("{0}: Connecting to: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $url)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        Try {
            $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop

            $stopLoop = $True
        } Catch {
            If ($_.Exception.Message -match '429') {
                $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                Out-PsLogging @loggingParams -MessageType Warning -Message $message

                Start-Sleep -Seconds 60
            } ElseIf ($_.ErrorDetails -match 'invalid filter') {
                $message = ("{0}: LogicMonitor returned `"invalid filter`". Please validate the value of the -Filter parameter and try again." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                Out-PsLogging @loggingParams -MessageType Error -Message $message

                Return "Error"
            } Else {
                $message = ("{0}: Unexpected error getting escalation chains. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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

        If ($response.items.Count -gt 0) {
            $message = ("{0}: Retrieved {1} escalation chains of {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $response.items.Count, $response.total)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            Foreach ($item in $response.items) {
                $chains.Add($item)
            }

            If (($response.items.Count -eq 1) -or ($response.total -and ($response.total -eq $chains.id.Count))) {
                $message = ("{0}: Retrieved all escalation chains." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                $stopLoop = $true
            } Else {
                # Increment offset, to grab the next batch of escalation chains.
                $message = ("{0}: Incrementing the search offset by {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $BatchSize)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                $offset += $BatchSize
                $stopLoop = $false
            }
        } ElseIf ($response.id) {
            $chains = $response
            $stopLoop = $true
        } Else {
            $message = ("{0}: The `$response variable is empty." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $stopLoop = $true
        }

        $message = ("{0}: There are {1} escalation chains in `$chains." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $chains.id.Count)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    } While ($stopLoop -eq $false)

    $chains
} #2023.08.27.0