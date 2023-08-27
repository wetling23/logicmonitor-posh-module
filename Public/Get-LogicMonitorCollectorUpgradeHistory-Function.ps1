Function Get-LogicMonitorCollectorUpgradeHistory {
    <#
        .DESCRIPTION
            Retrieves collector upgrade status from LogicMonitor.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 10 August 2018
                - Initial release.
            V1.0.0.1 date: 7 September 2018
                - Fixed bug preventing correct history output.
                - Fixed bug stopping the retrieval loop prematurely.
            V1.0.0.2 date: 18 October 2018
                - Replaced "alert rules" references with "histories".
            V1.0.0.3 date: 14 March 2019
                - Added support for rate-limited re-try.
            V1.0.0.4 date: 23 August 2019
            V1.0.0.5 date: 26 August 2019
            V1.0.0.6 date: 18 October 2019
            V1.0.0.7 date: 4 December 2019
            V1.0.0.8 date: 15 May 2020
            V1.0.0.9 date: 23 July 2020
            V2023.06.12.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER BatchSize
            Default value is 1000. Represents the number of histories to request from LogicMonitor.
        .PARAMETER Version
            Represents the value of "newVersion", for which to filter. When ommitted, the command retrieves all histories, regarless of collector version.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorCollectorUpgradeHistory -AccessID <access ID> -AccessKey <access key> -AccountName <account name> -Verbose

            In this example, the function gets upgrade history for all collectors, in batches of 1000. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorCollectorUpgradeHistory -AccessID <access ID> -AccessKey <access key> -AccountName <account name> -Version 28.005

            In this example, the function gets upgrade history for all collectors, where "newVersion" is 28.005, in batches of 1000. Limited logging is written only to the console host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorCollectorUpgradeHistory -AccessID <accessID> -AccessKey <accessKey> -AccountName <accountName> -Filter 'filter=status!:0' -Verbose

            In this example, the command gets the properties of all collector upgrade histories where the status property is not 0. Verbose logging output is sent only to the host.
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllCollectors')]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [securestring]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'Version')]
        [Decimal]$Version,

        [Parameter(Mandatory, ParameterSetName = 'StringFilter')]
        [String]$Filter,

        [Int]$BatchSize = 1000,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    #region Initialize variables
    $histories = [System.Collections.Generic.List[PSObject]]::New() # Primary collection to be filled with Invoke-RestMethod response.
    $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $resourcePath = "/setting/collector/collectors/upgradeHistory" # Define the resourcePath, based on the type of query you are doing.
    $queryParams = $null
    [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
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

    #region Update filter/resourcePath
    Switch ($PsCmdlet.ParameterSetName) {
        "Version" {
            $filter = "filter=newVersion:`"$Version`""

            $filter = [regex]::Replace(
                $Filter,
                '(?<=[:|><~]").*?(?=")',
                {
                    param($m)
                    [Uri]::EscapeDataString($m.Value)
                }
            )

            $message = ("{0}: After parsing, the filter is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Filter)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
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

            $message = ("{0}: After parsing, the filter is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Filter)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
        }
    }
    #endregion Update filter/resourcePath

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

    #region Execute REST query
    Do {
        If ($Filter) {
            $queryParams = "?$Filter&offset=$offset&size=$BatchSize&sort=id"
        } Else {
            $queryParams = "?offset=$offset&size=$BatchSize&sort=id"
        }

        # Construct the query URL.
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

        $message = ("{0}: Connecting to: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $url)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        $stopLoop = $false
        Do {
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
                    $message = ("{0}: Unexpected error getting histories. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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

        If ($response.items.Count -gt 0) {
            $message = ("{0}: Retrieved {1} histories of {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $response.items.Count, $response.total)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            Foreach ($item in $response.items) {
                $histories.Add($item)
            }

            If (($response.items.Count -eq 1) -or ($response.total -and ($response.total -eq $histories.id.Count))) {
                $message = ("{0}: Retrieved all histories." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                $stopLoop = $true
            } Else {
                # Increment offset, to grab the next batch of histories.
                $message = ("{0}: Incrementing the search offset by {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $BatchSize)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                $offset += $BatchSize
                $stopLoop = $false
            }
        } ElseIf ($response.id) {
            $histories = $response
            $stopLoop = $true
        } Else {
            $message = ("{0}: The `$response variable is empty." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $stopLoop = $true
        }

        $message = ("{0}: There are {1} histories in `$histories." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $histories.id.Count)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    } Until ($stopLoop -eq $true)
    #endregion Execute REST query

    #region Output
    Return $histories
    #endregion Output
} #2023.06.12.0