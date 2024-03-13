Function Get-LogicMonitorEventSource {
    <#
        .DESCRIPTION
            Returns a list of LogicMonitor EventSources. By default, the function returns all EventSources. If a EventSource ID or name is provided, the function will 
            return properties for the specified EventSource.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 24 December 2020
                - Initial release.
            V2023.04.28.0
            V2023.08.23.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Id
            Represents the ID of the desired EventSource.
        .PARAMETER DisplayName
            Represents the display name of the desired EventSource.
        .PARAMETER ApplyTo
            Represents the 'apply to' expression of the desired EventSource(s).
        .PARAMETER BatchSize
            Default value is 1000. Represents the number of DataSoruces to request from LogicMonitor, in a single batch.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorEventSources -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Verbose

            In this example, the function will search for all monitored devices and will return their properties. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorEventSources -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -EventSourceId 6

            In this example, the function returns the EventSource with ID '6'.
        .EXAMPLE
            PS C:\> Get-LogicMonitorEventSources -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DisplayName 'Oracle Library Cache'

            In this example, the function returns the EventSource with display name 'Oracle Library Cache'.
        .EXAMPLE
            PS C:\> Get-LogicMonitorEventSources -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -ApplyTo 'system.hostname =~ "255.1.1.1"'

            In this example, the function returns the EventSource with the 'appliesTo' filter 'system.hostname =~ "255.1.1.1"'.
        .EXAMPLE
            PS C:\> Get-LogicMonitorEventSources -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -ApplyTo 'isWindows()&&hasCategory("collector")'

            In this example, the function returns the EventSource with the 'appliesTo' filter 'isWindows()&&hasCategory("collector")'.
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllEventSources')]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [SecureString]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'IDFilter')]
        [Int]$Id,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [String]$DisplayName,

        [Parameter(Mandatory, ParameterSetName = 'AppliesToFilter')]
        [String]$ApplyTo,

        [Int]$BatchSize = 1000,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    #region Initialize variables
    $eventSources = [System.Collections.Generic.List[PSObject]]::new() # Create a collection to hold the EventSources.
    [int]$offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    [string]$httpVerb = "GET" # Define what HTTP operation will the script run.
    [string]$resourcePath = "/setting/eventsources" # Define the resourcePath.
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

    #region URL prep
    Switch ($PsCmdlet.ParameterSetName) {
        "NameFilter" {
            $DisplayName = $DisplayName.Replace('_', '%5F')
            $DisplayName = $DisplayName.Replace(' ', '%20')

            $filter = "name:`"$DisplayName`""
        }
        "AppliesToFilter" {
            # Replace special characters to better encode the URL.
            $ApplyTo = $ApplyTo.Replace('"', '%2522')
            $ApplyTo = $ApplyTo.Replace('&', '%26')
            $ApplyTo = $ApplyTo.Replace("`r`n", "`n")
            $ApplyTo = $ApplyTo.Replace('#', '%23')
            $ApplyTo = $ApplyTo.Replace("`n", '%0A')
            $ApplyTo = $ApplyTo.Replace(')', '%29')
            $ApplyTo = $ApplyTo.Replace('(', '%28')
            $ApplyTo = $ApplyTo.Replace('>', '%3E')
            $ApplyTo = $ApplyTo.Replace('<', '%3C')
            $ApplyTo = $ApplyTo.Replace('/', '%2F')
            $ApplyTo = $ApplyTo.Replace(',', '%2C')
            $ApplyTo = $ApplyTo.Replace('*', '%2A')
            $ApplyTo = $ApplyTo.Replace('!', '%21')
            $ApplyTo = $ApplyTo.Replace('=', '%3D')
            $ApplyTo = $ApplyTo.Replace('~', '%7E')
            $ApplyTo = $ApplyTo.Replace(' ', '%20')
            $ApplyTo = $ApplyTo.Replace('|', '%7C')
            $ApplyTo = $ApplyTo.Replace('$', '%24')
            $ApplyTo = $ApplyTo.Replace('\', '%5C')
            $ApplyTo = $ApplyTo.Replace('_', '%5F')

            $filter = "appliesTo:`"$ApplyTo`""
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

        $stopLoop = $false
        Do {
            Try {
                $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop

                $stopLoop = $True
            } Catch {
                If ($_.Exception.Message -match '429') {
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                    Out-PsLogging @loggingParams -MessageType Warning -Message $message

                    Start-Sleep -Seconds 60
                } ElseIf ($_.ErrorDetails -match 'invalid filter') {
                    $message = ("{0}: LogicMonitor returned `"invalid filter`". Please validate the value of the -Filter parameter and try again." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                    Out-PsLogging @loggingParams -MessageType Error -Message $message

                    Return "Error"
                } Else {
                    $message = ("{0}: Unexpected error getting EventSource. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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

        If ($response.items.Count -gt 0) {
            $message = ("{0}: Retrieved {1} EventSources of {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $response.items.Count, $response.total)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            Foreach ($item in $response.items) {
                $eventSources.Add($item)
            }

            If (($response.items.Count -eq 1) -or ($response.total -and ($response.total -eq $eventSources.id.Count))) {
                $message = ("{0}: Retrieved all EventSources." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                $stopLoop = $true
            } Else {
                # Increment offset, to grab the next batch of devices.
                $message = ("{0}: Incrementing the search offset by {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $BatchSize)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                $offset += $BatchSize
                $stopLoop = $false
            }
        } ElseIf ($response.id) {
            $eventSources = $response
            $stopLoop = $true
        } Else {
            $message = ("{0}: The `$response variable is empty." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $stopLoop = $true
        }

        $message = ("{0}: There are {1} EventSources in `$eventSources." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $eventSources.id.Count)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    } Until (($response.total -eq $eventSources.id.Count) -or ($response.id.Count -eq $eventSources.id.Count))

    Return $eventSources
} #2023.08.23.0