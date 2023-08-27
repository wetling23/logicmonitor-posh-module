Function Get-LogicMonitorTopology {
    <#
        .DESCRIPTION
            Returns LogicMonitor topology data for a give device.
        .NOTES
            Author: Mike Hashemi
            V2023.06.15.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Id
            Represents Id of the device(s) for which the cmdlet will retrieve topology data.
        .PARAMETER Name
            Represents name of the device(s) for which the cmdlet will retrieve topology data (note, displayName not supported).
        .PARAMETER Filter
            Represents a string matching the API's filter format. This parameter can be used to filter for devices matching certain criteria (e.g. "Microsoft Windows Server 2012 R2 Standard" appears in systemProperties).

            See https://www.logicmonitor.com/support/rest-api-developers-guide/v1/devices/get-devices#Example-Request-5--GET-all-devices-that-have-a-spe
        .PARAMETER Context
            Represents the distance from the source device, to which the query should run. Valid options are '1stDegree', '2ndDegree', and 'Dynamic'.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorTopology -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6

            In this example, the command will search for the topology data (two degrees away) for the device with "6" in the ID property. Limited logging output will be sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorTopology -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Name server1 -Context 1stDegree

            In this example, the command will search for the topology data (one degree away) for the device with "server1" in the name property. Limited logging output will be sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorTopology -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Filter 'filter=name~"server1"'

            In this example, the command will search for the topology data for device(s) matching "server1" in the name property. Limited logging output will be sent only to the host.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [SecureString]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'IdFilter')]
        [Int[]]$Id,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [String]$Name,

        [Parameter(Mandatory, ParameterSetName = 'StringFilter')]
        [String]$Filter,

        [ValidateSet('1stDegree', '2ndDegree', 'Dynamic')]
        [String]$Context = '2ndDegree',

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    #region Initialize variables
    $topo = [System.Collections.Generic.List[PSObject]]::New() # Primary collection to be filled with Invoke-RestMethod response.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $resourcePath = "/topology/data" # Define the resourcePath.
    $queryParams = $null
    [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    Switch ($Context) {
        '1stDegree' { $algorithm = 'Neighbours-1' }
        '2ndDegree' { $algorithm = 'Neighbours-2' }
        'Dynamic' { $algorithm = 'I-Feel-Lucky' }
    }
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
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

    $message = ("{0}: Operating in the {1} parameter set." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $PsCmdlet.ParameterSetName)
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    #endregion Setup

    #region Update filter/resourcePath
    Switch ($PsCmdlet.ParameterSetName) {
        "NameFilter" {
            $filter = "filter=name:`"$Name`""

            $Filter = [regex]::Replace(
                $Filter,
                '(?<=[:|><~]").*?(?=")',
                {
                    param($m)
                    [Uri]::EscapeDataString($m.Value)
                }
            )
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

    #region Retrieve device Id(s)
    If ($PsCmdlet.ParameterSetName -in @('NameFilter', 'StringFilter')) {
        $result = Get-LogicMonitorDevice @commandParams @loggingParams -Filter $Filter

        If ($result.Id) { $result.Id | ForEach-Object { [Int[]]$Id += $_ } }
    }
    #endregion Retrieve device Id(s)

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
    Foreach ($device in $Id) {
        Do {
            $queryParams = "?resource=device.$device&algorithm=$algorithm"

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
                        $message = ("{0}: Unexpected error getting topology data. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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

            If ($response.vertices.Count -gt 0) {
                $message = ("{0}: Retrieved topology data for device ID {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $device)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                $topo.Add($response)
            }
        } Until ($stopLoop -eq $true)
    }
    #endregion Execute REST query

    #region Output
    If ($topo) {
        $message = ("{0}: Returning topology data for {1} devices." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $topo.vertices.Count)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        $topo
    }
    #endregion Output
} #2023.06.15.0