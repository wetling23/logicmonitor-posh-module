Function Get-LogicMonitorRole {
    <#
        .DESCRIPTION
            Retrieves role objects from LogicMonitor.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 8 August 2018
                - Initial release.
            V1.0.0.1 date: 14 March 2019
                - Added support for rate-limited re-try.
            V1.0.0.2 date: 18 March 2019
                - Updated alias publishing method.
            V1.0.0.3 date: 23 August 2019
            V1.0.0.4 date: 26 August 2019
            V1.0.0.5 date: 18 October 2019
            V1.0.0.6 date: 4 December 2019
            V1.0.0.7 date: 23 July 2020
            V2023.04.28.0
            V2023.05.09.0
            V2023.08.23.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Id
            Represents report ID of the desired role. Wildcard searches are not supported.
        .PARAMETER Filter
            Represents a string matching the API's filter format. This parameter can be used to filter for roles matching certain criteria.
        .PARAMETER BatchSize
            Default value is 1000. Represents the number of roles to request from LogicMonitor.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorRole -AccessID <access ID> -AccessKey <access key> -AccountName <account name> -Verbose

            In this example, the command gets all roles, in batches of 1000. Output is logged to the application log, and written to the host. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorRole -AccessID <accessID> -AccessKey <accessKey> -AccountName <accountName> -Filter 'filter=name:"readonly"' -LogPath C:\Temp\log.txt

            In this example, the command gets the properties of the role with name "readonly". Limited logging output is sent to the host and C:\Temp\log.txt.
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllRoles')]
    [alias('Get-LogicMonitorRoles')]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [Securestring]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'IDFilter')]
        [Int]$Id,

        [Parameter(Mandatory, ParameterSetName = 'StringFilter')]
        [String]$Filter,

        [Int]$BatchSize = 1000,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    #region Variables
    $roles = [System.Collections.Generic.List[PSObject]]::New() # Primary collection to be filled with Invoke-RestMethod response.
    $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $resourcePath = "/setting/roles" # Define the resourcePath, based on the type of query you are doing.
    $queryParams = $null
    $pattern1 = '[^a-zA-Z\d\s]' # Match any non-alpha numeric or white space character.
    $pattern2 = '(?:>:|<:|:|>|<|!:|:|~|!~)(?:")(.*?)(?:")' # Allow us to replace characters in the filter. We will leave some of the characters alone, since they are used by the API in certain spots. For example, ":" means equal between the property name and value but should be replaced in the value portion of the pair.
    $regex = [Regex]::new($pattern2)
    [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    If ($Id) {
        $resourcePath += "/$Id"
    }
    #endregion Variables

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

    $message = ("{0}: Operating in the {1} parameter set." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $PsCmdlet.ParameterSetName)
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    #endregion Setup

    Switch ($PsCmdlet.ParameterSetName) {
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
        }
    }

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
            $queryParams = "?filter=$Filter&offset=$offset&size=$BatchSize&sort=id"
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
                    $message = ("{0}: Unexpected error getting roles. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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
            $message = ("{0}: Retrieved {1} roles of {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $response.items.Count, $response.total)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            Foreach ($item in $response.items) {
                $roles.Add($item)
            }

            If (($response.items.Count -eq 1) -or ($response.total -and ($response.total -eq $roles.id.Count))) {
                $message = ("{0}: Retrieved all roles." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
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
            $roles = $response
            $stopLoop = $true
        } Else {
            $message = ("{0}: The `$response variable is empty." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $stopLoop = $true
        }

        $message = ("{0}: There are {1} roles in `$roles." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $roles.id.Count)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    } Until (($response.total -eq $roles.id.Count) -or ($response.id.Count -eq $roles.id.Count))

    Return $roles
} #2023.08.23.0