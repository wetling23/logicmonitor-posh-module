Function Get-LogicMonitorJobMonitor {
    <#
        .DESCRIPTION 
            Returns a list of LogicMonitor JobMonitors. By default, the function returns all JobMonitors. If a JobMonitor ID, name, or filter is provided, the function will 
            return properties for the specified JobMonitor.
        .NOTES 
            Author: Mike Hashemi
            V1.0.0.0 date: 29 December 2020
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
            Represents the ID of the desired JobMonitor.
        .PARAMETER Name
            Represents the name of the desired JobMonitor.
        .PARAMETER BatchSize
            Default value is 1000. Represents the number of DataSoruces to request from LogicMonitor, in a single batch.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorJobMonitor -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Verbose

            In this example, the function will search for all monitored devices and will return their properties. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorJobMonitor -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6

            In this example, the function returns the JobMonitor with ID '6'.
        .EXAMPLE
            PS C:\> Get-LogicMonitorJobMonitor -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -ApplyTo 'isWindows()'

            In this example, the function returns JobMonitors with an "applies to" filter equal to "isWindows()".
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllJobMonitors')]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [securestring]$AccessKey,

        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'IDFilter')]
        [int]$Id,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [string]$Name,

        [Parameter(Mandatory, ParameterSetName = 'AppliesToFilter')]
        [string]$ApplyTo,

        [int]$BatchSize = 1000,

        [boolean]$BlockStdErr = $false,

        [string]$EventLogSource,

        [string]$LogPath
    )

    #region Setup
    #region Initialize variables
    $jobMonitors = [System.Collections.Generic.List[PSObject]]::new() # Create a collection to hold the job monitors.
    [int]$offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    [string]$httpVerb = "GET" # Define what HTTP operation will the script run.
    [string]$resourcePath = "/setting/batchjobs" # Define the resourcePath.
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
            $Name = $Name.Replace('_', '%5F')
            $Name = $Name.Replace(' ', '%20')

            $filter = "name:`"$Name`""
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
                    $message = ("{0}: Unexpected error getting JobMonitors. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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
            $message = ("{0}: Retrieved {1} JobMonitors of {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $response.items.Count, $response.total)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            Foreach ($item in $response.items) {
                $jobMonitors.Add($item)
            }

            If (($response.items.Count -eq 1) -or ($response.total -and ($response.total -eq $jobMonitors.id.Count))) {
                $message = ("{0}: Retrieved all JobMonitors." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
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
            $jobMonitors = $response
            $stopLoop = $true
        } Else {
            $message = ("{0}: The `$response variable is empty." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $stopLoop = $true
        }

        $message = ("{0}: There are {1} JobMonitors in `$jobMonitors." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $jobMonitors.id.Count)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    } Until (($response.total -eq $jobMonitors.id.Count) -or ($response.id.Count -eq $jobMonitors.id.Count))

    Return $jobMonitors
} #2023.08.23.0