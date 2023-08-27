Function Get-LogicMonitorServiceProperty {
    <#
        .DESCRIPTION
            Retrieve properties of LogicMonitor services (e.g. ping checks and website transaction).
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 12 March 2017
                - Initial release.
            V1.0.0.1 date: 13 March 2017
                - Added OutputType paramater to Confirm-OutputPathAvailability call.
            V1.0.0.2 date: 3 May 2017
                - Removed code from writing to file and added Event Log support.
                - Updated code for verbose logging.
                - Changed Add-EventLogSource failure behavior to just block logging (instead of quitting the function).
            V1.0.0.3 date: 21 June 2017
                - Updated logging to reduce chatter.
            V1.0.0.4 date: 23 April 2018
                - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
                - Replaced ! with -NOT.
            V1.0.0.5 date: 14 March 2019
                - Added support for rate-limited re-try.
                - Updated whitespace.
            V1.0.0.6 date: 18 March 2019
                - Updated alias publishing method.
            V1.0.0.7 date: 23 August 2019
            V1.0.0.8 date: 26 August 2019
            V1.0.0.9 date: 18 October 2019
            V1.0.0.10 date: 4 December 2019
            V1.0.0.11 date: 23 July 2020
            V2023.04.28.0
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
            Represents Id of the desired service.
        .PARAMETER Name
            Represents the name of the desired service.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorServiceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 5 -Verbose

            In this example, the command will get all properties of the LogicMonitor service with ID "5". Verbose logging output will be written only to the session host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorServiceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Name "homepage" -LogPath C:\Temp\log.txt

            In this example, the command will get all properties of the LogicMonitor service with name "homepage". Limited logging will be written to the session host and C:\Temp\log.txt.
    #>
    [CmdletBinding(DefaultParameterSetName = 'IDFilter')]
    [Alias('Get-LogicMonitorServiceProperties', 'Get-LogicMonitorWebsiteProperty')]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [SecureString]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'IDFilter')]
        [Alias("ServiceId")]
        [Int]$Id,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [Alias("ServiceName")]
        [String]$Name,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    #region Initialize variables
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $resourcePath = "/website/websites" # Define the resourcePath, based on the type of service you're searching for.
    $queryParams = $null
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    $commandParams = @{
        AccountName = $AccountName
        AccessId    = $AccessId
        AccessKey   = $AccessKey
    }
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

    $message = ("{0}: Operating in the {1} parameter set." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $PsCmdlet.ParameterSetName)
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    #endregion Setup

    # Update $resourcePath to filter for a specific service.
    Switch ($PsCmdlet.ParameterSetName) {
        "NameFilter" {
            $service = Get-LogicMonitorServices @commandParams -Name $Name @loggingParams

            If ($service.id) {
                $Id = $service.id

                $message = ("{0}: Found ID {1} for {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Id, $Name)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
            } Else {
                $message = ("{0}: Failed to locate a service called {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Name)
                Out-PsLogging @loggingParams -MessageType Error -Message $message

                Return "Error"
            }
        }
    }

    $resourcePath += "/$Id/properties"

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
            } Else {
                $message = ("{0}: Unexpected error getting service properties. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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

    Return $response.items
} #2023.08.23.0