Function Update-LogicMonitorCollectorProperty {
    <#
        .DESCRIPTION
            Accepts a collector ID or description and one or more property name/value pairs, then updates the property(ies).
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 11 July 2018
                - Initial release.
            V1.0.0.1 date: 19 July 2018
                - Added support for both PUT and PATCH operations.
                - Updated how the $propertyData is built, based on input from Joe Tran (https://github.com/jtran1209/).
            V1.0.0.2 date: 19 July 2018
                - Removed mandatory flag from OpType.
            V1.0.0.3 date: 18 March 2019
                - Updated alias publishing method.
            V1.0.0.4 date: 23 August 2019
            V1.0.0.5 date: 26 August 2019
            V1.0.0.6 date: 18 October 2019
            V1.0.0.7 date: 4 December 2019
            V1.0.0.8 date: 10 December 2019
            V1.0.0.9 date: 23 July 2020
            V1.0.0.10 date: 21 September 2021
            V2023.05.19.0
            V2023.05.22.0
            V2023.08.22.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Represents the subdomain of the LogicMonitor customer.
        .PARAMETER CollectorId
            Represents the collector's ID.
        .PARAMETER DisplayName
            Represents the collectors description.
        .PARAMETER Properties
            Hash table of collector properties, supported by LogicMonitor. See https://www.logicmonitor.com/support/v3-swagger-documentation, for more information (specifically, the Collectors model).
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
        .PARAMETER OpType
            Default value is "PATCH". Defines whether the command should use PUT or PATCH. PUT updates the provided properties and returns the rest to default values while PATCH updates the provided properties without chaning the others.
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Update-LogicMonitorCollectorProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6 -Properties @{ hostname = 'server2'; collectorSize = 'small' } -Verbose

            In this example, the cmdlet will update the hostname and collectorSize properties for the collector with "6" in the ID property. The hostname will be set to "server2" and the collector size will be set to "Small". If the properties are not present, they will be added. Verbose output is sent to the host.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [alias('Update-LogicMonitorCollectorProperties')]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [SecureString]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'Default')]
        [Alias("CollectorId")]
        [Int[]]$Id,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [Alias("CollectorDisplayName")]
        [String]$DisplayName,

        [Parameter(Mandatory)]
        [Hashtable]$Properties,

        [ValidateSet('PUT', 'PATCH')]
        [String]$OpType = 'PATCH',

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    #region Initialize variables
    $httpVerb = $OpType
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
    #endregion Setup

    #region Validate input properties
    $message = ("{0}: Removing unsupported fields from the Properties hash table." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

    Foreach ($key in $($Properties.keys)) {
        If ($key -notin 'description', 'backupAgentId', 'enableFailBack', 'resendIval', 'suppressAlertClear', 'escalatingChainId', 'collectorGroupId', 'collectorGroupName', 'enableFailOverOnCollectorDevice', 'build') {
            $message = ("{0}: Unsupported field found ({1}), removing the entry from `$Properties." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $key)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $Properties.remove($key)
        }
    }
    #endregion Validate input properties

    #region Update filter/resourcePath
    Switch ($PsCmdlet.ParameterSetName) {
        "NameFilter" {
            $message = ("{0}: Attempting to retrieve the device ID of {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $DisplayName)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $collector = Get-LogicMonitorCollector @commandParams -DescriptionName $DisplayName @loggingParams

            If ($collector.id) {
                $collector | ForEach-Object { [Int[]]$Id += $_.id }
            } Else {
                $message = ("{0}: No collectors were retrieved using the provided name, see the cmdlet's logging for more details. To prevent errors, {1} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
                Out-PsLogging @loggingParams -MessageType Error -Message $message

                Return "Error"
            }
        }
    }
    #endregion Update filter/resourcePath

    #region Execute REST query
    $data = $($Properties | ConvertTo-Json -Depth 5)

    Foreach ($collector in $Id) {
        $resourcePath = ("/setting/collector/collectors/{0}" -f $collector)

        #region Auth and headers
        # Get current time in milliseconds.
        $epoch = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End (Get-Date).ToUniversalTime()).TotalMilliseconds)
        $requestVars = $httpVerb + $epoch + $data + $resourcePath
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
                $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -Body $data -ErrorAction Stop

                $stopLoop = $True
            } Catch {
                If ($_.Exception.Message -match '429') {
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                    Out-PsLogging @loggingParams -MessageType Warning -Message $message

                    Start-Sleep -Seconds 60
                } Else {
                    $message = ("{0}: Unexpected error updating the collector. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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

        If ($response.id) {
            $message = ("{0}: Successfully updated the collector ({1}) in LogicMonitor." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $collector)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            Return $response
        } Else {
            $message = ("{0}: Unexpected error updating the collector ({1}) in LogicMonitor. To prevent errors, {2} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Id, $MyInvocation.MyCommand)
            Out-PsLogging @loggingParams -MessageType Error -Message $message

            Return "Error"
        }
    }
    #endregion Execute REST query
} #2023.08.22.0