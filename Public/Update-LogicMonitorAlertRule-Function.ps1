Function Update-LogicMonitorAlertRule {
    <#
        .DESCRIPTION
            Accepts an alert rule ID or name and hashtable of properties, then updates the desired alert rule.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 8 May 2019
                - Initial release.
            V1.0.0.1 date: 23 August 2019
            V1.0.0.2 date: 26 August 2019
            V1.0.0.3 date: 18 October 2019
            V1.0.0.4 date: 4 December 2019
            V1.0.0.5 date: 10 December 2019
            V1.0.0.6 date: 23 July 2020
            V1.0.0.7 date: 21 September 2021
            V2023.04.28.0
            V2023.05.22.0
            V2023.05.23.0
            V2023.08.22.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Id
            Represents the device ID of a monitored device. Accepts pipeline input. Either this or the name is required.
        .PARAMETER Name
            Represents the device display name of a monitored device. Accepts pipeline input. Must be unique in LogicMonitor. Either this or the Id is required.
        .PARAMETER Properties
            Hash table of alert-rule properties supported by LogicMonitor. See https://www.logicmonitor.com/support/rest-api-developers-guide/v1/alert-rules/update-alert-rules/, for field names/data types.
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> $alertRule = Get-LogicMonitorAlertRule -AccessId <access id> -AccessKey <access key> -AccountName <account name> -Id 1
            PS C:\> $AlertRuleProperties = @{}
            PS C:\> $alertRule.psobject.properties | Foreach { $AlertRuleProperties[$_.Name] = $_.Value }
            PS C:\> $AlertRuleProperties.escalatingChainId = 6
            PS C:\> Update-LogicMonitorAlertRule -AccessId <access id> -AccessKey <access key> -AccountName <account name> -Id 1 -Properties $AlertRuleProperties -Verbose

            This example shows how to retrieve an alert rule (with Id 1), modify the "escalatingChainId" field and update the rule. Verbose logging output is sent only to the host.
        .EXAMPLE
            PS C:\> $AlertRuleProperties = @{}
            PS C:\> $AlertRuleProperties.Add('Name','alertRuleName')
            PS C:\> $AlertRuleProperties.Add('escalatingChainId',6)
            PS C:\> Update-LogicMonitorAlertRule -AccessId <access id> -AccessKey <access key> -AccountName <account name> -Id 1 -Properties $AlertRuleProperties

            This example shows how to create a hash table, which is then used to update the alert rule named "alertRuleName". Limited logging output is sent only to the host.
        .EXAMPLE
            PS C:\> $alertRule = Get-LogicMonitorAlertRule -AccessId <access id> -AccessKey <access key> -AccountName <account name> -Id 1
            PS C:\> $AlertRuleProperties = @{}
            PS C:\> $alertRule.psobject.properties | Foreach { $AlertRuleProperties[$_.Name] = $_.Value }
            PS C:\> @($AlertRuleProperties.GetEnumerator()) | Where-Object { $_.Name -eq 'deviceGroups' } | ForEach-Object { $Properties[$_.Key] = @($_.value.replace('old path','new path')) }
            PS C:\> Update-LogicMonitorAlertRule -AccessId <access id> -AccessKey <access key> -AccountName <account name> -Id 1 -Properties $AlertRuleProperties

            This example shows how to retrieve an alert rule (with Id 1), modify the deviceGroups field (which is an array) and update the rule. Limited logging output is sent only to the host.
        .EXAMPLE
            PS C:\> Update-LogicMonitorAlertRule -AccessId <access id> -AccessKey <access key> -AccountName <account name> -Id 1 -Properties @{name = 'New Name'; deviceGroups = @('Top Level Group/Sub-group/server*', 'Top Level Group/Sub-group2/network*')}

            This example shows how to change the name and associated device group(s) for the alert rule with ID 1. The new name will be "New Name" and any existing device groups will be replaced with 'Top Level Group/Sub-group/server*' and 'Top Level Group/Sub-group2/network*'. Limited logging output is sent only to the host.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [SecureString]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = "Default", ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Int[]]$Id,

        [Parameter(Mandatory, ParameterSetName = "Name", ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String]$Name,

        [Parameter(Mandatory)]
        [Hashtable]$Properties,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    Begin {
        #region Setup
        #region Initialize variables
        $httpVerb = 'PATCH'
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
    } Process {
        #region Validate input properties
        $message = ("{0}: Removing unsupported fields from the Properties hash table." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        Foreach ($key in $($Properties.keys)) {
            If ($key -notin 'name', 'priority', 'levelStr', 'devices', 'deviceGroups', 'datasource', 'instance', 'datapoint', 'escalationInterval', 'escalatingChainId', 'suppressAlertClear', 'suppressAlertAckSdt') {
                $message = ("{0}: Unsupported field found ({1}), removing the entry from `$Properties." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $key)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                $Properties.remove($key)
            }
        }

        # Need to replace the string with an array, for devices and device groups.
        @($Properties.GetEnumerator()) | Where-Object { $_.value -eq '{*}' } | ForEach-Object { $Properties[$_.Key] = @('*') }
        #endregion Validate input properties

        #region Update filter/resourcePath
        Switch ($PsCmdlet.ParameterSetName) {
            "Name" {
                $message = ("{0}: Attempting to retrieve the alert rule ID of {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Name)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                $alertRule = Get-LogicMonitorAlertRule @commandParams -Name $Name @loggingParams

                If ($alertRule.id) {
                    $alertRule | ForEach-Object { [Int[]]$Id += $_.id }
                } Else {
                    $message = ("{0}: No alert rules were retrieved using the provided name, see the cmdlet's logging for more details. To prevent errors, {1} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
                    Out-PsLogging @loggingParams -MessageType Error -Message $message

                    Return "Error"
                }
            }
        }
        #endregion Update filter/resourcePath

        #region Execute REST query
        $data = $($Properties | ConvertTo-Json -Depth 5)

        Foreach ($rule in $Id) {
            $resourcePath = ("/setting/alert/rules/{0}" -f $rule)

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
                        $message = ("{0}: Unexpected error updating alert rule. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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
                $message = ("{0}: Successfully updated the alert rule ({1}) in LogicMonitor." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $rule)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                Return $response
            } Else {
                $message = ("{0}: Unexpected error updating the alert rule ({1}) in LogicMonitor. To prevent errors, {2} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Id, $MyInvocation.MyCommand)
                Out-PsLogging @loggingParams -MessageType Error -Message $message

                Return "Error"
            }
        }
        #endregion Execute REST query
    }
} #2023.08.22.0