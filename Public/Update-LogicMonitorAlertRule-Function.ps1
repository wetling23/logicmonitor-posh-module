Function Update-LogicMonitorAlertRule {
    <#
        .DESCRIPTION
            Accepts an alert rule ID or name a hashtable of properties, then updates the desired alert rule.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 8 May 2019
                - Initial release.
            V1.0.0.1 date: 23 August 2019
            V1.0.0.2 date: 26 August 2019
            V1.0.0.3 date: 18 October 2019
            V1.0.0.4 date: 4 December 2019
            V1.0.0.5 date: 10 December 2019
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
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> $alertRule = Get-LogicMonitorAlertRule -AccessId <access id> -AccessKey <access key> -AccountName <account name> -Id 1
            PS C:\> $AlertRuleProperties = @{}
            PS C:\> $alertRule.psobject.properties | Foreach { $AlertRuleProperties[$_.Name] = $_.Value }
            PS C:\> $AlertRuleProperties.escalatingChainId = 6
            PS C:\> Update-LogicMonitorAlertRule -AccessId <access id> -AccessKey <access key> -AccountName <account name> -Id 1 -Properties $AlertRuleProperties -Verbose

            This example shows how to retrieve an alert rule (with Id 1), modify the "escalatingChainId" field and update the rule. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> $AlertRuleProperties = @{}
            PS C:\> $AlertRuleProperties.Add('Name','alertRuleName')
            PS C:\> $AlertRuleProperties.Add('escalatingChainId',6)
            PS C:\> Update-LogicMonitorAlertRule -AccessId <access id> -AccessKey <access key> -AccountName <account name> -Id 1 -Properties $AlertRuleProperties

            This example shows how to create a hash table, which is then used to update the alert rule named "alertRuleName".
        .EXAMPLE
            PS C:\> $alertRule = Get-LogicMonitorAlertRule -AccessId <access id> -AccessKey <access key> -AccountName <account name> -Id 1
            PS C:\> $AlertRuleProperties = @{}
            PS C:\> $alertRule.psobject.properties | Foreach { $AlertRuleProperties[$_.Name] = $_.Value }
            PS C:\> @($AlertRuleProperties.GetEnumerator()) | Where-Object { $_.Name -eq 'deviceGroups' } | ForEach-Object { $Properties[$_.Key] = @($_.value.replace('old path','new path')) }
            PS C:\> Update-LogicMonitorAlertRule -AccessId <access id> -AccessKey <access key> -AccountName <account name> -Id 1 -Properties $AlertRuleProperties

            This example shows how to retrieve an alert rule (with Id1 1), modify the deviceGroups field (which is an array) and update the rule.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [securestring]$AccessKey,

        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory, ParameterSetName = "Default", ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [string]$Id,

        [Parameter(Mandatory, ParameterSetName = "Name", ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [string]$Name,

        [Parameter(Mandatory)]
        [hashtable]$Properties,

        [string]$EventLogSource,

        [string]$LogPath
    )

    Begin {
        # Request info.
        [string]$data = ""
        [string]$httpVerb = "PATCH"
        [string]$resourcePath = "/setting/alert/rules"
        [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
        $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

        # Setup parameters for calling Get-LogicMonitor* cmdlet(s).
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') {
            If ($EventLogSource -and (-NOT $LogPath)) {
                $commandParams = @{
                    Verbose        = $true
                    EventLogSource = $EventLogSource
                }
            }
            ElseIf ($LogPath -and (-NOT $EventLogSource)) {
                $commandParams = @{
                    Verbose = $true
                    LogPath = $LogPath
                }
            }
        }
        Else {
            If ($EventLogSource -and (-NOT $LogPath)) {
                $commandParams = @{
                    EventLogSource = $EventLogSource
                }
            }
            ElseIf ($LogPath -and (-NOT $EventLogSource)) {
                $commandParams = @{
                    LogPath = $LogPath
                }
            }
        }
    }
    Process {
        $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $message = ("{0}: Attempting to update the `$resourcePath variable." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        Switch ($PsCmdlet.ParameterSetName) {
            Default {
                $resourcePath += "/$Id"
            }
            "Name" {
                $message = ("{0}: Attempting to retrieve the alert rule ID of {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Name)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                $alertRule = Get-LogicMonitorAlertRule -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -Name $Name @commandParams

                $resourcePath += "/$($alertRule.id)"

                $message = ("{0}: The value of `$resourcePath is {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
            }
        }

        # Clean up input object.
        $message = ("{0}: Removing unsupported fields from the hash table." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        Foreach ($key in $($Properties.keys)) {
            If ($key -notin 'name', 'priority', 'levelStr', 'devices', 'deviceGroups', 'datasource', 'instance', 'datapoint', 'escalationInterval', 'escalatingChainId', 'suppressAlertClear', 'suppressAlertAckSdt') {
                $message = ("{0}: Unsupported field found ({1}), removing the entry from `$Properties." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $key)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                $Properties.remove($key)
            }
        }

        # Need to replace the string with an array, for devices and device groups.
        @($Properties.GetEnumerator()) | Where-Object { $_.value -eq '{*}' } | ForEach-Object { $Properties[$_.Key] = @('*') }

        $data = $Properties | ConvertTo-Json

        # Construct the query URL.
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"

        # Get current time in milliseconds
        $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

        # Concatenate Request Details
        $requestVars = $httpVerb + $epoch + $data + $resourcePath

        # Construct Signature
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
        $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
        $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
        $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

        # Construct Headers
        $headers = @{
            "Authorization" = "LMv1 $accessId`:$signature`:$epoch"
            "Content-Type"  = "application/json"
            "X-Version"     = 2
        }

        Do {
            Try {
                $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -Body $data -ErrorAction Stop

                $stopLoop = $True
            }
            Catch {
                If ($_.Exception.Message -match '429') {
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

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
                    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

                    Return "Error"
                }
            }
        }
        While ($stopLoop -eq $false)

        $response
    }
} #1.0.0.5