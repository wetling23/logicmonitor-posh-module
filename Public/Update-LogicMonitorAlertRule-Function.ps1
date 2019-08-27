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
            Default value is "LogicMonitorPowershellModule". Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> $alertRule = Get-LogicMonitorAlertRule -AccessId <access id> -AccessKey <access key> -AccountName <account name> -Id 1
            PS C:\> $AlertRuleProperties = @{}
            PS C:\> $alertRule.psobject.properties | Foreach { $AlertRuleProperties[$_.Name] = $_.Value }
            PS C:\> $AlertRuleProperties.escalatingChainId = 6
            PS C:\> Update-LogicMonitorAlertRule -AccessId <access id> -AccessKey <access key> -AccountName <account name> -Id 1 -Properties $AlertRuleProperties

            This example shows how to retrieve an alert rule (with Id 1), modify the "escalatingChainId" field and update the rule.
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

        [string]$EventLogSource = 'LogicMonitorPowershellModule',

        [switch]$BlockLogging
    )

    Begin {
        # Request info.
        [string]$data = ""
        [string]$httpVerb = "PATCH"
        [string]$resourcePath = "/setting/alert/rules"
        [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
        $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    }
    Process {
        If (-NOT($BlockLogging)) {
            $return = Add-EventLogSource -EventLogSource $EventLogSource

            If ($return -ne "Success") {
                $message = ("{0}: Unable to add event source ({1}). No logging will be performed." -f [datetime]::Now, $EventLogSource)
                Write-Host $message

                $BlockLogging = $True
            }
        }

        $message = ("{0}: Beginning {1}." -f [datetime]::Now, $MyInvocation.MyCommand)
        If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

        $message = ("{0}: Attempting to update the `$resourcePath variable." -f [datetime]::Now, $MyInvocation.MyCommand)
        If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

        Switch ($PsCmdlet.ParameterSetName) {
            Default {
                $resourcePath += "/$Id"
            }
            "Name" {
                $message = ("{0}: Attempting to retrieve the alert rule ID of {1}." -f [datetime]::Now, $Name)
                If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                $alertRule = Get-LogicMonitorAlertRule -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -Name $Name -EventLogSource $EventLogSource

                $resourcePath += "/$($alertRule.id)"

                $message = ("{0}: The value of `$resourcePath is {1}." -f [datetime]::Now, $resourcePath)
                If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }
            }
        }

        # Clean up input object.
        $message = ("{0}: Removing unsupported fields from the hash table." -f [datetime]::Now, $MyInvocation.MyCommand)
        If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

        Foreach ($key in $($Properties.keys)) {
            If ($key -notin 'name', 'priority', 'levelStr', 'devices', 'deviceGroups', 'datasource', 'instance', 'datapoint', 'escalationInterval', 'escalatingChainId', 'suppressAlertClear', 'suppressAlertAckSdt') {
                $message = ("{0}: Unsupported field found ({1}), removing the entry from `$Properties." -f [datetime]::Now, $key)
                If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

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
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f [datetime]::Now, $MyInvocation.MyCommand, $_.Exception.Message)
                    If ($BlockLogging) { Write-Waring $message } Else { Write-Warning $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Warning -Message $message -EventId 5417 }

                    Start-Sleep -Seconds 60
                }
                ElseIf ($_.Exception.Message -eq 'The remote server returned an error: (400) Bad Request.') {
                    $message = ("{0}: Error updating the alert rule. The specific message is: {1}" -f [datetime]::Now, $_.ErrorDetails.Message)
                    If ($BlockLogging) { Write-Error $message } Else { Write-Error $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $message -EventId 5417 }

                    Return "Error"
                }
                Else {
                    $message = ("{0}: Unexpected error getting devices. To prevent errors, {1} will exit. PowerShell returned: {2}" -f [datetime]::Now, $MyInvocation.MyCommand, $_.Exception.Message)
                    If ($BlockLogging) { Write-Error $message } Else { Write-Error $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $message -EventId 5417 }

                    Return "Error"
                }
            }
        }
        While ($stopLoop -eq $false)

        $response
    }
} #1.0.0.2