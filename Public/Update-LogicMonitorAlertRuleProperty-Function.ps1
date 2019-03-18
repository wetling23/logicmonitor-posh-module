Function Update-LogicMonitorAlertRuleProperty {
    <#
        .DESCRIPTION
            Accepts an alert rule ID or name and one or more property name/value pairs, then updates the property(ies).
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 8 August 2018
                - Initial release.
            V1.0.0.1 date: 13 August 2018
                - Changed $queryParams to $null.
                - Added support for pipeline input of the Id.
            V1.0.0.2 date: 18 March 2019
                - Updated alias publishing method.
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Id
            Represents the collector's ID. Accepts pipeline input by property name.
        .PARAMETER Name
            Represents the collectors description.
        .PARAMETER PropertyName
            Represents the name of the target property. Note that LogicMonitor properties are case sensitive.
        .PARAMETER PropertyValue
            Represents the value of the target property.
        .PARAMETER EventLogSource
            Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> Update-LogicMonitorAlertRuleProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6 -PropertyNames hostname,collectorSize -PropertyValues server2,small

            In this example, the cmdlet will update the hostname and collectorSize properties for the collector with "6" in the ID property. The hostname will be set to "server2" and the collector size will be set to "Small". If the properties are not present, they will be added.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [alias('Get-LogicMonitorAlertRulesProperties')]
    Param (
        [Parameter(Mandatory = $True)]
        [string]$AccessId,

        [Parameter(Mandatory = $True)]
        [string]$AccessKey,

        [Parameter(Mandatory = $True)]
        [string]$AccountName,

        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ParameterSetName = 'Default')]
        [Alias("AlertRuleId")]
        [int]$Id,

        [Parameter(Mandatory = $True, ParameterSetName = 'NameFilter')]
        [Alias("AlertRuleName")]
        [string]$Name,

        [Parameter(Mandatory = $True)]
        [ValidateSet('name', 'priority', 'levelStr', 'devices', 'deviceGroups', 'datasource', 'instance', 'datapoint', 'escalationInterval', 'escalatingChainId', 'suppressAlertClear', 'suppressAlertAckSdt')]
        [string[]]$PropertyNames,

        [Parameter(Mandatory = $True)]
        [string[]]$PropertyValues,

        [string]$EventLogSource = 'LogicMonitorPowershellModule',

        [switch]$BlockLogging
    )

    Begin {
        If (-NOT($BlockLogging)) {
            $return = Add-EventLogSource -EventLogSource $EventLogSource

            If ($return -ne "Success") {
                $message = ("{0}: Unable to add event source ({1}). No logging will be performed." -f (Get-Date -Format s), $EventLogSource)
                Write-Host $message -ForegroundColor Yellow;

                $BlockLogging = $True
            }
        }

        $message = ("{0}: Beginning {1}." -f (Get-Date -Format s), $MyInvocation.MyCommand)
        If ($BlockLogging) {Write-Host $message -ForegroundColor White} Else {Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

        # Initialize variables.
        [int]$index = 0
        [hashtable]$propertyData = @{}
        [string]$data = ""
        [string]$httpVerb = 'PUT'
        [string]$queryParams = ""
        [string]$resourcePath = "/setting/alert/rules"
        [System.Net.SecurityProtocolType]$AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    }
    Process {
        If ($PropertyNames -notcontains "name" -or $PropertyNames -notcontains "priority") {
            $message = ("{0}: The alert rule name and priority are required, but one or both were not provided. Please try again." -f (Get-Date -Format s))
            If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $message -EventId 5417}

            Return "Error"
        }
        Else {
            # Update $resourcePath to filter for a specific alert rule, when an alert rule ID, or name are provided by the user.
            Switch ($PsCmdlet.ParameterSetName) {
                Default {
                    $resourcePath += "/$Id"
                }
                "NameFilter" {
                    $message = ("{0}: Attempting to retrieve the collector ID of {1}." -f (Get-Date -Format s), $Name)
                    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

                    $alertRule = Get-LogicMonitorAlertRules -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -Name $Name -EventLogSource $EventLogSource

                    $resourcePath += "/$($alertRule.id)"

                    $message = ("{0}: The value of `$resourcePath is {1}." -f (Get-Date -Format s), $resourcePath)
                    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}
                }
            }

            $message = ("{0}: Finished updating `$resourcePath. The value is {1}." -f (Get-Date -Format s), $resourcePath)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

            Foreach ($property in $PropertyNames) {
                Switch ($property) {
                    {$_ -in ("deviceGroups", "devices")} {
                        $propertyData.Add($_, @($PropertyValues[$index] -split ','))

                        $index++
                    }
                    default {
                        $propertyData.Add($_, $($PropertyValues[$index]))

                        $index++
                    }
                }
            }

            # I am assigning $propertyData to $data, so that I can use the same $requestVars concatination and Invoke-RestMethod as other cmdlets in the module.
            $data = $propertyData | ConvertTo-Json -Depth 6

            $message = ("{0}: Finished updating `$data. The value update is {1}." -f (Get-Date -Format s), $data)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

            # Construct the query URL.
            $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

            # Get current time in milliseconds
            $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

            # Concatenate Request Details
            $requestVars = $httpVerb + $epoch + $data + $resourcePath

            # Construct Signature
            $hmac = New-Object System.Security.Cryptography.HMACSHA256
            $hmac.Key = [Text.Encoding]::UTF8.GetBytes($accessKey)
            $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
            $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
            $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

            # Construct Headers
            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("Authorization", "LMv1 $accessId`:$signature`:$epoch")
            $headers.Add("Content-Type", 'application/json')

            # Make Request
            $message = ("{0}: Executing the REST query." -f (Get-Date -Format s))
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

            Try {
                $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -Body $data -ErrorAction Stop
            }
            Catch {
                $message = ("{0}: It appears that the web request failed. Check your credentials and try again. To prevent errors, the {1} function will exit. The specific error message is: {2}" `
                        -f (Get-Date -Format s), $MyInvocation.MyCommand, $_.Message.Exception)
                If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $message -EventId 5417}

                Return "Error", $response
            }

            If ($response.status -ne "200") {
                $message = ("{0}: LogicMonitor reported an error (status {1}). The message is: {2}" -f (Get-Date -Format s), $response.status, $response.errmsg)
                If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $message -EventId 5417}
            }

            Return $response
        }
    }
} #1.0.0.2