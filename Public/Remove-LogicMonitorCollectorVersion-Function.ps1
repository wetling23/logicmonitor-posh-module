Function Remove-LogicMonitorCollectorVersion {
    <#
        .DESCRIPTION
            Accepts a collector ID or description, and a start time, then schedules the downgrade of the collector, to the previous version.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 7 September 2018
                - Initial release.
            V1.0.0.1 date: 10 September 2018
                - Updated comments.
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
        .PARAMETER Description
            Represents the collectors description.
        .PARAMETER StartDate
            Represents the downgrade start date and time. If no value is provided, the current date and time are.
        .PARAMETER EventLogSource
            Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorCollectorVersion -AccessId <accessId> -AccessKey <accessId> -AccountName <accountName> -Id 6 -StartDate "09/07/2018 15:05"

            In this example, the cmdlet downgrades collector 6, beginning at 15:05 on 7 September 2018. Output is sent to the console and to the Windows event log.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorCollectorVersion -AccessId <accessId> -AccessKey <accessId> -AccountName <accountName> -Id 6 -StartDate "09/07/2018 2:00 PM" -BlockLogging

            In this example, the cmdlet downgrades collector 6, beginning at 2:00 PM on 7 September 2018. The output will be sent only to the console.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param (
        [Parameter(Mandatory = $True)]
        [string]$AccessId,

        [Parameter(Mandatory = $True)]
        [string]$AccessKey,

        [Parameter(Mandatory = $True)]
        [string]$AccountName,

        [Parameter(Mandatory = $True, ParameterSetName = "Default", ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [int]$Id,

        [Parameter(Mandatory = $True, ParameterSetName = "Name", ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [string]$Description,

        [datetime]$StartDate,

        [string]$EventLogSource = 'LogicMonitorPowershellModule',

        [switch]$BlockLogging
    )

    Begin {
        # Initialize variables.
        [hashtable]$downgradeProperties = @{}
        [hashtable]$propertyData = @{}
        [string]$data = ""
        [string]$httpVerb = "PATCH"
        [string]$queryParams = ""
        [string]$resourcePath = "/setting/collector/collectors"
        [System.Net.SecurityProtocolType]$AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    }
    Process {
        If (-NOT($BlockLogging)) {
            $return = Add-EventLogSource -EventLogSource $EventLogSource

            If ($return -ne "Success") {
                $message = ("{0}: Unable to add event source ({1}). No logging will be performed." -f (Get-Date -Format s), $EventLogSource)
                Write-Host $message -ForegroundColor Yellow;

                $BlockLogging = $True
            }
        }

        $message = ("{0}: Beginning {1}." -f (Get-Date -Format s), $MyInvocation.MyCommand)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

        $message = ("{0}: Validating start time/date." -f (Get-Date -Format s))
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

        If ($StartDate -eq $null) {
            # Neither start date is not provided.
            [datetime]$StartDate = (Get-Date)
        }

        $startEpoch = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End ($StartDate).ToUniversalTime()).TotalSeconds)

        # Update $resourcePath to filter for a specific collector, when a collector ID or Description is provided by the user.
        Switch ($PsCmdlet.ParameterSetName) {
            Default {
                $resourcePath += "/$Id"
            }
            "Name" {
                $message = ("{0}: Attempting to retrieve the collector ID of {1}." -f (Get-Date -Format s), $Description)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

                $collector = Get-LogicMonitorCollectors -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -CollectorDescriptionName $Description -EventLogSource $EventLogSource

                $resourcePath += "/$($collector.id)"

                $message = ("{0}: The value of `$resourcePath is {1}." -f (Get-Date -Format s), $resourcePath)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}
            }
        }

        $message = ("{0}: Finished updating `$resourcePath. The value is:`r`n {1}." -f (Get-Date -Format s), $resourcePath)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

        # Sleeping because we get an error about scheduling, if we don't wait.
        Start-Sleep -Seconds 5

        $downgradeProperties = @{
            "startEpoch"  = $startEpoch
            "description" = "Collector downgrade initiated by LogicMonitor PowerShell module ($env:USERNAME on $env:COMPUTERNAME)."
        }

        $propertyData.Add("onetimeDowngradeInfo", $downgradeProperties)

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
        $headers.Add("X-Version", '2')

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

        Return $response
    }
} #1.0.0.1