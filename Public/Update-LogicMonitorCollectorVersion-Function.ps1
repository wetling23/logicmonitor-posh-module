##does not work yet. It seems that the API accepts the request, but does not take any action.
Function Update-LogicMonitorCollectorVersion {
    <#
        .DESCRIPTION
            Accepts a collector ID or description, a version number, and a start time, then schedules the installation of a new version of the collector.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 30 August 2018
                - Initial release.
        .LINK

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
        .PARAMETER MajorVersion
            
        .PARAMETER MinorVersion
            
        .PARAMETER StartDate

        .PARAMETER StartTime

        .PARAMETER EventLogSource
            Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> Update-LogicMonitorCollectorVersion -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -CollectorId 6 -MajorVersion 27 -MinorVersion 2

            In this example, the cmdlet will upgrade the collector to 27.002. The installation will run immediately.
        .EXAMPLE
            PS C:\> Update-LogicMonitorCollectorVersion -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -CollectorId 6 -MajorVersion 27 -MinorVersion 2 -StartDate 08/30/2018 -StartTime 12:00

            In this example, the cmdlet will upgrade the collector to 27.002. The installation will run at 12:00 on 30 August 2018.
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
        [string]$DisplayName,

        [int]$MajorVersion,

        [int]$MinorVersion,

        [datetime]$StartDate,

        [datetime]$StartTime,

        [string]$EventLogSource = 'LogicMonitorPowershellModule',

        [switch]$BlockLogging
    )

    Begin {
        # Initialize variables.
        [int]$index = 0
        [hashtable]$propertyData = @{}
        [string]$standardProperties = ""
        [string]$data = ""
        [string]$httpVerb = "PATCH"
        [string]$queryParams = "?patchFields=onetimeUpgradeInfo"
        [string]$resourcePath = "/setting/collectors"
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
        If ($BlockLogging) {Write-Host $message -ForegroundColor White} Else {Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

        If (($StartDate -eq $null) -and ($StartTime -eq $null)) {
            # Neither start time nor end time provided.
            $StartDate = (Get-Date).AddMinutes(1)
        }
        ElseIf (($StartDate -eq $null) -and ($StartTime -ne $null)) {
            # Start date not provided. Start time is provided.
            $StartDate = (Get-Date -Format d)
            [datetime]$StartDate = $StartDate
            $StartDate = $StartDate.Add($StartTime)
        }
        ElseIf (($StartDate -ne $null) -and ($StartTime -eq $null)) {
            # Start date is provided. Start time is not provided.
            $StartTime = (Get-Date -Format HH:mm)
            [datetime]$StartDate = $StartDate
            $StartDate = $StartDate.Add($StartTime)
        }
        Else {
            $StartDate = $StartDate.Add($StartTime)
        }

        $startEpoch = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End ($StartDate).ToUniversalTime()).TotalMilliseconds)

        # Update $resourcePath to filter for a specific collector, when a collector ID or displayName is provided by the user.
        Switch ($PsCmdlet.ParameterSetName) {
            Default {
                $resourcePath += "/$Id"
            }
            NameFilter {
                $message = ("{0}: Attempting to retrieve the collector ID of {1}." -f (Get-Date -Format s), $DisplayName)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

                $collector = Get-LogicMonitorDevices -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -DeviceDisplayName $DisplayName -EventLogSource $EventLogSource

                $resourcePath += "/$($collector.id)"

                $message = ("{0}: The value of `$resourcePath is {1}." -f (Get-Date -Format s), $resourcePath)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}
            }
        }

        $message = ("{0}: Finished updating `$resourcePath. The value is {1}." -f (Get-Date -Format s), $resourcePath)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417}

        $propertyData = @{
            "majorVersion" = $MajorVersion
            "minorVersion" = $MinorVersion
            "startEpoch"   = $startEpoch
            "description"  = "Collector upgrade initiated by LogicMonitor PowerShell module."
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
} #1.0.0.0