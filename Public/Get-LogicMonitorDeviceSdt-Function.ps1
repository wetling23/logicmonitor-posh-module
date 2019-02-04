Function Get-LogicMonitorDeviceSdt {
    <#
        .DESCRIPTION 
            Retrieves a list of Standard Down Time (SDT) entries from LogicMonitor, for a specific device. This cmdlet uses the /device/devices tree.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 1 February 2019
                - Initial release.
            V1.0.0.1 date: 4 February 2019
                - Fixed bug where no output was returned.
        .LINK

        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER DeviceDisplayName
            Represents the device display name of the desired device.
        .PARAMETER DeviceId
            Represents the device ID of the desired device.
        .PARAMETER EventLogSource
            Default value is "LogicMonitorPowershellModule". Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDeviceSdt -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceDisplayName server1

            In this example, the command gets all active SDTs for a server with the display name 'server1'.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDeviceSdt -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceId 2

            In this example, the command gets all active SDTs for a server with the ID '2'.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [string]$AccessId,

        [Parameter(Mandatory = $True)]
        [string]$AccessKey,

        [Parameter(Mandatory = $True)]
        [string]$AccountName,

        [Parameter(ParameterSetName = "DeviceDisplayName")]
        [string]$DeviceDisplayName,

        [Parameter(ParameterSetName = "DeviceId")]
        [string]$DeviceId,

        [string]$EventLogSource = 'LogicMonitorPowershellModule',

        [switch]$BlockLogging
    )

    Begin {
        # Initialize variables.
        $filter = $null # The script
        $httpVerb = "GET" # Define what HTTP operation will the script run.
        $resourcePath = "/device/devices" # Define the resourcePath, based on what you're searching for.
        $queryParams = $null
        $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
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

        # Deal with getting and handling the device ID.
        Switch ($PsCmdlet.ParameterSetName) {
            {$_ -eq "DeviceId"} {
                $resourcePath += "/$DeviceId/sdts"

                $message = ("{0}: Updated resource path to {1}." -f (Get-Date -Format s), $resourcePath)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
            }
            {$_ -eq "DeviceDisplayName"} {
                # Get the device ID, based on the display name.
                $deviceId = (Get-LogicMonitorDevices -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -DeviceDisplayName $DeviceDisplayName).id

                If ($deviceId -as [int64]) {
                    $resourcePath += "/$deviceId/sdts"

                    $message = ("{0}: Updated resource path to {1}." -f (Get-Date -Format s), $resourcePath)
                    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
                }
                Else {
                    $message = ("{0}: No device ID found for {1}. To prevent errors, {2} will exit." -f (Get-Date -Format s), $DeviceDisplayName, $MyInvocation.MyCommand)
                    If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417}

                    Return "Error"
                }
            }
        }

        # Construct the query URL.
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

        # Get current time in milliseconds
        $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

        # Concatenate request details.
        $requestVars = $httpverb + $epoch + $body + $resourcePath

        # Construct signature.
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = [Text.Encoding]::UTF8.GetBytes($accessKey)
        $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
        $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
        $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

        # Construct headers.
        $auth = "LMv1 " + $accessId + ":" + $signature + ":" + $epoch
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Authorization", $auth)
        $headers.Add("Content-Type", "application/json")
        $headers.Add("X-Version", "2")

        Try {
            $response = Invoke-RestMethod -Uri $url -Method $httpverb -Header $headers -ErrorAction Stop
        }
        Catch {
            $message = ("{0}: Unexpected error getting device SDTs. To prevent errors, {1} will exit." -f (Get-Date -Format s), $MyInvocation.MyCommand)
            If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417}

            Return "Error"
        }

        Return $response
    }
} #1.0.0.1