Function Remove-LogicMonitorDevice {
    <#
        .DESCRIPTION
            Accepts a device ID, display name, or device IP/DNS name, then deletes it.
        .NOTES 
            Author: Mike Hashemi
            V1.0.0.0 date: 19 June 2017
                - Initial release.
            V1.0.0.1 date: 7 August 2017
                - Changed ! to -Not.
                - Updated .EXAMPLE.
            V1.0.0.2 date: 28 August 2017
                - Updated NameFilter code.
            V1.0.0.3 date: 23 April 2018
                - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
            V1.0.0.4 date: 2 July 2018
                - Updated white space.
                - The cmdlet now only returns the API response (after the query is made, we'll still return "Error" if there is a problem eariler in the code).
            V1.0.0.5 date: 14 March 2019
                - Added support for rate-limited re-try.
            V1.0.0.6 date: 15 April 2019
            V1.0.0.7 date: 23 August 2019
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Id
            Represents the device ID of a desired device.
        .PARAMETER DisplayName
            Represents the device display name of a desired device.
        .PARAMETER Name
            Represents the device name of a desired device.
        .PARAMETER EventLogSource
            Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 45

            Deletes the device with Id 45.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Name "10.0.0.1"

            Deletes the device with name 10.0.0.1. If more than one device is returned, the function will exit.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DisplayName "server1.domain.local"

            Deletes the device with display name "server1.domain.local".
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param (
        [Parameter(Mandatory = $True)]
        [string]$AccessId,

        [Parameter(Mandatory = $True)]
        [string]$AccessKey,

        [Parameter(Mandatory = $True)]
        [string]$AccountName,

        [Parameter(Mandatory = $True, ParameterSetName = 'Default')]
        [Alias('DeviceId')]
        [int]$Id,

        [Parameter(Mandatory = $True, ParameterSetName = 'NameFilter')]
        [Alias('DeviceDisplayName')]
        [string]$DisplayName,

        [Parameter(Mandatory = $True, ParameterSetName = 'IPFilter')]
        [Alias('DeviceName')]
        [string]$Name,

        [string]$EventLogSource = 'LogicMonitorPowershellModule',

        [switch]$BlockLogging
    )

    If (-NOT($BlockLogging)) {
        $return = Add-EventLogSource -EventLogSource $EventLogSource

        If ($return -ne "Success") {
            $message = ("{0}: Unable to add event source ({1}). No logging will be performed." -f [datetime]::Now, $EventLogSource)
            Write-Host $message

            $BlockLogging = $True
        }
    }

    $message = ("{0}: Beginning {1}." -f [datetime]::Now, $MyInvocation.MyCommand)
    If ($BlockLogging) { Write-Host $message -ForegroundColor White } Else { Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

    # Initialize variables.
    [int]$index = 0
    $propertyData = ""
    $data = ""
    $httpVerb = 'DELETE'
    $queryParams = $null
    [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    $message = ("{0}: Updated `$resourcePath. The value is {1}." -f [datetime]::Now, $resourcePath)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

    # Update $resourcePath to filter for a specific device, when a device ID, name, or displayName is provided by the user.
    Switch ($PsCmdlet.ParameterSetName) {
        Default {
            $resourcePath = "/device/devices/$Id"
        }
        "NameFilter" {
            $message = ("{0}: Attempting to retrieve the device ID of {1}." -f [datetime]::Now, $DisplayName)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

            $device = Get-LogicMonitorDevice -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -DisplayName $DisplayName -EventLogSource $EventLogSource
            
            If ($device.id) {
                $resourcePath = "/device/devices/$($device.id)"
            }
            Else {
                $message = ("{0}: No device was returned when searching for {1}. To prevent errors, {2} will exit." `
                        -f [datetime]::Now, $DisplayName, $MyInvocation.MyCommand)
                If ($BlockLogging) { Write-Host $message -ForegroundColor Red } Else { Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417 }

                Return "Error"
            }

            $message = ("{0}: The value of `$resourcePath is {1}." -f [datetime]::Now, $resourcePath)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }
        }
        "IPFilter" {
            $message = ("{0}: Attempting to retrieve the device ID of {1}." -f [datetime]::Now, $Name)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

            If ($Id -eq $null) {
                $device = Get-LogicMonitorDevices -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -Name $Name -EventLogSource $EventLogSource
            }

            If ($device.count -gt 1) {
                $message = ("{0}: More than one device with the name {1} were detected (specifically {2}). To prevent errors, {3} will exit." `
                        -f [datetime]::Now, $Name, $device.count, $MyInvocation.MyCommand)
                If ($BlockLogging) { Write-Host $message -ForegroundColor Red } Else { Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417 }

                Return "Error"
            }
            ElseIf ($device.id) {
                $Id = $device.id
                $resourcePath = "/device/devices/$($device.id)"
            }
            Else {
                $message = ("{0}: No device was returned when searching for {1}. To prevent errors, {2} will exit." `
                        -f [datetime]::Now, $Name, $MyInvocation.MyCommand)
                If ($BlockLogging) { Write-Host $message -ForegroundColor Red } Else { Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417 }

                Return "Error"
            }

            $message = ("{0}: The value of `$resourcePath is {1}." -f [datetime]::Now, $resourcePath)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }
        }
    }

    # Construct the query URL.
    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

    $message = ("{0}: The value of `$url is {1}." -f [datetime]::Now, $url)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

    # Get current time in milliseconds
    $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

    # Concatenate Request Details
    $requestVars = $httpVerb + $epoch + $resourcePath

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
    $headers.Add("X-Version", 2)

    # Make Request
    $message = ("{0}: Executing the REST query." -f [datetime]::Now)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

    Try {
        $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop
    }
    Catch {
        If ($_.ErrorDetails.message | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage -ErrorAction SilentlyContinue) {
            $message = ("{0}: The request failed and the error message is: `"{1}`". The error code is: {2}." -f [datetime]::Now, ($_.ErrorDetails.message | ConvertFrom-Json | Select-Object -ExpandProperty errorMessage -ErrorAction SilentlyContinue), ($_.ErrorDetails.message | ConvertFrom-Json | Select-Object -ExpandProperty errorCode -ErrorAction SilentlyContinue))
            If ($BlockLogging) { Write-Error $message } Else { Write-Error $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $message -EventId 5417 }
        }
        Else {
            $message = ("{0}: Unexpected error adding DeviceGroup called `"{1}`". The specific error is: {2}" -f [datetime]::Now, $Properties.Name, $_.Exception.Message)
            If ($BlockLogging) { Write-Error $message } Else { Write-Error $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $message -EventId 5417 }
        }

        Return "Error"
    }

    Return $response
} #1.0.0.7