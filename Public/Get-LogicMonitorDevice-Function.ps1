Function Get-LogicMonitorDevice {
    <#
        .DESCRIPTION
            Returns a list of LogicMonitor-monitored devices and all of their properties. By default, the function returns all devices. 
            If a device ID, device name (IP or DNS name), or device display name is provided, the function will return properties for 
            the specified device.
        .NOTES
            Author: Mike Hashemi
            V1 date: 21 November 2016
            V1.0.0.1 date: 13 January 2017
                - Added support for single-device retrieval.
            V1.0.0.2 date: 31 January 2017
                - Removed custom-object creation.
            V1.0.0.3 date: 31 January 2017
                - Updated error output color.
                - Streamlined header creation (slightly).
            V1.0.0.4 date: 31 January 2017
                - Added $logPath output to host.
            V1.0.0.5 date: 31 January 2017
                - Added additional logging.
            V1.0.0.6 date: 10 February 2017
                - Updated procedure order.
            V1.0.0.7 date: 3 May 2017
                - Removed code from writing to file and added Event Log support.
                - Updated code for verbose logging.
                - Changed Add-EventLogSource failure behavior to just block logging (instead of quitting the function).
            V1.0.0.8 date: 21 June 2017
                - Updated logging to reduce chatter.
            V1.0.0.9 date: 23 April 2018
                - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
                - Replaced ! with -NOT.
            V1.0.0.10 date: 16 June 2018
                - Updated tabs.
                - Removed $props hash table, since it is not used.
            V1.0.0.11 date: 13 March 2019
                - Updated default batch count.
                - Renamed cmdlet and added command alias.
            V1.0.0.12 date: 14 March 2019
                - Added support for rate-limited re-try.
            V1.0.0.13 date: 18 March 2019
                - Updated in-line help.
            V1.0.0.14 date: 18 March 2019
                - Updated alias publishing method.
            V1.0.0.15 date: 26 April 2019
                - Added missing loop-status set.
            V1.0.0.16 date: 22 May 2019
                - Modified looping.
                - Updated date calculation.
            V1.0.0.17 date: 23 August 2019
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Id
            Represents deviceId of the desired device.
        .PARAMETER DisplayName
            Represents display name of the desired device.
        .PARAMETER Name
            Represents IP address or FQDN of the desired device.
        .PARAMETER BatchSize
            Default value is 1000. Represents the number of devices to request from LogicMonitor, in a single batch.
        .PARAMETER EventLogSource
            Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName>

            In this example, the function will search for all monitored devices and will return their properties.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6

            In this example, the function will search for the monitored device with "6" in the ID property and will return its properties.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DisplayName server1

            In this example, the function will search for the monitored device with "server1" in the displayName property and will return its properties.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Name 10.1.1.1

            In this example, the function will search for the monitored device with "10.1.1.1" in the name property and will return its properties.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDevice -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Name server1.domain.local

            In this example, the function will search for the monitored device with "server1.domain.local" (the FQDN) in the name property and will return its properties.
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllDevices')]
    [alias('Get-LogicMonitorDevices')]
    Param (
        [Parameter(Mandatory)]
        $AccessId,

        [Parameter(Mandatory)]
        $AccessKey,

        [Parameter(Mandatory)]
        $AccountName,

        [Parameter(Mandatory, ParameterSetName = 'IDFilter')]
        [Alias("DeviceId")]
        [int]$Id,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [Alias("DeviceDisplayName")]
        [string]$DisplayName,

        [Parameter(Mandatory, ParameterSetName = 'IPFilter')]
        [Alias("DeviceName")]
        [string]$Name,

        [int]$BatchSize = 1000,

        [string]$EventLogSource = 'LogicMonitorPowershellModule',

        [switch]$BlockLogging
    )

    If (-NOT($BlockLogging)) {
        $return = Add-EventLogSource -EventLogSource $EventLogSource

        If ($return -ne "Success") {
            $message = ("{0}: Unable to add event source ({1}). No logging will be performed." -f [datetime]::Now, $EventLogSource)
            Write-Warning $message;

            $BlockLogging = $True
        }
    }

    $message = ("{0}: Beginning {1}." -f [datetime]::Now, $MyInvocation.MyCommand)
    If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

    $message = ("{0}: Operating in the {1} parameter set." -f [datetime]::Now, $PsCmdlet.ParameterSetName)
    If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

    # Initialize variables.
    $devices = [System.Collections.Generic.List[PSObject]]::New() # Primary collection to be filled with Invoke-RestMethod response.
    $singleDeviceCheckDone = $false # Controls when a Do loop exits, if we are getting a single dashboard (by ID or name).
    $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    $firstLoopDone = $false # Will change to true, once the function determines how many times it needs to loop, to retrieve all devices.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $resourcePath = "/device/devices" # Define the resourcePath, based on the type of device you're searching for.
    $queryParams = $null
    [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    $message = ("{0}: The resource path is: {1}." -f [datetime]::Now, $resourcePath)
    If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

    # Update $resourcePath to filter for a specific device, when a device ID is provided by the user.
    If ($PsCmdlet.ParameterSetName -eq "IDFilter") {
        $resourcePath += "/$Id"

        $message = ("{0}: Updated resource path to {1}." -f [datetime]::Now, $resourcePath)
        If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }
    }

    Do {
        Switch ($PsCmdlet.ParameterSetName) {
            { $_ -in ("IDFilter", "AllDevices") } {
                $queryParams = "?offset=$offset&size=$BatchSize&sort=id"

                $message = ("{0}: Updated `$queryParams variable in {1}. The value is {2}." -f [datetime]::Now, $($PsCmdlet.ParameterSetName), $queryParams)
                If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }
            }
            "NameFilter" {
                $queryParams = "?filter=displayName:`"$DisplayName`"&offset=$offset&size=$BatchSize&sort=id"

                $message = ("{0}: Updated `$queryParams variable in {1}. The value is {2}." -f [datetime]::Now, $($PsCmdlet.ParameterSetName), $queryParams)
                If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }
            }
            "IPFilter" {
                $queryParams = "?filter=name:`"$Name`"&offset=$offset&size=$BatchSize&sort=id"

                $message = ("{0}: Updated `$queryParams variable in {1}. The value is {2}." -f [datetime]::Now, $($PsCmdlet.ParameterSetName), $queryParams)
                If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }
            }
        }

        # Construct the query URL.
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

        If ($firstLoopDone -eq $false) {
            $message = ("{0}: Building request header." -f [datetime]::Now)
            If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

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
        }

        Switch ($PsCmdlet.ParameterSetName) {
            "AllDevices" {
                $message = ("{0}: Entering switch statement for all-device retrieval." -f [datetime]::Now)
                If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                $queryParams = "?offset=$offset&size=$BatchSize&sort=id"

                $message = ("{0}: Updated `$queryParams variable in {1}. The value is {2}." -f [datetime]::Now, $($PsCmdlet.ParameterSetName), $queryParams)
                If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                # Make Request
                $message = ("{0}: Executing the REST query." -f [datetime]::Now)
                If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                $stopLoop = $false
                Do {
                    Try {
                        $response = ([System.Collections.Generic.List[PSObject]]@(Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop).items)

                        $stopLoop = $True
                        $firstLoopDone = $True
                    }
                    Catch {
                        If ($_.Exception.Message -match '429') {
                            $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f [datetime]::Now, $MyInvocation.MyCommand, $_.Exception.Message)
                            If ($BlockLogging) { Write-Warning $message } Else { Write-Warning $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Warning -Message $message -EventId 5417 }

                            Start-Sleep -Seconds 60
                        }
                        Else {
                            $message = ("{0}: Unexpected error getting devices. To prevent errors, {1} will exit. PowerShell returned: {2}" -f [datetime]::Now, $MyInvocation.MyCommand, $_.Exception.Message)
                            If ($BlockLogging) { Write-Error $message } Else { Write-Error $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417 }

                            Return "Error"
                        }
                    }
                }
                While ($stopLoop -eq $false)

                If ($firstLoopDone -and ($null -ne $response)) {
                    # If no dashboard ID or name is provided...
                    $devices.AddRange($response)

                    $message = ("{0}: There are {1} devices in `$devices." -f [datetime]::Now, $devices.count)
                    If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                    # Increment offset, to grab the next batch of devices.
                    $message = ("{0}: Incrementing the search offset by {1}." -f [datetime]::Now, $BatchSize)
                    If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                    $offset += $BatchSize
                }
            }
            # If a device ID, IP, or display name is provided...
            { $_ -in ("IDFilter", "NameFilter", "IPFilter") } {
                $message = ("{0}: Entering switch statement for single-device retrieval." -f [datetime]::Now)
                If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                # Make Request
                $message = ("{0}: Executing the REST query." -f [datetime]::Now)
                If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                $stopLoop = $false
                Do {
                    Try {
                        $response = [System.Collections.Generic.List[PSObject]]@(Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop)

                        $stopLoop = $True
                        $firstLoopDone = $True
                        $singleDeviceCheckDone = $True
                    }
                    Catch {
                        If ($_.Exception.Message -match '429') {
                            $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f [datetime]::Now, $MyInvocation.MyCommand, $_.Exception.Message)
                            If ($BlockLogging) { Write-Warning $message } Else { Write-Warning $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Warning -Message $message -EventId 5417 }

                            Start-Sleep -Seconds 60
                        }
                        Else {
                            $message = ("{0}: Unexpected error getting device. To prevent errors, {1} will exit. PowerShell returned: {2}" -f [datetime]::Now, $MyInvocation.MyCommand, $_.Exception.Message)
                            If ($BlockLogging) { Write-Error $message } Else { Write-Error $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417 }

                            Return "Error"
                        }
                    }
                }
                While ($stopLoop -eq $false)

                $devices.AddRange($response)

                $message = ("{0}: There are {1} devices in `$devices." -f [datetime]::Now, $($devices.count))
                If (($BlockLogging) -AND ($devices['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }
            }
        }
    }
    Until (($null -eq $response) -or ($singleDeviceCheckDone))

    $devices
} #1.0.0.17