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
            V1.0.0.2 date: 13 March 2019
                - Added error message to command output.
            V1.0.0.3 date: 14 March 2019
                - Added support for rate-limited re-try.
                - Changed the format of the returned object.
            V1.0.0.4 date: 14 March 2019
                - Added support for rate-limited re-try.
            V1.0.0.5 date: 23 August 2019
            V1.0.0.6 date: 26 August 2019
            V1.0.0.7 date: 18 October 2019
            V1.0.0.8 date: 4 December 2019
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER DisplayName
            Represents the device display name of the desired device.
        .PARAMETER Id
            Represents the device ID of the desired device.
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDeviceSdt -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DisplayName server1 -Verbose

            In this example, the command gets all active SDTs for a server with the display name 'server1'. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDeviceSdt -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 2

            In this example, the command gets all active SDTs for a server with the ID '2'.
    #>
    [CmdletBinding(DefaultParameterSetName = 'DeviceIdFilter')]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [securestring]$AccessKey,

        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory, ParameterSetName = "DeviceDisplayNameFilter")]
        [Alias("DeviceDisplayName")]
        [string]$DisplayName,

        [Parameter(Mandatory, ParameterSetName = "DeviceIdFilter")]
        [Alias("DeviceId")]
        [string]$Id,

        [string]$EventLogSource,

        [string]$LogPath
    )

    Begin {
        # Initialize variables.
        $httpVerb = "GET" # Define what HTTP operation will the script run.
        $resourcePath = "/device/devices" # Define the resourcePath, based on what you're searching for.
        $queryParams = $null
        [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
        $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    }
    Process {
        # Deal with getting and handling the device ID.
        Switch ($PsCmdlet.ParameterSetName) {
            { $_ -eq "DeviceIdFilter" } {
                $resourcePath += "/$Id/sdts"

                $message = ("{0}: Updated resource path to {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
            }
            { $_ -eq "DeviceDisplayNameFilter" } {
                # Get the device ID, based on the display name.
                $id = (Get-LogicMonitorDevices -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -DisplayName $DisplayName).id

                If ($id -as [int64]) {
                    $resourcePath += "/$id/sdts"

                    $message = ("{0}: Updated resource path to {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
                    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
                }
                Else {
                    $message = ("{0}: No device ID found for {1}. To prevent errors, {2} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $DisplayName, $MyInvocation.MyCommand)
                    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

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
        $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
        $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
        $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
        $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

        # Construct headers.
        $headers = @{
            "Authorization" = "LMv1 $accessId`:$signature`:$epoch"
            "Content-Type"  = "application/json"
            "X-Version"     = 2
        }

        Do {
            Try {
                $response = Invoke-RestMethod -Uri $url -Method $httpverb -Header $headers -ErrorAction Stop

                $stopLoop = $True
            }
            Catch {
                If ($_.Exception.Message -match '429') {
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }

                    Start-Sleep -Seconds 60
                }
                Else {
                    $message = ("{0}: Unexpected error getting device SDTs. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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

        Return $response.items
    }
} #1.0.0.8