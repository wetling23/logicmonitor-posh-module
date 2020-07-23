Function Get-LogicMonitorCollectorInstaller {
    <#
        .DESCRIPTION
            Generates and downloads a 64-bit Windows, LogicMonitor Collector installer. If successful, return the download path.
        .NOTES
            Author: Mike Hashemi
            V1 date: 27 December 2016
            V1.0.0.1 date 15 January 2017
                - Added parameter sets for collector properties.
                - Added support for collector ID retrieval based on the hostname.
            V1.0.0.2 date 31 January 2017
                - Updated code to support the Get-LogicMonitorCollectors syntax for ID retrieval.
                - Updated error handling.
            V1.0.0.3 date: 31 January 2017
                - Updated error output color.
                - Streamlined header creation (slightly).
            V1.0.0.4 date: 31 January 2017
                - Added $logPath output to host.
            V1.0.0.5 date: 31 Janyary 2017
                - Added additional logging.
            V1.0.0.6 date: 10 February 2017
                - Updated procedure order.
                - Updated documentation.
            V1.0.0.7 date: 3 May 2017
                - Removed code from writing to file and added Event Log support.
                - Updated code for verbose logging.
                - Changed Add-EventLogSource failure behavior to just block logging (instead of quitting the function).
            V1.0.0.8 date: 14 May 2017
                - Fixed bug in output (incorrect index number).
                - Replaced ! with -NOT.
            V1.0.0.9 date: 23 April 2018
                - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
            V1.0.0.10 date: 10 May 2018
                - Replaced Invoke-WebRequest with a System.Net.WebClient object.
                - Added support for synchronous and asynchronous downloads.
                - Added parameter type casting.
            V1.0.0.11 date: 14 March 2019
                - Added support for rate-limited re-try.
            V1.0.0.12 date: 29 July 2019
            V1.0.0.13 date: 9 August 2019
            V1.0.0.14 date: 15 August 2019
            V1.0.0.15 date: 23 August 2019
            V1.0.0.16 date: 26 August 2019
            V1.0.0.17 date: 3 September 2019
            V1.0.0.18 date: 3 September 2019
            V1.0.0.19 date: 18 October 2019
            V1.0.0.20 date: 4 December 2019
            V1.0.0.21 date: 23 July 2020
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER CollectorID
            Represents the ID number of the desired collector. If no ID is provided and it cannot be found in the registry, the script will exit.
        .PARAMETER CollectorHostName
            Mandatory parameter. Represents the short name of the EDGE Hub.
        .PARAMETER OutputPath
            Mandatory parameter. Represents the path, to which the installer will be downloaded. The default value is $env:TEMP.
        .PARAMETER Async
            When this switch is included, the cmdlet will initiate the download and exit before it is finished. The default behavior is to wait for the download to complete.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorCollectorInstaller -AccessID <access id> -AccessKey <access key> -Account <account name> -Hostname "server1" -Verbose

            In this example, the cmdlet connects to LogicMonitor and downloads the 64-bit Windows installer for collector "server1". The file is saved to C:\users\<username>\AppData\Temp\lmInstaller.exe. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorCollectorInstaller -AccessID <access id> -AccessKey <access key> -Account <account name> -Id 11"

            In this example, the cmdlet connects to LogicMonitor and downloads the 64-bit Windows installer for collector 11. The file is saved to C:\users\<username>\AppData\Temp\lmInstaller.exe.
        .EXAMPLE
            PS C:\> Get-LogicMonitorCollectorInstaller -AccessID <access id> -AccessKey <access key> -Account <account name> -Id 11 -Async"

            In this example, the cmdlet connects to LogicMonitor and downloads the 64-bit Windows installer for collector 11. The file is saved to C:\users\<username>\AppData\Temp\lmInstaller.exe.
            The cmdlet will continue (and exit) while the download is in progress.
    #>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [securestring]$AccessKey,

        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory, ParameterSetName = "Default")]
        [Alias("CollectorID")]
        [int]$Id,

        [Parameter(Mandatory, ParameterSetName = "Name")]
        [Alias("CollectorHostName")]
        [string]$Hostname,

        [ValidateSet("nano", "small", "medium", "large")]
        [string]$Size = "medium",

        [ValidateSet("Win32", "Win64", "Linux32", "Linux64")]
        [string]$Os = "Win64",

        [ValidateScript( {
                If (-Not ($_ | Test-Path) ) {
                    Throw "File or folder does not exist"
                }
                If (-Not ($_ | Test-Path -PathType Container) ) {
                    Throw "The Path argument must be a file. Folder paths are not allowed."
                }
                Return $true
            })]
        [System.IO.FileInfo]$OutputPath = $env:TEMP,

        [switch]$Async,

        [boolean]$BlockStdErr = $false,

        [string]$EventLogSource,

        [string]$LogPath
    )

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    # Initialize variables.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    Switch ($PsCmdlet.ParameterSetName) {
        Default {
            $resourcePath = "/setting/collector/collectors/$Id/installers/$Os"
            $queryParams = "?monitorOthers=true&collectorSize=$Size"
        }
        Name {
            Try {
                $message = ("{0}: Attempting to retrieve the collector ID from LogicMonitor." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $_.Exception.Message)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                # LogicMonitor for the collector hostname and return the id property value, for the one collector matching the desired hostname.
                $collector = Get-LogicMonitorCollectors -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -Hostname $Hostname
            }
            Catch {
                $message = ("{0}: Unexpected error retrieving the collector Id from LogicMonitor. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
                    Error message: {2}`r
                    Error code: {3}`r
                    Invoke-Request: {4}`r
                    Headers: {5}`r
                    Body: {6}" -f
                    ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage),
                    ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
                )
                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                Return "Error"
            }

            If ($collector.Id -as [int]) {
                $message = ("{0}: The ID property of {1} is {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Hostname, $collector.Id)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                $resourcePath = "/setting/collectors/$($collector.Id)/installers/$Os"
                $queryParams = "?monitorOthers=true&collectorSize=$Size"
            }
            Else {
                $message = ("{0}: The search of LogicMonitor for {1}'s collector ID value returned a non-number. The value is: {2}. To prevent errors, {3} will exit." -f `
                        ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Hostname, $collector.Id, $MyInvocation.MyCommand)
                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                Return "Error"
            }
        }
    }

    # Construct the query URL.
    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

    # Get current time in milliseconds
    $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

    # Concatenate Request Details
    $requestVars = $httpVerb + $epoch + $resourcePath

    # Construct Signature
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
    $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
    $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
    $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

    # Create the web client object and add headers
    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add("Authorization", "LMv1 $accessId`:$signature`:$epoch")
    $webClient.Headers.Add("Content-Type", 'application/json')
    $webClient.Headers.Add("X-Version", '2')

    # Make Request
    Switch ($Async) {
        $True {
            $message = ("{0}: Beginning download of the LogicMonitor Collector installer to {1}. {2} will continue while the download is in progress." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $OutputPath, $MyInvocation.MyCommand)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            Try {
                $webClient.DownloadFileAsync($url, "$($OutputPath.FullName)\lmInstaller.exe")
                Register-ObjectEvent -InputObject $webClient -EventName DownloadFileCompleted -SourceIdentifier WebClient.DownloadFileComplete -Action { Unregister-Event -SourceIdentifier WebClient.DownloadFileComplete; $webClient.Dispose(); }
            }
            Catch {
                $message = ("{0}: Unexpected error downloading the LogicMonitor Collector installer. The specific error is: {1}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $_.Exception.Message)
                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                Return "Error"
            }

            Return "$($OutputPath.FullName)\lmInstaller.exe"
        }
        $False {
            $message = ("{0}: Beginning download of the LogicMonitor Collector installer to {1}. {2} will continue when the download is complete." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $OutputPath, $MyInvocation.MyCommand)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            Try {
                $webClient.DownloadFile($url, "$($OutputPath.FullName)\lmInstaller.exe")
                $webClient.Dispose()
            }
            Catch {
                $message = ("{0}: Unexpected error downloading the LogicMonitor Collector installer. The specific error is: {1}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $_.Exception.Message)
                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                Return "Error"
            }

            If ((Test-Path -Path "$($OutputPath.FullName)\lmInstaller.exe") -and ((Get-Item -Path "$($OutputPath.FullName)\lmInstaller.exe").Length -gt 10MB)) {
                $message = ("{0}: The LogicMonitor installer was downloaded. Returning the download path." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                Return "$($OutputPath.FullName)\lmInstaller.exe"
            }
            Else {
                $message = ("{0}: There was no detectable error downloading the LogicMonitor installer, but it is not present in the download location ({1}). To prevent errors, the function {2} will exit" `
                        -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $OutputPath, $MyInvocation.MyCommand)
                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                Return "Error"
            }
        }
    }
} #1.0.0.21