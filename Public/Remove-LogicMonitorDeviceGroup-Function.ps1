Function Remove-LogicMonitorDeviceGroup {
    <#
        .DESCRIPTION
            Accepts a device group ID then deletes the device group.
        .NOTES
            Author: Sven Borer
            V1.0.0.0 date: 1 September 2021
                - Initial release.
            V1.0.0.1 date: 15 September 2021
                - Update by Mike Hahsemi
            V1.0.0.2 date: 30 September 2021
            V2023.04.28.0
            V2023.08.23.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Represents the subdomain of the LogicMonitor customer. Default value is "synoptek".
        .PARAMETER Id
            Represents the device group ID. Also accepts input from Get-LogicMonitorDeviceGroup.
        .PARAMETER HardDelete
            When this switch is included, the command will permanently delete the device group. The default behavior moves the device group to "Recently Delete", from which it can be recovered.
        .PARAMETER KeepChildren
            When this switch is included, the command will delete the specified group, its children, but resources in the group(s) will not be deleted. Any resources located in the specified group (or sub-groups) will remainin in other configured groups (e.g. dynamic groups). If a resource is a member of only a deleted group, it will be placed in the root group. The default behavior of this command is to delete resources.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorDeviceGroup -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 45 -Verbose

            In this example, the function will remove the device group with ID "45" and it will be moved to the "Recently Deleted" list. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorDeviceGroup -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 45 -HardDelete -LogPath C:\temp\log.txt

            In this example, the function will remove the device group with ID "45" and it will not be recoverable. Limited logging output will be written to C:\temp\log.txt.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorDeviceGroup -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 45 -KeepChildren

            In this example, the function will remove the device group with ID "45" and it will be moved to the "Recently Deleted" list. Child device groups will be moved to the root group. Limited logging output will be written only to the host.
        .EXAMPLE
            PS C:\> $group = Get-LogicMonitorDeviceGroup -AccessId $accessid -AccessKey $accesskey -AccountName synoptek -Filter "filter=fullPath~`"Foo/Bar`""
            PS C:\> $group | Sort-Object | Remove-LogicMonitorDeviceGroup -AccessId $accessid -AccessKey $accesskey -AccountName synoptek

            In this example, the function will remove the device Bar (and its subgroups) within Foo path. Note: Sort-Object is used to make sure we delete the children first. If the parent is deleted first, an error will be generated, because the child no longer exists.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDeviceGroup -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> | ? fullpath -like "Foo/Bar*" | Remove-LogicMonitorDeviceGroup

            In this example, the function will remove the device groups named Bar* within Foo path. Note: If there are subfolders, it could potentially fail, so better sort it by desc first so the most nested groups get removed first.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [SecureString]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Int]$Id,

        [Switch]$HardDelete,

        [Switch]$KeepChildren,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    Process {
        #region Setup
        #region Initialize variables
        $httpVerb = "DELETE" # Define what HTTP operation will the script run.
        $resourcePath = "/device/groups/$Id"
        $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
        #endregion Initialize variables

        #region Logging
        # Setup parameters for splatting.
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') {
            If ($EventLogSource -and (-NOT $LogPath)) {
                $loggingParams = @{
                    Verbose        = $true
                    EventLogSource = $EventLogSource
                }
            } ElseIf ($LogPath -and (-NOT $EventLogSource)) {
                $loggingParams = @{
                    Verbose = $true
                    LogPath = $LogPath
                }
            } Else {
                $loggingParams = @{
                    Verbose = $true
                }
            }
        } Else {
            If ($EventLogSource -and (-NOT $LogPath)) {
                $loggingParams = @{
                    EventLogSource = $EventLogSource
                }
            } ElseIf ($LogPath -and (-NOT $EventLogSource)) {
                $loggingParams = @{
                    LogPath = $LogPath
                }
            } Else {
                $loggingParams = @{}
            }
        }
        #endregion Logging

        $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
        #endregion Setup

        If ($Id -lt 2) {
            $message = ("{0}: Please specify an Id greater than 1 (Root)." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

            Return "Error"
        }

        If ($HardDelete) {
            $q1 = "deleteHard=true"
        }
        Else {
            $q1 = "deleteHard=false"
        }

        If ($KeepChildren) {
            $q2 = "deleteChildren=false"
        }
        Else {
            $q2 = "deleteChildren=true"
        }

        $queryParams = "?$q1&$q2"

        #region Auth and headers
        # Get current time in milliseconds.
        $epoch = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End (Get-Date).ToUniversalTime()).TotalMilliseconds)
        $requestVars = $httpVerb + $epoch + $resourcePath
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
        $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
        $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
        $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

        $headers = @{
            "Authorization" = "LMv1 $AccessId`:$signature`:$epoch"
            "Content-Type"  = "application/json"
            "X-Version"     = 3
        }
        #endregion Auth and headers

        # Construct the query URL.
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

        $message = ("{0}: Connecting to: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $url)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        $stopLoop = $false
        Do {
            Try {
                $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop

                $stopLoop = $True
            } Catch {
                If ($_.Exception.Message -match '429') {
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                    Out-PsLogging @loggingParams -MessageType Warning -Message $message

                    Start-Sleep -Seconds 60
                } Else {
                    $message = ("{0}: Unexpected error removing DeviceGroup with id `"{1}`". To prevent errors, {2} will exit. If present, the following details were returned:`r`n
                Error message: {3}`r
                Error code: {4}`r
                Invoke-Request: {5}`r
                Headers: {6}`r
                Body: {7}" -f
                ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Id, $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage),
                ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
                    )
                    Out-PsLogging @loggingParams -MessageType Error -Message $message

                    Return "Error"
                }
            }
        } While ($stopLoop -eq $false)

        $response
    }
} #2023.08.23.0