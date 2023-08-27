Function Remove-LogicMonitorWebsiteGroup {
    <#
        .DESCRIPTION
            Accepts a website group ID then deletes the website group.
        .NOTES
            Author: Mike Hashemi
            V2023.08.27.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Represents the subdomain of the LogicMonitor customer. Default value is "synoptek".
        .PARAMETER Id
            Represents the website group ID. Also accepts input from Get-LogicMonitorWebsiteGroup.
        .PARAMETER KeepChildren
            When this switch is included, the command will delete the specified group, its children, but resources in the group(s) will not be deleted. Any resources located in the specified group (or sub-groups) will remainin in other configured groups (e.g. dynamic groups). If a resource is a member of only a deleted group, it will be placed in the root group. The default behavior of this command is to delete resources.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorWebsiteGroup -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 45 -Verbose

            In this example, the function will remove the website group with ID "45". Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorWebsiteGroup -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 45 -KeepChildren

            In this example, the function will remove the website group with ID "45". Child website groups will be moved to the root group. Limited logging output will be written only to the host.
        .EXAMPLE
            PS C:\> $group = Get-LogicMonitorWebsiteGroup -AccessId $accessid -AccessKey $accesskey -AccountName synoptek -Filter "filter=fullPath~`"Foo/Bar`""
            PS C:\> $group | Sort-Object | Remove-LogicMonitorWebsiteGroup -AccessId $accessid -AccessKey $accesskey -AccountName synoptek

            In this example, the function will remove the website group Bar (and its subgroups) within Foo path. Note: Sort-Object is used to make sure we delete the children first. If the parent is deleted first, an error will be generated, because the child no longer exists.
        .EXAMPLE
            PS C:\> Get-LogicMonitorWebsiteGroup -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> | ? fullpath -like "Foo/Bar*" | Remove-LogicMonitorWebsiteGroup

            In this example, the function will remove the website groups named Bar* within Foo path. Note: If there are subfolders, it could potentially fail, so better sort it by desc first so the most nested groups get removed first.
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

        [Switch]$KeepChildren,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    Process {
        #region Setup
        #region Initialize variables
        $httpVerb = "DELETE" # Define what HTTP operation will the script run.
        $resourcePath = "/website/groups/$Id"
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

        If ($KeepChildren) {
            $q2 = "deleteChildren=0"
        }
        Else {
            $q2 = "deleteChildren=1"
        }

        $queryParams = "?$q2"

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
                    $message = ("{0}: Unexpected error removing website group with id `"{1}`". To prevent errors, {2} will exit. If present, the following details were returned:`r`n
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
} #2023.08.27.0