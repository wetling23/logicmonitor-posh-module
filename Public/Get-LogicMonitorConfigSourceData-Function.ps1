Function Get-LogicMonitorConfigSourceData {
    <#
        .DESCRIPTION
            Returns a list of LogicMonitor ConfigSources. By default, the function returns all ConfigSources. If a ConfigSource ID or name is provided, the function will 
            return properties for the specified ConfigSource.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 12 March 2021
                - Initial release.
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER DeviceDisplayName
            Represents the LogicMonitor display name of the device, for which config backups will backups will be retrieved.
        .PARAMETER DeviceIp
            Represents the LogicMonitor name/IP of the device, for which config backups will backups will be retrieved.
        .PARAMETER DeviceId
            Represents the LogicMonitor device ID of the device, for which config backups will backups will be retrieved.
        .PARAMETER EntryCount
            Represents the number of config backups to retrieve, for each ConfigSource/instance. Valid entries are "All" of a desired number and the responses are ordered with the newest backup first. The default value is "1" (the most recent backup).
        .PARAMETER ConfigSourceName
            Represents the name (not display name) of the desired ConfigSource. As of this version, display name is not supported because multiple ConfigSources can share a display name.
        .PARAMETER ConfigSourceId
            Represents the ID of the desired ConfigSource.
        .PARAMETER InstanceName
            Represents the ConfigSource instance name, to retrieve. If the InstanceName is parameter is defined, but ConfigSourceName or ConfigSourceId are not, the InstanceName filter will be ignored.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorConfigSourceData -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceDisplayName 'router1' -EntryCount All -ConfigSourceName 'Cisco_IOS' -Verbose

            In this example, the command will return all of the available config backups for all instances under the Cisco_IOS ConfigSource on router1. Verbose logging output will be sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorConfigSourceData -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceDisplayName 'router1' -EntryCount 2 -ConfigSourceName 'Cisco_IOS' -Verbose -LogPath C:\Temp\log.txt

            In this example, the command will return the two most recent config backups for all instances of the Cisco_IOS ConfigSource on router1. Verbose logging output will be sent to the host and C:\Temp\log.txt
        .EXAMPLE
            PS C:\> Get-LogicMonitorConfigSourceData -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceId 100 -EntryCount 2 -ConfigSourceName Cisco_IOS -InstanceName running-config

            In this example, the command will return the two most recent config backups of the running-config instance of the Cisco_IOS ConfigSource on the device with ID 100. Limited logging output will be sent to the host only.
        .EXAMPLE
            PS C:\> Get-LogicMonitorConfigSourceData -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceId 100 -ConfigSourceId 200

            In this example, the command will return the most recent config backups of all instances of the ConfigSource with ID 200 on the device with ID 100. Limited logging output will be sent to the host only.
        .EXAMPLE
            PS C:\> Get-LogicMonitorConfigSourceData -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DeviceId 100 -InstanceName running-config

            In this example, the command will return the most recent config backups of all instances of all ConfigSources on the device with ID 100 (the instance name filter will be ignored). Limited logging output will be sent to the host only.
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllCs')]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [securestring]$AccessKey,

        [Parameter(Mandatory)]
        [string]$AccountName,

        [string]$DeviceDisplayName,

        [string]$DeviceIp,

        [string]$DeviceId,

        [ValidateScript({
        If(-NOT($_ -match '^(\bAll\b|[0-9]+)$') ){
            Throw "The value of EntryCount is incorrect."
        }
        Return $true
        })]
        [string]$EntryCount = 1,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [string]$ConfigSourceName,
        
        [Parameter(Mandatory, ParameterSetName = 'IDFilter')]
        [int]$ConfigSourceId,

        [string]$InstanceName,

        [boolean]$BlockStdErr = $false,

        [string]$EventLogSource,

        [string]$LogPath
    )

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    #region Setup
    # Initialize variables.
    [string]$httpVerb = "GET" # Define what HTTP operation will the script run.
    $queryParams = '?filter=dataSourceType:"CS"'
    $i = 0 # Used later, to count the times we go through a foreach loop.
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    # Splatting for Get-LogicMonitor* cmdlet(s).
    If ($PSBoundParameters['Verbose']) {
        $commandParams = @{
            Verbose = $true
        }

        If ($EventLogSource -and (-NOT $LogPath)) {
            $CommandParams.Add('EventLogSource', $EventLogSource)
        } ElseIf ($LogPath -and (-NOT $EventLogSource)) {
            $CommandParams.Add('LogPath', $LogPath)
        }
    } Else {
        If ($EventLogSource -and (-NOT $LogPath)) {
            $commandParams = @{
                EventLogSource = $EventLogSource
            }
        } ElseIf ($LogPath -and (-NOT $EventLogSource)) {
            $commandParams = @{
                LogPath = $LogPath
            }
        } Else {
            $commandParams = @{
                Verbose = $false
            }
        }
    }

    $message = ("{0}: Parsing device identity." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    If ($DeviceDisplayName) {
        $deviceId = (Get-LogicMonitorDevice -DisplayName $DeviceDisplayName -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName @commandParams).id
    }
    ElseIf ($DeviceIp) {
        $deviceId = (Get-LogicMonitorDevice -Name $DeviceIp -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName @commandParams).id
    }

    If (($DeviceId) -and ($DeviceId -as [int])) {
        $resourcePath = "/device/devices/$DeviceId/devicedatasources"

        $message = ("{0}: Set resource path = {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
    }
    Else {
        $message = ("{0}: No device ID identified. To prevent errors, {1} will exit. Please provide a valid LogicMonitor device ID, device display name, or device name/IP and try again." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

        Return "Error"
    }
    #endregion Setup

    #region Get all ConfigSources applied to device
    # Construct the query URL.
    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

    $message = ("{0}: Building request header." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

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

    # Construct Headers
    $headers = @{
        "Authorization" = "LMv1 $AccessId`:$signature`:$epoch"
        "Content-Type"  = "application/json"
        "X-Version"     = 2
    }

    $message = ("{0}: Executing REST query to get all applied ConfigSources." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    $stopLoop = $false
    Do {
        Try {
            $appliedConfigSources = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop

            $stopLoop = $True
        } Catch {
            If ($_.Exception.Message -match '429') {
                $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }

                Start-Sleep -Seconds 60
            } Else {
                $message = ("{0}: Unexpected error getting applied ConfigSources. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
                    Error message: {2}`r
                    Error code: {3}`r
                    Invoke-Request: {4}`r
                    Headers: {5}`r
                    Body: {6}" -f
                    ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage -ErrorAction SilentlyContinue),
                    ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode -ErrorAction SilentlyContinue), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
                )
                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                Return "Error"
            }
        }
    }
    While ($stopLoop -eq $false)
    #endregion Get all ConfigSources applied to device

    #region Get all instances
    If (($appliedConfigSources.items.id) -and (($appliedConfigSources.items | Where-Object { $_.dataSourceName -eq $ConfigSourceName }) -or ($appliedConfigSources.items | Where-Object { $_.id -eq $ConfigSourceId }))) {
        $message = ("{0}: Found the desired ConfigSource." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        If (-NOT($ConfigSourceId)) {
            $message = ("{0}: ConfigSource ID not provided, attempting to identify it." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $ConfigSourceId = ($appliedConfigSources.items | Where-Object { $_.dataSourceName -eq $ConfigSourceName }).id
        }

        $message = ("{0}: Attempting to get all instances of ConfigSource with ID {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $ConfigSourceId)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $resourcePath += "/$ConfigSourceId/instances"

        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"

        # Get current time in milliseconds
        $epoch = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End (Get-Date).ToUniversalTime()).TotalMilliseconds)

        # Concatenate Request Details
        $requestVars = $httpVerb + $epoch + $resourcePath

        # Construct Signature
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
        $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
        $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
        $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

        # Construct Headers
        $headers = @{
            "Authorization" = "LMv1 $AccessId`:$signature`:$epoch"
            "Content-Type"  = "application/json"
            "X-Version"     = 2
        }

        $message = ("{0}: Executing REST query to get all instances of CS {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $ConfigSourceId)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $stopLoop = $false
        Do {
            Try {
                $instances = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop
                $stopLoop = $True
            } Catch {
                If ($_.Exception.Message -match '429') {
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }

                    Start-Sleep -Seconds 60
                } Else {
                    $message = ("{0}: Unexpected error getting instances. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
                    Error message: {2}`r
                    Error code: {3}`r
                    Invoke-Request: {4}`r
                    Headers: {5}`r
                    Body: {6}" -f
                        ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage -ErrorAction SilentlyContinue),
                        ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode -ErrorAction SilentlyContinue), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
                    )
                    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                    Return "Error"
                }
            }
        }
        While ($stopLoop -eq $false)
        #endregion Get all instances

        #region Get data
        If (($instances.items) -and ($InstanceName)) {
            $message = ("{0}: Parsing instance ID for {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $InstanceName)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $desiredInstances = ($instances.items | Where-Object { ($_.Displayname -match $InstanceName) -or ($_.name -match $InstanceName) })
        }
        ElseIf ($instances.items) {
            $desiredInstances = $instances.items
        }

        Foreach ($instance in $desiredInstances) {
            $i++

            $message = ("{0}: Getting the most recent config backup for instance {1}. This is instance {2} of {3}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $instance.id, $i, $desiredInstances.id.Count)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $resourcePath = "/device/devices/$DeviceId/devicedatasources/$ConfigSourceId/instances/$($instance.id)/config"

            $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"

            # Get current time in milliseconds
            $epoch = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End (Get-Date).ToUniversalTime()).TotalMilliseconds)

            # Concatenate Request Details
            $requestVars = $httpVerb + $epoch + $resourcePath

            # Construct Signature
            $hmac = New-Object System.Security.Cryptography.HMACSHA256
            $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
            $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
            $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
            $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

            # Construct Headers
            $headers = @{
                "Authorization" = "LMv1 $AccessId`:$signature`:$epoch"
                "Content-Type"  = "application/json"
                "X-Version"     = 2
            }

            $message = ("{0}: Executing REST query to get config backup." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $stopLoop = $false
            Do {
                Try {
                    $data = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop
                    $stopLoop = $True
                } Catch {
                    If ($_.Exception.Message -match '429') {
                        $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }

                        Start-Sleep -Seconds 60
                    } Else {
                        $message = ("{0}: Unexpected error getting config backup. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
                    Error message: {2}`r
                    Error code: {3}`r
                    Invoke-Request: {4}`r
                    Headers: {5}`r
                    Body: {6}" -f
                            ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage -ErrorAction SilentlyContinue),
                            ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode -ErrorAction SilentlyContinue), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
                        )
                        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                        Return "Error"
                    }
                }
            }
            While ($stopLoop -eq $false)

            If ($data.items) {
                $message = ("{0}: Retrieved {1} backups. Returning {2} backups." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $data.items.id.Count, $EntryCount)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                If ($EntryCount -eq "All") {
                    ($data.items | Sort-Object -Property pollTimestamp -Descending).Config # Sorted this way, the newest backup is first in the list.
                }
                Else {
                    ($data.items | Sort-Object -Property pollTimestamp -Descending | Select-Object -Last $EntryCount).Config # Sorted this way, the newest backup is first in the list.
                }
            } Else {
                $message = ("{0}: No data returned." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message -BlockStdErr $BlockStdErr }
            }
        }
    }
    ElseIf ($appliedConfigSources.items.id) {
        $message = ("{0}: Identified {1} applied ConfigSources. No ConfigSource filter provided, getting all instances." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $appliedConfigSources.items.id.Count)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        If ($InstanceName) {
            $message = ("{0}: A value for -InstanceName ({1}) was provided, but nothing for -ConfigSourceName/ConfigSourceNameId. The instance-name filter will be ignored." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $InstanceName)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
        }

        Foreach ($cs in $appliedConfigSources.items) {
            $message = ("{0}: Attempting to get all instances of ConfigSource with ID {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $cs.id)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $resourcePath = "/device/devices/$DeviceId/devicedatasources/$($cs.id)/instances"

            $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"

            # Get current time in milliseconds
            $epoch = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End (Get-Date).ToUniversalTime()).TotalMilliseconds)

            # Concatenate Request Details
            $requestVars = $httpVerb + $epoch + $resourcePath

            # Construct Signature
            $hmac = New-Object System.Security.Cryptography.HMACSHA256
            $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
            $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
            $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
            $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

            # Construct Headers
            $headers = @{
                "Authorization" = "LMv1 $AccessId`:$signature`:$epoch"
                "Content-Type"  = "application/json"
                "X-Version"     = 2
            }

            $message = ("{0}: Executing REST query to get all instances of CS {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $cs.id)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $stopLoop = $false
            Do {
                Try {
                    $instances = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop
                    $stopLoop = $True
                } Catch {
                    If ($_.Exception.Message -match '429') {
                        $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }

                        Start-Sleep -Seconds 60
                    } Else {
                        $message = ("{0}: Unexpected error getting all instances. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
                    Error message: {2}`r
                    Error code: {3}`r
                    Invoke-Request: {4}`r
                    Headers: {5}`r
                    Body: {6}" -f
                            ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage -ErrorAction SilentlyContinue),
                            ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode -ErrorAction SilentlyContinue), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
                        )
                        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                        Return "Error"
                    }
                }
            }
            While ($stopLoop -eq $false)

            If ($instances.items) {
                Foreach ($instance in $instances.items) {
                    $i++

                    $message = ("{0}: Getting the most recent config backup for instance {1}. This is instance {2} of {3}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $instance.id, $i, $desiredInstances.id.Count)
                    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                    $resourcePath = "/device/devices/$DeviceId/devicedatasources/$($cs.id)/instances/$($instance.id)/config"

                    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"

                    # Get current time in milliseconds
                    $epoch = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End (Get-Date).ToUniversalTime()).TotalMilliseconds)

                    # Concatenate Request Details
                    $requestVars = $httpVerb + $epoch + $resourcePath

                    # Construct Signature
                    $hmac = New-Object System.Security.Cryptography.HMACSHA256
                    $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
                    $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
                    $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
                    $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

                    # Construct Headers
                    $headers = @{
                        "Authorization" = "LMv1 $AccessId`:$signature`:$epoch"
                        "Content-Type"  = "application/json"
                        "X-Version"     = 2
                    }

                    $message = ("{0}: Executing REST query to get config backup." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                    $stopLoop = $false
                    Do {
                        Try {
                            $data = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop
                            $stopLoop = $True
                        } Catch {
                            If ($_.Exception.Message -match '429') {
                                $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }

                                Start-Sleep -Seconds 60
                            } Else {
                                $message = ("{0}: Unexpected error getting config backup. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
                    Error message: {2}`r
                    Error code: {3}`r
                    Invoke-Request: {4}`r
                    Headers: {5}`r
                    Body: {6}" -f
                                    ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage -ErrorAction SilentlyContinue),
                                    ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode -ErrorAction SilentlyContinue), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
                                )
                                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                                Return "Error"
                            }
                        }
                    }
                    While ($stopLoop -eq $false)

                    If ($data.items) {
                        $message = ("{0}: Retrieved {1} backups. Returning {2} backups." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $data.items.id.Count, $EntryCount)
                        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                        If ($EntryCount -eq "All") {
                            ($data.items | Sort-Object -Property pollTimestamp -Descending).Config # Sorted this way, the newest backup is first in the list.
                        }
                        Else {
                            ($data.items | Sort-Object -Property pollTimestamp -Descending | Select-Object -First $EntryCount).Config # Sorted this way, the newest backup is first in the list.
                        }
                    } Else {
                        $message = ("{0}: No data returned." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message -BlockStdErr $BlockStdErr }
                    }
                }
            }
        }
    }
    Else {
        $message = ("{0}: No ConfigSources discovered. No further work for {1} to do." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        Return
    }
    #endregion Get data
} #1.0.0.0