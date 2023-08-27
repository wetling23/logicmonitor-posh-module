Function Update-LogicMonitorDeviceProperty {
    <#
        .DESCRIPTION
            Accepts a device ID, display name, or device IP/DNS name, and one or more property name/value pairs, then updates the property(ies).
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 12 December 2016
            V2022.10.24.0
            V2023.05.23.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Id
            Represents the device ID of a monitored device.
        .PARAMETER DisplayName
            Represents the device's display name.
        .PARAMETER Name
            Represents the devices's name (IP or FQDN), as specified in LogicMonitor.
        .PARAMETER Operation
            Represents the type of operation to execute.
            - "Add" indicates that the properties included in the payload will be added, but all existing properties will remain the same. If the property exists already, it will not be updated.
            - "Update" indicates that the properties included in the request payload will be added if they don’t already exist, or updated if they do already exist, but all other existing properties will remain the same. LogicMonitor refers to this as "replace".
            - "Replace" indicates that the properties will be replaced with those included in the request payload. LogicMonitor refers to this as "refresh".
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Update-LogicMonitorDeviceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6 -Properties @{ customProperties = @(@{ name = 'location'; value = 'Denver' }, @{ name = 'assignedTeam'; value = 'finance' }) } -Operation Add

            In this example, the cmdlet will attempt to add the location and assignedTeam properties to the device with ID 6. If one or both exist, the existing values will NOT be updated. Limited logging output will be written to the host only.
        .EXAMPLE
            PS C:\> Update-LogicMonitorDeviceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6 -Properties @{ customProperties = @(@{ name = 'location'; value = 'Denver'}, @{ name = 'assignedTeam'; value = 'finance' }) } -Operation Update

            In this example, the cmdlet will attempt to add or update the location and assignedTeam properties to the device with ID 6. If one or both exist, the existing values WILL be updated. Limited logging output will be written to the host only.
        .EXAMPLE
            PS C:\> Update-LogicMonitorDeviceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6 -Properties @{ customProperties = @(@{ name = 'location'; value = 'Denver' }, @{ name = 'assignedTeam'; value = 'finance' }) } -Operation Replace -Verbose

            In this example, the cmdlet will attempt to add the location and assignedTeam properties to the device with ID 6. All other custom properties will be removed. Verbose logging output will be written to the host only.
        .EXAMPLE
            PS C:\> Update-LogicMonitorDeviceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6 -Properties @{ displayName = "<new device display name>"; description = "<new or updated description>"; customProperties = @(@{ name = "addr"; value = "127.0.0.1" }) } -Operation Update -Verbose

            In this example, the cmdlet will attempt to add or update the addr property to the device with ID 6. The cmdlet will also attempt to update the displayName and description properties. If any of the properties exist, the existing values WILL be updated. Verbose logging output will be written to the host only.
        .EXAMPLE
            PS C:\> Update-LogicMonitorDeviceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6 -Properties @{ customProperties = @(@{ name = 'location'; value = '' }) } -Operation Update -Verbose

            In this example, the cmdlet will attempt to add or update the location property to the device with ID 6. The value will be set to a blank string (the property will not be removed). Verbose logging output will be written to the host only.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [alias('Update-LogicMonitorDeviceProperties')]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [Securestring]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'Default')]
        [Alias("DeviceId")]
        [Int]$Id,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [Alias("DeviceDisplayName")]
        [String]$DisplayName,

        [Parameter(Mandatory, ParameterSetName = 'IPFilter')]
        [Alias("DeviceName")]
        [String]$Name,

        [Parameter(Mandatory)]
        [Hashtable]$Properties,

        [Parameter(Mandatory)]
        [ValidateSet('Add', 'Update', 'Replace')]
        [String]$Operation,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    #region Initialize variables
    $httpVerb = 'PATCH'
    $resourcePath = "/device/devices"
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    Switch ($Operation) {
        "Add" {
            $queryParams = "?opType=add"
        }
        "Update" {
            $queryParams = "?opType=replace"
        }
        "Replace" {
            $queryParams = "?opType=refresh"
        }
    }
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

    #region Set resource path
    # Update $resourcePath to filter for a specific device, when a device ID, name, or displayName is provided by the user.
    Switch ($PsCmdlet.ParameterSetName) {
        Default {
            $resourcePath += "/$Id"
        }
        "NameFilter" {
            $message = ("{0}: Attempting to retrieve the device ID of {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $DisplayName)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $device = Get-LogicMonitorDevice -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -DisplayName $DisplayName @loggingParams

            $resourcePath += "/$($device.id)"

            $message = ("{0}: The value of `$resourcePath is {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
        }
        "IPFilter" {
            $message = ("{0}: Attempting to retrieve the device ID of {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Name)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $device = Get-LogicMonitorDevice -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -Name $Name @loggingParams

            If ($device.count -gt 1) {
                $message = ("{0}: More than one device with the name {1} were detected (specifically {2}). To prevent errors, {3} will exit." `
                        -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Name, $device.count, $MyInvocation.MyCommand)
                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                Return "Error"
            }

            $resourcePath += "/$($device.id)"

            $message = ("{0}: The value of `$resourcePath is {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
        }
    }

    $message = ("{0}: Finished updating `$resourcePath. The value is {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
    #endregion Set resource path

    #region Prepare query
    $data = $($Properties | ConvertTo-Json -Depth 5)
    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

    $message = ("{0}: Connecting to: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $url)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    # Get current time in milliseconds
    $epoch = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End (Get-Date).ToUniversalTime()).TotalMilliseconds)

    # Concatenate Request Details
    $requestVars = $httpVerb + $epoch + $data + $resourcePath

    # Construct Signature
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
    $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
    $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
    $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

    # Construct headers.
    $headers = @{
        "Authorization" = "LMv1 $accessId`:$signature`:$epoch"
        "Content-Type"  = "application/json"
        "X-Version"     = 3
    }
    #endregion Prepare query

    #region Run query
    $message = ("{0}: Executing the REST query." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    Try {
        $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -Body $data -ErrorAction Stop
    } Catch {
        If ($_.Exception.Message -match '429') {
            $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
            If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }

            Start-Sleep -Seconds 60
        } Else {
            $message = ("{0}: Unexpected error updating LogicMonitor device property. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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
    }
    #endregion Parse properties

    Return $response
} #2023.05.23.0