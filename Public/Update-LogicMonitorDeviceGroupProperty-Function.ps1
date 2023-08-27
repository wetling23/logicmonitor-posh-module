Function Update-LogicMonitorDeviceGroupProperty {
    <#
        .DESCRIPTION
            Accepts a device group ID or name and one or more property name/value pairs, then updates the property(ies).
        .NOTES
            Author: Mike Hashemi
            V2023.06.14.0
            V2023.06.29.0
            V2023.08.22.0
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
            PS C:\> Update-LogicMonitorDeviceGroupProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6 -Properties @{ name = 'Group1'; customProperties = @(@{ name = 'custom.propertyName'; value = '123456' }) } -Operation Add

            In this example, the cmdlet will attempt to add the 'custom.propertyName' property to the device with ID 6. If it already exists, the existing values will NOT be updated. The 'name' property will be updated to 'Group1'. Limited logging output will be written to the host only.
        .EXAMPLE
            PS C:\> Update-LogicMonitorDeviceGroupProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6 -Properties @{ name = 'Group1'; customProperties = @(@{ name = 'custom.propertyName'; value = '123456' }) } -Operation Update

            In this example, the cmdlet will attempt to add or update the name and custom.propertyName properties on the device with ID 6. If one or both exist, the existing values WILL be updated. Limited logging output will be written to the host only.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [Securestring]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'Default')]
        [Alias("DeviceId")]
        [Int[]]$Id,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
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
    $resourcePath = "/device/groups"
    $requiredProps = @('name')
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

    $commandParams = @{
        AccountName = $AccountName
        AccessId    = $AccessId
        AccessKey   = $AccessKey
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

    #region Validate input properties
    # Checking for the required properties.
    Foreach ($prop in $requiredProps) {
        If (-NOT($Properties.keys.Contains($prop))) {
            $message = ("{0}: Missing required property: {1}. Please update the -Filter parameter and try again." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $prop)
            Out-PsLogging @loggingParams -MessageType Error -Message $message

            Return "Error"
        }
    }

    $message = ("{0}: Removing unsupported fields from the Properties hash table." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

    Foreach ($key in $($Properties.keys)) {
        If ($key -notin 'groupType', 'description', 'appliesTo', 'disableAlerting', 'defaultCollectorId', 'awsTestResult', 'extra', 'enableNetflow', 'azureTestResult', 'parentId', 'customProperties', 'defaultAutoBalancedCollectorGroupId', 'saasTestResult', 'name', 'gcpTestResult') {
            $message = ("{0}: Unsupported field found ({1}), removing the entry from `$Properties." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $key)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $Properties.remove($key)
        }
    }
    #endregion Validate input properties

    #region Update filter/resourcePath
    Switch ($PsCmdlet.ParameterSetName) {
        "StringFilter" {
            $message = ("{0}: URL encoding special characters in the filter." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $Filter = [regex]::Replace(
                $Filter,
                '(?<=[:|><~]").*?(?=")',
                {
                    param($m)
                    [Uri]::EscapeDataString($m.Value)
                }
            )

            $message = ("{0}: After parsing, the filter is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Filter)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $deviceGroup = Get-LogicMonitorDeviceGroup @commandParams -Filter $Filter @loggingParams

            If ($deviceGroup.id) {
                $deviceGroup | ForEach-Object { [Int[]]$Id += $_.id }
            } Else {
                $message = ("{0}: No device groups were retrieved using the provided filter, see the cmdlet's logging for more details. To prevent errors, {1} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
                Out-PsLogging @loggingParams -MessageType Error -Message $message

                Return "Error"
            }
        }
        "NameFilter" {
            $message = ("{0}: Attempting to retrieve the device ID of {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Name)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $deviceGroup = Get-LogicMonitorDeviceGroup @commandParams -Name $Name @loggingParams

            If ($deviceGroup.id) {
                $deviceGroup | ForEach-Object { [Int[]]$Id += $_.id }
            } Else {
                $message = ("{0}: No device groups were retrieved using the provided name, see the cmdlet's logging for more details. To prevent errors, {1} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
                Out-PsLogging @loggingParams -MessageType Error -Message $message

                Return "Error"
            }
        }
    }
    #endregion Update filter/resourcePath

    #region Execute REST query
    $data = $($Properties | ConvertTo-Json -Depth 5)

    Foreach ($group in $Id) {
        $resourcePath = ("/device/groups/{0}" -f $group)

        #region Auth and headers
        # Get current time in milliseconds.
        $epoch = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End (Get-Date).ToUniversalTime()).TotalMilliseconds)
        $requestVars = $httpVerb + $epoch + $data + $resourcePath
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
                $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -Body $data -ErrorAction Stop

                $stopLoop = $True
            } Catch {
                If ($_.Exception.Message -match '429') {
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                    Out-PsLogging @loggingParams -MessageType Warning -Message $message

                    Start-Sleep -Seconds 60
                } Else {
                    $message = ("{0}: Unexpected error updating the device group. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
                    Error message: {2}`r
                    Error code: {3}`r
                    Invoke-Request: {4}`r
                    Headers: {5}`r
                    Body: {6}" -f
                    ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage),
                    ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
                    )
                    Out-PsLogging @loggingParams -MessageType Error -Message $message

                    Return "Error"
                }
            }
        } While ($stopLoop -eq $false)

        If ($response.id) {
            $message = ("{0}: Successfully updated the device group ({1}) in LogicMonitor." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $group)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            Return $response
        } Else {
            $message = ("{0}: Unexpected error updating the device group ({1}) in LogicMonitor. To prevent errors, {2} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Id, $MyInvocation.MyCommand)
            Out-PsLogging @loggingParams -MessageType Error -Message $message

            Return "Error"
        }
    }
    #endregion Execute REST query
} #2023.08.22.0