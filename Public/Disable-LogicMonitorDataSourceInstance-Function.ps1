Function Disable-LogicMonitorLogicModuleInstance {
    <#
        .DESCRIPTION
            Accepts a comma-separated list of LogicModules to disable (-LogicModuleName), on a user-specified device. Accepts a properly-formatted string for filtering instances.
        .NOTES
            Author: Mike Hashemi
            V2022.05.02.0
            V2022.05.03.0
            V2022.05.03.1
            V2022.05.04.0
            V2022.05.04.1
            V2022.06.09.0
            V2022.09.29.0
            V2022.10.27.0
            V2022.11.30.0
            V2023.06.12.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Device
            Represents a custom PowerShell object that represents the properties of a LogicMonitor device. Required properties are: displayName and id.
        .PARAMETER DeviceId
            Represents a LogicMonitor device ID.
        .PARAMETER LogicModuleName
            A comma-separated list of LogicModule names (not display names), for which instances will be disabled.
        .PARAMETER DeviceLogicModuleId
            A comma-separated list of device-specific LogicModule IDs, for which instances will be disabled. Note that this is different than the LogicModule ID in the portal.
        .PARAMETER Filter
            Represents a string matching the API's filter format. This parameter can be used to filter for instances matching certain criteria (e.g. "camera" is in the instance description).

            See https://www.logicmonitor.com/support/rest-api-developers-guide/v1/devices/get-devices#Example-Request-5--GET-all-devices-that-have-a-spe
        .PARAMETER AlertingOnly
            When included, the cmdlet will only disable alerting, leaving the instance enabled.
        .PARAMETER BatchSize
            Default value is 200. Represents the number of objects to request from LogicMonitor, in a single batch.
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Disable-LogicMonitorLogicModuleInstance -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -LogicModuleName snmp64_if- -Verbose

            In this example, the cmdlet will disable all instances of the snmp64_if- DataSource. Verbose output is sent to the host only.
        .EXAMPLE
            PS C:\> Disable-LogicMonitorLogicModuleInstance -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -LogicModuleName snmp64_if- -AlertingOnly -Verbose -LogPath C:\Temp\log.txt

            In this example, the cmdlet will disable alerting for all instances of the snmp64_if- DataSource. Verbose output is sent to the host and C:\Temp\log.txt.
        .EXAMPLE
            PS C:\> Disable-LogicMonitorLogicModuleInstance -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -LogicModuleName snmp64_if- -Filter 'description!~"camera",description!~"uplink"'

            In this example, the cmdlet will disable all instances of the snmp64_if- DataSource, that do not match the filter (any instance where the description is not like "camera" or "uplink"). Verbose output is sent to the host only.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [alias('Disable-DataSourceInstance')]
    [alias("Disable-LogicMonitorDataSourceInstance")]
    param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [SecureString]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'Default', ValueFromPipeline = $true)]
        [ValidateScript({
                If ($_.GetType().Name -ne 'PSCustomObject' ) {
                    Throw "Provided property is not a PSCustomObject."
                }
                Return $true
            })]
        [PSCustomObject]$Device,

        [Parameter(Mandatory, ParameterSetName = 'Id')]
        [Int]$DeviceId,

        [alias('DisableLogicModuleName')]
        [String[]]$LogicModuleName,

        [Int[]]$DeviceLogicModuleId,

        [String]$Filter,

        [Switch]$AlertingOnly,

        [Int]$BatchSize = 200,

        [String]$EventLogSource,

        [String]$LogPath
    )

    Begin {}
    Process {
        #region Setup
        #region Initialize variables
        $offset = 0
        $httpVerb = 'GET'
        $exitCode = $null
        $dataSources = [System.Collections.Generic.List[PSObject]]::new()
        $appliedLogicModules = [System.Collections.Generic.List[PSObject]]::new()

        If ($DeviceId) {
            $device = [PSCustomObject]@{
                Id = $DeviceId
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

        #region Validate instance filter
        If ($Filter) {
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

            $Filter = $Filter -replace '\?Filter='

            $message = ("{0}: After parsing, the filter is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Filter)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
        }
        #endregion Validate instance filter

        #region Get LogicModules
        $message = ("{0}: Attempting to get LogicModules from {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $(If ($Device.displayName) { $Device.displayName } Else { $Device.id }))
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        Do {
            $queryParams = "?offset=$offset&size=$BatchSize&sort=id"
            $resourcePath = "/device/devices/$($Device.id)/devicedatasources"

            $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

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

            Try {
                $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop
            } Catch {
                $message = ("{0}: Unexpected error getting LogicModules applied to {1}. Error: {2}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $(If ($Device.displayName) { $Device.displayName } Else { $Device.id }), $_.Exception.Message)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                Return "Error"
            }

            If ($response.data.items) {
                Foreach ($item in $response.data.items) {
                    $dataSources.Add($item)
                }
            } ElseIf ($response.items) {
                Foreach ($item in $response.items) {
                    $dataSources.Add($item)
                }
            }

            $offset = $offset + $BatchSize
        } While (($dataSources.id.Count -lt $response.data.total) -or ($dataSources.id.Count -lt $response.total))

        $message = ("{0}: Found {1} LogicModules applied to the device." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $dataSources.id.Count)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
        #endregion Get LogicModules

        #region Parse data
        $foundModule = 0
        Switch ($LogicModuleName, $DeviceLogicModuleId) {
            { If ($LogicModuleName.Count -ge 1) { If ($_ -is [String]) { $true } ElseIf ($_ -is [Array]) { $true } Else { $false } } ElseIf ($LogicModuleName.Count -eq 0) { $false } } {
                $name = ($_ | Out-String).Trim()

                $message = ("{0}: Checking for applied modules with the name: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $name)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                If ($name -in $dataSources.dataSourceName) {
                    $foundModule++
                    $appliedLogicModules.Add($($dataSources | Where-Object { $_.dataSourceName -eq $name }))

                    If ($appliedLogicModules.instanceNumber -gt 0) {
                        $message = ("{0}: Found instances under {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $appliedLogicModules.dataSourceName)
                        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
                    } Else {
                        $message = ("{0}: No instances found for {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $appliedLogicModules.dataSourceName)
                        Out-PsLogging @loggingParams -MessageType Warning -Message $message
                    }
                }
            }
            { If ($DeviceLogicModuleId.Count -ge 1) { If ($_ -is [Int]) { $true } ElseIf ($_ -is [Array]) { $true } Else { $false } } ElseIf ($DeviceLogicModuleId.Count -eq 0) { $false } } {
                $id = $_ | Out-String

                $message = ("{0}: Checking for applied modules with the ID: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $id)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                If ($id -in $dataSources.id) {
                    $foundModule++
                    $appliedLogicModules = $dataSources | Where-Object { $_.id -eq $id }

                    If ($appliedLogicModules.instanceNumber -gt 0) {
                        $message = ("{0}: Found instances under {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $appliedLogicModules.id)
                        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
                    } Else {
                        $message = ("{0}: No instances found for {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $appliedLogicModules.id)
                        Out-PsLogging @loggingParams -MessageType Warning -Message $message
                    }
                }
            }
        }

        If ($foundModule -gt 0) {
            Foreach ($module in $appliedLogicModules) {
                $message = ("{0}: Attempting to retrieve properties of the {1} instances." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $module.dataSourceName)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                $resourcePath = "/device/devices/$($Device.id)/devicedatasources/$($module.Id)/instances"

                If ($Filter) { $queryParams = "?filter=$Filter" } Else { $queryParams = $null }

                $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

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

                Try {
                    $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop
                } Catch {
                    $message = ("{0}: Unexpected error getting instances under {1}. Error: {2}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $appliedLogicModules.dataSourceName, $_.Exception.Message)
                    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                    Return "Error"
                }

                If ($response.items) {
                    $message = ("{0}: Found {1} matching instances. Attempting to disable." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $response.items.id.Count)
                    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
                } Else {
                    $message = ("{0}: No instances found." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message }

                    Return "Error"
                }

                Foreach ($instance in $response.items) {
                    $response = $null
                    $resourcePath = "/device/devices/$($Device.id)/devicedatasources/$($module.Id)/instances/$($instance.id)"
                    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"

                    If ($AlertingOnly) {
                        $body = @{
                            disableAlerting = $true
                        } | ConvertTo-Json -Compress
                    } Else {
                        $body = @{
                            disableAlerting = $true
                            stopMonitoring  = $true
                        } | ConvertTo-Json -Compress
                    }

                    #region Auth and headers
                    # Get current time in milliseconds.
                    $epoch = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End (Get-Date).ToUniversalTime()).TotalMilliseconds)
                    $requestVars = "PATCH" + $epoch + $body + $resourcePath
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

                    Try {
                        $response = Invoke-RestMethod -Uri $url -Method "PATCH" -Header $headers -Body $body -ErrorAction Stop
                    } Catch {
                        $message = ("{0}: Unexpected error disabling the instance, `"{1}`". Error: {2}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $instance.name, $_.Exception.Message)
                        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                        $exitCode = "Error"
                    }

                    If ($response.id) {
                        $message = ("{0}: On the instance `"{1}`", alerting is {2} and monitoring is {3}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $instance.name, $(If ($response.disableAlerting -eq 'False') { "disabled" } Else { "enabled" }), $(If ($response.stopMonitoring -eq 'False') { "disabled" } Else { "enabled" }))
                        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
                    } Else {
                        $message = ("{0}: Failed to disable the instance, `"{1}`"." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $instance.name)
                        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
                    }
                }
            }
        } Else {
            $message = ("{0}: No instances found." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
        }
        #endregion Parse data
    }
    End {
        Return $exitCode
    }
} #2023.06.12.0