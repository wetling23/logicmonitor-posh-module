Function Disable-DataSourceInstance {
    <#
        .DESCRIPTION
            Accepts a comma-separated list of DataSources to disable (-DisableDataSourceName), on a user-specified device. Accepts a properly-formatted string for filtering instances.
        .NOTES
            Author: Mike Hashemi
            V2022.05.02.0
            V2022.05.03.0
            V2022.05.03.1
            V2022.05.04.0
            V2022.05.04.1
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
        .PARAMETER DisableDataSourceName
            A comma-separated list of DataSource names (not display names), for which instances will be disabled.
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
            PS C:\> Disable-DataSourceInstance -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DisableDataSourceName snmp64_if- -Verbose

            In this example, the cmdlet will disable all instances of the snmp64_if- DataSource. Verbose output is sent to the host only.
        .EXAMPLE
            PS C:\> Disable-DataSourceInstance -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DisableDataSourceName snmp64_if- -AlertingOnly -Verbose -LogPath C:\Temp\log.txt

            In this example, the cmdlet will disable alerting for all instances of the snmp64_if- DataSource. Verbose output is sent to the host and C:\Temp\log.txt.
        .EXAMPLE
            PS C:\> Disable-DataSourceInstance -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DisableDataSourceName snmp64_if- -Filter 'description!~"camera",description!~"uplink"'

            In this example, the cmdlet will disable all instances of the snmp64_if- DataSource, that do not match the filter (any instance where the description is not like "camera" or "uplink"). Verbose output is sent to the host only.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [securestring]$AccessKey,

        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'Default', ValueFromPipeline = $true)]
        [ValidateScript({
                If ($_.GetType().Name -ne 'PSCustomObject' ) {
                    Throw "Provided property is not a PSCustomObject."
                }
                Return $true
            })]
        [PSCustomObject]$Device,

        [Parameter(Mandatory, ParameterSetName = 'Id')]
        [int]$DeviceId,

        [Parameter(Mandatory = $True)]
        [string[]]$DisableDataSourceName,

        [string]$Filter,

        [switch]$AlertingOnly,

        [int]$BatchSize = 200,

        [string]$EventLogSource,

        [string]$LogPath
    )

    Begin {
        $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Info -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType First -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Info -Message $message }
    }
    Process {
        #region Setup
        # Initialize variables.
        $offset = 0
        $httpVerb = 'GET'
        $exitCode = 0
        $dataSources = [System.Collections.Generic.List[PSObject]]::new()
        $pattern1 = '[^a-zA-Z\d\s]' # Match any non-alpha numeric or white space character.
        $pattern2 = '(?:>:|<:|:|>|<|!:|:|~|!~)(?:")(.*?)(?:")' # Allow us to replace characters in the filter. We will leave some of the characters alone, since they are used by the API in certain spots. For example, ":" means equal between the property name and value but should be replaced in the value portion of the pair.
        $regex = [Regex]::new($pattern2)

        If ($DeviceId) {
            $device = [PSCustomObject]@{
                Id = $DeviceId
            }
        }

        If ($Filter -match $pattern1) {
            $message = ("{0}: URL encoding special characters in the filter." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $regex.Matches($Filter) | ForEach-Object {
                $Filter = $Filter -replace ([regex]::Escape($_.Groups[1].value)), ([uri]::EscapeDataString($_.Groups[1].value))
            }

            $Filter = $Filter -replace '\?Filter='

            $message = ("{0}: After parsing, the filter is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Filter)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
        }
        #endregion Setup

        #region Get LogicModules
        $message = ("{0}: Attempting to get LogicModules from {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $(If ($Device.displayName) { $Device.displayName } Else { $Device.id }))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        Do {
            $queryParams = "?offset=$offset&size=$BatchSize&sort=id"
            $resourcePath = "/device/devices/$($Device.id)/devicedatasources"

            $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

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
                "X-Version"     = 3
            }

            Try {
                $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop
            } Catch {
                $message = ("{0}: Unexpected error getting LogicModules applied to {1}. Error: {2}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $(If ($Device.displayName) { $Device.displayName } Else { $Device.id }), $_.Exception.Message)
                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

                Return 1
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
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
        #endregion Get LogicModules

        #region Parse data
        Foreach ($dsName in $DisableDataSourceName) {
            If ($dsName -in $dataSources.dataSourceName) {
                $appliedDataSource = $dataSources | Where-Object { $_.dataSourceName -eq $dsName }

                If ($appliedDataSource.instanceNumber -gt 0) {
                    $message = ("{0}: Found instances under {1}. Attempting to retrieve them." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $appliedDataSource.dataSourceName)
                    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                    $resourcePath = "/device/devices/$($Device.id)/devicedatasources/$($appliedDataSource.Id)/instances"

                    If ($Filter) { $queryParams = "?filter=$Filter" } Else { $queryParams = $null }

                    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

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
                        "X-Version"     = 3
                    }

                    Try {
                        $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop
                    } Catch {
                        $message = ("{0}: Unexpected error getting instances under {1}. Error: {2}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $appliedDataSource.dataSourceName, $_.Exception.Message)
                        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

                        Return 1
                    }

                    If ($response.items) {
                        $message = ("{0}: Found {1} matching instances. Attempting to disable them." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $response.items.id.Count)
                        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
                    } Else {
                        $message = ("{0}: No instances found." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message }

                        Return 1
                    }

                    Foreach ($instance in $response.items) {
                        $response = $null
                        $resourcePath = "/device/devices/$($Device.id)/devicedatasources/$($appliedDataSource.Id)/instances/$($instance.id)"
                        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"

                        # Get current time in milliseconds
                        $epoch = [Math]::Round((New-TimeSpan -Start (Get-Date -Date "1/1/1970") -End (Get-Date).ToUniversalTime()).TotalMilliseconds)

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

                        # Concatenate Request Details
                        $requestVars = "PATCH" + $epoch + $body + $resourcePath

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
                            "X-Version"     = 3
                        }

                        Try {
                            $response = Invoke-RestMethod -Uri $url -Method "PATCH" -Header $headers -Body $body -ErrorAction Stop
                        } Catch {
                            $message = ("{0}: Unexpected error disabling the instance, `"{1}`". Error: {2}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $instance.name, $_.Exception.Message)
                            If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

                            $exitCode = 1
                        }

                        If ($response.id) {
                            $message = ("{0}: Disabled the instance: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $instance.name)
                            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
                        } Else {
                            $message = ("{0}: Failed to disable the instance, `"{1}`"." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $instance.name)
                            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
                        }
                    }
                } Else {
                    $message = ("{0}: No instances found." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
                }
            } Else {
                $message = ("{0}: Script complete. No DataSources found assigned to {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Device.id)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
            }
        }
        #endregion Parse data
    }
    End {
        Return $exitCode
    }
} #2022.05.04.0