Function Update-LogicMonitorDeviceProperty {
    <#
        .DESCRIPTION
            Accepts a device ID, display name, or device IP/DNS name, and one or more property name/value pairs, then updates the property(ies).
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 12 December 2016
            V1.0.0.1 date: 31 January 2017
                - Updated syntax and logging.
                - Improved error handling.
            V1.0.0.2 date: 31 January 2017
                - Updated error output color.
                - Streamlined header creation (slightly).
            V1.0.0.3 date: 31 January 2017
                - Added $logPath output to host.
            V1.0.0.4 date: 31 January 2017
                - Added additional logging.
            V1.0.0.5 date: 10 February 2017
                - Updated procedure order.
            V1.0.0.6 date: 3 May 2017
                - Removed code from writing to file and added Event Log support.
                - Updated code for verbose logging.
                - Changed Add-EventLogSource failure behavior to just block logging (instead of quitting the function).
            V1.0.0.7 date: 21 June 2017
                - Updated logging to reduce chatter.
            V1.0.0.8 date: 12 July 2017
                - Added -EventLogSource to a couple of cmdlet calls.
            V1.0.0.9 date: 1 August 2017
                - Updated inline documentation.
            V1.0.0.10 date: 28 September 2017
                - Replaced ! with -Not.
            V1.0.0.11 date: 23 April 2018
                - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
            V1.0.0.12 date: 11 July 2018
                - Updated white space.
                - Updated in-line help.
            V1.0.0.13 date: 18 July 2018
                - More whites space updates.
                - Added the API's response to the return data when there is an Invoke-RestMethod failure.
            V1.0.0.14 date: 18 March 2019
                - Updated alias publishing method.
            V1.0.0.15 date: 23 August 2019
            V1.0.0.16 date: 26 August 2019
            V1.0.0.17 date: 18 October 2019
            V1.0.0.18 date: 4 December 2019
            V1.0.0.19 date: 10 December 2019
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
        .PARAMETER PropertyName
            Represents the name of the target property. Note that LogicMonitor properties are case sensitive.
        .PARAMETER PropertyValue
            Represents the value of the target property.
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Update-LogicMonitorDeviceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6 -PropertyNames Location,AssignedTeam -PropertyValues Denver,Finance -Verbose

            In this example, the function will update the Location and AssignedTeam properties for the device with "6" in the ID property. The location will be set to "Denver" and the assigned team will be "Finance". If the properties are not present, they will be added. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Update-LogicMonitorDeviceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DisplayName server1 -PropertyNames Location -PropertyValues Denver

            In this example, the function will update the Location property for the device with "server1" in the displayName property. The location will be set to "Denver". If the property is not present, it will be added.
        .EXAMPLE
            PS C:\> Update-LogicMonitorDeviceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Name 10.0.0.0 -PropertyNames Location -PropertyValues Denver

            In this example, the function will update the Location property for the device with "10.0.0.0" in the name property. The location will be set to "Denver". If the property is not present, it will be added.
        .EXAMPLE
            PS C:\> Update-LogicMonitorDeviceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Name server1.domain.local -PropertyNames Location -PropertyValues Denver

            In this example, the function will update the Location property for the device with "server1.domain.local" in the name property. The location will be set to "Denver". If the property is not present, it will be added.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [alias('Get-LogicMonitorDeviceProperties')]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [securestring]$AccessKey,

        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'Default')]
        [Alias("DeviceId")]
        [int]$Id,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [Alias("DeviceDisplayName")]
        [string]$DisplayName,

        [Parameter(Mandatory, ParameterSetName = 'IPFilter')]
        [Alias("DeviceName")]
        [string]$Name,

        [Parameter(Mandatory)]
        [string[]]$PropertyNames,

        [Parameter(Mandatory)]
        [string[]]$PropertyValues,

        [string]$EventLogSource,

        [string]$LogPath
    )

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    # Initialize variables.
    [int]$index = 0
    $propertyData = ""
    $standardProperties = ""
    $data = ""
    $httpVerb = 'PATCH'
    $queryParams = "?patchFields="
    $resourcePath = "/device/devices"
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    # Setup parameters for calling Get-LogicMonitor* cmdlet(s).
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') {
        If ($EventLogSource -and (-NOT $LogPath)) {
            $commandParams = @{
                Verbose        = $true
                EventLogSource = $EventLogSource
            }
        }
        ElseIf ($LogPath -and (-NOT $EventLogSource)) {
            $commandParams = @{
                Verbose = $true
                LogPath = $LogPath
            }
        }
    }
    Else {
        If ($EventLogSource -and (-NOT $LogPath)) {
            $commandParams = @{
                EventLogSource = $EventLogSource
            }
        }
        ElseIf ($LogPath -and (-NOT $EventLogSource)) {
            $commandParams = @{
                LogPath = $LogPath
            }
        }
    }

    # Update $resourcePath to filter for a specific device, when a device ID, name, or displayName is provided by the user.
    Switch ($PsCmdlet.ParameterSetName) {
        Default {
            $resourcePath += "/$Id"
        }
        "NameFilter" {
            $message = ("{0}: Attempting to retrieve the device ID of {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $DisplayName)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $device = Get-LogicMonitorDevice -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -DisplayName $DisplayName @commandParams

            $resourcePath += "/$($device.id)"

            $message = ("{0}: The value of `$resourcePath is {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
        }
        "IPFilter" {
            $message = ("{0}: Attempting to retrieve the device ID of {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Name)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $device = Get-LogicMonitorDevice -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -Name $Name @commandParams

            If ($device.count -gt 1) {
                $message = ("{0}: More than one device with the name {1} were detected (specifically {2}). To prevent errors, {3} will exit." `
                        -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Name, $device.count, $MyInvocation.MyCommand)
                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

                Return "Error"
            }

            $resourcePath += "/$($device.id)"

            $message = ("{0}: The value of `$resourcePath is {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
        }
    }

    $message = ("{0}: Finished updating `$resourcePath. The value is {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    # For each property, assign the name and value to $propertyData.
    Foreach ($property in $PropertyNames) {
        Switch ($property) {
            { $_ -in ("name", "displayName", "preferredCollectorId", "hostGroupIds", "description", "disableAlerting", "link", "enableNetflow", "netflowCollectorId") } {
                $queryParams += "$property,"

                $message = ("{0}: Added {1} to `$queryParams. The new value of `$queryParams is: {2}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $property, $queryParams)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                $message = ("{0}: Updating/adding standard property: {1} with a value of {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $property, $($PropertyValues[$index]))
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                $standardProperties += "`"$property`":`"$($PropertyValues[$index])`","

                $index++
            }
            Default {
                $customProps = $True

                $message = ("{0}: Found that there is a custom property present." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                If ($property -like "*pass") {
                    $message = ("{0}: Updating/adding property: {1} with a value of ********." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $property)
                    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
                }
                Else {
                    $message = ("{0}: Updating/adding property: {1} with a value of {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $property, $($PropertyValues[$index]))
                    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
                }

                $propertyData += "{`"name`":`"$property`",`"value`":`"$($PropertyValues[$index])`"},"

                $index++
            }
        }
    }

    If ($customProps -eq $True) {
        $queryParams += "customProperties&opType=replace"
    }
    Else {
        $queryParams = $queryParams.TrimEnd(",")
        $queryParams += "&opType=replace"
    }

    # Trim the trailing comma.
    $propertyData = $propertyData.TrimEnd(",")

    $standardProperties = $standardProperties.TrimEnd(",")

    If (($standardProperties.Length -gt 0) -and ($propertyData.Length -gt 0)) {
        $message = ("{0}: The length of `$standardProperties is {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $standardProperties.Length)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        # Assign the entire string to the $data variable.
        $data = "{$standardProperties,`"customProperties`":[$propertyData]}"
    }
    ElseIf (($standardProperties.Length -gt 0) -and ($propertyData.Length -le 0)) {
        $data = "{$standardProperties}"
    }
    Else {
        # Assign the entire string to the $data variable.
        $data = "{`"customProperties`":[$propertyData]}"
    }

    $message = ("{0}: Finished updating `$data. The value update is {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $data)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    # Construct the query URL.
    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

    # Get current time in milliseconds
    $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

    # Concatenate Request Details
    $requestVars = $httpVerb + $epoch + $data + $resourcePath

    # Construct Signature
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))))
    $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
    $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
    $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

    # Construct Headers
    $headers = @{
        "Authorization" = "LMv1 $accessId`:$signature`:$epoch"
        "Content-Type"  = "application/json"
    }

    # Make Request
    $message = ("{0}: Executing the REST query." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    Try {
        $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -Body $data -ErrorAction Stop
    }
    Catch {
        If ($_.Exception.Message -match '429') {
            $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
            If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }

            Start-Sleep -Seconds 60
        }
        Else {
            $message = ("{0}: Unexpected error updating LogicMonitor device property. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
            Error message: {2}`r
            Error code: {3}`r
            Invoke-Request: {4}`r
            Headers: {5}`r
            Body: {6}" -f
                ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage),
                ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
            )
            If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

            Return "Error", $response
        }
    }

    If ($response.status -ne "200") {
        $message = ("{0}: LogicMonitor reported an error (status {1}). The message is: {2}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $response.status, $response.errmsg)
        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }
    }

    Return $response
} #1.0.0.19