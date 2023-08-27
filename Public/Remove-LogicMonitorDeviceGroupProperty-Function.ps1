Function Remove-LogicMonitorDeviceGroupProperty {
    <#
        .DESCRIPTION
            Accepts a device group ID or display name, and one or more property names, then deletes the property(ies).
        .NOTES
            Author: Mike Hashemi
            V2023.06.29.0
                - Initial release
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Represents the subdomain of the LogicMonitor customer. Default value is "synoptek".
        .PARAMETER Id
            Represents the device group ID of a monitored device group.
        .PARAMETER Name
            Represents the IP address or DNS name of the device group to be monitored. This IP/name must be unique on the monitoring collector.
        .PARAMETER PropertyName
            Mandatory parameter. Represents the name of the target property. Note that LogicMonitor properties are case sensitive.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorDeviceGroupProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 45 -PropertyName Location -Verbose

            In this example, the function will remove the Location property for the device group with "45" in the ID property. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorDeviceGroupProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Name "10.0.0.1" -PropertyName Location

            In this example, the function will remove the Location property for the device group with "10.0.0.1" in the name property.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorDeviceGroupProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Displayname "server1 - Customer" -PropertyName Location,AssignedTeam

            In this example, the function will remove the Location and AssignedTeam properties for the device group with "server1 - Customer" in the display name property.
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
        [Alias('DeviceGroupId')]
        [Int]$Id,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [Alias('DeviceGroupName')]
        [String]$Name,

        [Parameter(Mandatory)]
        [Alias('PropertyNames')]
        [String[]]$PropertyName,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    #region Initialize variables
    $httpVerb = 'DELETE'
    $queryParams = $null
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

    $message = ("{0}: Updated `$resourcePath. The value is {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

    #region Execute REST query
    # For each property, append the name to the $resourcePath.
    Foreach ($property in $PropertyName) {
        # Update $resourcePath to filter for a specific device group, when a device ID or name is provided by the user.
        Switch ($PsCmdlet.ParameterSetName) {
            Default {
                $resourcePath = "/device/groups/$Id/properties"
            }
            'NameFilter' {
                $message = ("{0}: Attempting to retrieve the device ID of {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Displayname)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

                If ($Id -eq $null) {
                    $deviceGroup = Get-LogicMonitorDeviceGroup -AccessId $AccessId -AccessKey $AccessKey -AccountName $AccountName -Name $Name @loggingParams
                }

                If ($deviceGroup.id) {
                    $Id = $deviceGroup.id
                    $resourcePath = "/device/groups/$Id/properties"
                } Else {
                    $message = ("{0}: No device group was returned when searching for {1}. To prevent errors, {2} will exit." `
                            -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Displayname, $MyInvocation.MyCommand)
                    Out-PsLogging @loggingParams -MessageType Error -Message $message

                    Return "Error"
                }

                $message = ("{0}: The value of `$resourcePath is {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
                If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
            }
        }

        $resourcePath += "/$property"

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

        If ($response.Length -gt 0) {
            $message = ("{0}: Failed to delete the property: {1}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $property)
            Out-PsLogging @loggingParams -MessageType Error -Message $message

            Return "Error"
        } Else {
            $message = ("{0}: Deleted property: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $property)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
        }
    }
    #endregion Execute REST query

    Return "Success"
} #2023.06.29.0