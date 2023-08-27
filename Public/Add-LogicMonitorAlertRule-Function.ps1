Function New-LogicMonitorAlertRule {
    <#
        .DESCRIPTION
            Creates Alert Rule in LogicMonitor.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 29 July 2020
            V1.0.0.1 date: 6 August 2020
            V1.0.0.2 date: 21 September 2021
            V2022.11.11.0
            V2023.05.25.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Settings
            Mandatory parameter. Represents a hashtable of alert rule properties and their values. As of 29 July 2020, omitting the following fields will cause the command to exit: name, priority, and escalatingChainId. Omitting the following fields will cause the command to use default values: escalationInterval, datapoint, instance, and datasource
        .PARAMETER BatchSize
            Default value is 1000. Represents the number of alert rules to request from LogicMonitor.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> $Properties = @{
                        datapoint           = "*"
                        datasource          = "*"
                        deviceGroups        = @("GroupName/SubGroupName")
                        devices             = @("*")
                        escalatingChainId   = 10
                        escalationInterval  = 0
                        instance            = "*"
                        levelStr            = "Error"
                        name                = "Error Test"
                        priority            = 99999999
                        suppressAlertAckSdt = $false
                        suppressAlertClear  = $false
                    }

                    New-LogicMonitorAlertRule -AccessID <access ID> -AccessKey <access key> -AccountName <account name> -Settings $Properties -Verbose

            In this example, the function will create an alert rule called "Error Test" with the specified properties (all required properties are specified). Verbose logging output will be written only to the host.
        .EXAMPLE
            PS C:\> $Properties = @{
                        deviceGroups        = @("*")
                        escalatingChainId   = 10
                        escalationInterval  = 0
                        instance            = "*"
                        levelStr            = "Warn"
                        name                = "Warning Test"
                        priority            = 99999999
                        resourceProperties  = @(@{ name = 'propertyName1'; value = 'propertyValue1' }, @{ name = 'propertyName2'; value = 'propertyValue2' })
                        suppressAlertAckSdt = $false
                        suppressAlertClear  = $false
                    }

                    New-LogicMonitorAlertRule -AccessID <access ID> -AccessKey <access key> -AccountName <account name> -Settings $Properties -LogPath C:\Temp\test.log

            In this example, the function will create an alert rule called "Error Test" with the specified properties (not all required fields are included, causing default values to be used). Limited logging output will be written to C:\Temp\test.log.
    #>
    [CmdletBinding()]
    [Alias("Add-LogicMonitorAlertRule")]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [securestring]$AccessKey,

        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory)]
        [Alias("Settings")]
        [hashtable]$Properties,

        [boolean]$BlockStdErr = $false,

        [string]$EventLogSource,

        [string]$LogPath
    )

    #region Setup
    #region Initialize variables
    $httpVerb = "POST" # Define what HTTP operation will the script run.
    $resourcePath = "/setting/alert/rules" # Define the resourcePath, based on the type of query you are doing.
    $requiredProps = @('name', 'priority')
    $defaultableProps = @('datasource', 'instance', 'datapoint', 'escalationInterval')
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

    #region Validate input properties
    # Checking for the required properties.
    Foreach ($prop in $requiredProps) {
        If (-NOT($Properties.Contains($prop))) {
            $message = ("{0}: Missing required property: {1}. Please update the -Filter parameter and try again." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $prop)
            Out-PsLogging @loggingParams -MessageType Error -Message $message

            Return "Error"
        }
    }

    Foreach ($prop in $defaultableProps) {
        If (-NOT($Properties.Contains($prop))) {
            $message = ("{0}: Missing required property: {1}, defaulting to `"*`"." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $prop)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            Try {
                $Properties.Add($prop, '*')
            } Catch {
                $message = ("{0}: Unexpected error adding default {1} value to the hash table. To prevent errors, {2} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $_, $MyInvocation.MyCommand)
                Out-PsLogging @loggingParams -MessageType Error -Message $message

                Return "Error"
            }
        }
    }

    $message = ("{0}: Removing unsupported fields from the Properties hash table." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

    Foreach ($key in $($Properties.keys)) {
        If ($key -notin 'datapoint', 'instance', 'devices', 'escalatingChainId', 'resourceProperties', 'sendAnomalySuppressedAlert', 'priority', 'suppressAlertAckSdt', 'datasource', 'suppressAlertClear', 'name', 'levelStr', 'deviceGroups', 'escalationInterval') {
            $message = ("{0}: Unsupported field found ({1}), removing the entry from `$Properties." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $key)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $Properties.remove($key)
        }
    }
    #endregion Validate input properties

    #region Execute REST query
    $data = ($Properties | ConvertTo-Json -Depth 5)

    # Construct the query URL.
    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"

    $message = ("{0}: Connecting to: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $url)
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

    #region Auth and headers
    # Get current time in milliseconds.
    $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)
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

    Try {
        $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -Body $data -ErrorAction Stop
    }
    Catch {
        If ($_.Exception.Message -match '429') {
            $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
            Out-PsLogging @loggingParams -MessageType Warning -Message $message

            Start-Sleep -Seconds 60
        }
        Else {
            $message = ("{0}: Unexpected error creating alert rule. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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
    #endregion Execute REST query

    #region Output
    If ($response.id) {
        $message = ("{0}: Successfully created the alert rule in LogicMonitor." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    } Else {
        $message = ("{0}: Unexpected error creating an alert rule in LogicMonitor. To prevent errors, {1} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
        Out-PsLogging @loggingParams -MessageType Error -Message $message

        Return "Error"
    }

    Return $response
    #endregion Output
} #2023.05.25.0