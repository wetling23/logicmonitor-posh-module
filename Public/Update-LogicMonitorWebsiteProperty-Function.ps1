Function Update-LogicMonitorWebsiteProperty {
    <#
        .DESCRIPTION
            Accepts a website ID or name and one or more property name/value pairs, then updates the property(ies), replacing existing values if the property is already defined.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 23 February 2017
                - Initial release.
            V1.0.0.1 date: 23 April 2018
                - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
            V1.0.0.2 date: 15 March 2019
                - Updated to use API v2 and changed input parameters.
            V1.0.0.3 date: 23 August 2019
            V1.0.0.4 date: 26 August 2019
            V1.0.0.5 date: 18 October 2019
            V1.0.0.6 date: 4 December 2019
            V1.0.0.7 date: 10 December 2019
            V1.0.0.8 date: 23 July 2020
            V1.0.0.9 date: 19 October 2020
            V1.0.0.10 date: 21 September 2021
            V1.0.0.11 date: 20 June 2022
            V2023.01.06.0
            V2023.03.01.0
            V2023.08.22.0
            V2023.08.27.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Id
            Mandatory parameter. Represents the website ID of a monitored website.
        .PARAMETER Properties
            Represents a hash table of property name/value pairs for the target object.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Update-LogicMonitorwebsiteProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6 -PropertyTable @{"name"="newName"} -Verbose

            In this example, the command will change the name of the website with id 6, to 'newName'. Verbose logging output is sent to the host.
        .EXAMPLE
            PS C:\> $site = Get-LogicMonitorWebsite -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6
            PS C:\> Update-LogicMonitorwebsiteProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Name website1 -PropertyTable @{ "name"="newName"; "domain"="1.1.1.1"; type = 'webcheck'; testLocation = $site.testLocation }

            In this example, the command will change the name of the website with name 'website1, to 'newName' and will update the domain value to 1.1.1.1. The required property, "testLocation" value will be retrieved from the existing value. Limitied logging output will be only sent to the host.
        .EXAMPLE
            PS C:\> Update-LogicMonitorwebsiteProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6 -PropertyTable @{ name = 'site1'; type = 'webcheck'; testLocation = @{ all = $false; smgIds = @(2, 3, 4) } } -LogPath C:\Temp\log.txt

            In this example, the command will set the list of checkpoint locations to 2, 3, and 4 (US - Washington DC, US - Oregon, and Europe - Dublin). Limited logging is sent to the host and C:\Temp\log.txt.
    #>
    [CmdletBinding(DefaultParameterSetName = 'IdFilter')]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [SecureString]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'IdFilter')]
        [Int[]]$Id,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [String]$Name,

        [Parameter(Mandatory)]
        [Alias('PropertyTable')]
        [Hashtable]$Properties,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    #region Initialize variables
    $httpVerb = 'PATCH'
    $resourcePath = "/website/websites"
    $requiredProps = @('testLocation', 'type', 'name')
    $queryParams = $null
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

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
        If ($key -notin 'template', 'testLocation', 'overallAlertLevel', 'pollingInterval', 'description', 'disableAlerting', 'type', 'stopMonitoring', 'userPermission', 'individualSmAlertEnable', 'checkpoints', 'steps', 'transition', 'globalSmAlertCond', `
                'isInternal', 'domain', 'name', 'useDefaultLocationSetting', 'useDefaultAlertSetting', 'individualAlertLevel') {
            $message = ("{0}: Unsupported field found ({1}), removing the entry from `$Properties." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $key)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $Properties.remove($key)
        }
    }
    #endregion Validate input properties

    # Update $resourcePath to filter for a specific website, when a website name is provided by the user.
    Switch ($PsCmdlet.ParameterSetName) {
        "NameFilter" {
            $message = ("{0}: Attempting to retrieve the website ID of {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Name)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $website = Get-LogicMonitorWebsite @commandParams -Name $Name @commandParams

            $resourcePath += "/$($website.id)"
        }
    }

    #region Update filter/resourcePath
    Switch ($PsCmdlet.ParameterSetName) {
        "NameFilter" {
            $message = ("{0}: Attempting to retrieve the website ID of {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Name)
            If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

            $website = Get-LogicMonitorWebsite @commandParams -Name $Name @loggingParams

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

    Foreach ($site in $Id) {
        $resourcePath += "/$site"
    }

    $data = $Properties | ConvertTo-Json -Depth 6

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
                $message = ("{0}: Unexpected error updating LogicMonitor website property. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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

    Return $response
} #2023.08.27.0