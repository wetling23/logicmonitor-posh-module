Function Update-LogicMonitorConfigSource {
    <#
        .DESCRIPTION
            Accept a ConfigSource ID and a hashtable of properties. Update the desired ConfigSource with the provided properties.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 22 October 2021
                - Initial release.
            V2023.04.28.0
            V2023.05.19.0
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
            Represents the ID of the desired ConfigSource.
        .PARAMETER Name
            Represents the name the desired ConfigSource. The cmdlet will look-up the ConfigSource ID.
        .PARAMETER Properties
            Represents a hash table of property name/value pairs for the target object.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Update-LogicMonitorConfigSourceProperty -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Id 6 -Properties @{ description = 'Gets data.'} -Verbose

            In this example, the command will update the description property for the ConfigSource with "6" in the ID property. If the description is not set, it will be added. Verbose logging output is sent only to the session host.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [secureString]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'Default')]
        [Int]$Id,

        [Parameter(Mandatory, ParameterSetName = 'NameId')]
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
    <# Note that, as of 22 August 2023, I do not see /setting/configsources in the Swagger doc, with a PATCH method. The update works, but because it is not documented, I have not identified required/supported properties. #>
    $httpVerb = 'PATCH' # Define what HTTP operation will the script run.
    $queryParams = $null
    $resourcePath = "/setting/configsources"
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    $commandParams = @{
        AccountName = $AccountName
        AccessId    = $AccessId
        AccessKey   = $AccessKey
    }

    If ($PSCmdlet.ParameterSetName -eq 'NameId') {
        $id = (Get-LogicMonitorConfigSource @commandParams -DisplayName $Name).id
    }
    $resourcePath += "/$Id"
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

    #region Execute REST query
    $data = $($Properties | ConvertTo-Json -Depth 5)

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
                $message = ("{0}: Unexpected error updating the ConfigSource. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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
        $message = ("{0}: Successfully updated the ConfigSource ({1}) in LogicMonitor." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Id)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        Return $response
    } Else {
        $message = ("{0}: Unexpected error updating the ConfigSource ({1}) in LogicMonitor. To prevent errors, {2} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Id, $MyInvocation.MyCommand)
        Out-PsLogging @loggingParams -MessageType Error -Message $message

        Return "Error"
    }
    #endregion Execute REST query
} #2023.08.22.0