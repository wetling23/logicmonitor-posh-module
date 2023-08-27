Function New-LogicMonitorReportGroup {
    <#
        .DESCRIPTION
            Create a new LogicMonitor report group.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 27 February 2020
                - Initial release.
            V1.0.0.1 date: 23 July 2020
            V1.0.0.2 date: 21 September 2021
            V2023.04.28.0
            V2023.06.07.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Properties
            Mandatory parameter. Represents the properties values of the new ReportGroup. Required field is "name". Valid properties can be found at https://www.logicmonitor.com/swagger-ui-master/dist/#/Report%20Groups/addReportGroup.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> $table = @{name = 'group1'; description = 'Sample description'; userPermission = 'write'}
            PS C:\> New-LogicMonitorReportGroup -AccessId <access Id> -AccessKey <access key> -AccountName <account name> -Properties $table -Verbose

            In this example, the function will create a new ReportGroup with the following properties:
                - Name: group1
                - Description: Sample description
                - Permissions: write
                    - This is an optional parameter. As of 27 February 2020, I am not aware of any valid value, other than 'write'.
            Verbose output is sent to the host.
    #>
    [CmdletBinding()]
    [Alias("Add-LogicMonitorReportGroup")]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [securestring]$AccessKey,

        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory)]
        [hashtable]$Properties,

        [boolean]$BlockStdErr = $false,

        [string]$EventLogSource,

        [string]$LogPath
    )

    #region Setup
    # Initialize variables.
    $httpVerb = "POST" # Define what HTTP operation will the script run.
    $resourcePath = "/report/groups"
    $requiredProps = @('name')
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

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

    $message = ("{0}: Removing unsupported fields from the Properties hash table." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

    Foreach ($key in $($Properties.keys)) {
        If ($key -notin 'name', 'description') {
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

    Try {
        $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -Body $data -ErrorAction Stop
    } Catch {
        If ($_.Exception.Message -match '429') {
            $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
            Out-PsLogging @loggingParams -MessageType Warning -Message $message

            Start-Sleep -Seconds 60
        } Else {
            $message = ("{0}: Unexpected error creating ReportGroup. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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
        $message = ("{0}: Successfully created the ReportGroup in LogicMonitor." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    } Else {
        $message = ("{0}: Unexpected error creating a ReportGroup in LogicMonitor. To prevent errors, {1} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
        Out-PsLogging @loggingParams -MessageType Error -Message $message

        Return "Error"
    }

    Return $response
    #endregion Output
} #2023.06.07.0