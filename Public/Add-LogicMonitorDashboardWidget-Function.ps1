Function New-LogicMonitorDashboardWidget {
    <#
        .DESCRIPTION
            Create a new LogicMonitor dashboard widget.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 2 March 2021
                - Initial release.
            V1.0.0.1 date: 16 March 2021
            V1.0.0.2 date: 18 March 2021
            V1.0.0.3 date: 21 September 2021
            V2023.06.07.0
            V2023.08.25.0
            V2024.05.02.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Properties
            Mandatory parameter. Represents the properties values of the new dashboard. Required fields are "name" and "parentId". Valid properties can be found at https://www.logicmonitor.com/swagger-ui-master/dist/#/Device%20Groups/addDashboard.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> $table = [PsCustomObject]@{name = 'widget1'; dashboardId = 1}
            PS C:\> Add-LogicMonitorDashboard -AccessId <access Id> -AccessKey <access key> -AccountName <account name> -Properties $table

            In this example, the function will create a new dashboard widget with the following properties:
                - Name: widget1
                - Dashboard ID: 1
            Limited logging output is sent to the host.
        .EXAMPLE
            PS C:\> $table = [PsCustomObject]@{
                        name = 'widget1'
                        dashboardId = 1
                        type = 'text'
                        content = 'text content'
                        description = 'This is a test widget.'
                        interval = 15
                        theme = 'borderPurple'
                    }
            PS C:\> Add-LogicMonitorDashboard -AccessId <access Id> -AccessKey <access key> -AccountName <account name> -Properties $table -Verbose -LogPath log.txt

            In this example, the function will create a new dashboard with the following properties:
                - Name: widget1
                - Dashboard ID: 1
                - Type: text
                - Description: This is a test widget.
                - Widget update interval: 15 minutes
                - Theme: boarderPurple
            The widget will be a text widget (with "text content" inside) that updates every 15 minutes. Verbose logging output is sent to the host and log.txt in the current directory.
    #>
    [CmdletBinding()]
    [Alias("Add-LogicMonitorDashboardWidget")]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [SecureString]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory)]
        [PSCustomObject]$Properties,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    # Initialize variables.
    $httpVerb = "POST" # Define what HTTP operation will the script run.
    $resourcePath = "/dashboard/widgets"
    $requiredProps = @('name', 'dashboardId', 'type')
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

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand); If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    #endregion Setup

    #region Validate input properties
    # Checking for the required properties
    Foreach ($prop in $requiredProps) {
        If (-NOT($Properties.$prop)) {
            $message = ("{0}: Missing required property: {1}. Please update the -Filter parameter and try again." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $prop); Out-PsLogging @loggingParams -MessageType Error -Message $message

            Return "Error"
        }
    }
    #endregion Validate input properties

    #region Execute REST query
    $data = ($Properties | ConvertTo-Json -Depth 5)

    # Construct the query URL.
    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"

    $message = ("{0}: Connecting to: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $url); If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

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
    }
    Catch {
        If ($_.Exception.Message -match '429') {
            $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message); Out-PsLogging @loggingParams -MessageType Warning -Message $message

            Start-Sleep -Seconds 60
        }
        Else {
            # Left the body out of the error message, because the body can be really long and it is annoying to have to scroll up to see the error message.
            $errormsg = Try { ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage) } Catch { $error[1].Exception.Message }
            $errorcode = Try { ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode) } Catch { "none" }
            $message = ("{0}: Unexpected error adding widget called `"{1}`". To prevent errors, the cmdlet will exit. If present, the following details were returned:`r`n
                Error message: {2}`r
                Error code: {3}`r
                Invoke-Request: {4}`r
                Headers: {5}" -f
                ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Properties.Name, $errormsg, $errorcode, $_.Exception.Message, ($headers | Out-String)
            ); Out-PsLogging @loggingParams -MessageType Error -Message $message
        }

        Return "Error"
    }

    #region Output
    If ($response.id) {
        $message = ("{0}: Successfully created the dashboard widget in LogicMonitor." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss")); If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    } Else {
        $message = ("{0}: Unexpected error creating an dashboard widget in LogicMonitor. To prevent errors, {1} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand); Out-PsLogging @loggingParams -MessageType Error -Message $message

        Return "Error"
    }

    Return $response
    #endregion Output
} #2024.05.02.0