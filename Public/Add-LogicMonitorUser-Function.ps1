Function New-LogicMonitorUser {
    <#
        .DESCRIPTION
            Create a new LogicMonitor device group.
        .NOTES
            Author: Mike Hashemi
            V2023.05.31.0
                - Initial release
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Properties
            Mandatory parameter. Represents the properties values of the new DeviceGroup. Required fields are "name" and "parentId". Valid properties can be found at https://www.logicmonitor.com/swagger-ui-master/dist/#/Device%20Groups/addDeviceGroup.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
        ##--
            PS C:\> $table = @{name = 'group1'; parentId = 1}
            PS C:\> New-LogicMonitorUser -AccessId <access Id> -AccessKey <access key> -AccountName <account name> -Properties $table

            In this example, the function will create a new DeviceGroup with the following properties:
                - Name: group1
                - Group ID of the parent: 1
            Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> $userProps = @{
                        firstName           = 'John'
                        lastName            = 'Doe'
                        email               = 'jdoe@domain.com'
                        username            = 'jdoe@domain.com'
                        forcePasswordChange = $true
                        twoFAEnabled        = $true
                        note                = 'User created by New-LogicMonitorUser.'
                        password            = 'als;dfj9232o3js,dfASD'
                        viewPermission      = @{
                            Resources  = $true
                            Websites   = $true
                            Reports    = $true
                            Dashboards = $true
                            Mapping    = $false
                            Logs       = $false
                            Alerts     = $false
                            Trace      = $false
                            Settings   = $false
                        }
                        roles = @(
                            @{
                                id = 181
                            }
                        )
                    }
            PS C:\> New-LogicMonitorUser -AccessId <access Id> -AccessKey <access key> -AccountName <account name> -Properties $userProps -Verbose

            In this example, the cmdlet will create a new user with the following properties:
                - First name: John
                - Last name: Doe
                - E-mail address: jdoe@domain.com
                - Username: jdoe@domain.com
                - Password change required
                - 2FA enabled
                - Note: "User created by New-LogicMonitorUser."
                - Password: A temporary password
                - View permissions: Allowed to see resources, websites, reports, and dashboards
                - Roles: The role with ID 181
            Note that email, password, roles, and username are required properties.

            Verbose logging output is sent only to the host.
    #>
    [CmdletBinding()]
    [Alias("Add-LogicMonitorUser")]
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
    #region Initialize variables
    $httpVerb = "POST" # Define what HTTP operation will the script run.
    $resourcePath = "/setting/admins"
    $stopLoop = $false
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
    $i = 0
    Foreach ($prop in @('email', 'password', 'roles', 'username')) {
        If (-NOT ($Properties.ContainsKey($prop))) {
            $message = ("{0}: Missing required property: {1}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $prop)
            Out-PsLogging @loggingParams -MessageType Error -Message $message

            $i++
        }
    }

    If ($i -gt 0) {
        $message = ("{0}: Missing required properties. Please update the input hash table and try again." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdEr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

        Return "Error"
    }
    #endregion Validate input properties

    #region Execute REST query
    $data = ($Properties | ConvertTo-Json -Depth 10)

    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"

    $message = ("{0}: Connecting to: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $url)
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

    Do {
        #region Auth and headers
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

        $message = ("{0}: Executing the REST query ({1})." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $url)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        Try {
            $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -Body $data -ErrorAction Stop
            $stopLoop = $true
        } Catch {
            If ($_.Exception.Message -match '429') {
                $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                Out-PsLogging @loggingParams -MessageType Warning -Message $message

                Start-Sleep -Seconds 60
            } Else {
                $message = ("{0}: Unexpected error adding user. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
                Error message: {2}`r
                Error code: {3}`r
                Invoke-Request: {4}`r
                Headers: {5}`r
                Body: {6}" -f
                ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage),
                ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
                )
                Out-PsLogging @loggingParams -MessageType Error -Message $message
            }

            Return "Error"
        }
    } Until ($stopLoop -eq $true)
    #endregion Execute REST query

    #region Output
    $response
    #endregion Output
} #2023.05.31.0