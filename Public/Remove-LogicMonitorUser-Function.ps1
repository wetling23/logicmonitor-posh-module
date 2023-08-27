Function Remove-LogicMonitorUser {
    <#
        .DESCRIPTION
            Deletes user objects from LogicMonitor.
        .NOTES
            Author: Mike Hashemi
            V2023.06.05.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Id
            Represents the LogicMonitor ID of the desired user.
        .PARAMETER Filter
            Represents a string matching the API's filter format. This parameter can be used to filter for users matching certain criteria.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorUser -AccessID <access ID> -AccessKey <access key> -AccountName <account name> -Id 1233, 456 -Verbose

            In this example, the cmdlet will delete users with ID 123 and 456. Verbose logging output is written only to the host.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorUser -AccessID <access ID> -AccessKey <access key> -AccountName <account name> -Id 6 -LogPath C:\Temp\log.txt

            In this example, the cmdlet will delete the user with ID 6. Limit logging output is written to C:\Temp\log.txt
        .EXAMPLE
            PS C:\> Remove-LogicMonitorUser -AccessID <accessID> -AccessKey <accessKey> -AccountName <accountName> -Filter 'filter=username:"jdoe@domain.com"|"jsmith@domain.com"' -Verbose

            In this example, the command will get the ID value for users with username "jdoe@domain.com" and "jsmith@domain.com", before using the ID to delete those users. Verbose logging output is sent only to the host.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [SecureString]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'IDFilter')]
        [Int[]]$Id,

        [Parameter(Mandatory, ParameterSetName = 'StringFilter')]
        [String]$Filter,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    #region Setup
    #region Variables
    $users = [System.Collections.Generic.List[PSObject]]::New() # Primary collection to be filled with Invoke-RestMethod response.
    $httpVerb = "DELETE" # Define what HTTP operation will the script run.
    $resourcePath = "/setting/admins" # Define the resourcePath, based on the type of query you are doing.
    [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    $commandParams = @{
        AccessId    = $AccessId
        AccessKey   = $AccessKey
        AccountName = $AccountName
    }
    #endregion Variables

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
    Out-PsLogging @loggingParams -MessageType Verbose -Message $message

    $message = ("{0}: Operating in the `"{1}`" parameter set." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $PsCmdlet.ParameterSetName)
    If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    #endregion Setup

    #region Get users using filter
    Switch ($PsCmdlet.ParameterSetName) {
        'StringFilter' {
            $users = Get-LogicMonitorUser @commandParams -Filter $Filter @loggingParams

            If ($users.id) {
                $users | ForEach-Object { [Int[]]$Id += $_.id }
            } Else {
                $message = ("{0}: No users were retrieved using the provided filter, see the cmdlet's logging for more details. To prevent errors, {1} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
                Out-PsLogging @loggingParams -MessageType Error -Message $message

                Return "Error"
            }
        }
    }
    #region Get users using filter

    #region Execute REST query
    Foreach ($user in $Id) {
        $resourcePath = ("/setting/admins/{0}" -f $user)

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
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"

        $message = ("{0}: Connecting to: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $url)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }

        $stopLoop = $false
        Do {
            Try {
                Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop

                $stopLoop = $True
            } Catch {
                If ($_.Exception.Message -match '429') {
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                    Out-PsLogging @loggingParams -MessageType Warning -Message $message

                    Start-Sleep -Seconds 60
                } Else {
                    $message = ("{0}: Unexpected error deleting user. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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

        $message = ("{0}: Deleted user with ID {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $user)
        If ($loggingParams.Verbose) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message }
    }
    #endregion Execute REST query
} #2023.06.05.0