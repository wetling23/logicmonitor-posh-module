Function Get-LogicMonitorWebsiteGroup {
    <#
        .DESCRIPTION
            Returns a list of LogicMonitor website groups. Accepts a WebsiteGroup name, ID, or a filter, to retrieve filtered data.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 27 February 2020
                - Initial release
            V1.0.0.1 date: 23 July 2020
            V1.0.0.2 date: 13 April 2021
            V1.0.0.3 date: 30 July 2021
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Id
            Represents website ID of the desired website. Wildcard searches are not supported.
        .PARAMETER Name
            Represents display name of the desired website. Represents display name of the desired report. A "like" search is conducted.
        .PARAMETER Filter
            Represents a string matching the API's filter format. This parameter can be used to filter for website groups matching certain criteria (e.g. "siteType" appears in properties).

            See https://www.logicmonitor.com/support/rest-api-developers-guide/v1/devices/get-devices#Example-Request-5--GET-all-devices-that-have-a-spe
        .PARAMETER BatchSize
            Default value is 1000. Represents the number of websites to request in each batch.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorWebsiteGroup -AccessId <accessID> -AccessKey <accessKey> -AccountName <accountName> -Verbose

            In this example, the function will search for all website groups, Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorWebsiteGroup -AccessId <accessID> -AccessKey <accessKey> -AccountName <accountName> -Id 6 -LogPath log.txt

            In this example, the function will search for a website group with "6" in the id property. Limited logging output is sent to log.txt in the current directory.
        .EXAMPLE
            PS C:\> Get-LogicMonitorWebsiteGroup -AccessId <accessID> -AccessKey <accessKey> -AccountName <accountName> -Name cnn.com

            In this example, the function will search for a website with "cnn.com" in the name property. Non-verbose output is returned to the shell.
        .EXAMPLE
            PS C:\> Get-LogicMonitorWebsiteGroup -AccessId <accessID> -AccessKey <accessKey> -AccountName <accountName> -Name cnn.com

            In this example, the function will search for a website with "cnn.com" in the name property. Non-verbose output is returned to the shell. Limited logging output will be written only to the session host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorWebsiteGroup -AccessId <accessID> -AccessKey <accessKey> -AccountName <accountName> -Filter "filter=properties.name:`"siteType`",properties.value:`"iis`"" -Verbose -EventSource LmScript

            In this example, the function will search for all websites with a property called "siteType", with a value of "iis". Verbose logging output will be written to the session host and the Application event log.
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllGroups')]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [securestring]$AccessKey,

        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'IDFilter')]
        [int]$Id,

        [Parameter(Mandatory, ParameterSetName = 'NameFilter')]
        [string]$Name,

        [Parameter(Mandatory, ParameterSetName = 'StringFilter')]
        [string]$Filter,

        [int]$BatchSize = 1000,

        [boolean]$BlockStdErr = $false,

        [string]$EventLogSource,

        [string]$LogPath
    )

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    $message = ("{0}: Operating in the {1} parameter set." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $PsCmdlet.ParameterSetName)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    # Initialize variables.
    $websiteGroups = [System.Collections.Generic.List[PSObject]]::New() # Primary collection to be filled with Invoke-RestMethod response.
    $singlewebsiteGroupCheckDone = $false # Controls when a Do loop exits, if we are getting a single dashboard (by ID or name).
    $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    $firstLoopDone = $false # Will change to true, once the function determines how many times it needs to loop, to retrieve all website groups.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $resourcePath = "/website/groups" # Define the resourcePath, based on the type of website you're searching for.
    $queryParams = $null
    $pattern1 = '[^a-zA-Z\d\s]' # Match any non-alpha numeric or white space character.
    $pattern2 = '(?:>:|<:|:|>|<|!:|:|~|!~)(?:")(.*?)(?:")' # Allow us to replace characters in the filter. We will leave some of the characters alone, since they are used by the API in certain spots. For example, ":" means equal between the property name and value but should be replaced in the value portion of the pair.
    $regex = [Regex]::new($pattern2)
    [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    $message = ("{0}: Retrieving website groups. The resource path is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    Do {
        Switch ($PsCmdlet.ParameterSetName) {
            "NameFilter" {
                $queryParams = "?filter=name:`"$Name`"&offset=$offset&size=$BatchSize&sort=id"
            }
            "StringFilter" {
                If ($Filter -match $pattern1) {
                    $message = ("{0}: URL encoding special characters in the filter." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                    $regex.Matches($Filter) | ForEach-Object {
                        $Filter = $Filter -replace ([regex]::Escape($_.Groups[1].value)), ([uri]::EscapeDataString($_.Groups[1].value))
                    }

                    $message = ("{0}: After parsing, the filter is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $Filter)
                    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
                }

                $queryParams = "?$Filter&offset=$offset&size=$BatchSize&sort=id"
            }
            "AllGroups" {
                $queryParams = "?offset=$offset&size=$BatchSize&sort=id"
            }
            "IDFilter" {
                # Update $resourcePath to filter for a specific website group, when a website group ID is provided by the user.
                $resourcePath += "/$Id"

                $message = ("{0}: Updated resource path to {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
            }
        }

        If ($queryParams) {
            $message = ("{0}: Updated `$queryParams variable in {1}. The value is {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $($PsCmdlet.ParameterSetName), $queryParams)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
        }

        If ($firstLoopDone -eq $false) {
            $message = ("{0}: Building request header." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

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
                "Authorization" = "LMv1 $accessId`:$signature`:$epoch"
                "Content-Type"  = "application/json"
                "X-Version"     = 2
            }
        }

        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

        # Make Request
        $message = ("{0}: Executing the REST query." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $stopLoop = $false
        Do {
            Try {
                $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop

                $stopLoop = $True
                $firstLoopDone = $True
            } Catch {
                If ($_.Exception.Message -match '429') {
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }

                    Start-Sleep -Seconds 60
                } ElseIf ($_.ErrorDetails -match 'invalid filter') {
                    $message = ("{0}: LogicMonitor returned `"invalid filter`". Please validate the value of the -Filter parameter and try again." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                    Return "Error"
                } Else {
                    $message = ("{0}: Unexpected error getting website groups. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
                        Error message: {2}`r
                        Error code: {3}`r
                        Invoke-Request: {4}`r
                        Headers: {5}`r
                        Body: {6}" -f
                        ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorMessage),
                        ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue | Select-Object -ExpandProperty errorCode), $_.Exception.Message, ($headers | Out-String), ($data | Out-String)
                    )
                    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                    Return "Error"
                }
            }
        }
        While ($stopLoop -eq $false)

        If ($firstLoopDone -and ($response.items.Count -gt 0)) {
            $message = ("{0}: Found {1} more website groups." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $response.items.Count)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $websiteGroups.AddRange([System.Collections.Generic.List[PSObject]]@($response.items))

            If ($response.items.Count -eq 1) {
                $stopLoop = $true
            } Else {
                $stopLoop = $false
            }
        } ElseIf ($firstLoopDone -and $response.id) {
            $websiteGroups = $response

            $stopLoop = $true
        } Else {
            $message = ("{0}: The `$response variable is empty." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $stopLoop = $true
        }

        $message = ("{0}: There are {1} website groups in `$websiteGroups." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $websiteGroups.id.Count)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        If ($stopLoop -eq $false) {
            # Increment offset, to grab the next batch of website groups.
            $message = ("{0}: Incrementing the search offset by {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $BatchSize)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $offset += $BatchSize
        }
    }
    Until (($stopLoop -eq $true) -or ($singlewebsiteGroupCheckDone))

    $websiteGroups
} #1.0.0.3