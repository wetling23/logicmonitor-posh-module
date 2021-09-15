Function Get-LogicMonitorDataSource {
    <#
        .DESCRIPTION
            Returns a list of LogicMonitor DataSources. By default, the function returns all datasources. If a DataSource ID or name is provided, the function will 
            return properties for the specified DataSource.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 5 March 2017
                - Initial release.
                - Bug in the AppliesToFilter parameter set. Engaged LogicMonitor for support.
            V1.0.0.2 date: 3 May 2017
                - Removed code from writing to file and added Event Log support.
                - Updated code for verbose logging.
                - Changed Add-EventLogSource failure behavior to just block logging (instead of quitting the function).
            V1.0.0.3 date: 21 June 2017
                - Updated logging to reduce chatter.
            V1.0.0.4 date: 1 August 2017
                - Updated code to support XML output when a DataSource ID is provided.
            V1.0.0.5 date: 18 August 2017
                - Changed the "AppliesTo" query filter.
            V1.0.0.6 date: 23 April 2018
                - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
            V1.0.0.7 date: 15 May 2018
                - Fixed typo in the cmdlet name.
            V1.0.0.8 date: 14 June 2018
                - Updated whitespace.
            V1.0.0.9 date: 21 June 2018
                - Added encoding of &, to UTF-8.
                - Added example.
            V1.0.0.10 date: 14 March 2019
                - Added support for rate-limited re-try.
            V1.0.0.11 date: 18 March 2019
                - Updated alias publishing method.
            V1.0.0.12 date: 23 August 2019
            V1.0.0.13 date: 26 August 2019
            V1.0.0.14 date: 18 October 2019
            V1.0.0.15 date: 4 December 2019
            V1.0.0.16 date: 23 July 2020
            V1.0.0.17 date: 15 September 2021
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER DataSourceId
            Represents the ID of the desired DataSource.
        .PARAMETER XmlOutput
            When included, the function will request XML output from LogicMonitor. The switch is only available when a DataSource ID is specified.
        .PARAMETER DisplayName
            Represents the display name of the desired DataSource.
        .PARAMETER ApplyTo
            Represents the "AppliesTo" filter of the desired DataSource.
        .PARAMETER Filter
            Represents a string matching the API's filter format. This parameter can be used to filter for DataSources matching certain criteria (e.g. "hasMultiInstances" is "true").

            See https://www.logicmonitor.com/support/rest-api-developers-guide/v1/devices/get-devices#Example-Request-5--GET-all-devices-that-have-a-spe
        .PARAMETER BatchSize
            Default value is 1000. Represents the number of DataSoruces to request from LogicMonitor, in a single batch.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDataSource -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Verbose

            In this example, the function will search for all monitored devices and will return their properties. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDataSource -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DataSourceId 6

            In this example, the function returns the DataSource with ID '6'.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDataSource -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DataSourceId 6 -XmlOutput

            In this example, the function returns the DataSource with ID '6', in XML format.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDataSource -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -DisplayName 'Oracle Library Cache'

            In this example, the function returns the DataSource with display name 'Oracle Library Cache'.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDataSource -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -ApplyTo 'system.hostname =~ "255.1.1.1"'

            In this example, the function returns the DataSource with the 'appliesTo' filter 'system.hostname =~ "255.1.1.1"'.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDataSource -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -ApplyTo 'isWindows()&&hasCategory("collector")'

            In this example, the function returns the DataSource with the 'appliesTo' filter 'isWindows()&&hasCategory("collector")'.
        .EXAMPLE
            PS C:\> Get-LogicMonitorDataSource -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -Filter 'filter=version:12345'

            In this example, the function will search for DataSources with "12345" in the version field. Note that the quotes around the value are required.
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllDataSources')]
    [alias('Get-LogicMonitorDataSources')]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [securestring]$AccessKey,

        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'IDFilter')]
        [Alias("DataSourceId")]
        [int]$Id,

        [Parameter(ParameterSetName = 'IDFilter')]
        [switch]$XmlOutput,

        [Parameter(Mandatory, ParameterSetName = 'DisplayNameFilter')]
        [Alias("DataSourceDisplayName")]
        [string]$DisplayName,

        [Parameter(Mandatory, ParameterSetName = 'AppliesToFilter')]
        [Alias("DataSourceApplyTo")]
        [string]$ApplyTo,

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
    [int]$currentBatchNum = 0 # Start at zero and increment in the while loop, so we know how many times we have looped.
    [int]$offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    [int]$dataSourceBatchCount = 1 # Define how many times we need to loop, to get all DataSource.
    [boolean] $firstLoopDone = $false # Will change to true, once the function determines how many times it needs to loop, to retrieve all DataSources.
    [string]$httpVerb = "GET" # Define what HTTP operation will the script run.
    [string]$resourcePath = "/setting/datasources" # Define the resourcePath.
    $queryParams = $null
    $pattern1 = '[^a-zA-Z\d\s]' # Match any non-alpha numeric or white space character.
    $pattern2 = '(?:>:|<:|:|>|<|!:|:|~|!~)(?:")(.*?)(?:")' # Allow us to replace characters in the filter. We will leave some of the characters alone, since they are used by the API in certain spots. For example, ":" means equal between the property name and value but should be replaced in the value portion of the pair.
    $regex = [Regex]::new($pattern2)
    $dataSources = [System.Collections.Generic.List[PSObject]]::New() # Primary collection to be filled with Invoke-RestMethod response.
    [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    $message = ("{0}: The resource path is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    Do {
        Switch ($PsCmdlet.ParameterSetName) {
            "AllDataSources" {
                $queryParams = "?offset=$offset&size=$BatchSize&sort=id"
            }
            "IDFilter" {
                $resourcePath += "/$Id"

                $message = ("{0}: Updated resource path to {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                If ($XmlOutput) {
                    $queryParams = "?format=xml&offset=$offset&size=$BatchSize&sort=id"
                }
                Else {
                    $queryParams = "?offset=$offset&size=$BatchSize&sort=id"
                }
            }
            "DisplayNameFilter" {
                # Replace special characters to better encode the URL.
                $DisplayName = $DisplayName.Replace('_', '%5F')
                $DisplayName = $DisplayName.Replace(' ', '%20')

                $queryParams = "?filter=displayName:`"$DisplayName`"&offset=$offset&size=$BatchSize&sort=id"
            }
            "AppliesToFilter" {
                # Replace special characters to better encode the URL.
                $ApplyTo = $ApplyTo.Replace('"', '%2522')
                $ApplyTo = $ApplyTo.Replace('&', '%26')
                $ApplyTo = $ApplyTo.Replace("`r`n", "`n")
                $ApplyTo = $ApplyTo.Replace('#', '%23')
                $ApplyTo = $ApplyTo.Replace("`n", '%0A')
                $ApplyTo = $ApplyTo.Replace(')', '%29')
                $ApplyTo = $ApplyTo.Replace('(', '%28')
                $ApplyTo = $ApplyTo.Replace('>', '%3E')
                $ApplyTo = $ApplyTo.Replace('<', '%3C')
                $ApplyTo = $ApplyTo.Replace('/', '%2F')
                $ApplyTo = $ApplyTo.Replace(',', '%2C')
                $ApplyTo = $ApplyTo.Replace('*', '%2A')
                $ApplyTo = $ApplyTo.Replace('!', '%21')
                $ApplyTo = $ApplyTo.Replace('=', '%3D')
                $ApplyTo = $ApplyTo.Replace('~', '%7E')
                $ApplyTo = $ApplyTo.Replace(' ', '%20')
                $ApplyTo = $ApplyTo.Replace('|', '%7C')
                $ApplyTo = $ApplyTo.Replace('$', '%24')
                $ApplyTo = $ApplyTo.Replace('\', '%5C')
                $ApplyTo = $ApplyTo.Replace('_', '%5F')

                $queryParams = "?filter=appliesTo:`"$ApplyTo`"&offset=$offset&size=$BatchSize&sort=id"
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
        }

        $message = ("{0}: Updated `$queryParams variable in {1}. The value is {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $($PsCmdlet.ParameterSetName), $queryParams)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

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
                    $message = ("{0}: Unexpected error getting DataSources. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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
            $message = ("{0}: Found {1} more DataSources." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $response.items.Count)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $datasources.AddRange([System.Collections.Generic.List[PSObject]]@($response.items))

            If ($response.items.Count -eq 1) {
                $stopLoop = $true
            } Else {
                $stopLoop = $false
            }
        } ElseIf ($firstLoopDone -and $response.id) {
            $datasources = $response

            $stopLoop = $true
        } Else {
            $message = ("{0}: The `$response variable is empty." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $stopLoop = $true
        }

        $message = ("{0}: There are {1} DataSources in `$datasources." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $datasources.id.Count)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        If ($stopLoop -eq $false) {
            # Increment offset, to grab the next batch of devices.
            $message = ("{0}: Incrementing the search offset by {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $BatchSize)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $offset += $BatchSize
        }
    }
    Until (($stopLoop -eq $true) -or ($singleDeviceCheckDone))

    $datasources
} #1.0.0.17