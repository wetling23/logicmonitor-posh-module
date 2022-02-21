Function Get-LogicMonitorSdt {
    <#
        .DESCRIPTION
            Retrieves a list of Standard Down Time (SDT) entries from LogicMonitor.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 9 July 2018
                - Initial release.
            V1.0.0.1 date: 9 July 2018
                - Changed references to "devices", to "SDT entries".
                - Added parameter site assignment to the SdtEntry parameter, so it cannot be used with the SdtId parameter set.
            V1.0.0.2 date: 24 October 2018
                - Fixed bug in ParameterSetName.
            V1.0.0.3 date: 22 January 2019
                - Removed SdtType from the list of mandatory parameters.Function Get-LogicMonitorSdt.
            V1.0.0.4 date: 14 March 2019
                - Added support for rate-limited re-try.
            V1.0.0.5 date: 23 August 2019
            V1.0.0.6 date: 26 August 2019
            V1.0.0.7 date: 18 October 2019
            V1.0.0.8 date: 4 December 2019
            V1.0.0.9 date: 23 July 2020
            V1.0.0.10 date: 2 October 2020
            V2022.02.21.0
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Filter
            Represents a hash table defining an API query filter. Valid keys are: id, admin, comment, monthDay, hour, minute, endHour, endMinute, duration, startDateTimeOnLocal, startDateTime, endDateTimeOnLocal, 
            endDateTime, isEffective, timezone, type, weekOfMonth, sdtType, weekDay, deviceId, deviceDisplayName. Invaid keys will be removed before calling the API.
        .PARAMETER Id
            Represents the ID of a specific SDT entry. Accepts pipeline input.
        .PARAMETER AdminName
            Deprecated parameter. Represents the user name of the user who created the SDT entry.
        .PARAMETER SdtType
            Deprecated parameter. Represents the type of SDT entries which to return. Valid values are CollectorSDT, DeviceGroupSDT, DeviceSDT, ServiceCheckpointSDT, ServiceSDT.
        .PARAMETER IsEffective
            Deprecated parameter. When included, only returns SDT entries that are currently active.
        .PARAMETER BatchSize
            Default value is 1000. Represents the number of SDT entries to request from LogicMonitor, in a single batch.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorSdt -AccessId $AccessID -AccessKey $accessKey -AccountName <account name> -Id A_8 -Verbose

            This example shows how to get the SDT entry with ID "A_8". Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> $allSdts = Get-LogicMonitorSdt -AccessId $AccessID -AccessKey $accessKey -AccountName <account name> -BlockLogging

            This example shows how to get all SDT entries and store them in a variable called "allSdts". The command's limited logging is output only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorSdt -AccessId $AccessID -AccessKey $AccessKey -AccountName <account name> -AdminName <username> -SdtType DeviceGroupSDT

            This example shows how to get all device group SDT entries created by the user in <username>.
        .EXAMPLE
            PS C:\> Get-LogicMonitorSdt -AccessId $AccessID -AccessKey $AccessKey -AccountName <account name> -Filter @{deviceId = "101"; type = "DeviceSDT"} -Verbose -LogPath C:\Temp\log.txt

            This example shows how to get all device-type SDT entries for the device with ID 101. Verbose logging is written to the host and to C:\Temp\log.txt
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllSdt')]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessID,

        [Parameter(Mandatory)]
        [securestring]$AccessKey,

        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory, ParameterSetName = "StringFilter")]
        [hashtable]$Filter,

        [Parameter(Mandatory, ParameterSetName = "Id", ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias("SdtId")]
        [string]$Id,

        [Parameter(Mandatory, ParameterSetName = "AdminName")]
        [string]$AdminName,

        [Parameter(ParameterSetName = "AdminName")]
        [Parameter(ParameterSetName = "Id")]
        [Parameter(ParameterSetName = "AllSdt")]
        [ValidateSet('ServiceSDT', 'CollectorSDT', 'DeviceDataSourceInstanceSDT', 'DeviceBatchJobSDT', 'DeviceClusterAlertDefSDT', 'DeviceDataSourceInstanceGroupSDT', 'DeviceDataSourceSDT', 'DeviceEventSourceSDT', 'DeviceGroupSDT', 'DeviceSDT', 'WebsiteCheckpointSDT', 'WebsiteGroupSDT', 'WebsiteSDT')]
        [string]$SdtType,

        [switch]$IsEffective,

        [int]$BatchSize = 1000,

        [boolean]$BlockStdErr = $false,

        [string]$EventLogSource,

        [string]$LogPath
    )

    Begin {
        # Initialize variables.
        [boolean]$firstLoopDone = $false # Will change to true, once the function determines how many times it needs to loop, to retrieve all alerts.
        $hashstr = $null # Filter as a string.
        $sdts = [System.Collections.Generic.List[PSObject]]::new() # Create a collection to hold the alerts.
        $response = $null
        $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
        $httpVerb = "GET" # Define what HTTP operation will the script run.
        $resourcePath = "/sdt/sdts" # Define the resourcePath, based on what you're searching for.
        $queryParams = $null
        [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
        $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    }
    Process {
        $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        Switch ($PsCmdlet.ParameterSetName) {
            { $_ -eq "Id" } {
                $resourcePath += "/$Id"

                $message = ("{0}: Updated resource path to {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
            }
            { $_ -eq "StringFilter" } {
                $message = ("{0}: Checking filter for invalid keys." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                Foreach ($key in $($Filter.keys)) {
                    If ($key -notin 'id', 'admin', 'comment', 'monthDay', 'hour', 'minute', 'endHour', 'endMinute', 'duration', 'startDateTimeOnLocal', 'startDateTime', 'endDateTimeOnLocal', `
                            'endDateTime', 'isEffective', 'timezone', 'type', 'weekOfMonth', 'sdtType', 'weekDay', 'deviceId', 'deviceDisplayName') {

                        $message = ("{0}: Unable to filter by {1}, removing the entry." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $key)
                        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                        $filter.remove($key)
                    }
                }

                $message = ("{0}: Converting special characters to URL encoding." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                Foreach ($clone in ($Filter.Clone()).Keys) {
                    $filter.$clone = ($filter.$clone).Replace('"', '%2522')
                    $filter.$clone = ($filter.$clone).Replace('&', '%26')
                    $filter.$clone = ($filter.$clone).Replace("`r`n", "`n")
                    $filter.$clone = ($filter.$clone).Replace('#', '%23')
                    $filter.$clone = ($filter.$clone).Replace("`n", '%0A')
                    $filter.$clone = ($filter.$clone).Replace(')', '%29')
                    $filter.$clone = ($filter.$clone).Replace('(', '%28')
                    $filter.$clone = ($filter.$clone).Replace('>', '%3E')
                    $filter.$clone = ($filter.$clone).Replace('<', '%3C')
                    $filter.$clone = ($filter.$clone).Replace('/', '%2F')
                    $filter.$clone = ($filter.$clone).Replace(',', '%2C')
                    $filter.$clone = ($filter.$clone).Replace('*', '%2A')
                    $filter.$clone = ($filter.$clone).Replace('!', '%21')
                    $filter.$clone = ($filter.$clone).Replace('=', '%3D')
                    $filter.$clone = ($filter.$clone).Replace('~', '%7E')
                    $filter.$clone = ($filter.$clone).Replace(' ', '%20')
                    $filter.$clone = ($filter.$clone).Replace('|', '%7C')
                    $filter.$clone = ($filter.$clone).Replace('$', '%24')
                    $filter.$clone = ($filter.$clone).Replace('\', '%5C')
                    $filter.$clone = ($filter.$clone).Replace('_', '%5F')
                }

                $message = ("{0}: Converting the filter hashtable to a string." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                foreach ($key in $($filter.keys)) {
                    $hashstr += $key + ":" + "`"$($filter[$key])`"" + ","
                }
                $filter = ($hashstr.trimend(',')).Replace("`"", "%22")
            }
        }

        # Build the filter, if any of the following conditions are met.
        Switch ($IsEffective, $SdtType) {
            { $_.IsPresent } {
                $filter += "isEffective:`"True`","

                $message = ("{0}: Updating `$filter variable in {1}. The value is {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $($PsCmdlet.ParameterSetName), $queryParams)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                Continue
            }
            { $_ -in 'ServiceSDT', 'CollectorSDT', 'DeviceDataSourceInstanceSDT', 'DeviceBatchJobSDT', 'DeviceClusterAlertDefSDT', 'DeviceDataSourceInstanceGroupSDT', 'DeviceDataSourceSDT', 'DeviceEventSourceSDT', 'DeviceGroupSDT', 'DeviceSDT', 'WebsiteCheckpointSDT', 'WebsiteGroupSDT', 'WebsiteSDT' } {
                $filter += "type:`"$sdtType`","

                $message = ("{0}: Updating `$filter variable in {1}. The value is {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $($PsCmdlet.ParameterSetName), $queryParams)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                Continue
            }
        }

        If ($PsCmdlet.ParameterSetName -eq "AdminName") {
            $filter += "admin:`"$AdminName`","

            $message = ("{0}: Updating `$filter variable in {1}. The value is {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $($PsCmdlet.ParameterSetName), $queryParams)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
        }

        If (-NOT([string]::IsNullOrEmpty($filter))) {
            $filter = $filter.TrimEnd(",")
        }

        # Determine how many times "GET" must be run, to return all SDT entries, then loop through "GET" that many times.
        While (($response.Count -ge 1) -or ($firstLoopDone -eq $false)) {
            $message = ("{0}: The request loop has run {1} times." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $batchCount)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            If ([string]::IsNullOrEmpty($filter)) {
                $queryParams = "?offset=$offset&size=$BatchSize&sort=id"
            }
            Else {
                $queryParams = "?filter=$filter&offset=$offset&size=$BatchSize&sort=id"
            }

            $message = ("{0}: Updated `$queryParams variable in {1}. The value is {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $($PsCmdlet.ParameterSetName), $queryParams)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            # Construct the query URL.
            $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

            # Build header.
            If ($firstLoopDone -eq $false) {
                $message = ("{0}: Building request header." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                # Get current time in milliseconds
                $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

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
                    "Authorization" = "LMv1 $AccessID`:$signature`:$epoch"
                    "Content-Type"  = "application/json"
                    "X-Version"     = 2
                }
            }

            # Make the API request.
            $message = ("{0}: Executing the REST query." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $stopLoop = $false
            Do {
                Try {
                    $response = [System.Collections.Generic.List[PSObject]]@((Invoke-RestMethod -Uri $url -Method $httpverb -Header $headers -ErrorAction Stop).items)

                    $stopLoop = $True
                }
                Catch {
                    If ($_.Exception.Message -match '429') {
                        $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }

                        Start-Sleep -Seconds 60
                    }
                    Else {
                        $message = ("{0}: Unexpected error getting alerts. To prevent errors, {1} will exit. If present, the following details were returned:`r`n
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

            $sdts.AddRange($response)

            $message = ("{0}: Executed REST query. There are {1} entries in `$sdts." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $sdts.id.Count)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $offset += $BatchSize
            $firstLoopDone = $true
        }

        Return $sdts
    }
} #V2022.02.21.0