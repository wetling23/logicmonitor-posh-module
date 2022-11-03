Function Get-LogicMonitorAlert {
    <#
        .DESCRIPTION
            Retrieves Alert objects from LogicMonitor.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 16 January 2017
                - Initial release.
            V2022.10.24.0
            V2022.11.01.0
            V2022.11.03.0
            V2022.11.03.1
            V2022.11.03.2
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Filter
            Represents a hashtable of filterable alert properties and the value, for which to filter. Valid values are:
                'id', 'type', 'acked', 'rule', 'chain', 'severity', 'cleared', 'sdted', 'monitorObjectName', 'monitorObjectGroups', 'resourceTemplateName', 'instanceName', 'dataPointName'
            Invalid keys in the hashtable are removed before the query is run.
        .PARAMETER BatchSize
            Default value is 1000. Represents the number of alerts to request from LogicMonitor.
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID $accessId -AccessKey $accessKey -AccountName synoptek -Verbose

            In this example, the cmdlet will get all alerts (up to the maximum), as far back as five years (or the maximum data-retention limit).
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID $accessId -AccessKey $accessKey -AccountName synoptek -StartDate (Get-Date -Month 1 -Day 1) -Verbose

            In this example, the cmdlet will get all alerts beginning after the start of the current month.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID $accessId -AccessKey $accessKey -AccountName synoptek -EndDate (Get-Date).AddHours(-1) -Verbose

            In this example, the cmdlet will get all alerts that ended before one hour ago.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID $accessId -AccessKey $accessKey -AccountName synoptek -Filter 'severity<"3",sdted:"false",cleared:"",startEpoch<:"1667495125"' -Verbose

            In this example, the cmdlet will get all open alerts, which started before November 3, 2022 5:05:25 PM (GMT) and that are a higher severity than "3" and are not in SDT.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID $accessId -AccessKey $accessKey -AccountName synoptek -Filter 'filter=severity:2,cleared:"false"' -Verbose

            In this example, the cmdlet will get all open alerts with severity "2", as far bas as five years (or the maximum data-retention limit).
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID $accessId -AccessKey $accessKey -AccountName synoptek -Filter 'severity<"3",sdted:"false",cleared:"false",startEpoch>:"1667494500",startEpoch<:"1667495125"' -Verbose

            In this example, the cmdlet will get all open alerts that began between November 3, 2022 4:55:00 PM (GMT) and November 3, 2022 5:05:25 PM (GMT).
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessID $accessId -AccessKey $accessKey -AccountName synoptek -Filter ('filter=type:"websiteAlert",cleared:"false",startEpoch>:"{0}"' -f $(([DateTimeOffset](Get-Date).AddMinutes(-90)).ToUnixTimeSeconds())) -Verbose

            In this example, the cmdlet will get all open website alerts, that started before 90 minutes ago.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName synoptek -Cleared All -Verbose

            In this example, the cmdlet will get all alerts (up to the maximum), as far back as five years (or the maximum data-retention limit).
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName synoptek -Cleared No -Verbose

            In this example, the cmdlet will get all alerts (up to the maximum), as far back as five years (or the maximum data-retention limit).
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName synoptek -Cleared Yes -FilterArray @(@{ name = 'startEpoch'; value = (Get-Date).AddHours(-1); comparison = '>:' }) -Verbose

            In this example, the cmdlet will get all cleared alerts that started more than one hour ago.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName synoptek -Cleared Yes -FilterArray @(@{ name = 'endEpoch'; value = (Get-Date).AddDays(-10); comparison = '>:'}, @{name = 'type'; value = 'dataSourceAlert'; comparison = ':'}) -Verbose

            In this example, the cmdlet will get all cleared DataSource alerts that ended before 10 days ago.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName synoptek -Cleared No -FilterArray @(@{ name = 'startEpoch'; value = (Get-Date -Month 1 -Day 1); comparison = '>:' }, @{ name = 'sdted'; value = 'true'; comparison = ':' }) -Verbose

            In this example, the cmdlet will get all open alerts that began after the first of the current month, and which are in SDT.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName synoptek -Cleared No -FilterArray @(@{ name = 'startEpoch'; value = (Get-Date).AddDays(-1); comparison = '>:' }, @{ name = 'severity'; value = 2; comparison = '<:' }) -Verbose

            In this example, the cmdlet will get all open alerts that began after one day ago and have a severity of "2" or more.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName synoptek -Cleared No -FilterArray @(@{ name = 'severity'; value = '3'; comparison = '<' }, @{ name = 'sdted'; value = 'false'; comparison = ':'}) -Verbose

            In this example, the cmdlet will get all open alerts with a severity creater than "3" and which are not in SDT.
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName synoptek -Cleared All -FilterArray @(@{ name = 'dataPointName'; value = 'IdleMinutes'; comparison = ':' }) -Verbose

            In this example, the cmdlet get all alerts for the datapoint called "IdleMinutes".
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName synoptek -Cleared All -FilterArray @(@{ name = 'id'; value = "DS10742262"; comparison = ':' }) -Verbose

            In this example, the cmdlet will get all alerts with the ID "DS10742262".
        .EXAMPLE
            PS C:\> Get-LogicMonitorAlert -AccessId $accessId -AccessKey $accessKey -AccountName synoptek -Cleared All -FilterArray @(@{ name = 'monitorObjectName'; value = "server1"; comparison = ':' }) -Verbose

            In this example, the cmdlet will get all alerts for the resource with display name, "server1".
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllAlerts')]
    Param (
        [Parameter(Mandatory)]
        [String]$AccessId,

        [Parameter(Mandatory)]
        [SecureString]$AccessKey,

        [Parameter(Mandatory)]
        [String]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'FilterArray')]
        [Array]$FilterArray,

        [Parameter(ParameterSetName = 'AllAlerts')]
        [Parameter(ParameterSetName = 'FilterArray')]
        [ValidateSet('All', 'Yes', 'No')]
        [String]$Cleared = 'All',

        [Parameter(ParameterSetName = 'ManualStartEnd')]
        [datetime]$StartDate,

        [Parameter(ParameterSetName = 'ManualStartEnd')]
        [datetime]$EndDate,

        [Parameter(ParameterSetName = 'AllAlerts')]
        [switch]$All,

        [Parameter(ParameterSetName = 'Filter')]
        [string]$Filter,

        [Int]$BatchSize = 1000,

        [Boolean]$BlockStdErr = $false,

        [String]$EventLogSource,

        [String]$LogPath
    )

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    #region Setup
    #region Initilize variables
    $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    $batchCount = 0 # Counter so we know how many times we have looped through the request.
    [boolean]$firstLoopDone = $false # Will change to true, once the function determines how many times it needs to loop, to retrieve all alerts.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $resourcePath = "/alert/alerts" # Define the resourcePath.
    $alerts = [System.Collections.Generic.List[PSObject]]::new() # Create a collection to hold the alerts.
    $filterList = [System.Collections.Generic.List[PSObject]]::new()
    $response = $null
    [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    If ($All) { $Cleared = 'All' } # Forcing $Cleared, for backwards compatibility.
    #endregion Initilize variables
    #endregion Setup

    $message = ("{0}: Operating in the {1} parameter set." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $PsCmdlet.ParameterSetName)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    Switch ($PsCmdlet.ParameterSetName) {
        'AllAlerts' {
            $message = ("{0}: Preparing to look for alerts between {1} and {2} (local time)." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), (Get-Date).AddYears(-5), (Get-Date))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $filterList.Add("startEpoch>:`"$(([DateTimeOffset](Get-Date).AddYears(-5)).ToUnixTimeSeconds())`"")
            $filterList.Add("endEpoch<:`"$(([DateTimeOffset](Get-Date)).ToUnixTimeSeconds())`"")

            Switch ($Cleared) {
                'All' {
                    $filterList.Add('cleared:"*"')
                }
                'Yes' {
                    $filterList.Add("cleared:true")
                }
                'No' {
                    $filterList.Remove($($filterList | Where-Object { $_ -match 'endEpoch.*' }))
                    $filterList.Add("cleared:`"`"")
                    $filterList.Add("startEpoch<:`"{0}`"" -f ([DateTimeOffset](Get-Date)).ToUnixTimeSeconds()) # Replacing endDate, because it will be 0 for open alerts
                }
            }
        }
        'FilterArray' {
            #region Validate hashtable keys
            $temp = [System.Collections.Generic.List[PSObject]]::new()
            Foreach ($item in $FilterArray) {
                $temp.Add($item)
            }

            Foreach ($filter in $FilterArray) {
                If ($filter.Name -notin @(
                        'id'
                        'type'
                        'acked'
                        'rule'
                        'chain'
                        'severity'
                        'cleared'
                        'sdted'
                        'monitorObjectName'
                        'monitorObjectGroups'
                        'resourceTemplateName'
                        'instanceName'
                        'dataPointName'
                        'startEpoch'
                        'endEpoch'
                    )) {

                    $message = ("{0}: Removing unsupported property from the filter: {1}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $filter.Name)
                    If ($loggingParams.Verbose) { If ($loggingParams.LogPath -or $loggingParams.EventSource) { Out-PsLogging @loggingParams -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                    $null = $temp.Remove($filter)
                }
            }

            $FilterArray = $temp
            #endregion Validate hashtable keys

            #region Build parsed list
            Foreach ($item in $FilterArray) {
                Switch ($item) {
                    { $_.name -eq 'startEpoch' } {
                        If ($_.value -as [datetime]) {
                            $filterList.Add("startEpoch$($_.comparison)`"$(([DateTimeOffset]$($_.value)).ToUnixTimeSeconds())`"")
                        } ElseIf ($_.value -as [int]) {
                            $filterList.Add("startEpoch$($_.comparison)`"$($_.value)`"")
                        } Else {
                            $message = ("{0}: The value of the startEpoch ({1}) is not a valid datetime object." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $_.value)
                            If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                            Return "Error"
                        }
                    }
                    { $_.name -eq 'endEpoch' } {
                        If ($_.value -as [datetime]) {
                            $filterList.Add("endEpoch$($_.comparison)`"$(([DateTimeOffset]$($_.value)).ToUnixTimeSeconds())`"")
                        } ElseIf ($_.value -as [int]) {
                            $filterList.Add("endEpoch$($_.comparison)`"$($_.value)`"")
                        } Else {
                            $message = ("{0}: The value of the endEpoch ({1}) is not a valid datetime object." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $_.value)
                            If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                            Return "Error"
                        }
                    }
                    { $_.name -notin @('startEpoch', 'endEpoch', 'cleared') } {
                        $filterList.Add("$($_.name)$($_.comparison)`"$($_.value)`"")
                    }
                }
            }

            Switch ($Cleared) {
                'All' {
                    $filterList.Add('cleared:"*"')
                }
                'Yes' {
                    $filterList.Add("cleared:true")
                }
                'No' {
                    $null = $filterList.Remove($($filterList | Where-Object { $_ -match 'endEpoch.*' }))
                    $filterList.Add("cleared:`"`"")
                    $filterList.Add("startEpoch<:`"{0}`"" -f ([DateTimeOffset](Get-Date)).ToUnixTimeSeconds())
                }
            }
            #endregion Build parsed list
        }
        'ManualStartEnd' {
            $message = ("{0}: Parsing start/end dates." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            If ($StartDate -and -NOT($EndDate)) {
                [decimal]$StartDate = ([DateTimeOffset]$StartDate).ToUnixTimeSeconds()
                $filter = "startEpoch>:`"$StartDate`""
            } ElseIf (-NOT($StartDate) -and $EndDate) {
                [decimal]$EndDate = ([DateTimeOffset]$EndDate).ToUnixTimeSeconds()
                $filter = "endEpoch<:`"$EndDate`""
            } ElseIf ($StartDate -and $EndDate) {
                [decimal]$StartDate = ([DateTimeOffset]$StartDate).ToUnixTimeSeconds()
                [decimal]$EndDate = ([DateTimeOffset]$EndDate).ToUnixTimeSeconds()
                $filter = "startEpoch>:`"$StartDate`",endEpoch<:`"$EndDate`""
            }

            If ($StartDate -or $EndDate) {
                $message = ("{0}: Start date: {1} and end date: {2}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $StartDate, $EndDate)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
            }
        }
    }

    #region Validate comparison operators
    If (($filterList) -and ($filterList -match ':<')) {
        $toReplace = $filterList -match ':<'
        $null = $filterList.Remove($toReplace)

        $filterList.Add($($toReplace -replace ':<', '<:'))

        $message = ("{0}: The filter contains an invalid comparison operator, `":<`". Replaced the invalid value with `"<:`"." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message -BlockStdErr $BlockStdErr }
    }
    #endregion Validate comparison operators

    $message = ("{0}: Initial filter: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $(If ($filterList) { ($filterList -join ',') } Else { (($Filter.TrimStart(',')) -replace "^filter=") }))
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    #region Set filter into encoded string
    If ($filterList) {
        $filterString = "$([System.Net.WebUtility]::UrlEncode($filterList -join ','))"
    } ElseIf ($Filter) {
        # If the filter includes cleared:false or cleared:"false", make sure to remove "endEpoch" and its value.
        $filterString = [System.Net.WebUtility]::UrlEncode($(If ($Filter -match '(cleared:"false"|cleared:false|cleared:"")') { ((($Filter -replace 'endEpoch', 'startEpoch') -replace ',,', ',') -replace '(cleared:["]false["]|cleared:false)', 'cleared:""').TrimEnd(',').TrimStart(',') -replace "^filter=" } Else { $Filter.TrimStart(',') -replace "^filter=" }))
    }

    $message = ("{0}: Encoded filter: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $filterString)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
    #endregion Set filter into encoded string

    #region Get alerts
    While (($response.Count -ge 1) -or ($firstLoopDone -eq $false)) {
        $message = ("{0}: The request loop has run {1} times." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $batchCount)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $queryParams = "?filter=$filterString&sort=startEpoch&offset=$offset&size=$BatchSize"

        # Construct the query URL.
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

        # Build header.
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
                "Authorization" = "LMv1 $AccessId`:$signature`:$epoch"
                "Content-Type"  = "application/json"
                "X-Version"     = 3
            }
        }

        # Make the API request.
        $message = ("{0}: Executing the REST query." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $stopLoop = $false
        Do {
            Try {
                $response = [System.Collections.Generic.List[PSObject]]@((Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop).items)

                $stopLoop = $True
            } Catch {
                If ($_.Exception.Message -match '429') {
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }

                    Start-Sleep -Seconds 60
                } Else {
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

        $alerts.AddRange($response)

        $message = ("{0}: Executed REST query. There are {1} entries in `$alerts." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $alerts.id.Count)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $offset += $BatchSize
        $firstLoopDone = $true
        $batchCount++
    }
    #endregion Get alerts

    #region Output
    $message = ("{0}: Returning {1} alerts." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), ($alerts | Measure-Object).Count)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    Return $alerts
    #endregion Output
} #V2022.11.03.2