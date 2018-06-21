#This function is not in the module, because as is, it only returns up to 10000 alerts (tested 3 May 2017). If LM ever allows me to get all alerts, I will add it to the module.
Function Get-LogicMonitorAlerts {
    <#
.DESCRIPTION 
    Retrieves Alert objects from LogicMonitor.
.NOTES 
    Author: Mike Hashemi
    V1.0.0.0 date: 16 January 2017
        - Initial release.
    V1.0.0.2 date: 10 February 2017
        - Updated procedure order.
    V1.0.0.3 date: 23 April 2018
        - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
        - Updated logging setup.
.LINK
.PARAMETER AccessId
    Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.    
.PARAMETER AccessKey
    Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
.PARAMETER AccountName
    Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
.PARAMETER BatchSize
    Default value is 250. Represents the number of alerts to request from LogicMonitor.
.PARAMETER WriteLog
    Switch parameter. When included (and a log path is defined), the script will send output to a log file and to the screen.
.PARAMETER LogPath
    Path where the function should store its log. When omitted, output will be sent to the shell.
.EXAMPLE
    PS C:\> Get-LogicMonitorAlerts -AccessID <access ID> -AccessKey <access key> -AccountName <account name>

    In this example, the function gets all active alerts, in batches of 250.
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        $AccessId,

        [Parameter(Mandatory = $True)]
        $AccessKey,

        [Parameter(Mandatory = $True)]
        $AccountName,

        [int]$BatchSize = 250,

        [switch]$WriteLog,

        [string]$LogPath
    )

    If (-NOT($BlockLogging)) {
        $return = Add-EventLogSource -EventLogSource $EventLogSource
    
        If ($return -ne "Success") {
            $message = ("{0}: Unable to add event source ({1}). No logging will be performed." -f (Get-Date -Format s), $EventLogSource)
            Write-Host $message -ForegroundColor Yellow;

            $BlockLogging = $True
        }
    }

    $message = Write-Output ("{0}: Beginning {1}" -f (Get-Date -Format s), $MyInvocation.MyCommand)
    If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}

    # Initialize variables.
    $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    $batchCount = 0 # Counter so we know how many times we have looped through the request
    $loopDone = $false # Switch for knowing when to stop requesting alerts. Will change to $true once $response.data.items.count is a positive number.
    $firstLoopDone = $false # Will change to true, once the function determines how many times it needs to loop, to retrieve all alerts.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $props = @{} # Initialize hash table for custom object (created later).
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols    
        
    # Define the resourcePath.
    $resourcePath = "/alert/alerts"

    # Determine how many times "GET" must be run, to return all alerts, then loop through "GET" that many times.
    While ($loopDone -ne $true) {
        $message = Write-Output ("{0}: The request loop has run {1} times." -f (Get-Date -Format s), $batchCount)
        If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}

        $queryParams = "?offset=$offset&size=$BatchSize&sort=id"
        
        # Construct the query URL.
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

        # Build header.
        If ($firstLoopDone -eq $false) {
            $message = Write-Output ("{0}: Building request header." -f (Get-Date -Format s))
            If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}

            # Get current time in milliseconds
            $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)
        
            # Concatenate Request Details
            $requestVars = $httpVerb + $epoch + $resourcePath

            # Construct Signature
            $hmac = New-Object System.Security.Cryptography.HMACSHA256
            $hmac.Key = [Text.Encoding]::UTF8.GetBytes($accessKey)
            $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
            $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
            $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

            # Construct Headers
            $auth = 'LMv1 ' + $accessId + ':' + $signature + ':' + $epoch
            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("Authorization", $auth)
            $headers.Add("Content-Type", 'application/json')
        }
        
        # Make Request
        $message = Write-Output ("{0}: Executing the REST query." -f (Get-Date -Format s))
        If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}

        Try {
            $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop
        }
        Catch {
            $message = Write-Output ("{0}: It appears that the web request failed. Check your credentials and try again. To prevent errors, the Get-LogicMonitorAlerts function`
                will exit. The specific error message is: {1}" -f (Get-Date -Format s), $_.Message.Exception)
            If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
        
            Return
        }

        $alerts += $response.data.items

        # The first time through the loop, figure out how many times we need to loop (to get all alerts).
        If ($firstLoopDone -eq $false) {
            # Get and sort the list of all possible device properties.
            $outputProperties = $response.data.items | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty name
            $outputProperties += $response.data.items.monitorObjectGroups | Select-Object -ExpandProperty name | Sort-Object | Get-Unique
            $outputProperties = $outputProperties | Sort-Object

            $message = Write-Verbose ("{0}: Output properties: {1}" -f (Get-Date -Format s), $outputProperties.name)
            If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}

            $firstLoopDone = $true
        }

        If ($response.data.items.Count -eq $BatchSize) {
            # The response was full of alerts (up to the number in $BatchSize), so there are probably more. Increment offset, to grab the next batch of alerts.
            $message = Write-Output ("{0}: There are more alerts to retrieve. Incrementing offset by {1}." -f (Get-Date -Format s), $BatchSize)
            If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
            
            $message = Write-Verbose ("{0}: The value of `$response.data.items.count is {1}." -f (Get-Date -Format s), $($response.data.items.Count))
            If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}

            $offset += $BatchSize
            $batchCount++
        }
        Else {
            # The number of returned alerts was less than the $BatchSize so we must have run out alerts to retrieve.
            $message = Write-Output ("{0}: There are no more alerts to retrieve." -f (Get-Date -Format s))
            If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}
			
            $message = Write-Verbose ("{0}: The value of `$response.data.items.count is {1}." -f (Get-Date -Format s), $($response.data.items.Count))
            If ($WriteLog -and ($logPath -ne $null)) {Write-Host $message; $message | Out-File -FilePath $logPath -Append} Else {Write-Host $message}

            $loopDone = $true
        }
    }

    # Assign the value of all properties (including custom properties) to a custom PowerhShell object, which the function will return to the pipeline.
    Foreach ($alert in $alerts) {
        Foreach ($property in $outputProperties) {
            $props.$property = $alert.$property
        }
        New-Object PSObject -Property $props
    }
}
#1.0.0.3