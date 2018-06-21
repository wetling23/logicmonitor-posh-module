Function Get-LogicMonitorServices {
<#
.DESCRIPTION 
    Returns a list of LogicMonitor services and all of their properties. By default, the function returns all services. 
    If a service ID, or name is provided, the function will return properties for the specified service.
.NOTES 
    Author: Mike Hashemi
    V1.0.0.0 date: 30 January 2017
    V1.0.0.1 date: 31 January 2017
        - Removed custom-object creation.
    V1.0.0.2 date: 31 January 2017
        - Updated error output color.
        - Streamlined header creation (slightly).
    V1.0.0.3 date 31 January 2017
        - Added $logPath output to host.
    V1.0.0.4 date 31 January 2017
        - Added additional logging.
    V1.0.0.5 date: 10 February 2017
        - Updated procedure order.
    V1.0.0.6 date: 3 May 2017
        - Removed code from writing to file and added Event Log support.
        - Updated code for verbose logging.
        - Changed Add-EventLogSource failure behavior to just block logging (instead of quitting the function).
    V1.0.0.7 date: 21 June 2017
		- Updated logging to reduce chatter.
    V1.0.0.8 date: 23 April 2018
        - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
        - Replaced ! with -NOT.
.LINK
    
.PARAMETER AccessId
    Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.    
.PARAMETER AccessKey
    Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
.PARAMETER AccountName
    Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
.PARAMETER ServiceID
    Represents the ID of the desired service.
.PARAMETER ServiceName
    Represents the name of the desired service.
.PARAMETER BatchSize
	Default value is 300. Represents the number of devices to request in each batch.
.PARAMETER EventLogSource
    Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
.PARAMETER BlockLogging
    When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
.EXAMPLE
    PS C:\> Get-LogicMonitorServices -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName>

    In this example, the function will search for all services and will return their properties.
.EXAMPLE
    PS C:\> Get-LogicMonitorDeviceGroups -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -ServiceID 6

    In this example, the function will search for the service with "6" in the ID property and will return its properties.
.EXAMPLE
    PS C:\> Get-LogicMonitorDeviceGroups -AccessId <accessId> -AccessKey <accessKey> -AccountName <accountName> -ServiceName webMonitor1

    In this example, the function will search for the service with "webMonitor1" in the name property and will return its properties.
#>
[CmdletBinding(DefaultParameterSetName=’AllServices’)]
    Param (
        [Parameter(Mandatory=$True)]
		[Parameter(ParameterSetName=’AllServices’)]
		[Parameter(ParameterSetName=’IDFilter’)]
		[Parameter(ParameterSetName=’NameFilter’)]
        $AccessId,

        [Parameter(Mandatory=$True)]
		[Parameter(ParameterSetName=’AllServices’)]
		[Parameter(ParameterSetName=’IDFilter’)]
		[Parameter(ParameterSetName=’NameFilter’)]
        $AccessKey,

		[Parameter(Mandatory=$True)]
		[Parameter(ParameterSetName=’AllServices’)]
		[Parameter(ParameterSetName=’IDFilter’)]
		[Parameter(ParameterSetName=’NameFilter’)]
        $AccountName,

        [Parameter(Mandatory=$True,ParameterSetName=’IDFilter’)]
        [int]$ServiceID,

        [Parameter(Mandatory=$True,ParameterSetName=’NameFilter’)]
        [string]$ServiceName,

		[int]$BatchSize = 300,

        [string]$EventLogSource = 'LogicMonitorPowershellModule',

        [switch]$BlockLogging
    )

    If (-NOT($BlockLogging)) {
        $return = Add-EventLogSource -EventLogSource $EventLogSource
    
        If ($return -ne "Success") {
            $message = ("{0}: Unable to add event source ({1}). No logging will be performed." -f (Get-Date -Format s), $EventLogSource)
            Write-Host $message -ForegroundColor Yellow;

            $BlockLogging = $True
        }
    }

    $message = ("{0}: Beginning {1}." -f (Get-Date -Format s), $MyInvocation.MyCommand)
    If ($BlockLogging) {Write-Host $message -ForegroundColor White} Else {Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

	$message = ("{0}: Operating in the {1} parameter set." -f (Get-Date -Format s), $PsCmdlet.ParameterSetName)
    If ($BlockLogging) {Write-Host $message -ForegroundColor White} Else {Write-Host $message -ForegroundColor White; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

    # Initialize variables.
    $currentBatchNum = 0 # Start at zero and increment in the while loop, so we know how many times we have looped.
    $offset = 0 # Define how many agents from zero, to start the query. Initial is zero, then it gets incremented later.
    $serviceBatchCount = 1 # Define how many times we need to loop, to get all services.
    $firstLoopDone = $false # Will change to true, once the function determines how many times it needs to loop, to retrieve all services.
    $httpVerb = "GET" # Define what HTTP operation will the script run.
    $props = @{} # Initialize hash table for custom object (created later).
	$resourcePath = "/service/services"
	$queryParams = $null
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
	
    $message = ("{0}: Retrieving service properties. The resource path is: {1}." -f (Get-Date -Format s), $resourcePath)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

    # Update $resourcePath to filter for a specific service, when a service ID is provided by the user.
    If ($PsCmdlet.ParameterSetName -eq "IDFilter") {
   		$resourcePath += "/$ServiceID"

		$message = ("{0}: A collector ID was provided. Updated resource path to {1}." -f (Get-Date -Format s), $resourcePath)
		If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
	}

    # Determine how many times "GET" must be run, to return all services, then loop through "GET" that many times.
    While ($currentBatchNum -lt $serviceBatchCount) { 
		Switch ($PsCmdlet.ParameterSetName) {
			{$_ -in ("IDFilter", "AllServices")} {
				$queryParams ="?offset=$offset&size=$BatchSize&sort=id"

				$message = ("{0}: Updating `$queryParams variable in {1}. The value is {2}." -f (Get-Date -Format s), $($PsCmdlet.ParameterSetName), $queryParams)
				If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
			}
			"NameFilter" {				
				$queryParams = "?filter=name:$ServiceName&offset=$offset&size=$BatchSize&sort=id"

				$message = ("{0}: Updating `$queryParams variable in {1}. The value is {2}." -f (Get-Date -Format s), $($PsCmdlet.ParameterSetName), $queryParams)
				If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
			}
		}

        # Construct the query URL.
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

        If ($firstLoopDone -eq $false) {
			$message = ("{0}: Building request header." -f (Get-Date -Format s))
			If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

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
			$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
			$headers.Add("Authorization","LMv1 $accessId`:$signature`:$epoch")
			$headers.Add("Content-Type",'application/json')
		}

        # Make Request
        $message = ("{0}: Executing the REST query." -f (Get-Date -Format s))
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

        Try {
            $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -ErrorAction Stop
        }
        Catch {
            $message = ("{0}: It appears that the web request failed. Check your credentials and try again. To prevent errors, the Get-LogicMonitorServices function will exit. The specific error message is: {1}" `
                -f (Get-Date -Format s), $_.Message.Exception)
            If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417}
        
            Return
        }

		Switch ($PsCmdlet.ParameterSetName) {
			"AllServices" {
				$message = ("{0}: Entering switch statement for all-service retrieval." -f (Get-Date -Format s))
				If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

				# If no service ID, or name is provided...
				$services += $response.data.items

				$message = ("{0}: There are {1} services in `$services. LogicMonitor reports a total of {2} services." -f (Get-Date -Format s), $($services.count), $($response.data.count))
				If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

				# The first time through the loop, figure out how many times we need to loop (to get all services).
				If ($firstLoopDone -eq $false) {
					[int]$serviceBatchCount = ((($response.data.total)/$BatchSize) + 1)
					
					$message = ("{0}: The function will query LogicMonitor {1} times to retrieve all services." -f (Get-Date -Format s), ($serviceBatchCount-1))
					If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

					$firstLoopDone = $true

					$message = ("{0}: Completed the first loop." -f (Get-Date -Format s))
					If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
				}

				# Increment offset, to grab the next batch of services.
				$offset += $BatchSize

				$message = ("{0}: Retrieving data in batch #{1} (of {2})." -f (Get-Date -Format s), $currentBatchNum, ($serviceBatchCount-1))
				If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

				# Increment the variable, so we know when we have retrieved all services.
				$currentBatchNum++
			}
			# If a service ID, or name is provided...
			{$_ -in ("IDFilter", "NameFilter")} {
				$message = ("{0}: Entering switch statement for single-service retrieval." -f (Get-Date -Format s))
				If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
                
                If ($PsCmdlet.ParameterSetName -eq "IDFilter") {
					$services = $response.data
				}
			    Else {
				    $services = $response.data.items
			    }

                If ($services.count -eq 0) {
				    $message = ("{0}: There was an error retrieving the service. LogicMonitor reported that zero services were retrieved." -f (Get-Date -Format s))
				    If ($BlockLogging) {Write-Host $message -ForegroundColor Red} Else {Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417}

                    Return "Error"
                }
				Else {
				    $message = ("{0}: There are {1} services in `$services." -f (Get-Date -Format s), $($services.count))
				    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
                }

				# The first time through the loop, figure out how many times we need to loop (to get all services).
				If ($firstLoopDone -eq $false) {
					[int]$serviceBatchCount = ((($response.data.total)/$BatchSize) + 1)
					
					$message = ("{0}: The function will query LogicMonitor {1} times to retrieve all services." -f (Get-Date -Format s), ($serviceBatchCount-1))
					If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}

					$firstLoopDone = $True

					$message = ("{0}: Completed the first loop." -f (Get-Date -Format s))
					If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
				}

				$message = ("{0}: Retrieving data in batch #{1} (of {2})." -f (Get-Date -Format s), $currentBatchNum, ($serviceBatchCount-1))
				If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) {Write-Verbose $message} ElseIf ($PSBoundParameters['Verbose']) {Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417}
			}
		}

        Return $services
	}
} #1.0.0.8