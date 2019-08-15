Function Add-LogicMonitorDeviceGroup {
    <#
        .DESCRIPTION
            Create a new LogicMonitor device group.
        .NOTES
            Author: Mike Hashemi
            V1 date: 2 February 2017
                - Initial release.
            V1.0.0.3 date: 10 February 2017
                - Updated procedure order.
            V1.0.0.4 date: 3 May 2017
                - Removed code from writing to file and added Event Log support.
                - Updated code for verbose logging.
                - Changed Add-EventLogSource failure behavior to just block logging (instead of quitting the function).
            V1.0.0.5 date: 21 June 2017
                - Updated logging to reduce chatter.
            V1.0.0.6 date: 23 April 2018
                - Updated code to allow PowerShell to use TLS 1.1 and 1.2.
                - Replaced ! with -NOT.
            V1.0.0.7 date: 21 June 2018
                - Updated white space.
            V1.0.1.0 date: 14 August 2019
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
        .PARAMETER EventLogSource
            Default value is "LogicMonitorPowershellModule" Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> $table = @{name = 'group1'; parentId = 1}
            PS C:\> Add-LogicMonitorDeviceGroup -AccessId <access Id> -AccessKey <access key> -AccountName <account name> -Properties $table

            In this example, the function will create a new DeviceGroup with the following properties:
                - Name: group1
                - Group ID of the parent: 1
        .EXAMPLE
            PS C:\> $table = @{
                        name = 'group1'
                        parentId = 1
                        appliesTo = 'isLinux()'
                        customProperties = @(
                            @{
                                name = 'testProperty'
                                value = 'someValue'
                            }
                        )
                    }
            PS C:\> Add-LogicMonitorDeviceGroup -AccessId <access Id> -AccessKey <access key> -AccountName <account name> -Properties $table

            In this example, the function will create a new DeviceGroup with the following properties:
                - Name: group1
                - Group ID of the parent: 1
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        $AccessId,
        
        [Parameter(Mandatory = $True)]
        $AccessKey,

        [Parameter(Mandatory = $True)]
        $AccountName,

        [Parameter(Mandatory = $True)]
        [hashtable]$Properties,

        [string]$EventLogSource = 'LogicMonitorPowershellModule',

        [switch]$BlockLogging
    )

    If (-NOT($BlockLogging)) {
        $return = Add-EventLogSource -EventLogSource $EventLogSource

        If ($return -ne "Success") {
            $message = ("{0}: Unable to add event source ({1}). No logging will be performed." -f (Get-Date -Format s), $EventLogSource)
            Write-Host $message

            $BlockLogging = $True
        }
    }

    $message = ("{0}: Beginning {1}." -f (Get-Date -Format s), $MyInvocation.MyCommand)
    If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

    # Initialize variables.
    $httpVerb = "POST" # Define what HTTP operation will the script run.
    $resourcePath = "/device/groups"
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    # Checking for the required properties
    If (-NOT($Properties.ContainsKey('name'))) {
        $message = ("{0}: No group name provided. Please update the provided properties and re-submit the request.")
        If ($BlockLogging) { Write-Error $message } Else { Write-Error $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $message -EventId 5417 }

        Return "Error"
    }
    If (-NOT($Properties.ContainsKey('parentId'))) {
        $message = ("{0}: No parent DeviceGroup ID provided. Please update the provided properties and re-submit the request.")
        If ($BlockLogging) { Write-Error $message } Else { Write-Error $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $message -EventId 5417 }

        Return "Error"
    }
    If ($Properties.ContainsKey('customProperties') -and (-NOT($Properties.customProperties.ContainsKey('name')))) {
        $message = ("{0}: Custom properties were supplied, but no name key was provided. Please update the provided properties and re-submit the request.")
        If ($BlockLogging) { Write-Error $message } Else { Write-Error $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $message -EventId 5417 }

        Return "Error"
    }

    $data = ($Properties | ConvertTo-Json)

    # Construct the query URL.
    $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath"

    # Get current time in milliseconds
    $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

    # Concatenate Request Details
    $requestVars = $httpVerb + $epoch + $data + $resourcePath

    # Construct Signature
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($accessKey)
    $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
    $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
    $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

    # Construct Headers
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "LMv1 $accessId`:$signature`:$epoch")
    $headers.Add("Content-Type", 'application/json')
    $headers.Add("X-Version", 2)

    # Make Request
    $message = ("{0}: Executing the REST query ({1})." -f (Get-Date -Format s), $url)
    If (($BlockLogging) -AND (($PSBoundParameters['Verbose']) -or $VerbosePreference -eq 'Continue')) { Write-Verbose $message } ElseIf (($PSBoundParameters['Verbose']) -or ($VerbosePreference -eq 'Continue')) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

    Try {
        $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers -Body $data -ErrorAction Stop
    }
    Catch {
        If ($_.ErrorDetails.message | ConvertFrom-Json | Select-Object -ExpandProperty errorMessage -ErrorAction SilentlyContinue) {
            $message = ("{0}: The request failed and the error message is: `"{1}`". The error code is: {2}." -f (Get-Date -Format s), ($_.ErrorDetails.message | ConvertFrom-Json | Select-Object -ExpandProperty errorMessage -ErrorAction SilentlyContinue), ($_.ErrorDetails.message | ConvertFrom-Json | Select-Object -ExpandProperty errorCode -ErrorAction SilentlyContinue))
            If ($BlockLogging) { Write-Error $message } Else { Write-Error $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $message -EventId 5417 }
        }
        Else {
            $message = ("{0}: Unexpected error adding DeviceGroup called `"{1}`". The specific error is: {2}" -f (Get-Date -Format s), $Properties.Name, $_.Exception.Message)
            If ($BlockLogging) { Write-Error $message } Else { Write-Error $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $message -EventId 5417 }
        }

        Return "Error"
    }

    $response
}
#1.0.1.0