Function Remove-LogicMonitorSdt {
    <#
        .DESCRIPTION
            Accepts a LogicMonitor SDT ID and removes the SDT entry.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 4 April 2019
                - Initial release.
            V1.0.0.1 date: 23 August 2019
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER AccessId
            Mandatory parameter. Represents the access ID used to connected to LogicMonitor's REST API.
        .PARAMETER AccessKey
            Mandatory parameter. Represents the access key used to connected to LogicMonitor's REST API.
        .PARAMETER AccountName
            Mandatory parameter. Represents the subdomain of the LogicMonitor customer.
        .PARAMETER Id
            Represents the ID of a specific SDT entry. Accepts pipeline input.
        .PARAMETER EventLogSource
            Default value is "LogicMonitorPowershellModule". Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> Remove-LogicMonitorSdt -AccessId $accessID -AccessKey $accessKey -AccountName <account name> -Id A_8

            This example shows how to remove the SDT entry with ID "A_8".
        .EXAMPLE
            PS C:\> Get-LogicMonitorDeviceSdt -AccessId $accessID -AccessKey $accessKey -AccountName <account name> | Where-Object {$_.comment -match "testing"} | Remove-LogicMonitorSdt -AccessId $accessID -AccessKey $accessKey -AccountName <account name>
        .EXAMPLE
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [string]$AccessId,

        [Parameter(Mandatory = $True)]
        [string]$AccessKey,

        [Parameter(Mandatory = $True)]
        [string]$AccountName,

        [Parameter(Mandatory = $True, ParameterSetName = "Id", ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias("SdtId")]
        [string]$Id,

        [string]$EventLogSource = 'LogicMonitorPowershellModule',

        [switch]$BlockLogging
    )

    Begin {
    }
    Process {
        # Initialize variables.
        $httpVerb = "DELETE" # Define what HTTP operation will the script run.
        $resourcePath = "/sdt/sdts" # Define the resourcePath, based on what you're searching for.
        $queryParams = $null
        [boolean]$stopLoop = $false # Ensures we run Invoke-RestMethod at least once.
        $AllProtocols = [System.Net.SecurityProtocolType]'Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

        If (-NOT($BlockLogging)) {
            $return = Add-EventLogSource -EventLogSource $EventLogSource

            If ($return -ne "Success") {
                $message = ("{0}: Unable to add event source ({1}). No logging will be performed." -f [datetime]::Now, $EventLogSource)
                Write-Verbose $message

                $BlockLogging = $True
            }
        }

        $message = ("{0}: Beginning {1}." -f [datetime]::Now, $MyInvocation.MyCommand)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

        $resourcePath += "/$Id"

        $message = ("{0}: Updated resource path to {1}." -f [datetime]::Now, $resourcePath)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

        # Construct the query URL.
        $url = "https://$AccountName.logicmonitor.com/santaba/rest$resourcePath$queryParams"

        $message = ("{0}: Building request header." -f [datetime]::Now)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

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
        $headers.Add("Authorization", "LMv1 $accessId`:$signature`:$epoch")
        $headers.Add("Content-Type", 'application/json')
        $headers.Add("X-Version", 2)

        # Make Request
        $message = ("{0}: Executing the REST query." -f [datetime]::Now)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Information -Message $message -EventId 5417 }

        Do {
            Try {
                $response = Invoke-RestMethod -Uri $url -Method $httpverb -Header $headers -ErrorAction Stop

                $stopLoop = $True
            }
            Catch {
                If ($_.Exception.Message -match '429') {
                    $message = ("{0}: Rate limit exceeded, retrying in 60 seconds." -f [datetime]::Now, $MyInvocation.MyCommand, $_.Exception.Message)
                    If ($BlockLogging) { Write-Host $message -ForegroundColor Yellow } Else { Write-Host $message -ForegroundColor Yellow; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Warning -Message $message -EventId 5417 }

                    Start-Sleep -Seconds 60
                }
                Else {
                    $message = ("{0}: Unexpected error getting SDTs. To prevent errors, {1} will exit. PowerShell returned: {2}" -f [datetime]::Now, $MyInvocation.MyCommand, $_.Exception.Message)
                    If ($BlockLogging) { Write-Host $message -ForegroundColor Red } Else { Write-Host $message -ForegroundColor Red; Write-EventLog -LogName Application -Source $eventLogSource -EntryType Error -Message $message -EventId 5417 }

                    Return "Error"
                }
            }
        }
        While ($stopLoop -eq $false)

        Return $response
    }
} #1.0.0.1