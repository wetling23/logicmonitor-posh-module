Function Add-EventLogSource {
    <#
        .DESCRIPTION
            Adds an Event Log source, for script/module logging. Adding an Event Log source requires administrative rights.
        .NOTES 
            Author: Mike Hashemi
            V1.0.0.0 date: 19 April 2017
                - Initial release.
            V1.0.0.1 date: 1 May 2017
                - Minor updates to status handling.
            V1.0.0.2 date: 4 May 2017
                - Added additional return value.
            V1.0.0.3 date: 22 May 2017
                - Changed output to reduce the number of "Write-Host" messages.
            V1.0.0.4 date: 21 June 2017
                - Fixed typo.
                - Significantly improved performance.
                - Changed logging.
            V1.0.0.5 date: 21 June 2017
                - Added a return value if the event log source exists.
            V1.0.0.6 date: 28 June 2017
                - Added [CmdletBinding()].
            V1.0.0.7 date: 28 June 2017
                - Added a check for the source, then a check on the status of the query.
            V1.0.0.8 date: 13 March 2018
                - Updated whitespace.
                - Updated output to only output status on 'verbose'.
            V1.0.0.9 date: 23 August 2019
        .PARAMETER EventLogSource
            Mandatory parameter. This parameter is used to specify the event source, that script/modules will use for logging.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        $EventLogSource
    )

    $message = ("{0}: Beginning {1}." -f [datetime]::Now, $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose']) { Write-Verbose $message }

    # Check if $EventLogSource exists as a source. If the shell is not elevated and the check fails to access the Security log, assume the source does not exist.
    Try {
        $sourceExists = [System.Diagnostics.EventLog]::SourceExists("$EventLogSource")
    }
    Catch {
        $sourceExists = $False
    }

    If ($sourceExists -eq $False) {
        $message = ("{0}: The event source `"{1}`" does not exist. Prompting for elevation." -f [datetime]::Now, $EventLogSource)
        Write-Host $message -ForegroundColor White

        Try {
            Start-Process PowerShell -Verb RunAs -ArgumentList "New-EventLog -LogName Application -Source $EventLogSource -ErrorAction Stop"
        }
        Catch [System.InvalidOperationException] {
            $message = ("{0}: It appears that the user cancelled the operation." -f [datetime]::Now)
            Write-Host $message -ForegroundColor Yellow
            Return "Error"
        }
        Catch {
            $message = ("{0}: Unexpected error launching an elevated Powershell session. The specific error is: {1}" -f [datetime]::Now, $_.Exception.Message)
            Write-Host $message -ForegroundColor Red
            Return "Error"
        }

        Return "Success"
    }
    Else {
        $message = ("{0}: The event source `"{1}`" already exists. There is no action for {2} to take." -f [datetime]::Now, $EventLogSource, $MyInvocation.MyCommand)
        Write-Verbose $message

        Return "Success"
    }
} #1.0.0.9