Function Out-PsLogging {
    <#
        .DESCRIPTION
            Logging function, for host, event log, or a log file.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 3 December 2019
                - Initial release.
            V1.0.0.1 date: 7 January 2020
            V1.0.0.2 date: 22 January 2020
            V1.0.0.3 date: 17 March 2020
            V1.0.0.4 date: 15 June 2020
            V1.0.0.5 date: 30 June 2020
            V1.0.0.6 date: 8 April 2021
            V1.0.0.7 date: 10 September 2021
            V1.0.0.8 date: 20 September 2021
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER EventLogSource
            Default parameter set. Represents the Windows Application log event source.
        .PARAMETER LogPath
            Path and file name of the target log file. If the file does not exist, the cmdlet will create it.
        .PARAMETER ScreenOnly
            When this switch parameter is included, the logging output is written only to the host.
        .PARAMETER Message
            Message to output.
        .PARAMETER MessageType
            Type of message to output. Valid values are "Info", "Warning", "Error", and "Verbose". When writing to a log file, all output is "info" but will be written to the host, with the appropriate message type.
        .PARAMETER BlockStdErr
            When set to $True, the cmdlet will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .EXAMPLE
            PS C:\> Out-PsLogging -Message "Test" -MessageType Info -LogPath C:\Temp\log.txt

            In this example, the message, "Test" will be written to the host and appended to C:\Temp\log.txt. If the path does not exist, or the user does not have write access, the message will only be written to the host.
        .EXAMPLE
            PS C:\> Out-PsLogging -Message "Test" -MessageType Warning -EventLogSource TestScript

            In this example, the message, "Test" will be written to the host and to the Windows Application log, as a warning and with the event log source/event ID "TestScript"/5417.
            If the event source does not exist and the session is elevated, the event source will be created.
            If the event source does not exist and the session is not elevated, the message will only be written to the host.
        .EXAMPLE
            PS C:\> Out-PsLogging -Message "Test" -MessageType Verbose -ScreenOnly

            In this example, the message, "Test" will be written to the host as a verbose message.
    #>
    [CmdletBinding(DefaultParameterSetName = 'SessionOnly')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'EventLog')]
        [string]$EventLogSource,

        [ValidateScript( {
                If (-NOT ($_ | Split-Path -Parent | Test-Path) ) {
                    Throw "Path does not exist."
                }
                If (-NOT ($_ | Test-Path) ) {
                    "" | Add-Content -Path $_
                }
                If (-NOT ($_ | Test-Path -PathType Leaf) ) {
                    Throw "The LogPath argument must be a file."
                }
                Return $true
            })]
        [Parameter(Mandatory, ParameterSetName = 'File')]
        [System.IO.FileInfo]$LogPath,

        [switch]$ScreenOnly,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter(Mandatory)]
        [ValidateSet('Info', 'Warning', 'Error', 'Verbose', 'First')]
        [string]$MessageType,

        [boolean]$BlockStdErr
    )

    # Initialize variables.
    $elevatedSession = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    If ($PsCmdlet.ParameterSetName -eq "EventLog") {
        If ([System.Diagnostics.EventLog]::SourceExists("$EventLogSource")) {
            # The event source does not exists, nothing else to do.

            $logType = "EventLog"
        }
        ElseIf (-NOT ([System.Diagnostics.EventLog]::SourceExists("$EventLogSource")) -and $elevatedSession) {
            # The event source does not exist, but the session is elevated, so create it.
            Try {
                New-EventLog -LogName Application -Source $EventLogSource -ErrorAction Stop

                $logType = "EventLog"
            }
            Catch {
                Write-Error ("[ERROR] {0}: Unable to create the event source ({1}). No logging will be done." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $EventLogSource)

                $logType = "SessionOnly"
            }
        }
        ElseIf (-NOT $elevatedSession) {
            # The event source does not exist, and the session is not elevated.
            Write-Error ("[ERROR] {0}: The event source ({1}) does not exist and the command was not run in an elevated session, unable to create the event source. No logging will be done." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $EventLogSource)

            $logType = "SessionOnly"
        }
    }
    ElseIf ($PsCmdlet.ParameterSetName -eq "File") {
        # Check if we have rights to the path in $LogPath.
        Try {
            [System.Io.File]::OpenWrite($LogPath).Close()
        }
        Catch {
            Write-Error ("[ERROR] {0}: Unable to write to the log file path ({1}). No logging will be done." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $LogPath)

            $logType = "SessionOnly"
        }

        $logType = "LogFile"
    }
    Else {
        $logType = "SessionOnly"
    }

    Switch ($logType) {
        "SessionOnly" {
            Switch ($MessageType) {
                "Info" { Write-Host "[INFO] $Message" }
                "Warning" { Write-Warning "[WARNING] $Message" }
                "Error" { If ($BlockStdErr) { Write-Host "[ERROR] $Message" -ForegroundColor Red } Else { Write-Error "[ERROR] $Message" } }
                "Verbose" { Write-Verbose "[VERBOSE] $Message" -Verbose }
                "First" { Write-Verbose "[INFO] $Message" -Verbose }
            }
        }
        "EventLog" {
            Switch ($MessageType) {
                "Info" { Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message "[INFO] $Message" -EventId 5417; Write-Host "[INFO] $Message" }
                "Warning" { Write-EventLog -LogName Application -Source $EventLogSource -EntryType Warning -Message "[WARNING] $Message" -EventId 5417; Write-Warning "[WARNING] $Message" }
                "Error" { Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message "[ERROR] $Message" -EventId 5417; If ($BlockStdErr) { Write-Host "[ERROR] $Message" -ForegroundColor Red } Else { Write-Error "[ERROR] $Message" } }
                "Verbose" { Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message "[VERBOSE] $Message" -EventId 5417; Write-Verbose "[VERBOSE] $Message" -Verbose }
                "First" { Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message "[INFO] $Message" -EventId 5417; Write-Verbose "[INFO] $Message" -Verbose }
            }
            If ($BlockStdErr) {

            }
        }
        "LogFile" {
            Switch ($MessageType) {
                "Info" { [System.IO.File]::AppendAllLines([string]$LogPath, [string[]]"[INFO] $Message", [Text.Encoding]::UTF8); Write-Host "[INFO] $Message" }
                "Warning" { [System.IO.File]::AppendAllLines([string]$LogPath, [string[]]"[WARNING] $Message", [Text.Encoding]::UTF8); Write-Warning "[WARNING] $Message" }
                "Error" { [System.IO.File]::AppendAllLines([string]$LogPath, [string[]]"[ERROR] $Message", [Text.Encoding]::UTF8); If ($BlockStdErr) { Write-Host "[ERROR] $Message" -ForegroundColor Red } Else { Write-Error "[ERROR] $Message" } }
                "Verbose" { [System.IO.File]::AppendAllLines([string]$LogPath, [string[]]"[VERBOSE] $Message", [Text.Encoding]::UTF8); Write-Verbose "[VERBOSE] $Message" -Verbose }
                "First" { [System.IO.File]::WriteAllLines($LogPath, "[INFO] $Message", [Text.Encoding]::UTF8); Write-Verbose "[INFO] $Message" -Verbose }
            }
        }
    }
} #1.0.0.8