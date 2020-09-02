# General
Windows PowerShell module for accessing the LogicMonitor REST API.

This project is also published in the PowerShell Gallery at https://www.powershellgallery.com/packages/LogicMonitor/.

# Installation
* From PowerShell Gallery: Install-Module -Name LogicMonitor
* From GitHub: Save `/bin/<version>/LogicMonitor/<files>` to your module directory

# Behavior changes
## 1.0.1.39
* New parameter set in Get-LogicMonitorDevice. Added -Filter parameter, which accepts a properly-formatted string. When included, the cmdlet returns devices matching the filter. For example, 'filter=systemProperties.value:"Microsoft Windows Server 2012 R2 Standard"' will return all devices with "Microsoft Windows Server 2012 R2 Standard" in the value field of systemProperties. Note that quotes around the value portion of the filter are required.
## 1.0.1.35
* As of 23 July 2020, LogicMonitor's JobMonitor uses wscript (via lmbatchjobwrapper.js) to monitor the status of Windows scheduled tasks. There is a known bug in wscript that causes wscript to hang, when a given amount of data is written to the stderr stream. The result of the hang, is that the schedule tasks stops processing, but remains "running" until the job is ended, at which time, the script resumes from the spot at which it hung. This version of the module adds the -BlockStdErr parameter to all cmdlets. The default value of the parameter is "$false", which represents normal operation. When -BlockStdErr is set to "$true", the module's Out-PsLogging command will not write to the stderr stream. Instead, Write-Host is used with red text. LogicMonitor has been made aware of the bug and the resulting impact on JobMonitors.

Discussion of the issue can be found at: https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk
## 1.0.1.29
* First version that does not include support for TLS 1.1 connections. The commands default to TLS 1.2.
## 1.0.1.18
* New behavior in logging.
** Instead of only logging to the Windows event log, the module now defaults to host only.
** The EventLogSource parameter is still available. If the provided source does not exist, the command will switch to host-only output.
** The new option is the LogPath parameter. Provide a path and file name (e.g. C:\Temp\log.txt) for logging. The module will attempt to create the log file, if it does not exist, and will switch to host-only output, if the file cannot be created (or the desired path is not writable).
## 1.0.1.17
* When Invoke-Request returns an error, all cmdlets return more data about the contents. Previously, the exception message was all that was returned.
* Added check for 429 respone to all cmdlets, to detect a rate-limiting situation and retry the request. Previously, only some of the cmdlets detected rate limiting.
## 1.0.1.12
* The cmdlets now require AccessKey to be a secure string.
## 1.0.1.10
* Add-LogicMonitorDeviceGroup no longer accepts properties as two separate parameters. Instead, the cmdlet requires a hash table of desired properties. Name and ParentId remain required.
* Add-LogicMonitorDevice no longer accepts properties as two separate parameters. Instead, the cmdlet requires a hash table of desired properties. Removed the HostGroupId requirement.