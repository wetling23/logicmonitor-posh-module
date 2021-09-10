# General
Windows PowerShell module for accessing the LogicMonitor REST API.

This project is also published in the PowerShell Gallery at https://www.powershellgallery.com/packages/LogicMonitor/.

# Installation
- From PowerShell Gallery: Install-Module -Name LogicMonitor
- From GitHub: Save `/bin/<version>/LogicMonitor/<files>` to your module directory

# Behavior changes
## 1.0.1.79
- Out-PsLogging
  - Prepending [INFO], [WARNING], [ERROR], [VERBOSE] blocks before each message.
## 1.0.1.61
- Get-LogicMonitorConfigSourceData
  - Instead of returning just the config content, the cmdlet now returns all of the instance properties.
- Add-LogicMonitorDashboardWidget
  - The error message no longer returns the entire body. In my testing, the body was really long and it was annoying to scroll back up to the beginning of the error message.
## 1.0.1.54
- Get-LogicMonitorAuditLog
  - Added support for a string filter. The -StartDate and -EndDate parameters were moved to their own parameter set.
## 1.0.1.48
- Get-LogicMonitorDevice
  - Changed the output so that all parameter discard properties from LogicMontior (e.g. total) and just return the "item(s)".
## 1.0.1.43
- Get-LogicMonitorAlert
  - Added free-form filters (formatted as a hash table). If a key is provided, that is not supported by the API, it will be removed.
  - Added StartDate and EndDate parameters. If neither is provided, the time range defaults to the previous five years. If only the start date is provided, the end date defaults to the current day. If only the end date is provided, the start date defaults to the previous day (-1).
  - The "-All" parameter is deprecated and may be removed at a future date. Omitting -All and -StartDate/-EndDate will achieve the same results because LogicMonitor does not keep five years of alert data.
- Get-LogicMonitorSdt
- Added free-form filters (formatted as a hash table) to the Get-LogicMonitorAlert and Get-LogicMonitorSdt cmdlets.
- The "-AdminName", "-SdtType", and "-IsEffective" parameters are deprecated and may be removed at a future date. In place of these parameters, use -Filter (e.g. "-Filter @{iseffective = "True"; sdtType = "DeviceSDT"; admin = "user@domain.com"}").
## 1.0.1.39
- New parameter set in Get-LogicMonitorDevice. Added -Filter parameter, which accepts a properly-formatted string. When included, the cmdlet returns devices matching the filter. For example, 'filter=systemProperties.value:"Microsoft Windows Server 2012 R2 Standard"' will return all devices with "Microsoft Windows Server 2012 R2 Standard" in the value field of systemProperties. Note that quotes around the value portion of the filter are required.
## 1.0.1.35
- As of 23 July 2020, LogicMonitor's JobMonitor uses wscript (via lmbatchjobwrapper.js) to monitor the status of Windows scheduled tasks. There is a known bug in wscript that causes wscript to hang, when a given amount of data is written to the stderr stream. The result of the hang, is that the schedule tasks stops processing, but remains "running" until the job is ended, at which time, the script resumes from the spot at which it hung. This version of the module adds the -BlockStdErr parameter to all cmdlets. The default value of the parameter is "$false", which represents normal operation. When -BlockStdErr is set to "$true", the module's Out-PsLogging command will not write to the stderr stream. Instead, Write-Host is used with red text. LogicMonitor has been made aware of the bug and the resulting impact on JobMonitors.

Discussion of the issue can be found at: https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk
## 1.0.1.29
- First version that does not include support for TLS 1.1 connections. The commands default to TLS 1.2.
## 1.0.1.18
- New behavior in logging.
  - Instead of only logging to the Windows event log, the module now defaults to host only.
  - The EventLogSource parameter is still available. If the provided source does not exist, the command will switch to host-only output.
  - The new option is the LogPath parameter. Provide a path and file name (e.g. C:\Temp\log.txt) for logging. The module will attempt to create the log file, if it does not exist, and will switch to host-only output, if the file cannot be created (or the desired path is not writable).
## 1.0.1.17
- When Invoke-Request returns an error, all cmdlets return more data about the contents. Previously, the exception message was all that was returned.
- Added check for 429 respone to all cmdlets, to detect a rate-limiting situation and retry the request. Previously, only some of the cmdlets detected rate limiting.
## 1.0.1.12
- The cmdlets now require AccessKey to be a secure string.
## 1.0.1.10
- Add-LogicMonitorDeviceGroup no longer accepts properties as two separate parameters. Instead, the cmdlet requires a hash table of desired properties. Name and ParentId remain required.
- Add-LogicMonitorDevice no longer accepts properties as two separate parameters. Instead, the cmdlet requires a hash table of desired properties. Removed the HostGroupId requirement.