#
# Module manifest for module 'LogicMonitor'
#
# Generated by: Mike Hashemi
#
# Generated on: 1/6/2023
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'LogicMonitor.psm1'

# Version number of this module.
ModuleVersion = '2023.09.25.0'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '6ef13f0b-48da-4c3b-81b2-03fa464ef8fd'

# Author of this module
Author = 'Mike Hashemi'

# Company or vendor of this module
CompanyName = ''

# Copyright statement for this module
Copyright = '(c) 2023 mhashemi. All rights reserved.'

# Description of the functionality provided by this module
Description = 'LogicMonitor REST API-related functions.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = 'Add-EventLogSource',
                'Disable-LogicMonitorLogicModuleInstance',
                'Enable-LogicMonitorLogicModuleInstance',
                'Get-LogicMonitorAlert', 'Get-LogicMonitorAlertRule',
                'Get-LogicMonitorAuditLog', 'Get-LogicMonitorCollector',
                'Get-LogicMonitorCollectorAvailableVersion',
                'Get-LogicMonitorCollectorGroup',
                'Get-LogicMonitorCollectorInstaller',
                'Get-LogicMonitorCollectorUpgradeHistory',
                'Get-LogicMonitorConfigSource', 'Get-LogicMonitorConfigSourceData',
                'Get-LogicMonitorDashboard', 'Get-LogicMonitorDashboardGroup',
                'Get-LogicMonitorDashboardWidget', 'Get-LogicMonitorDataSource',
                'Get-LogicMonitorDataSourceDevice', 'Get-LogicMonitorDevice',
                'Get-LogicMonitorDeviceDataSource', 'Get-LogicMonitorDeviceGroup',
                'Get-LogicMonitorDeviceGroupProperty',
                'Get-LogicMonitorDeviceProperty', 'Get-LogicMonitorDeviceSdt',
                'Get-LogicMonitorEscalationChain', 'Get-LogicMonitorEventSource',
                'Get-LogicMonitorIntegration', 'Get-LogicMonitorJobMonitor',
                'Get-LogicMonitorPropertySource', 'Get-LogicMonitorRawData',
                'Get-LogicMonitorReport','Get-LogicMonitorReportGroup',
                'Get-LogicMonitorRole', 'Get-LogicMonitorSdt', 'Get-LogicMonitorTopology',
                'Get-LogicMonitorUser', 'Get-LogicMonitorWebsite', 'Get-LogicMonitorWebsiteGroup',
                'Get-LogicMonitorWebsiteProperty',
                'New-LogicMonitorAlertRule', 'New-LogicMonitorCollector',
                'New-LogicMonitorDashboard', 'New-LogicMonitorDashboardGroup',
                'New-LogicMonitorDashboardWidget', 'New-LogicMonitorDevice',
                'New-LogicMonitorDeviceGroup', 'New-LogicMonitorReportGroup',
                'New-LogicMonitorUser', 'New-LogicMonitorWebsite',
                'New-LogicMonitorWebsiteGroup',
                'Out-PsLogging',
                'Remove-LogicMonitorAlertRule', 'Remove-LogicMonitorCollector',
                'Remove-LogicMonitorCollectorVersion', 'Remove-LogicMonitorDashboardGroup',
                'Remove-LogicMonitorDevice', 'Remove-LogicMonitorDeviceGroup',
                'Remove-LogicMonitorDeviceGroupProperty', 'Remove-LogicMonitorDeviceProperty',
                'Remove-LogicMonitorReport', 'Remove-LogicMonitorRole','Remove-LogicMonitorSdt',
                'Remove-LogicMonitorUser', 'Remove-LogicMonitorWebsiteGroup',
                'Send-LogicMonitorLmLogEntry',
                'Start-LogicMonitorDeviceSdt',
                'Update-LogicMonitorAlertRule', 'Update-LogicMonitorCollectorProperty',
                'Update-LogicMonitorCollectorVersion', 'Update-LogicMonitorConfigSourceProperty',
                'Update-LogicMonitorDashboardWidgetProperty',
                'Update-LogicMonitorDeviceGroupProperty', 'Update-LogicMonitorDeviceProperty',
                'Update-LogicMonitorWebsiteGroupProperty', 'Update-LogicMonitorWebsiteProperty'

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = '*'

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = 'LogicMonitor'

        # A URL to the license for this module.
        LicenseUri = 'https://choosealicense.com/licenses/mit/'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/wetling23/logicmonitor-posh-module'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
            ReleaseNotes = 'Upated Get-LogicMonitorReport (streamlined code, added examples). Upated Remove-LogicMonitorAlertRule (fixed bug in Name parameter set). Added Remove-LogicMonitorReport, Remove-LogicMonitorReportGroup, and Remove-LogicMonitorRole. Consolidated Get-LogicMonitorUserRole into Get-LogicMonitorRole.'

        # Prerelease string of this module
        # Prerelease = ''

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        # RequireLicenseAcceptance = $false

        # External dependent modules of this module
        # ExternalModuleDependencies = @()

    } # End of PSData hashtable

 } # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

