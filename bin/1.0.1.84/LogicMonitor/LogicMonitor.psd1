@{

    # Script module or binary module file associated with this manifest
    RootModule        = 'LogicMonitor.psm1'

    # Version number of this module.
    ModuleVersion     = '1.0.1.84'

    # ID used to uniquely identify this module
    GUID              = '6ef13f0b-48da-4c3b-81b2-03fa464ef8fd'

    # Author of this module
    Author            = 'Mike Hashemi'

    # Company or vendor of this module
    CompanyName       = ''

    # Copyright statement for this module
    Copyright         = '(c) 2021 mhashemi. All rights reserved.'

    # Description of the functionality provided by this module
    Description       = 'LogicMonitor REST API-related functions.'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.0'

    # Name of the Windows PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the Windows PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of the .NET Framework required by this module
    # DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module
    # CLRVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules = @()

    # Functions to export from this module
    FunctionsToExport = 'Add-EventLogSource', 'Add-LogicMonitorAlertRule', 'Add-LogicMonitorCollector', 'Add-LogicMonitorDashboard',
    'Add-LogicMonitorDashboardGroup', 'Add-LogicMonitorDashboardWidget', 'Add-LogicMonitorDevice', 'Add-LogicMonitorDeviceGroup',
    'Add-LogicMonitorReportGroup', 'Add-LogicMonitorWebsiteGroup',
    'Confirm-OutputPathAvailability',
    'Get-LogicMonitorAlert', 'Get-LogicMonitorAlertRule', 'Get-LogicMonitorAuditLog',
    'Get-LogicMonitorCollectorAvailableVersion', 'Get-LogicMonitorCollectorInstaller', 'Get-LogicMonitorCollector',
    'Get-LogicMonitorCollectorUpgradeHistory', 'Get-LogicMonitorConfigSource', 'Get-LogicMonitorConfigSourceData', 'Get-LogicMonitorDashboard',
    'Get-LogicMonitorDashboardGroup', 'Get-LogicMonitorDashboardWidget', 'Get-LogicMonitorDataSource', 'Get-LogicMonitorDataSourceDevice',
    'Get-LogicMonitorDeviceDataSource', 'Get-LogicMonitorDeviceGroupProperty', 'Get-LogicMonitorDeviceGroup', 'Get-LogicMonitorDeviceProperty',
    'Get-LogicMonitorDevice', 'Get-LogicMonitorEscalationChain', 'Get-LogicMonitorEventSource', 'Get-LogicMonitorDeviceSdt',
    'Get-LogicMonitorJobMonitor', 'Get-LogicMonitorPropertySource', 'Get-LogicMonitorReport', 'Get-LogicMonitorReportGroup',
    'Get-LogicMonitorRawData', 'Get-LogicMonitorRole', 'Get-LogicMonitorSdt', 'Get-LogicMonitorWebsite', 'Get-LogicMonitorWebsiteGroup',
    'Get-LogicMonitorWebsiteProperty',
    'Out-PsLogging',
    'Remove-LogicMonitorAlertRule', 'Remove-LogicMonitorCollector', 'Remove-LogicMonitorCollectorVersion',
    'Remove-LogicMonitorDevice', 'Remove-LogicMonitorDeviceProperty', 'Remove-LogicMonitorDeviceGroup', 'Remove-LogicMonitorSdt',
    'Send-LogicMonitorLmLogEntry',
    'Start-LogicMonitorDeviceSdt',
    'Update-LogicMonitorAlertRule', 'Update-LogicMonitorAlertRuleProperty', 'Update-LogicMonitorCollectorProperty',
    'Update-LogicMonitorCollectorVersion', 'Update-LogicMonitorDashboardWidgetProperty', 'Update-LogicMonitorDeviceProperty',
    'Update-LogicMonitorWebsiteProperty'

    # Cmdlets to export from this module
    CmdletsToExport   = '*'

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module
    AliasesToExport   = '*'

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    # FileList = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData       = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags         = @("LogicMonitor")

            # A URL to the license for this module.
            # LicenseUri = ''

            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/wetling23/logicmonitor-posh-module'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = 'Updated Get-LogicMonitorAlert to 1.0.0.14 (removed filter restrictions).'

            # External dependent modules of this module
            # ExternalModuleDependencies = ''

        } # End of PSData hashtable
    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''

}