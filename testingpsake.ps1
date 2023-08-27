properties {
    $repoPath = "C:\codeRepository\personal\logicmonitor-posh-module"
    $manifest = Import-PowerShellDataFile -Path $repoPath\LogicMonitor.psd1
    $outputPath = "$repoPath\bin\$($manifest.ModuleVersion)\LogicMonitor"
    $srcPsd1 = "$repoPath\LogicMonitor.psd1"
    $outPsd1 = "$outputPath\LogicMonitor.psd1"
    $outPsm1 = "$outputPath\LogicMonitor.psm1"
}

task default -depends Build, Zip

task Clean {
    if (Test-Path -LiteralPath $outputPath) {
        Remove-Item -Path $outputPath -Recurse -Force
    }
}

task Build -depends Clean {
    Write-Verbose "Creating module version [$($manifest.ModuleVersion)]"
    New-Item -Path $outputPath -ItemType Directory > $null

    # Private functions
    Get-ChildItem -Path "$repoPath\Private" -File | ForEach-Object {
        $_ | Get-Content |
            Add-Content -Path $outPsm1 -Encoding utf8
    }

    # Public functions
    Get-ChildItem -Path "$repoPath\Public" -File | ForEach-Object {
        $_ | Get-Content |
            Add-Content -Path $outPsm1 -Encoding utf8
    }

    Write-Verbose "Adding Export-ModuleMember to .psm1 file."
    Add-Content -Value 'Export-ModuleMember -Alias * -Function *' -Path $outPsm1

    Copy-Item -Path $srcPsd1 -Destination $outPsd1
}

task Zip -depends Build {
    Write-Verbose "Zipping module."

    Compress-Archive -Path $outputPath -DestinationPath "$repoPath\bin\$($manifest.ModuleVersion)\LogicMonitor.zip"
}