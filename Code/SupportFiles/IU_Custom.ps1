#. ..\AppDeployToolkit\AppDeployToolkitMain.ps1 -DisableLogging $true

function Kill-Process
{
    [CmdletBinding()]
    param (
        $SWName,
        $Match,
        $Like        
    )

    if ($Like) { gps | ?{$_.Path -like "*$SWName*"} | kill -Force } 
    if ($Match) { gps | ?{$_.Path -match $SWName} | kill -Force }
}

function Remove-EBIKey
{
    param (
        [parameter(mandatory=$true)]
        $SoftwareName
    )

    $RemoveEbi = @{
        Recurse = $true
        Include = $SoftwareName
        ErrorAction = 'SilentlyContinue'
    }
    Get-ChildItem -Path HKLM:\Software\EBI @RemoveEbi | Remove-Item
}

function Execute-Install
{
    param (
        [Parameter(Mandatory=$true)]
        $InstallArgs
    )

    foreach ($Inst in ($InstallArgs | Where-Object {$_.EnabledI -eq "1"} | sort sequence))
    {
        if ([string]::IsNullOrEmpty($instGlobal))
        {$instOpt=$Inst.InstallOption} else {$instOpt=$instGlobal}

        $DoIt=$false
        	    
	    If ($is64Bit -eq $true) {
            if ([string]::IsNullOrEmpty($Inst.x64Only) -or $Inst.x64Only -eq 1 -or $Inst.x64Only -eq 0){$DoIt=$true}
        }
        Else {
            if ([string]::IsNullOrEmpty($Inst.x64Only) -or $Inst.x64Only -eq 0){$DoIt=$true}
        }
        
        if ($DoIt)
        {    

            switch ($Inst.InstallType)
            {
                "MSI" {
                    if (![string]::IsNullOrEmpty($Inst.Transforms)) 
                    {Execute-MSI -Action Install -Path $Inst.Install -Transform $Inst.Transforms -Parameters $instOpt} else
                    {Execute-MSI -Action Install -Path $Inst.Install -Parameters $instOpt}
                } 
                "EXE" {
                    if (![string]::IsNullOrEmpty($_.InstallOption)) {$TmpArgs = $_.InstallOption.split(" ")}else{$TmpArgs = $instOpt}
                    
                    if (Test-Path "$dirfiles\$($Inst.Install)") {
                        if ($TmpArgs -eq "")
                        {Execute-Process -FilePath $Inst.Install -WindowStyle Hidden -WorkingDirectory $dirfiles} else
                        {Execute-Process -FilePath $Inst.Install -Arguments $TmpArgs -WindowStyle Hidden -WorkingDirectory $dirfiles}}
                }
                "MSP" {	
                    Execute-MSI -Action Patch -Path $Inst.Install -Parameters $instOpt
                }
                "APPV" {
                    Get-AppvClientPackage -All | ?{$_.Name -match $Inst.AppvName} | Stop-AppvClientPackage -Global | Remove-AppvClientPackage

                    $appvName = $Inst.Install.replace(".appv","")
                    $appvDir = (gci $dirfiles -Recurse -Filter "$appvName.appv" -ea SilentlyContinue).Directory.FullName
                    $appvFile = (gci $dirfiles -Recurse -Filter "$appvName.appv" -ea SilentlyContinue).FullName
                    $appvDeployConfig = (gci $dirfiles -Recurse -Filter "$appvName`_DeploymentConfig.xml" -ea SilentlyContinue).FullName

                    Add-AppvClientPackage $appvFile -DynamicDeploymentConfiguration $appvDeployConfig | Publish-AppvClientPackage -Global
                    Write-Host ""
                }
            }
        }
    }
}

function Execute-Uninstall
{
    param (
        [Parameter(Mandatory=$true)]
        $InstallArgs
    )

    foreach ($Inst in ($InstallArgs | Where-Object {$_.EnabledU -eq "1"} | sort sequence -Descending))
    {
        if ([string]::IsNullOrEmpty($uninstGlobal))
        {$uninstOpt=$Inst.UninstallOption} else {$uninstOpt=$uninstGlobal}

        switch ($Inst.InstallType)
        {
            "MSI" {
                Execute-MSI -Action Uninstall -Path $Inst.ProductCode -Parameters $uninstOpt
            }
            "EXE" {
                if (![string]::IsNullOrEmpty($_.UninstallOption)) {$TmpArgs = $_.UninstallOption.split(" ")}else{$TmpArgs = $uninstOpt}

                if (Test-Path $Inst.Uninstall) {
                    if ($TmpArgs -eq "")
                    {Execute-Process -FilePath $Inst.Uninstall} else
                    {Execute-Process -FilePath $Inst.Uninstall -Arguments $TmpArgs}}
            }
            "APPV" {
                Get-AppvClientPackage -All | ?{$_.Name -match $Inst.AppvName} | Stop-AppvClientPackage -Global | Remove-AppvClientPackage
            }
        }
    }
}

function New-LogStores
{
    if (!(Get-EventLog -List | ?{$_.LogDisplayName -match 'PKG-Applications'})) {
        New-EventLog -LogName 'PKG-Applications' -Source 'PKG-AppLocker'
        New-EventLog -LogName 'PKG-Applications' -Source 'PKG-Firewall'

        Limit-EventLog -LogName "PKG-Applications" -OverflowAction "OverWriteAsNeeded" -MaximumSize 190MB -EA SilentlyContinue
    } #else { Clear-EventLog -LogName PKG-Applications }
}

function Write-SpecLogEvent
{
    [CmdletBinding()]
    Param
    (
        [string[]]$FirewallRules,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Add","Remove")]
        $Action,
        $Prefix,
        [ValidateSet("Firewall","AppLocker")]
        $EventKind
    )

    New-LogStores

    $EventSplatting = @{
        Message = "[KOST-VAL][$Action $EventKind(s)][$Prefix]`n" +
                  $FirewallRules.ForEach({$_ + "`n"})
        EventId = '8101'
    }

    Write-EventLog -LogName PKG-Applications -Source "PKG-$EventKind" -EntryType Information @EventSplatting
}

function Remove-Firewall
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        $Prefix
    )    

    $firewallRules = @()

    Get-NetFirewallRule | ?{$_.DisplayName -match $Prefix} | % {            
        Remove-NetFirewallRule -InputObject $_
        $firewallRules += $_.DisplayName
    }
    Write-SpecLogEvent -FirewallRules $firewallRules -Action Remove -Prefix $Prefix -EventKind Firewall
}

function Set-Firewall
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [string[]]$Programs,
        [Parameter(Mandatory=$true)]
        $Prefix,
        [string[]]$Ports,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Add","Remove")]
        $ExecuteAction,
        [ValidateSet("Allow","Block")]
        $Action,
        [ValidateSet("Inbound","Outbound")]
        $Direction
    )

    $rules = @()

    if ($Programs) {
        $Programs.ForEach({
            $rule = $_.split(";")
            $rules += "New-NetFirewallRule -DisplayName `"$($Prefix + ":$(Split-Path $_ -Leaf)")`" -Direction $Direction -Program `"$_`" -Action $Action"
        })
    }

    if ($Ports) {
        $Ports.ForEach({
            $rule = $_.split(";")
            $rules += "New-NetFirewallRule -DisplayName $($rule[0]) -Direction Inbound -LocalPort $($rule[1]) -Protocol $($rule[2]) -Action Allow"
        })
    }

    $rules.foreach({
        iex $_
    })
    Write-SpecLogEvent -FirewallRules $rules -Action Add -Prefix $Prefix -EventKind Firewall
}

function Write-PkgEventApplocker
{
    [CmdletBinding()]
    Param
    (
        [string[]]$AppLockerFiles,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Add","Remove")]
        $Action,
        $Prefix
    )

    New-LogStores

    $appLockerAdd = @{
        Message = "[KOST-VAL][Add HashRule(s)][$Prefix]`n" +
                  $AppLockerFiles.ForEach({$_ + "`n"})
        EventId = '8101'
    }

    $appLockerDel = @{
        Message = "[KOST-VAL][Del HashRule(s)][$Prefix]`n" +
                  $AppLockerFiles.ForEach({$_ + "`n"})
        EventId = '8102'
    }

    switch ($Action) {
        "Add" { Write-EventLog -LogName PKG-Applications -Source 'PKG-AppLocker' -EntryType Information @appLockerAdd }
        "Remove" { Write-EventLog -LogName PKG-Applications -Source 'PKG-AppLocker' -EntryType Information @appLockerDel }
    }
}

function Set-ApplockerRules
{
    [CmdletBinding()]
    Param
    (
        [string[]]$AppLockerFolder,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Add","Remove")]
        $Action,
        [Parameter(Mandatory=$true)]
        $Prefix
    )

    [xml]$xmlApplocker = Get-AppLockerPolicy -Effective -Xml
    $HashRules = $xmlApplocker.AppLockerPolicy.RuleCollection

    $parent_xpath = '//AppLockerPolicy/RuleCollection/FileHashRule'
    $nodes = $xmlApplocker.SelectNodes($parent_xpath)
    $nodes | ? { $_.Name -match $Prefix} | % {
        $_.ParentNode.RemoveChild($_) | Out-Null
    }

    $xmlApplocker.OuterXml | Out-File "$env:TEMP\appi.xml"
    Set-AppLockerPolicy -XmlPolicy "$env:TEMP\appi.xml"

    $applocker = @()
    $AppLockerFolder.ForEach({
        $applocker += Get-AppLockerFileInformation -FileType Dll -Directory $_ -Recurse
        $applocker += Get-AppLockerFileInformation -FileType Exe -Directory $_ -Recurse
        $applocker += Get-AppLockerFileInformation -FileType Script -Directory $_ -Recurse

        if ($Action -eq 'Add') {
            Start-Sleep -Seconds 3
            $policies = Get-AppLockerPolicy -Effective
            $policies.Merge(($applocker | New-AppLockerPolicy -RuleType Hash -RuleNamePrefix $Prefix -Optimize -User S-1-1-0))
                $policies | Set-AppLockerPolicy -Merge
        }
    })        

    Write-PkgEventApplocker -AppLockerFiles $applocker.Path -Action $Action -Prefix $Prefix
}


<#
param (
    [Mandatory($true)]
    [ValidateSet("Install","Uninstall")]
    [string]$Action,
    [XmlElement]$InstallArgs
)

if ($Action -eq 'Install')
{

}
elseif ($Action -eq 'Uninstall')
{

}
#>