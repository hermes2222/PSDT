<#
.SYNOPSIS
	This script is a template that allows you to extend the toolkit with your own custom functions.
    # LICENSE #
    PowerShell App Deployment Toolkit - Provides a set of functions to perform common application deployment tasks on Windows.
    Copyright (C) 2017 - Sean Lillis, Dan Cunningham, Muhammad Mashwani, Aman Motazedian.
    This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
    You should have received a copy of the GNU Lesser General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.
.DESCRIPTION
	The script is automatically dot-sourced by the AppDeployToolkitMain.ps1 script.
.NOTES
    Toolkit Exit Code Ranges:
    60000 - 68999: Reserved for built-in exit codes in Deploy-Application.ps1, Deploy-Application.exe, and AppDeployToolkitMain.ps1
    69000 - 69999: Recommended for user customized exit codes in Deploy-Application.ps1
    70000 - 79999: Recommended for user customized exit codes in AppDeployToolkitExtensions.ps1
.LINK
	http://psappdeploytoolkit.com
#>
[CmdletBinding()]
Param (
)

##*===============================================
##* VARIABLE DECLARATION
##*===============================================

# Variables: Script
[string]$appDeployToolkitExtName = 'PSAppDeployToolkitExt'
[string]$appDeployExtScriptFriendlyName = 'App Deploy Toolkit Extensions'
[version]$appDeployExtScriptVersion = [version]'3.8.2'
[string]$appDeployExtScriptDate = '08/05/2020'
[hashtable]$appDeployExtScriptParameters = $PSBoundParameters

$AppInfos = $DeployXml.Deployment

if ($deploymentType -eq "Install") {         
    $Instructions = $DeployXml.Deployment.Install
}

if ($DeployXml.Deployment.SkipReverseUninstall -eq 1) { $ReverseMode = $true }
    
if ($deploymentType -eq "Uninstall") { 
    if ($ReverseMode) {            
        #region Reverse , replacement for [array]::Reverse($Instructions)
        $Instructions = $DeployXml.Deployment.UnInstall
        $m = $DeployXml.Deployment.Install.count
        for ($i = 0; $i -lt $m; $i++)
        { 
            $Instructions[$i] = $DeployXml.Deployment.UnInstall[$m - 1 - $i]
        }
        #endregion
    } else { $Instructions = $DeployXml.Deployment.UnInstall } 
}

$ToKill = $DeployXml.Deployment.ProcessKill.Trim() -split ";"
if ($ToKill) {
    $ToKill | % {
        $kill = $_
        if ($kill -match "\\") { 
            $RunningApp = (gps | where {$_.Path -like ("*" + $kill.replace("\\","*") + "*")} | kill -Force ) 
        } else {
            $RunningApp = (gps | where {$_.Path -match $kill} | kill -Force ) 
        }
    }
}    

if ($RunningApp){ 
    #Show-InstallationWelcome -CloseApps ([System.String]::Join(",", $RunningApp.ProcessName)) -ForceCloseAppsCountdown 1800 -AllowDefer -DeferTimes 1
}

##*===============================================
##* FUNCTION LISTINGS
##*===============================================

# <Your custom functions go here>
function Do-InstUninstall
{
    $counter = 1

    if ($DeployXml.Deployment.ProductCodes) {
        ($DeployXml.Deployment.ProductCodes -split ";").ForEach({
            Execute-MSI -Path $_ -Parameters "/QN" -Action Uninstall -LogName ($AppName + "_$counter") 
        })
    }
        
    foreach ($Instruction in $Instructions ) {
        $ignoreExitCodes = $Instruction.AllowedReturnCodes + "," + $Instruction.AllowedReturnCodesReboot
        $sCommand = $null
        $sCommandArgs = $null        
        
        switch ($Instruction.Type)
        {
            'msi' {
                if (!$Instruction.msi) { Write-Log -Message "Forbidden XML Structure: Missing <MSI> Tag" -Severity 3 -Source "Check-Instructions" }

                $sCommand = $Instruction.Msi.Replace(".\",$DirFiles + "\")
                if ($Instruction.Properties) { $sCommandArgs += " " + ($Instruction.Properties.Replace(".\",$DirFiles)) -join ";" }
                $sCommandArgs += (' ALLUSERS=1 MSIDISABLERMRESTART=1 MSIRESTARTMANAGERCONTROL=DisableShutdown MSIRMSHUTDOWN=1 REBOOT=ReallySuppress ROOTDRIVE=C:\ ARPNOMODIFY=1')
				#$sCommandArgs += (' ALLUSERS=1 MSIDISABLERMRESTART=1 MSIRESTARTMANAGERCONTROL=DisableShutdown MSIRMSHUTDOWN=2 REBOOT=ReallySuppress ROOTDRIVE=C:\ ARPNOREMOVE=1 ARPNOMODIFY=1 ARPNOREPAIR=1')
                                 
                if ($Instruction.MST) { $sCommandArgs += " TRANSFORMS=`"" + ($Instruction.MST.Replace(".\",$DirFiles + "\") -join ";") + "`""}
                if ($Instruction.MSP) { $sCommandArgs += " PATCH=`"" + (($Instruction.Msp.Replace(".\",$DirFiles + "\")) -join ";") + "`"" }
                Execute-MSI -Path $sCommand -Parameters $sCommandArgs -Action Install -LogName ($AppName + "_$counter") -IgnoreExitCodes $ignoreExitCodes
            
            };
            'msp' {
                if ($deploymentType -eq "Install") {
                    if (!$Instruction.Msp) { Write-Log -Message  "Unerlaubte XML Struktur: <Msp> Tag fehlt" -Severity 3 -Source "Check-Instructions" }

                    #if ($Instruction.Properties) { $sCommandArgs += " " + ($Instruction.Properties.Replace(".\",$DirFiles + "\")) -join ";" }
                    $sCommandArgs += (' ALLUSERS=1 MSIDISABLERMRESTART=1 MSIRESTARTMANAGERCONTROL=DisableShutdown MSIRMSHUTDOWN=2 REBOOT=ReallySuppress ROOTDRIVE=C:\ ARPNOREMOVE=1 ARPNOMODIFY=1 ARPNOREPAIR=1')

                    $sCommand = $Instruction.Msp.Replace(".\",$DirFiles + "\")
                    if ($Instruction.Properties) { 
                        $sCommandArgs += " " + ($Instruction.Properties.Replace(".\",$DirFiles + "\")) -join ";" 
                        Execute-MSI -Action Patch -Path $sCommand -Parameters $sCommandArgs -LogName ($AppName + "_$counter") -IgnoreExitCodes $ignoreExitCodes
                    } else { Execute-MSI -Action Patch -Path $sCommand -LogName ($AppName + "_$counter") -IgnoreExitCodes $ignoreExitCodes }
                }
            };
            'exe' {
                if (!$Instruction.exe) { Write-Log -Message  "Forbidden XML Structure: Missing <EXE> Tag" -Severity 3 -Source "Check-Instructions" }

                $sCommand = $Instruction.Exe.Replace(".\",$DirFiles + "\")
                
                if (Test-Path $sCommand){
                    if ($Instruction.Arguments) {
                        $sCommandArg = (($Instruction.Arguments.Replace(".\",$DirFiles + "\")) -join " ")
                        Execute-Process -Path $sCommand -Parameters $sCommandArg -WindowStyle Hidden -WorkingDirectory $DirFiles -IgnoreExitCodes $ignoreExitCodes
                    } else { Execute-Process -Path $sCommand -WindowStyle Hidden -WorkingDirectory $DirFiles -IgnoreExitCodes $ignoreExitCodes }
                }
            };
            'ps1' {
                if (!$Instruction.ps1) { Write-Log -Message "Forbidden XML Structure: Missing <PS1> Tag" -Severity 3 -Source "Check-Instructions" }

                . "$scriptDirectory\DeploymentScript.ps1"

                Do-Anything -Action $Instruction.Arguments -ErrorAction Stop -IgnoreExitCodes $ignoreExitCodes
            };
        };
        $Counter++ 
    }       
}

function Create-Shortcut
{
    [CmdletBinding()]
    param(
        $lnkName,
        $lnkDestination,
        $lnkTarget,
        $lnkArgument,
        $IconLocation
    )

    $lnkDestination = $lnkDestination.split(",")
    foreach ($dir in $lnkDestination)
    {
        #create the shortcut object
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut("$($dir)\$($lnkName).lnk")
        #program the shortcut will open
        $Shortcut.TargetPath = $lnkTarget
        #icon location & Id that the shortcut will use
        $Shortcut.IconLocation = "$($IconLocation.trim('\')),0"
        #any extra parameters that the shortcut may have
        $Shortcut.Arguments = "$lnkArgument"
        #save the modifications
        $Shortcut.Save()
    }
}

function New-FirewallRule
{
    param(
        [validateset("in","out")] $Direction="in",
        [validateset("allow","block","bypass")] $Action="allow",
        [validateset("public","private","domain","any")] $Profile="any", 
        [Parameter(Mandatory=$true)][validateset("UDP","TCP")] $Port,        
        $RuleName,
        $Program
    )
    try {
        Execute-Process -Path netsh -Parameters "advfirewall firewall add rule name=`"$RuleName`" dir=$Direction program=`"$Program`" action=$Action description=`"$RuleName`" protocol=$Port" -CreateNoWindow -IgnoreExitCodes '0,1'
    } catch { Write-Log -Message $_.Exception.Message -Severity 3 -Source Firewall }
}
function Remove-FirewallRule
{
    param(
        $RuleName
    )
    try {
        Execute-Process -Path netsh -Parameters "advfirewall firewall delete rule name=`"$RuleName`"" -CreateNoWindow -IgnoreExitCodes '0,1'
    } catch { Write-Log -Message $_.Exception.Message -Severity 3 -Source Firewall }
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

    switch ($Action){
        'Add' { $EventId = '8101' }
        'Remove' { $EventId = '8102' }
    }

    $reducedPath = @()

    foreach($item in $AppLockerFiles){
        if (($reducedPath -join "`r").Length -ge (32766 - 2766)){

            $splatt = Get-Informations -FilePaths $reducedPath -Prefix $Prefix -EventId $EventId -Action $Action
            Write-EventLog -LogName PKG-Applications -Source 'PKG-AppLocker' -EntryType Information @splatt
            
            $reducedPath = @()                       
        }
        $reducedPath += $item
    }

    if($reducedPath){
        $splatt = Get-Informations -FilePaths $reducedPath -Prefix $Prefix -EventId $EventId -Action $Action
        Write-EventLog -LogName PKG-Applications -Source 'PKG-AppLocker' -EntryType Information @splatt
    } elseif (!$reducedPath) {
        Write-EventLog -LogName PKG-Applications -Source 'PKG-AppLocker' -EntryType Information -Message "[KOST-VAL][Remove HashRule(s)][$Prefix]" -EventId 8102        
    }
}

function Get-Informations($FilePaths,$Prefix,$EventId, $Action)
{
    $appLockerAdd = @{
        Message = "[KOST-VAL][$($Action) HashRule(s)][$Prefix]`n" +
                    #$FilePaths.ForEach({$_ + "`n"})
                    ($FilePaths -join "`r")
        EventId = $EventId
    }

    Write-Output -InputObject $appLockerAdd
}

function Remove-Rules($Prefix)
{
    $policies = Get-AppLockerPolicy -Effective

    try{
        foreach($RuleCollectionTypes in $policies.Clone()){
            foreach($policy in $RuleCollectionTypes.RuleCollections){
                foreach($rule in $policy){
                    Write-Host $rule.Name -ForegroundColor Gray
                    if($rule.Name -like "$Prefix`:*"){
                        Write-Host "Remove: $($rule.Name)" -ForegroundColor Yellow
                        (($policies.RuleCollections | ?{$_.RuleCollectionType -match $policy.RuleCollectionType}).delete($rule.Id))
                    }
                }
            }
        }

    $policies.ToXml() | Out-File "$env:TEMP\appi.xml"
    Set-AppLockerPolicy -XmlPolicy "$env:TEMP\appi.xml"

    Start-Sleep -Seconds 5

    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Red
    }

    <#
    $policies = Get-AppLockerPolicy -Effective

    $rulesToDelete = @()

    try {    
        foreach($policy in $policies.RuleCollections){
            foreach($rule in $policy){
                if ($rule.name -like "$Prefix`:*"){
                    $policy.Delete($rule.id)             
                    $policies.ToXml() | Out-File "$env:TEMP\appi.xml"
                    Set-AppLockerPolicy -XmlPolicy "$env:TEMP\appi.xml"                    
                }                      
            }
        }
    } catch {
        Remove-Rules
    }
    #>
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

    Remove-Rules $Prefix

    <#

    [xml]$xmlApplocker = Get-AppLockerPolicy -Effective -Xml
    $HashRules = $xmlApplocker.AppLockerPolicy.RuleCollection

    $nodes = @()
    $nodes += $xmlApplocker.SelectNodes('//*/RuleCollection[@Type="Dll"]')
    $nodes += $xmlApplocker.SelectNodes('//*/RuleCollection[@Type="Exe"]')
    $nodes += $xmlApplocker.SelectNodes('//*/RuleCollection[@Type="Script"]')

    foreach($node in $nodes){
        if (!$node.FileHashRule -and !$node.FilePathRule -and !$node.FilePublisherRule){
            $node.ParentNode.RemoveChild($node)  
        }
    }

    $parent_xpath = '//AppLockerPolicy/RuleCollection/FileHashRule'
    $nodes = $xmlApplocker.SelectNodes($parent_xpath)
    $nodes | ? { $_.Name -like "$Prefix`:*"} | % {
        Write-Host $_.Name -ForegroundColor Yellow
        $_.ParentNode.RemoveChild($_) | Out-Null
    }

    $xmlApplocker.OuterXml | Out-File "$env:TEMP\appi.xml"
    Set-AppLockerPolicy -XmlPolicy "$env:TEMP\appi.xml"
    #>

    $applocker = @()
    foreach($item in $AppLockerFolder){
        switch ($(gci $item).GetType().name){
            'FileInfo' {
                $applocker += Get-AppLockerFileInformation -Path $item -ea SilentlyContinue
            }
            default {
                $applocker += Get-AppLockerFileInformation -FileType Dll -Directory $item -Recurse -ea SilentlyContinue
                $applocker += Get-AppLockerFileInformation -FileType Exe -Directory $item -Recurse -ea SilentlyContinue
                $applocker += Get-AppLockerFileInformation -FileType Script -Directory $item -Recurse -ea SilentlyContinue
            }
        }  
    }       

    if ($Action -eq 'Add') {
        Start-Sleep -Seconds 5
        $policies = Get-AppLockerPolicy -Effective
        $policies.Merge(($applocker | New-AppLockerPolicy -RuleType Hash -RuleNamePrefix $Prefix -Optimize -User S-1-1-0))
            $policies | Set-AppLockerPolicy -Merge
    }         

    $applocker.path.Path.ForEach({
        Write-Host $_ -ForegroundColor Green
    })
    Write-PkgEventApplocker -AppLockerFiles $applocker.Path -Action $Action -Prefix $Prefix
  
}

#************************

Function Edit-XmlNodes {
<# 
.SYNOPSIS
	Edit XML Nodes
.DESCRIPTION
	Edit XML Nodes. Function can be used when edition config files of a .NET program.
.PARAMETER doc
	New-Object System.Xml.XmlDocument (with loaded document)
.PARAMETER xpath
	x-path of an XML node
.EXA.PARAMETER value
	New Value of edited XML node
 .EXAMPLE
	Edit-XmlNodes -doc $xml -xpath "/configuration/applicationSettings/FUB.AAT.ControlCenter.Properties.Settings/setting/value" -value "$WEBSERVER/ASWWebService.asmx" 
.NOTES
    XML Node names and Attributes are CaSe SeNsItIvE!
.LINK
.AUTHOR
    Lobsiger Markus FUB 28.09.2018
#>
        param(
            [xml] $doc,
            [string] $xpath = $(throw "xpath is a required parameter"),
            [string] $value = $(throw "value is a required parameter")
        )
 
        $nodes = $doc.SelectNodes($xpath)
        $count = $nodes.Count
 
        Write-Verbose "Found '$count' nodes with path '$xpath'."
 
        foreach ($node in $nodes)
        {
            if ($node -ne $null)
            {
                if ($node.NodeType -eq "Element")
                {
                    $node.InnerXml = $value
                }
                else
                {
                    $node.Value = $value
                }
            }
        }
    }


Function Edit-XmlValues {
<# 
.SYNOPSIS
	Edit XML Values
.DESCRIPTION
	Edit XML Values. Function can be used when edition config files of a .NET program.
.PARAMETER doc
	New-Object System.Xml.XmlDocument (with loaded document)
.PARAMETER xpath
	x-path of an XML node
.PARAMETER attribute
	Attribute to edit
.EXA.PARAMETER value
	New Value of edited XML node
 .EXAMPLE
	Edit-XmlValues -doc $xml -xpath "/configuration/appSettings/add[1][@key='system_location']" -attribute "value" -value "$WEBSERVER/"
.NOTES
    XML Node names and Attributes are CaSe SeNsItIvE!
.LINK
.AUTHOR
    Lobsiger Markus FUB 28.09.2018
#>
        param(
            [xml] $doc,
            [string] $xpath = $(throw "xpath is a required parameter"),
            [string] $attribute = $(throw "attribute is a required parameter"),
            [string] $value = $(throw "value is a required parameter")
        )
 
        $xml.SelectSingleNode($xpath).SetAttribute($attribute, $value)

    }



Function Set-EBIInventoryKeys {
<# 
.SYNOPSIS
	Creates the registry key values for the EBI Inventory. The keys can be used for as detection method in Configuration Manager aplications.
.DESCRIPTION
	Creates the registry key values for the EBI Inventory. The keys can be used for as detection method in Configuration Manager aplications.
.PARAMETER ContinueOnError
	Continue if an error is encountered
.EXAMPLE
	Set-EBIInventoryKeys
.NOTES
.LINK
	http://psappdeploytoolkit.com
#>	Param(
		[boolean] $ContinueOnError = $true
	)
	# Variables: EBI Inventory Version
	$appInternalVersion = "$appVersionMajorRelease.$appVersionMinorRelease.$appVersionPatchLevel.$appVersionBuildNumber"
	$appFullName = "$appVendor" + " " + "$appName" + " " + "$appVersion"
	$appFullName = $InstallTitle
	
	# Creating registry key values
	Write-Log "Creating registry key values for the application [$appFullName]..."
	Set-RegistryKey -Key "HKEY_LOCAL_MACHINE\Software\EBI\PackageStatus\$appFullName" -Name "(Default)" -Type String -Value $appInternalVersion
	Set-RegistryKey -Key "HKEY_LOCAL_MACHINE\Software\EBI\PackageStatus\$appFullName" -Name VersionMajorRelease -Type String -Value $appVersionMajorRelease
	Set-RegistryKey -Key "HKEY_LOCAL_MACHINE\Software\EBI\PackageStatus\$appFullName" -Name VersionMinorRelease -Type String -Value $appVersionMinorRelease
	Set-RegistryKey -Key "HKEY_LOCAL_MACHINE\Software\EBI\PackageStatus\$appFullName" -Name VersionPatchLevel -Type String -Value $appVersionPatchLevel
	Set-RegistryKey -Key "HKEY_LOCAL_MACHINE\Software\EBI\PackageStatus\$appFullName" -Name VersionBuildNumber -Type String -Value $appVersionBuildNumber
	Set-RegistryKey -Key "HKEY_LOCAL_MACHINE\Software\EBI\PackageStatus\$appFullName" -Name MIF -Type String -Value $appMIF
	Set-RegistryKey -Key "HKEY_LOCAL_MACHINE\Software\EBI\PackageStatus\$appFullName" -Name InstDateTime -Type String -Value (Get-Date -Format "yyyyMMddHHmmss").ToString()
	Set-RegistryKey -Key "HKEY_LOCAL_MACHINE\Software\EBI\PackageStatus\$appFullName" -Name UninstallEXE -Type String -Value $appUninstallEXE
	Set-RegistryKey -Key "HKEY_LOCAL_MACHINE\Software\EBI\PackageStatus\$appFullName" -Name UninstallParam -Type String -Value $appUninstallParam
	Write-Log "Registry key values for the application [$appFullName] set"
}

Function Remove-EBIInventoryKeys {
<# 
.SYNOPSIS
	Removes the registry key values for the EBI Inventory. 
.DESCRIPTION
	Removes the registry key values for the EBI Inventory.
.PARAMETER ContinueOnError
	Continue if an error is encountered
.EXAMPLE
	Set-EBIInventoryKeys
.NOTES
.LINK
    http://psappdeploytoolkit.com
#>	Param(
		[boolean] $ContinueOnError = $true
	)
	# Variables: EBI Inventory Version
	$appFullName = "$appVendor" + " " + "$appName" + " " + "$appVersion"
	$appFullName = $InstallTitle
	
	# Remove registry key
	Write-Log "Removeing registry key values for the application [$appFullName]..."
	Remove-RegistryKey -Key "HKEY_LOCAL_MACHINE\Software\EBI\PackageStatus\$appFullName"
	Write-Log "Registry key values for the application [$appFullName] removed"
}

Function DoesItemExist{
<#
.SYNOPSIS
    Check if the item exists. Can check directories, files, registry keys, registry entries.
    Returns $true or $false.
.PARAMETER Path
    The path to the file, directory, registry key, or registry value that you want to see if it exists.
.PARAMETER regEntry
    Name of the registry entry you want to check.
.EXAMPLE
    DoesItemExist -Path "C:\Windows\Temp\Test\"
.EXAMPLE
    DoesItemExist -Path "C:\Windows\Temp\Install.log"
.EXAMPLE
    DoesItemExist -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\"
.EXAMPLE
    DoesItemExist -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\" -regEntry "RegisteredOrganization"
.NOTES
.LINK 
    http://psappdeploytoolkit.com 
#>
    param(
        [Parameter(Mandatory=$true, HelpMessage="Path to file, directory, or registry key.")]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path,
        [Parameter(Mandatory=$false, HelpMessage="Registry entry")]
        [ValidateNotNullOrEmpty()]
        $regEntry = $null
    )
    if($regEntry -ne $null){
        if (Test-Path $Path) {
            $Key = Get-Item -LiteralPath $Path
            if ($Key.GetValue($regEntry, $null) -ne $null) {
                Write-Log "[DoesItemExist] Registry entry: $regEntry exists."
                $true
            } else {
                Write-Log "[DoesItemExist] Registry entry: $regEntry does not exist."
                $false
            }
        } else {
            Write-Log "[DoesItemExist] Registry path to $regEntry does not exist."
            $false
        }
    }
    else{
        $Item = Get-ItemProperty $Path -ErrorVariable Error -ErrorAction SilentlyContinue
        if([IO.File]::Exists($Path) -eq "True"){
            Write-Log "[DoesItemExist] File exists at: $Path"
            $true
        }
        elseif([IO.Directory]::Exists($Path) -eq "True"){
            Write-Log "[DoesItemExist] Directory $Path exists."
            $true
        }
        elseif($Error.Count -eq 0){
            Write-Log "[DoesItemExist] Registry path at $Path exists."
            $true
        }
        else {
            Write-Log "[DoesItemExist] Item: $Path does not exist."
            $false
        }
        $Error.Clear()
    }
}

Function Get-ClientType {
<# 
.SYNOPSIS
	Retrieves information about the 'ClientType' device variable who is mirrored in the windows registry
.DESCRIPTION
	Retrieves information about the 'ClientType' device variable who is mirrored in the windows registry
.PARAMETER ContinueOnError
	Continue if an error is encountered
.EXAMPLE
	Get-ClientType
.NOTES
.LINK 
	http://psappdeploytoolkit.com 
#>	Param(
		[boolean] $ContinueOnError = $true
	)

	Try {
        $RegKeyValue = (Get-RegistryKey -Key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters").srvcomment
	}
	Catch {
		Write-Log "[Get-ClientType] Error retrieving 'ClientType' information."
		If ($ContinueOnError -eq $false) { Throw "Error retrieving 'ClientType' information." }
	}

    If (($RegKeyValue -eq $null) -or ($RegKeyValue -eq ""))
    {
        $ClientType = "Client Type undefined!"
        Write-Log "[Get-ClientType] Client Type undefined!"
    }
    Else
    {
        $ClientType = $RegKeyValue
        Write-Log "[Get-ClientType] Client Type '$ClientType' retrieved"
    }
    Return $ClientType
}

##*===============================================
##* END FUNCTION LISTINGS
##*===============================================

##*===============================================
##* SCRIPT BODY
##*===============================================

If ($scriptParentPath) {
	Write-Log -Message "Script [$($MyInvocation.MyCommand.Definition)] dot-source invoked by [$(((Get-Variable -Name MyInvocation).Value).ScriptName)]" -Source $appDeployToolkitExtName
}
Else {
	Write-Log -Message "Script [$($MyInvocation.MyCommand.Definition)] invoked directly" -Source $appDeployToolkitExtName
}

##*===============================================
##* END SCRIPT BODY
##*===============================================