<#
.SYNOPSIS
	This script performs the installation or uninstallation of an application(s).
.DESCRIPTION
	The script is provided as a template to perform an install or uninstall of an application(s).
	The script either performs an "Install" deployment type or an "Uninstall" deployment type.
	The install deployment type is broken down into 3 main sections/phases: Pre-Install, Install, and Post-Install.
	The script dot-sources the AppDeployToolkitMain.ps1 script which contains the logic and functions required to install or uninstall an application.
.PARAMETER DeploymentType
	The type of deployment to perform. Default is: Install.
.PARAMETER DeployMode
	Specifies whether the installation should be run in Interactive, Silent, or NonInteractive mode. Default is: Interactive. Options: Interactive = Shows dialogs, Silent = No dialogs, NonInteractive = Very silent, i.e. no blocking apps. NonInteractive mode is automatically set if it is detected that the process is not user interactive.
.PARAMETER AllowRebootPassThru
	Allows the 3010 return code (requires restart) to be passed back to the parent process (e.g. SCCM) if detected from an installation. If 3010 is passed back to SCCM, a reboot prompt will be triggered.
.PARAMETER TerminalServerMode
	Changes to "user install mode" and back to "user execute mode" for installing/uninstalling applications for Remote Destkop Session Hosts/Citrix servers.
.PARAMETER DisableLogging
	Disables logging to file for the script. Default is: $false.
.EXAMPLE
	Deploy-Application.ps1
.EXAMPLE
	Deploy-Application.ps1 -DeployMode 'Silent'
.EXAMPLE
	Deploy-Application.ps1 -AllowRebootPassThru -AllowDefer
.EXAMPLE
	Deploy-Application.ps1 -DeploymentType Uninstall
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
	[Parameter(Mandatory=$false)]
	[ValidateSet('Install','Uninstall')]
	[string]$DeploymentType = 'Install',
	[Parameter(Mandatory=$false)]
	[ValidateSet('Interactive','Silent','NonInteractive')]
	[string]$DeployMode = 'Interactive',
	[Parameter(Mandatory=$false)]
	[switch]$AllowRebootPassThru = $true,
	[Parameter(Mandatory=$false)]
	[switch]$TerminalServerMode = $false,
	[Parameter(Mandatory=$false)]
	[switch]$DisableLogging = $false,
    [string]$Condition = "1"

)

    $myXmlRoot = Split-Path $MyInvocation.MyCommand.path
    $DeployXmlPath = "$myXmlRoot\Deploy-Application.xml"

    $DeployXml = New-Object -TypeName "System.Xml.XmlDocument"
    $DeployXml.Load($DeployXmlPath)

Try {
	## Set the script execution policy for this process
	Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop' } Catch {}
	
	##*===============================================
	##* VARIABLE DECLARATION
	##*===============================================
	## Variables: Application

	[string]$appVendor = $DeployXml.Deployment.appVendor
	[string]$appName = $DeployXml.Deployment.appName
	[string]$appVersion = $DeployXml.Deployment.appVersion
	[string]$appArch = $DeployXml.Deployment.appArch			# optional x86 or x64
	[string]$appLang = $DeployXml.Deployment.appLang		# MUI, EN, DE, FR, IT
	[string]$appRevision = $DeployXml.Deployment.appRevision		# optional
	[string]$appScriptVersion = '1.0.0'
	[string]$appScriptDate = '09/24/2015'	# Month/Day/Year
	[string]$appScriptAuthor = '<author name> FUB'


	# Variables: EBI Inventory Version 3.6.7.0
	[string]$appVersionMajorRelease = $DeployXml.Deployment.appVersionMajor	# Sample: 1
	[string]$appVersionMinorRelease = $DeployXml.Deployment.appVersionMinor 	# Sample: 0
	[string]$appVersionPatchLevel = $DeployXml.Deployment.appVersionPatchLevel	# Sample: 0
	[string]$appVersionBuildNumber = $DeployXml.Deployment.appVersionBuildNumber	# Sample: 0
	[string]$appMIF = '{GUID}' 		# optional, GUID if available
	#
	[string]$appUninstallEXE = "\\sccm\sccm$\CLI\AM\$appVendor\$appName $appVersion\$appVersionMajorRelease.$appVersionMinorRelease.$appVersionPatchLevel.$appVersionBuildNumber\P\Deploy-Application.EXE" # msiexec.exe, uninstall.exe or Deploy-Application.EXE
	[string]$appUninstallParam = "-DeploymentType Uninstall -DeployMode Silent" # Uninstall Parameters
    #[string]$appFullName = "$appVendor" + " " + "$appName" + " " + "$appVersion"
    ##*===============================================
	##*===============================================
	## Variables: Install Titles (Only set here to override defaults set by the toolkit)
	[string]$installName = ''
	[string]$installTitle = ''
	
	##* Do not modify section below
	#region DoNotModify
	
	## Variables: Exit Code
	[int32]$mainExitCode = 0
	
	## Variables: Script
	[string]$deployAppScriptFriendlyName = 'Deploy Application'
	[version]$deployAppScriptVersion = [version]'3.6.5'
	[string]$deployAppScriptDate = '08/17/2015'
	[hashtable]$deployAppScriptParameters = $psBoundParameters
	#$installName + '_' + $appDeployToolkitName + '_' + $deploymentType + '.log'
	## Variables: Environment
	If (Test-Path -LiteralPath 'variable:HostInvocation') { $InvocationInfo = $HostInvocation } Else { $InvocationInfo = $MyInvocation }
	[string]$scriptDirectory = Split-Path -Path $InvocationInfo.MyCommand.Definition -Parent
	
	## Dot source the required App Deploy Toolkit Functions
	Try {
		[string]$moduleAppDeployToolkitMain = "$scriptDirectory\AppDeployToolkit\AppDeployToolkitMain.ps1"
		If (-not (Test-Path -LiteralPath $moduleAppDeployToolkitMain -PathType 'Leaf')) { Throw "Module does not exist at the specified location [$moduleAppDeployToolkitMain]." }
		If ($DisableLogging) { . $moduleAppDeployToolkitMain -DisableLogging } Else { . $moduleAppDeployToolkitMain }
	}
	Catch {
		If ($mainExitCode -eq 0){ [int32]$mainExitCode = 60008 }
		Write-Error -Message "Module [$moduleAppDeployToolkitMain] failed to load: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
		## Exit the script, returning the exit code to SCCM
		If (Test-Path -LiteralPath 'variable:HostInvocation') { $script:ExitCode = $mainExitCode; Exit } Else { Exit $mainExitCode }
	}

    #. "$dirSupportFiles\IU_Custom.ps1"

	## Show Progress Message (with the default message)
	Show-InstallationProgress
    
	#endregion
	##* Do not modify section above
	##*===============================================
	##* END VARIABLE DECLARATION
	##*===============================================

    if ($XmlContent.Applications.KillProcess.'#text') {
        $pKill = @{
            SWName = $XmlContent.Applications.KillProcess.'#text'.tostring()
            Match = [bool]$XmlContent.Applications.KillProcess.Match
            Like = [bool]$XmlContent.Applications.KillProcess.Wildcard
        }

        Kill-Process @pKill
    }		

	If ($deploymentType -ine 'Uninstall') {
		##*===============================================
		##* PRE-INSTALLATION
		##*===============================================
		[string]$installPhase = 'Pre-Installation'
		
		## Show Welcome Message, close Internet Explorer if required, allow up to 3 deferrals, verify there is enough disk space to complete the install, and persist the prompt
		# Show-InstallationWelcome -CloseApps 'iexplore' -AllowDefer -DeferTimes 3 -CheckDiskSpace -PersistPrompt
			
		## <Perform Pre-Installation tasks here>
        ## Delete previous EBIInventoryKeys		
        #Remove-EBIKey '*Adobe*Flash*Player*ActiveX*'
        
		##*===============================================
		##* INSTALLATION 
		##*===============================================
		[string]$installPhase = 'Installation'

        Do-InstUninstall
        #Execute-Install $Installation
		
		## <Perform Installation tasks here>
		
		##*===============================================
		##* POST-INSTALLATION
		##*===============================================
		[string]$installPhase = 'Post-Installation'
		
		## <Perform Post-Installation tasks here>
       
		## Set EBI Inventory Keys
		Set-EBIInventoryKeys
	}
	ElseIf ($deploymentType -ieq 'Uninstall')
	{
		##*===============================================
		##* PRE-UNINSTALLATION
		##*===============================================
		[string]$installPhase = 'Pre-Uninstallation'
		
		## Show Welcome Message, close Internet Explorer with a 60 second countdown before automatically closing
		# Show-InstallationWelcome -CloseApps 'iexplore' -CloseAppsCountdown 60
			
		## <Perform Pre-Uninstallation tasks here>
				
		##*===============================================
		##* UNINSTALLATION
		##*===============================================
		[string]$installPhase = 'Uninstallation'
		
		# <Perform Uninstallation tasks here>

        Do-InstUninstall
        #Execute-Uninstall $Installation
        		
		##*===============================================
		##* POST-UNINSTALLATION
		##*===============================================
		[string]$installPhase = 'Post-Uninstallation'
    
		## Remove EBI Inventory Keys
		Remove-EBIInventoryKeys
	}
	
	Invoke-WMIMethod -ComputerName localhost -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000121}" # Application Deployment Evaluation Cycle
	Invoke-WMIMethod -ComputerName localhost -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000022}" # Machine Policy Evaluation Cycle
	Invoke-WMIMethod -ComputerName localhost -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000002}" # Software Inventory Cycle	
	
	##*===============================================
	##* END SCRIPT BODY
	##*===============================================

    if (($Instructions.AllowedReturnCodesReboot -split ",") -contains $mainExitCode){
        $mainExitCode = 3010
    }
	
	## Call the Exit-Script function to perform final cleanup operations
	Exit-Script -ExitCode $mainExitCode
}
Catch {
	[int32]$mainExitCode = 60001
	[string]$mainErrorMessage = "$(Resolve-Error)"
	Write-Log -Message $mainErrorMessage -Severity 3 -Source $deployAppScriptFriendlyName
	Show-DialogBox -Text $mainErrorMessage -Icon 'Stop'
	Exit-Script -ExitCode $mainExitCode
}