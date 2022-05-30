function Do-Anything
{
	[CmdletBinding()]
	Param
	(
		# Action controls what the script does
		[Parameter(Mandatory=$true)]
		[ValidateSet("PreInstall","Install","PostInstall","PreUninstall","Uninstall","PostUninstall")]
		[string]$Action,
		[string]$Condition,
		[string]$IgnoreExitCodes = "0,3010"
	)

	##* Do not modify section below
	#region DoNotModify

	#. ".\AppDeployToolkit\AppDeployToolkitMain.ps1" -DisableLogging $True

	#endregion
	##* Do not modify section above

	##* Your own script
	#region OwnScript

	# Important: If a Cmdlet Return an object set the output to null -> Out-Null

	[int32]$ExitCode = 0

	# Create Pre- and Post- Inst-/Uninstall cases if needed
	switch ($Action)
	{
		'Install' {
			
			try {
                Get-ChildItem -Path HKLM:\Software\EBI -Recurse -Include *SUZI* -ErrorAction SilentlyContinue | Remove-Item
				
			} catch { $ExitCode = 1603; Write-Log -Message $_.Exception.Message -Source 'DeploymentScript' -Severity 3 }
		}

		'Uninstall' {
			try {
			    
			} catch { $ExitCode = 1603; Write-Log -Message $_.Exception.Message -Source 'DeploymentScript' -Severity 3 }
		}
	}

	$mainExitCode = $ExitCode
	
	<#
	Switch ($Results.ExitCode) {
		129 { [int32]$mainExitCode = 1641 }
		130 { [int32]$mainExitCode = 1641 }
          0 { }
		Default { [int32]$mainExitCode = $Results.ExitCode }
	}
	#>

	if ($mainExitCode -ne 0 -and $mainExitCode -ne 3010 -and $mainExitCode -ne $null -and ($IgnoreExitCodes -split ",") -notcontains $mainExitCode){
		Exit-Script -ExitCode $mainExitCode
	}
}
#endregion
##* Your own script