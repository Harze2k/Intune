# Version 1.6
# Note: Cleaned up extra | Out-String that was redundant.
# https://github.com/Harze2k/Intune/blob/main/IntuneCustomDetection.ps1
#
# Description:
# Just change the variable $appToCheck to what you need.
# Test locally so its found then upload as detection script for that app in Intune.
#

Function Get-CurrentUser 
{
	$LoggedInUser = (Get-CimInstance -ClassName Win32_ComputerSystem).Username
  		if($LoggedInUser.Contains('@')) 
    		{
    			Write-Host 'Most likley logged in with UPN, returning that instead'
      			Return $LoggedInUser
    		}
	$LoggedInUser = $LoggedInUser.split("\")
		if($null -ne $LoggedInUser)
      		{
        		$LoggedInUser = $LoggedInUser[1].TrimEnd()
        		Return $LoggedInUser
		}
		if($null -eq $LoggedInUser)
      		{
			Return "Error: No current user found"
		}
}

Function Get-Uninstaller 
{
  	[CmdletBinding()]
  	param(
    		[Parameter(Mandatory = $true)]
    		[ValidateNotNullOrEmpty()]
    		[string] $Name
  	)    	
	$objUser = New-Object System.Security.Principal.NTAccount($currUser)
	$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
    	$local_key     = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    	$machine_key32 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    	$machine_key64 = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
		if($currUser -ne "Error: No current user found")
      		{
        		$local_key_CU = "registry::HKEY_USERS\$($strSID.Value)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        		$keys = @($local_key, $local_key_CU, $machine_key32, $machine_key64)
      		}
      		else
		{
      			$keys = @($local_key, $machine_key32, $machine_key64)
      		}
    	Get-ItemProperty -Path $keys -ErrorAction 'SilentlyContinue' | Where-Object{ ($_.DisplayName -like "*$Name*") -or ($_.PsChildName -like "*$Name*") } | Select-Object PsPath,DisplayVersion,DisplayName,UninstallString,InstallSource,InstallLocation,QuietUninstallString,InstallDate
}

##### Variables - Change below #####
$appToCheck = "*Microsoft Teams*" #App to search for.
$errorCode = 1605 #Set your preferred code here.
$success = 0 #Set your preferred code here, 0 is the default used so maybe not change it.
##### Variables - Change above #####

$currUser = Get-CurrentUser
$app = Get-Uninstaller $appToCheck -ErrorAction SilentlyContinue 
  	if ($null -ne ($app))
  	{
  		Write-Host "$($app.DisplayName) is there, perfect! Code: $success"
    		Exit $success
 	}
  	else 
  	{
  		Write-Host "$appToCheck not installed.. Error: $errorCode"
    		Exit $errorCode
 	}
