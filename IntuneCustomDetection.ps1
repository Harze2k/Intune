# Version 2.0
# Added -UninstallMSI and -Quiet
# Get-Uninstaller -Name $appToCheck -UninstallMSI -Quiet
# Will get you the application uninstalled if its an Msi, no status returned.
#
# Get-Uninstaller -Name $appToCheck -UninstallMSI
# Will get you the application uninstalled if its an Msi, status from MsiExex (0 is prefered = success) and will get you pre-uninstall status from registry.
#
# Get-Uninstaller -Name $appToCheck
# Will get you regedit information about the app, searching as [CurrentUser] and [SYSTEM] context.
#
# Note: Improved error handling if no current user was found.
# https://github.com/Harze2k/Intune/blob/main/IntuneCustomDetection.ps1
#
# Description:
# Just change the variable $appToCheck to what you need.
# Test locally so its found then upload as detection script for that app in Intune.
#

Function Get-CurrentUser 
{
	$LoggedInUser = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).Username
	if($null -eq $LoggedInUser)
	{
  		Return "Error: No current user found"
	}
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
}

Function Get-Uninstaller 
{
  	[CmdletBinding()]
  	param(
    		[Parameter(Mandatory = $true)]
    		[ValidateNotNullOrEmpty()]
    		[string] $Name,
        	[Parameter(Mandatory = $false)]
    		[ValidateNotNullOrEmpty()]
    		[switch] $UninstallMSI,
            	[Parameter(Mandatory = $false)]
    		[ValidateNotNullOrEmpty()]
    		[switch] $Quiet

  	)    	
        $global:currUser = Get-CurrentUser
        $guidPattern = "(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}"
        $local_key     = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    	$machine_key32 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    	$machine_key64 = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
	if($currUser -ne "Error: No current user found")
      	{	
		$objUser = New-Object System.Security.Principal.NTAccount($global:currUser) -ErrorAction SilentlyContinue
		$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])  
            	$local_key_CU = "registry::HKEY_USERS\$($strSID.Value)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
            	$keys = @($local_key, $local_key_CU, $machine_key32, $machine_key64)
      	}
      	else
	{
      		$keys = @($local_key, $machine_key32, $machine_key64)
      	}

        $return = @(Get-ItemProperty -Path $keys -ErrorAction 'SilentlyContinue' | Where-Object { ($_.DisplayName -like "*$Name*") -or ($_.PsChildName -like "*$Name*") } -ErrorAction SilentlyContinue | Select-Object PsPath,DisplayVersion,DisplayName,UninstallString,InstallSource,InstallLocation,QuietUninstallString,InstallDate,MsiExec_Status -ErrorAction SilentlyContinue)
        if ($Quiet.IsPresent -eq $false -and ($UninstallMSI.IsPresent) -eq $false)
        {
            	Return $return
        }

        if ($UninstallMSI.IsPresent)
        {
            	for ($i=0;$i -le $return.count -1;$i++ )
            	{
                	if ($return[$i].QuietUninstallString -match 'MsiExec.exe /')
                	{
                    		if($Quiet.IsPresent)
                    		{
                        		$uninstall = $return[$i].UninstallString.replace('/I{',"/X{").replace('}',"} /qn").replace('MsiExec.exe ','')
                        		Start-Process "msiexec.exe" -ArgumentList "$uninstall" -NoNewWindow -Wait
                        		if ($i -lt $return.Count -1)
                        		{
                            			Start-Sleep -Seconds 5
                        		}
                    		}
                    		else
                    		{
                        		$uninstall = $return[$i].UninstallString.replace('/I{',"/X{").replace('}',"} /qn").replace('MsiExec.exe ','')
                        		$Guid = [Regex]::Matches($return[$i].UninstallString.replace('/I{',"/X{").replace('}',"} /qn").replace('MsiExec.exe ',''), $guidPattern).Value
                        		$ExitCode = (Start-Process "msiexec.exe" -ArgumentList "$uninstall" -NoNewWindow -Wait -PassThru).ExitCode
                        		if ($i -lt $return.Count -1)
                        		{
                           			Start-Sleep -Seconds 5
                        		}
                        		$return[$i].MsiExec_Status = ("[App: $($return[$i].DisplayName)] [GUID: $Guid] [Version: $($return[$i].DisplayVersion.ToString())] returned [ExitCode: $ExitCode] from MsiExec Uninstall.")
                        		if($i -eq $return.Count -1)
                        		{
                            			Start-Sleep -Seconds 3
                            			$return
                        		}
                    		}
                	}
               		elseif ($return[$i].UninstallString -match 'MsiExec.exe /')
                	{
                    		if($Quiet.IsPresent)
                    		{
                        		$uninstall = $return[$i].UninstallString.replace('/I{',"/X{").replace('}',"} /qn").replace('MsiExec.exe ','')
                        		Start-Process "msiexec.exe" -ArgumentList "$uninstall" -NoNewWindow -Wait
                       			if ($i -lt $return.Count -1)
                        		{
                            			Start-Sleep -Seconds 5
                        		}
                    		}
                    		else
                    		{   
		 			$uninstall = $return[$i].UninstallString.replace('/I{',"/X{").replace('}',"} /qn").replace('MsiExec.exe ','')
                        		$Guid = [Regex]::Matches($return[$i].UninstallString.replace('/I{',"/X{").replace('}',"} /qn").replace('MsiExec.exe ',''), $guidPattern).Value
                        		$ExitCode = (Start-Process "msiexec.exe" -ArgumentList "$uninstall" -NoNewWindow -Wait -PassThru).ExitCode
                        		if ($i -lt $return.Count -1)
                        		{
                            			Start-Sleep -Seconds 5
                        		}
                        		$return[$i].MsiExec_Status = ("[App: $($return[$i].DisplayName)] [GUID: $Guid] [Version: $($return[$i].DisplayVersion.ToString())] returned [ExitCode: $ExitCode] from MsiExec Uninstall.")
                        		if($i -eq $return.Count -1)
                        		{
                            			Start-Sleep -Seconds 3
                            			$return
                        		}
                        
                    		}
                	}
                	else 
                	{
                    		if($Quiet.IsPresent)
                    		{
                        		#Any action to do here#
                    		}
                    		else 
                    		{
                        		$return[$i].MsiExec_Status = ("[App: $($return[$i].DisplayName)] [GUID: Null] [Version: $($return[$i].DisplayVersion.ToString())] returned [ExitCode: Error: No MSI GUID found to uninstall.] from MsiExec Uninstall.")
                        		if($i -eq $return.Count -1)
                        		{
                            			Start-Sleep -Seconds 3
                            			$return
                        		}
                    		}
                	}
      		}	
	}
}

##### Variables - Change below #####
$appToCheck = "*Microsoft Teams*" #App to search for.
$errorCode = 1605 #Set your preferred code here.
$success = 0 #Set your preferred code here, 0 is the default used so maybe not change it.
##### Variables - Change above #####

$ReturnedStatus = Get-Uninstaller -Name $appToCheck
#$ReturnedStatus[0..$($ReturnedStatus.Count -1)].MsiExec_Status

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
