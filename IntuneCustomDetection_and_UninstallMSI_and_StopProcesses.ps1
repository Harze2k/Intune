# Version 2.6
<#
Get-Uninstaller -Name "Teams"                                       // Will retrun data from the registry for that application
Get-Uninstaller -Name "Teams" -CheckDetection                       // Quick check if present for Intune detection, $return true or $false
Get-Uninstaller -Name "Teams" -StopProcess                          // Will stop all processes related to the name "Teams" it can find and send back info about the closed processes and also about the application(s) found.
Get-Uninstaller -Name "Teams" -StopProcess -Quiet                   // All of the above but silent, nothing returned.
Get-Uninstaller -Name "Teams" -StopProcess -UninstallMSI            // Will stop all processes related to the name "Teams" it can find and send back info about the closed processes and also about the application(s) found. And silently uninstall any of them that has a MSI {GUID}. And return status from the uninstallation.
Get-Uninstaller -Name "Teams" -StopProcess -UninstallMSI -Quiet     // All of the above but silent, nothing returned.


Get-Uninstaller -Name "Discord" -StopProcess -CheckDetection -Quiet //Doesnt respect the Quiet yet, need a re write.
Might be other combos not working, not sure right now. Try it out :)

Or for use with detecting installed applications in intune:

$AppToCheck = "*Microsoft Teams*"
$ErrorCode = 1605 #Set your preferred code here.
$Success = 0

if (Get-Uninstaller -Name $AppToCheck -CheckDetection)
{
	Write-Host "$AppToCheck is there, perfect! Code: $Success"
    Exit $Success
}
else 
{
    Write-Host "$AppToCheck not installed.. Error: $ErrorCode"
    Exit $ErrorCode
}

#>
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
    		[switch] $UninstallMSI,
    		[switch] $Quiet,
    		[switch] $StopProcess,
            [Switch] $CheckDetection

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
        $return = @()
        $return = @(Get-ItemProperty -Path $keys -ErrorAction 'SilentlyContinue' | Where-Object { ($_.DisplayName -like "*$Name*") -or ($_.PsChildName -like "*$Name*") } -ErrorAction SilentlyContinue | Select-Object PsPath,DisplayVersion,DisplayName,UninstallString,InstallSource,InstallLocation,QuietUninstallString,InstallDate,MsiExec_Status,RunningStatus -ErrorAction SilentlyContinue)
        
        if (($PSBoundParameters.Count) -eq 1 -and ($PSBoundParameters.Keys) -eq 'Name')
        {
            Return $return  
        }

        if($StopProcess.IsPresent)
	    {
        	$SName = $Name.Replace('*','')
            $res = @()
            $status = Get-Process | Select-Object Product,ProcessName,Id,Name,HasExited | Where-Object {$_.Product -match "$SName" -or ($_.ProcessName) -match "$SName"}
            $res = ForEach($s in $status) {
            Stop-Process -Id $S.Id -PassThru -Force -ErrorAction SilentlyContinue
            }
            $StopStatus = "Found $($status.count) processes matching application: $SName and successfully closed $(($res.HasExited).Count)/$($status.count)"
            $statusCheck = Get-Process | Select-Object Product,ProcessName,Id,Name,HasExited | Where-Object {$_.Product -match "$SName" -or ($_.ProcessName) -match "$SName"}
            for ($i=0; $i -le $return.Count-1;$i++)
            {
               	if ($statusCheck -eq $null -and ($status) -eq $null)
               	{
              		$return[$i].RunningStatus = ("Stopped, $SName had 0 processes running.")
               	}
               	elseif($statusCheck.count -eq $status.count)
               	{
               		$return[$i].RunningStatus = ("Running, $SName has $($status.count)/$($statusCheck.count) processes still running.")
               	}
               	else
               	{
                	if(($statusCheck.count) -eq $null -or ($status.count) -eq 0) 
                	{
                    	$return[$i].RunningStatus = ("Stopped, $SName had $($status.count) processes running and now 0 remains.")
                    } 
                    else 
                    {
                        Start-sleep 1
                        $statusCheck2 = Get-Process | Select-Object Product,ProcessName,Id,Name,HasExited | Where-Object {$_.Product -match "$SName" -or ($_.ProcessName) -match "$SName"}
                        if(($statusCheck2.count) -eq $null -or ($statusCheck2.count) -eq 0)
                        {
                            $return[$i].RunningStatus = ("Stopped, $SName had $($status.count) processes running and now 0 remains. But had to run it 2 times.")
                        }
                        else
                        {
                            $return[$i].RunningStatus = ("Unknown, $SName had $($status.count) processes running and now $($statusCheck2.count) remains. Ran it 2 times.")
                        }  
                    }
                }
            }
            if ($Quiet.IsPresent -eq $false)
            {
                $return
            }
        }
        if($CheckDetection.IsPresent)
        {
            if($return[0..($return.length)].DisplayName -match $Name)
            {
               $true
            }
            else
            {
               $false
            }
        }
        for ($i=0;$i -le $return.count -1;$i++ )
    	{
		    if ($Quiet.IsPresent -eq $false -and ($UninstallMSI.IsPresent) -eq $false )
        	{
                Break
        	}
        	if ($UninstallMSI.IsPresent)
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
