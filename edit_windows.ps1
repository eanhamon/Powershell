#Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process

$user = "eharmon"
$group = "Tetraaccounting"
$directoryPath = "C:\Tetra"
$Password = ConvertTo-SecureString "password" -AsPlainText -Force
$acl = Get-Acl $directoryPath
$WallpaperURL = "https://www.alphr.com/wp-content/uploads/2022/06/9-6-1024x576.png"
$LockscreenUrl = "https://www.alphr.com/wp-content/uploads/2022/06/9-6-1024x576.png"
$ImageDestinationFolder = "c:\temp"
$WallpaperDestinationFile = "$ImageDestinationFolder\wallpaper.png"
$LockScreenDestinationFile = "$ImageDestinationFolder\LockScreen.png"


#user config
if (Get-LocalUser -Name $user -ErrorAction SilentlyContinue) {
    Write-Host "User $user already exists. Continuing with the script..."
} else {
    $Password = ConvertTo-SecureString "password" -AsPlainText -Force
    New-LocalUser -Name $user -FullName "Ean Harmon" -Password $Password
    Write-Host "User $user created successfully."
}


if (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue) {
    Write-Host "Group $group already exists. Continuing with the script..."
} else {
    New-LocalGroup -Name $group -Description "Tetra Shillings Accounting Group"
    Write-Host "Group $group created successfully."
}

if (Get-LocalGroupMember -Group $group | Where-Object { $_.Name -eq $user }) {
    Write-Host "User $user is already in $group. Continuing with the script..."
} else{
Add-LocalGroupMember -Group $group -Member $user}
#folder config


if (Test-Path -Path $directoryPath) {
    Write-Host "Directory $directoryPath exists."
} else {
    Write-Host "Directory $directoryPath does not exist."
}

$existingRule = $acl.Access | Where-Object {
    $_.IdentityReference -eq $group -and $_.FileSystemRights -eq "FullControl" -and $_.AccessControlType -eq "Allow"
}


# checks if folder has permissions
if ($existingRule) {
    Write-Host "The group $group already has FullControl permissions. Continuing..."
} else {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $group, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $acl.SetAccessRule($rule)
    Set-Acl $directoryPath $acl
    
    Write-Host "FullControl permissions granted to $group on $directoryPath."
}


#firewall rule to block icmp https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2025-ps
if (Get-NetFirewallRule -DisplayName "Block ICMPv4"){
Write-Host "firewall rule Block ICMPv4 already exists"} else{
New-NetFirewallRule -DisplayName "Block ICMPv4" -Direction Inbound -Protocol ICMPv4 -Action Block}


# sets password policy https://stackoverflow.com/questions/23260656/modify-local-security-policy-using-powershell
secedit /export /cfg c:\secpol.cfg
(gc C:\secpol.cfg).replace("MaximumPasswordAge = 42", "MaximumPasswordAge = 60") | Out-File C:\secpol.cfg
(gc C:\secpol.cfg).replace("PasswordHistorySize = 0", "PasswordHistorySize = 24") | Out-File C:\secpol.cfg
(gc C:\secpol.cfg).replace("MinimumPasswordLength = 0", "MinimumPasswordLength = 12") | Out-File C:\secpol.cfg
(gc C:\secpol.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") | Out-File C:\secpol.cfg
secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
rm -force c:\secpol.cfg -confirm:$false

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordHistorySize" -Value 24
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "MinimumPasswordLength" -Value 12
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordComplexity" -Value 1

gpupdate /force

# modify desktop background

mkdir $ImageDestinationFolder -erroraction silentlycontinue
Start-BitsTransfer -Source $WallpaperURL -Destination "$WallpaperDestinationFile"
Start-BitsTransfer -Source $LockscreenUrl -Destination "$LockScreenDestinationFile"

# https://powershellfaqs.com/change-wallpaper-with-powershell/
function Set-Wallpaper {
    param (
        [string]$imagePath,
        [int]$style
    )

    
    $SPI_SETDESKWALLPAPER = 0x0014
    $SPIF_UPDATEINIFILE = 0x01
    $SPIF_SENDCHANGE = 0x02

    Add-Type @"
        using System;
        using System.Runtime.InteropServices;
        public class Wallpaper {
            [DllImport("user32.dll", CharSet = CharSet.Auto)]
            public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
        }
"@

    [Wallpaper]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $imagePath, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)
}



Set-Wallpaper -imagePath $WallpaperDestinationFile -style 0  # 0 for the default wallpaper style
$error.clear()


# modify desktop theme https://stackoverflow.com/questions/32045681/windows-10-apply-theme-programmatically

Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0 -Type Dword -Force


#rename pc
Rename-Computer -NewName "$user-PC" -Force
