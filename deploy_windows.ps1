$ToolPath = "D:\Tools"
$CodePath = "D:\Dev\code"
$ToolsToAddToPathEnvironmentVariable = @(
    "Busybox", 
    "john\run", 
    "hashcat"
)

$WingetUserScopeSoftwareList = @(
    "Microsoft.VisualStudioCode",
    "volta.Volta",
    "Tencent.QQ.NT",
    "Tencent.WeChat",
    "qier222.YesPlayMusic",
    "Telegram.TelegramDesktop",
    "Valve.Steam",
    "JetBrains.Toolbox",
    "c0re100.qBittorrent-Enhanced-Edition",
    "9WZDNCRD29V9",
    "OBSProject.OBSStudio",
    "JetBrains.CLion",
    "JetBrains.WebStorm",
    "JetBrains.IntelliJIDEA.Ultimate",
    "JetBrains.DataGrip",
    "JetBrains.GoLand",
    "JetBrains.PyCharm.Professional",
    "Google.AndroidStudio"
)

$WingetSystemScopeSoftwareList = @(
    "Google.Chrome",
    "M2Team.NanaZip.Preview",
    "Anaconda.Miniconda3",
    "Helix.Helix",
    "Microsoft.WSL",
    "VideoLAN.VLC",
    "9NF7JTB3B17P"
)

$OptionalFeatureToEnable = @(
    "Microsoft-Hyper-V-All",
    "Microsoft-Windows-Subsystem-Linux",
    "TFTP",
    "Microsoft-Hyper-V",
    "Microsoft-Hyper-V-Tools-All",
    "Microsoft-Hyper-V-Management-PowerShell",
    "Microsoft-Hyper-V-Hypervisor",
    "Microsoft-Hyper-V-Services",
    "Microsoft-Hyper-V-Management-Clients",
    "TelnetClient",
    "LegacyComponents",
    "DirectPlay"
)

$RegistryPath = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarAl",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowTaskViewButton",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDa",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
)

$GitConfigure = @{
    username   = "undefined"
    email      = "undefined_1@outlook.com"
    sshKeyPath = $null
}

## 检查当前用户是否具有管理员权限
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    # 如果没有管理员权限，重新启动脚本并申请管理员权限
    $scriptPath = $MyInvocation.MyCommand.Path
    
    # 创建一个进程启动信息对象
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = "powershell"
    $startInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    $startInfo.Verb = "runas"
    
    # 启动新的进程
    [System.Diagnostics.Process]::Start($startInfo) | Out-Null
    # 退出当前进程
    exit
}

function RefreshEnvironmentVariables {
    param ()
    $envVars = [System.Environment]::GetEnvironmentVariables('Machine')
    $envVars += [System.Environment]::GetEnvironmentVariables('User')

    # 将环境变量加载到当前会话
    foreach ($key in $envVars.Keys) {
        ${Env:$key} = $envVars[$key]
    }
}

## 禁用SmartScreen
Write-Output "Disabling SmartScreen Filter..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0


## Tools文件夹添加至Defender排除项
Get-ChildItem -Path $ToolPath -Directory | Select-Object -ExpandProperty FullName | ForEach-Object {
    Write-Output "Add '$_' to defender exclusion Path."
    Add-MpPreference -ExclusionPath $_
}
Write-Output "Add '$CodePath' to defender exclusion Path."
Add-MpPreference -ExclusionPath $CodePath
# Add the Path environment variable
[System.Environment]::SetEnvironmentVariable("Path", [System.Environment]::GetEnvironmentVariable("Path", "User") + ";$ToolPath", [System.EnvironmentVariableTarget]::User)
foreach ($tool in $ToolsToAddToPathEnvironmentVariable) {
    $AbsluteToolPath = Join-Path -Path $ToolPath -ChildPath $tool
    if (Test-Path -Path $AbsluteToolPath -PathType Container) {
        Write-Output "Add '$($AbsluteToolPath)' to Path environment variable."
        [System.Environment]::SetEnvironmentVariable("Path", [System.Environment]::GetEnvironmentVariable("Path", "User") + ";$($AbsluteToolPath)", [System.EnvironmentVariableTarget]::User)
    }
}

foreach ($registryPath in $RegistryPath) {
    if (-not (Test-Path $registryPath)) {
        # 如果路径不存在，创建路径
        New-Item -Path $registryPath -Force | Out-Null
    }
}

# 任务栏显秒
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -Value 1 -PropertyType DWord -Force
# 修改开始菜单布局为更多固定
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_Layout" -Value 1 -PropertyType DWord -Force
# 禁用开始菜单建议项
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_IrisRecommendations" -Value 0 -PropertyType DWord -Force
# 任务栏靠左对齐
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarAl" -Name "SystemSettings_DesktopTaskbar_Al" -Value 0 -PropertyType DWord -Force
# 隐藏任务栏上的任务视图按钮
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowTaskViewButton" -Name "SystemSettings_DesktopTaskbar_TaskView" -Value 0 -PropertyType DWord -Force
# 隐藏任务栏上的"小组件"按钮
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDa" -Name "SystemSettings_DesktopTaskbar_Da" -Value 0 -PropertyType DWord -Force
# 禁用快速启动&休眠
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -PropertyType DWord -Force
powercfg -h off
# 关闭Windows聚焦
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnable" -Value 0 -PropertyType DWord -Force


RefreshEnvironmentVariables

foreach ($feature in $OptionalFeatureToEnable) {
    Write-Output "Enabling Windows Optional Feature: $feature"
    Enable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
}

winget upgrade --all
RefreshEnvironmentVariables

## 安装必须软件
# Visual Studio 2022 Community
winget install --id="Microsoft.VisualStudio.2022.Community" -e --overwrite "--passive --config dotfiles/.vsconfig" -h --accept-source-agreements --accept-package-agreements
# Miniconda3
winget install --id="Anaconda.Miniconda3" -e -h --accept-source-agreements --accept-package-agreements --overwrite "/InstallationType=JustMe /RegisterPython=1 /AddToPath=1 /S"
# Git
winget install --id="Git.Git" -e -h --accept-source-agreements --accept-package-agreements --overwrite "/SILENT /NORESTART /COMPONENTS='icons,ext\reg\shellhere,assoc,assoc_sh,windowsterminal,gitlfs' "
foreach ($software in $WingetSystemScopeSoftwareList) {
    winget install --id=$software -e -h --accept-source-agreements --accept-package-agreements --scope machine
}
foreach ($software in $WingetUserScopeSoftwareList) {
    winget install --id=$software -e -h --accept-source-agreements --accept-package-agreements --scope user
}

RefreshEnvironmentVariables


# 配置 Git
git config --global user.name $GitConfigure.username
git config --global user.email $GitConfigure.email

Get-Service -Name ssh-agent | Set-Service -StartupType Manual
Start-Service ssh-agent

if ($null -ne $GitConfigure.sshKeyPath) {
    ssh-add $GitConfigure.sshKeyPath
}else {
    # 使用默认路径或创建密钥
    if (-not (Test-Path -Path $env:USERPROFILE\.ssh\id_ed25519)) {
        Write-Output "SSH key not exist, Generating SSH Key..."
        ssh-keygen -t ed25519 -C $GitConfigure.email -N '' -q -f $env:USERPROFILE\.ssh\id_ed25519
    }
    ssh-add.exe $env:USERPROFILE\.ssh\id_ed25519
    Write-Output "Ssh Public Key:"
    Write-Output (Get-Content -Path $env:USERPROFILE\.ssh\id_ed25519.pub)
    Write-Output "Copied to clipboard."
    Set-Clipboard -Value (Get-Content -Path $env:USERPROFILE\.ssh\id_ed25519.pub)
}

# 复制配置文件到用户目录
Copy-Item -Path "dotfiles\*" -Destination $env:USERPROFILE -Recurse -Force
