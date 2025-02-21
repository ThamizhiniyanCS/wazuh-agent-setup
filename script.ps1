$ManagerIP = "10.9.108.141"
$BaseURL = "https://raw.githubusercontent.com/ThamizhiniyanCS/wazuh-agent-setup/refs/heads/main"

# Setting up Wazuh Agent
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.10.1-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER=$ManagerIP WAZUH_AGENT_GROUP='windows_lab' 

# Enabling Powershell Logging
function Enable-PSLogging {
    # Define registry paths for ScriptBlockLogging and ModuleLogging
    $scriptBlockPath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $moduleLoggingPath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    
    # Enable Script Block Logging
    if (-not (Test-Path $scriptBlockPath)) {
        $null = New-Item $scriptBlockPath -Force
    }
    Set-ItemProperty -Path $scriptBlockPath -Name EnableScriptBlockLogging -Value 1
    # Enable Module Logging
    if (-not (Test-Path $moduleLoggingPath)) {
        $null = New-Item $moduleLoggingPath -Force
    }
    Set-ItemProperty -Path $moduleLoggingPath -Name EnableModuleLogging -Value 1
    
    # Specify modules to log - set to all (*) for comprehensive logging
    $moduleNames = @('*')  # To specify individual modules, replace * with module names in the array
    New-ItemProperty -Path $moduleLoggingPath -Name ModuleNames -PropertyType MultiString -Value $moduleNames -Force
    Write-Output "Script Block Logging and Module Logging have been enabled."
}

Enable-PSLogging

Write-Output "[+] Successfully enabled Powershell logging!"

# Function to Download and Extract a ZIP File
function Download-And-Extract {
    param (
        [string]$url,
        [string]$downloadPath,
        [string]$extractPath
    )

    Invoke-WebRequest -Uri $url -OutFile $downloadPath

    if (!(Test-Path $extractPath)) {
        New-Item -ItemType Directory -Path $extractPath | Out-Null
    }

    Expand-Archive -Path $downloadPath -DestinationPath $extractPath -Force
    Remove-Item $downloadPath -Force
}

# Setting up Yara
Download-And-Extract -url "$BaseURL/bin.zip" -downloadPath "$env:TEMP\bin.zip" -extractPath "C:\Program Files (x86)\ossec-agent\active-response\bin"
Write-Output "[+] Successfully setup Yara!"

# Setting up Sysmon
Download-And-Extract -url "$BaseURL/Sysmon.zip" -downloadPath "$env:TEMP\Sysmon.zip" -extractPath "C:\"
C:\Sysmon\Sysmon64.exe -accecptula -i C:\Sysmon\sysmonconfig.xml
Write-Output "[+] Successfully setup Sysmon!"

# Setting up Suricata
Download-And-Extract -url "$BaseURL/Suricata.zip" -downloadPath "$env:TEMP\Suricata.zip" -extractPath "C:\Program Files\"
Write-Output "[+] Successfully setup Suricata!"

Start-Service -Name "WazuhSvc"

Read-Host "Press Enter to exit"
