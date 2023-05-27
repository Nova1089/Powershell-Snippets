function Initialize-ColorScheme
{
    $script:successColor = "Green"
    $script:infoColor = "DarkCyan"
    $script:failColor = "Red"
    # warning color is yellow, but that is built into Write-Warning
}

function Show-Introduction
{
    Write-Host "This script exports Azure AD user info." -ForegroundColor $infoColor
    Read-Host "Press Enter to continue"
}

function Use-Module($moduleName)
{    
    $keepGoing = -not(Test-ModuleInstalled $moduleName)
    while ($keepGoing)
    {
        Prompt-InstallModule $moduleName
        Test-SessionPrivileges
        Install-Module $moduleName

        if ((Test-ModuleInstalled $moduleName) -eq $true)
        {
            Write-Host "Importing module..." -ForegroundColor $infoColor
            Import-Module $moduleName
            $keepGoing = $false
        }
    }
}

function Test-ModuleInstalled($moduleName)
{    
    $module = Get-Module -Name $moduleName -ListAvailable
    return ($null -ne $module)
}

# new version
function Prompt-InstallModule($moduleName)
{
    do 
    {
        Write-Host "$moduleName module is required." -ForegroundColor $infoColor
        $confirmInstall = Read-Host -Prompt "Would you like to install the module? (y/n)"
    }
    while ($confirmInstall -inotmatch "^\s*y\s*$") # regex matches a y but allows spaces
}

# old version
function Prompt-InstallModule($moduleName)
{
    do 
    {
        Write-Host "$moduleName module is required." -ForegroundColor $infoColor
        $confirmInstall = Read-Host -Prompt "Would you like to install the module? (y/n)"
    }
    while ($confirmInstall -inotmatch "(?<!\S)y(?!\S)") # regex matches a y but allows spaces
}

# new version
function Test-SessionPrivileges
{
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentSessionIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($currentSessionIsAdmin -ne $true)
    {
        Write-Host ("Please run script with admin privileges.`n" +
        "1. Open Powershell as admin.`n" +
        "2. CD into script directory.`n" +
        "3. Run .\scriptname`n") -ForegroundColor $failColor
        Read-Host "Press Enter to exit"
        exit
    }
}

# old version
function Test-SessionPrivileges
{
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentSessionIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($currentSessionIsAdmin -ne $true)
    {
        Throw "Please run script with admin privileges. 
            1. Open Powershell as admin.
            2. CD into script directory.
            3. Run .\scriptname.ps1"
    }
}

function TryConnect-MgGraph
{
    $connected = Test-ConnectedToMgGraph

    while(-not($connected))
    {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor $infoColor
        Connect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        $connected = Test-ConnectedToMgGraph

        if (-not($connected))
        {
            Read-Host "Failed to connect to Microsoft Graph. Press Enter to try again"
        }
        else
        {
            Write-Host "Successfully connected!" -ForegroundColor $successColor
        }
    }    
}

function Test-ConnectedToMgGraph
{
    return $null -ne (Get-MgContext)
}

function TryConnect-ExchangeOnline
{
    $connectionStatus = Get-ConnectionInformation -ErrorAction SilentlyContinue

    while ($null -eq $connectionStatus)
    {
        Write-Host "Connecting to Exchange Online..."
        Connect-ExchangeOnline -ErrorAction SilentlyContinue
        $connectionStatus = Get-ConnectionInformation

        if ($null -eq $connectionStatus)
        {
            Read-Host -Prompt "Failed to connect to Exchange Online. Press Enter to try again"
        }
    }
}

function TryConnect-MsolService
{
    Get-MsolDomain -ErrorVariable errorConnecting -ErrorAction SilentlyContinue | Out-Null

    while ($errorConnecting)
    {
        Write-Host "Connecting to MsolService..." -ForegroundColor $infoColor
        Connect-MsolService -ErrorAction SilentlyContinue
        Get-MSolDomain -ErrorVariable errorConnecting -ErrorAction SilentlyContinue | Out-Null   

        if ($errorConnecting)
        {
            Read-Host -Prompt "Failed to connect to MsolService. Press Enter to try again"
        }
    }
}

# new
function New-DesktopPath($fileName, $fileExt, [switch]$includeTimeStamp)
{
    $desktopPath = [Environment]::GetFolderPath("Desktop")

    if ($includeTimeStamp)
    {
            $timeStamp = (Get-Date -Format yyyy-MM-dd-hh-mm).ToString()
        return "$desktopPath\$fileName $timeStamp.$fileExt"
    }
    return "$desktopPath\$fileName.$fileExt"
}

# old
function New-DesktopPath($fileName, $fileExt)
{
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $timeStamp = (Get-Date -Format yyyy-MM-dd-hh-mm).ToString()
    return "$desktopPath\$fileName $timeStamp.$fileExt"
}

function Get-DesktopPath
{
    # this method is preferable to $home\desktop because it accounts for the desktop path being moved into OneDrive
    return [Environment]::GetFolderPath("Desktop")
}


function New-TimeStamp
{
    return (Get-Date -Format yyyy-MM-dd-hh-mm).ToString()
}

# new version
function Prompt-YesOrNo($question)
{
    Write-Host "$question`n[Y] Yes  [N] No"

    do
    {
        $response = Read-Host
        $validResponse = $response -imatch '^\s*[yn]\s*$' # regex matches y or n but allows spaces
        if (-not($validResponse)) 
        {
            Write-Warning "Please enter y or n."
        }
    }
    while (-not($validResponse))

    if ($response -imatch '^\s*y\s*$') # regex matches a y but allows spaces
    {
        return $true
    }
    return $false
}

# old version
function Prompt-YesOrNo($question)
{
    do
    {
        $response = Read-Host "$question y/n"
    }
    while ($response -inotmatch '(?<!\S)[yn](?!\S)') # regex matches y or n but allows spaces

    if ($response -imatch '(?<!\S)y(?!\S)') # regex matches a y but allows spaces
    {
        return $true
    }
    return $false   
}

function Prompt-YesOrNo($question, [switch]$includeYesToAll, [switch]$includeNoToAll)
{
    $prompt = ("$question`n" + 
                "[Y] Yes  [N] No")
    
    if ($includeYesToAll -and $includeNoToAll)
    {
        $prompt += "  [A] Yes to All  [L] No to All"

        $response = Read-HostAndValidate -prompt $prompt -regex '^\s*[ynal]\s*$' -warning "Please enter y, n, a, or l."
    }
    elseif($includeYesToAll)
    {
        $prompt += "  [A] Yes to All"

        $response = Read-HostAndValidate -prompt $prompt -regex '^\s*[yna]\s*$' -warning "Please enter y, n, or a."
    }
    elseif($includeNoToAll)
    {
        $prompt += "  [L] No to All"

        $response = Read-HostAndValidate -prompt $prompt -regex '^\s*[ynl]\s*$' -warning "Please enter y, n, or l."        
    }
    else
    {
        $response = Read-HostAndValidate -prompt $prompt -regex '^\s*[yn]\s*$' -warning "Please enter y or n." 
    }

    return $response.Trim().ToUpper()
}

function Read-HostAndValidate($prompt, $regex, $warning)
{
    Write-Host $prompt

    do
    {
        $response = Read-Host

        if ($response -inotmatch $regex)
        {
            Write-Warning $warning
        }
    }
    while ($response -inotmatch $regex)

    return $response
}

function SafelyInvoke-RestMethod($uri, $method, $headers, $body)
{
    try
    {
        $response = Invoke-RestMethod -Uri $uri -Method $method -Headers $headers -Body $body -ErrorVariable "responseError"
    }
    catch
    {
        Write-Host $responseError -ForegroundColor $failColor
        exit
    }

    return $response
}

