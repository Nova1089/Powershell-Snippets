function Initialize-ColorScheme
{
    $script:successColor = "Green"
    $script:infoColor = "DarkCyan"
    $script:failColor = "Red"
    $script:warningColor = "Yellow"
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

# new version basic
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

# new version advanced
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

function SafelyInvoke-RestMethod($method, $uri, $headers, $body)
{
    try
    {
        $response = Invoke-RestMethod -Method $method -Uri $uri -Headers $headers -Body $body -ErrorVariable "responseError"
    }
    catch
    {
        Write-Host $responseError[0].Message -ForegroundColor $failColor
        exit
    }

    return $response
}

function Convert-SecureStringToPsCredential($secureString)
{
    # Just passing "null" for username, because username will not be used.
    return New-Object System.Management.Automation.PSCredential("null", $secureString)
}

function Convert-SecureStringToPlainText($secureString)
{
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
}

function ConvertTo-Base64($text)
{
    return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($text))
}

function Convert-PsCredentialToBase64($psCredential)
{
    # append :x because FreshDesk expecting that (could x or anything else)
    return ConvertTo-Base64 ($psCredential.GetNetworkCredential().Password + ":X") 
}

function ConvertFrom-Base64($base64Text)
{
    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64Text))
}

function Prompt-Csv($expectedHeaders)
{
    do
    {
        $path = Read-Host "Enter path to CSV"
        $path = $path.Trim('"')
        $extension = [IO.Path]::GetExtension($path)

        if ($extension -ne '.csv')
        {
            Write-Warning "File type is $extension. Please enter a CSV."
            $keepGoing = $true
            continue
        }

        try
        {
            $records = Import-CSV -Path $path -ErrorAction SilentlyContinue
        }
        catch
        {
            Write-Warning "CSV not found."
            $keepGoing = $true
            continue
        }

        if ($records.Count -eq 0)
        {
            Write-Warning "CSV is empty."
            $keepGoing = $true
            continue
        }

        $hasExpectedHeaders = Validate-CsvHeaders -ImportedCsv $records -ExpectedHeaders $expectedHeaders
        if (-not($hasExpectedHeaders))
        {
            $keepGoing = $true
            continue
        }
        
        $keepGoing = $false
    }
    while ($keepGoing)

    Write-Host "CSV was found and validated." -ForegroundColor $successColor

    return $records
}

function Validate-CsvHeaders($importedCsv, $expectedHeaders)
{
    $hasExpectedHeaders = $true

    if ($null -eq $expectedHeaders)
    {
        return $true
    }

    foreach ($header in $expectedHeaders)
    {
        # check if first record has a property named $header
        if ($importedCsv[0].psobject.properties.match($header).Count -eq 0)
        {
            Write-Warning "CSV is missing a header called $header."
            $hasExpectedHeaders = $false
        }
    }
    
    if (-not($hasExpectedHeaders))
    {
        Write-Host "Please add the missing headers and try again." -ForegroundColor $warningColor
    }

    return $hasExpectedHeaders
}

function Prompt-TextFile
{
    do
    {
        $path = Read-Host "Enter path to .txt file. (i.e. C:\FileName.txt)"
        $path = $path.Trim('"')
        $content = Get-Content -Path $path -ErrorAction SilentlyContinue

        if ($null -eq $content)
        {
            Write-Warning "File not found or contents are empty."
            $keepGoing = $true
            continue
        }
        else
        {
            $keepGoing = $false
        }
    }
    while ($keepGoing)

    return $content
}

function Parse-StringWithDelimiter($string, $delimiter)
{
    return ($string.Split("$delimiter")).Trim()
}

function Validate-Email($email)
{
    # Expects email in format of word1.word2@domain.com where word1 is first name and word2 is last name.  
    $isValidEmail = $email -imatch '^\s*[\w\.-]+\.[\w\.-]+@[\w\.-]+\.\w{2,4}\s*$'
    
    if (-not($isValidEmail))
    {
        Write-Warning ("Email is invalid: $email `n" +
                "    Expected format is firstname.lastname@domain.com `n")
    }

    return $isValidEmail
}