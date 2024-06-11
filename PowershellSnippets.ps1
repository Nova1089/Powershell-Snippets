function Initialize-ColorScheme
{
    Set-Variable -Name "successColor" -Value "Green" -Scope "Script" -Option "Constant"
    Set-Variable -Name "infoColor" -Value "DarkCyan" -Scope "Script" -Option "Constant"
    Set-Variable -Name "warningColor" -Value "Yellow" -Scope "Script" -Option "Constant"
    Set-Variable -Name "failColor" -Value "Red" -Scope "Script" -Option "Constant"
}

function Show-Introduction
{
    Write-Host "This script does some stuff..." -ForegroundColor $infoColor
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

function TryConnect-MgGraph($scopes)
{
    $connected = Test-ConnectedToMgGraph
    while (-not($connected))
    {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor $infoColor

        if ($null -ne $scopes)
        {
            Connect-MgGraph -Scopes $scopes -ErrorAction SilentlyContinue | Out-Null
        }
        else
        {
            Connect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }

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

function TryConnect-AzureAD
{
    $connected = Test-ConnectedToAzureAD

    while (-not($connected))
    {
        Write-Host "Connecting to Azure AD..." -ForegroundColor $infoColor
        Connect-AzureAD -ErrorAction SilentlyContinue | Out-Null

        $connected = Test-ConnectedToAzureAD
        if (-not($connected))
        {
            Write-Warning "Failed to connect to Azure AD."
            Read-Host "Press Enter to try again"
        }
    }
}

function Test-ConnectedToAzureAD
{
    try
    {
        Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue | Out-Null
    }
    catch
    {
        return $false
    }
    return $true
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
    return (Get-Date -Format yyyy-MM-dd-hh-mmtt).ToString()
}

function Show-TimeStamp
{
    $timeStamp = Get-Date -Format yyyy-MM-dd-hh-mmtt
    Write-Host $timestamp -ForegroundColor $infoColor
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
        Read-Host "Press Enter to exit"
        exit
    }

    return $response
}

function SafelyInvoke-WebRequest($method, $uri, $headers, $body)
{
    try
    {
        $response = Invoke-WebRequest -Method $method -Uri $uri -Headers $headers -Body $body -ErrorVariable "responseError"
    }
    catch
    {
        Write-Host $responseError[0].Message -ForegroundColor $failColor
        Read-Host "Press Enter to exit"
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

function Encode-UriQueryParams($queryParams)
{ 
    return [uri]::EscapeDataString($queryParams)
}

function Encode-Uri($uri)
{ 
    return [uri]::EscapeUriString($uri)
}

function Encode-Uri($uri)
{ 
    $encodedUri = [uri]::EscapeUriString($uri)
    $encodedUri = $encodedUri.Replace("'", "%27")
    return $encodedUri
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

function Validate-BrsEmail($email)
{
    $isValidEmail = $email -imatch '^\s*[\w\.-]+\.[\w\.-]+(@blueravensolar\.com)\s*$'
    
    if (-not($isValidEmail))
    {
        Write-Warning ("Email is invalid: $email `n" +
            "    Expected format is PreferredFirstName.LastName@blueravensolar.com `n")
    }

    return $isValidEmail
}

function Get-FilePathWithoutExtension($path)
{
    $folder = Split-Path -Path $path -Parent
    $fileName = Split-Path -Path $path -Leaf
    $baseFileName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
    return "$folder\$baseFileName"
}

function Test-FileHasExtension([string]$fileName, [string]$extension)
{
    $actualExtension = [System.IO.Path]::GetExtension($fileName)
    return $actualExtension -ieq $extension.Trim()
}

function Test-IsMemberOfGroup($azureUser, $groupUpn)
{
    $userMemberships = Get-AzureADUserMembership -ObjectId $azureUser.ObjectId

    foreach ($group in $userMemberships)
    {
        if ($group.Mail -ieq $groupUpn)
        {
            return $true
        }
    }
    return $false
}

function Test-IsMemberOfGroup($userUpn, $groupUpn)
{
    return ($null -ne (Get-AzureADGroup -SearchString $groupUpn | Get-AzureADGroupMember -All $true | Where-Object { $_.UserPrincipalName -ieq $userUpn }))
}

function Get-NameFromEmail($email)
{
    return ($email.Split('@'))[0]
}

function Write-ProgressInPipeline
{
    [Cmdletbinding()]
    Param
    (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)]
        [object[]] $inputObjects,
        [string] $activity = "Processing items...",
        [string] $status = "items processed"
    )

    Begin 
    { 
        $itemsProcessed = 1
    }

    Process
    {
        Write-Progress -Activity $activity -Status "$itemsProcessed $status"
        $itemsProcessed++
        return $_
    }
}

function Write-ObjectInPipeline
{
    [Cmdletbinding()]
    Param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [object[]] $inputObjects,
        [string] $activity = "Processing items..."
    )

    Begin 
    { 
        $itemsProcessed = 1
    }

    Process
    {
        Write-Progress -Activity $activity -Status "$itemsProcessed`: $($_.ToString())"
        $itemsProcessed++
        return $_
    }
}

function Prompt-SelectSiteFromList($sites)
{
    Write-Host "Select the desired site."

    $index = 1
    foreach ($site in $sites)
    {
        Write-Host "[$index] $($site.WebUrl)"
        $index++
    }
    
    do
    {
        $selectedIndex = Read-Host
        $selectedIndex = $selectedIndex.Trim()

        if (($selectedIndex -notmatch '^\d+$') -or # check if answer is a digit
            ($selectedIndex -lt 1) -or
            ($selectedIndex -gt $sites.Count))
        {
            Write-Warning "Please enter a digit from 1 to $($sites.Count)."
            $keepGoing = $true
            continue
        }
    }
    while ($keepGoing)

    return $sites[$selectedIndex - 1]
}

function Format-FileSize($sizeInBytes)
{
    if ($sizeInBytes -lt 1KB)
    {
        $formattedSize = $sizeInBytes.ToString() + " B"
    }
    elseif ($sizeInBytes -lt 1MB)
    {
        $formattedSize = $sizeInBytes / 1KB
        $formattedSize = ("{0:n2}" -f $formattedSize) + " KB"
    }
    elseif ($sizeInBytes -lt 1GB)
    {
        $formattedSize = $sizeInBytes / 1MB
        $formattedSize = ("{0:n2}" -f $formattedSize) + " MB"
    }
    elseif ($sizeInBytes -lt 1TB)
    {
        $formattedSize = $sizeInBytes / 1GB
        $formattedSize = ("{0:n2}" -f $formattedSize) + " GB"
    }
    elseif ($sizeInBytes -ge 1TB)
    {
        $formattedSize = $sizeInBytes / 1TB
        $formattedSize = ("{0:n2}" -f $formattedSize) + " TB"
    }
    return $formattedSize
}

function Get-SubstringWithRegex($string, $regex)
{
    if ($string -match $regex)
    {
        # $matches is an automatic variable that is populated when using the -match operator.
        return $matches[0]
    }
    else
    {
        Write-Warning "Could not find substring in string: $string with regex: $regex"
    }
}

function Get-Percent($divisor, $dividend)
{
    $percent = $divisor / $dividend * 100
    $roundedToInt = [Math]::Round($percent)
    return "$roundedToInt%"
}

function Show-Separator($title, [ConsoleColor]$color = "DarkCyan", [switch]$noLineBreaks)
{
    if ($title)
    {
        $separator = " $title "
    }
    else
    {
        $separator = ""
    }

    # Truncate if it's too long.
    If (($separator.length - 6) -gt ((Get-host).UI.RawUI.BufferSize.Width))
    {
        $separator = $separator.Remove((Get-host).UI.RawUI.BufferSize.Width - 5)
    }

    # Pad with dashes.
    $separator = "--$($separator.PadRight(((Get-host).UI.RawUI.BufferSize.Width)-3,"-"))"

    if (-not($noLineBreaks))
    {        
        # Add line breaks.
        $separator = "`n$separator`n"
    }

    Write-Host $separator -ForegroundColor $color
}

function Show-Separator2
{
    Param
    (
        [ValidateSet("Blue", "Green", "Cyan", "Red", "Magenta", "Yellow", "Gray", "White", "Black")]
        $color = "Cyan",  

        [parameter(Position = 0)]
        $title
    )

    # Pad the title with spaces.
    $separator = " $title "

    # Truncate the string if it is to long.
    If (($separator.length - 6) -gt ((Get-host).UI.RawUI.BufferSize.Width))
    {
        $separator = $separator.Remove((Get-host).UI.RawUI.BufferSize.Width - 5)
    }

    # Pad the string with dashes.
    $separator = "--$($separator.PadRight(((Get-host).UI.RawUI.BufferSize.Width)-3,"-"))"

    Write-Host $separator -ForegroundColor $color
}