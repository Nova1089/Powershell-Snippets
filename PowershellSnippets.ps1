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
    $keepGoing = -not(Confirm-ModuleInstalled $moduleName)
    while ($keepGoing)
    {
        Prompt-InstallModule $moduleName
        Confirm-AdminPrivilege
        Install-Module $moduleName

        if ((Confirm-ModuleInstalled $moduleName) -eq $true)
        {
            Write-Host "Importing module..." -ForegroundColor $infoColor
            Import-Module $moduleName
            $keepGoing = $false
        }
    }
}

function Confirm-ModuleInstalled($moduleName)
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
        $confirmInstall = Read-Host "Would you like to install the module? (y/n)"
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
function Confirm-AdminPrivilege
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
function Confirm-AdminPrivilege
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
    $connected = Confirm-ConnectedToMgGraph
    while(-not($connected))
    {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor $infoColor
        Connect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        $connected = Confirm-ConnectedToMgGraph

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
    $connected = $null -ne (Get-MgContext)
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

        $connected = $null -ne (Get-MgContext)
        if (-not($connected))
        {
            Write-Host "Failed to connect to Microsoft Graph." -ForegroundColor $script:warningColor
            Read-Host "Press Enter to try again"
        }
        else
        {
            Write-Host "Successfully connected!" -ForegroundColor $successColor
        }
    }    
}

function TryConnect-ExchangeOnline
{
    $connectionStatus = Get-ConnectionInformation -ErrorAction SilentlyContinue

    while ($null -eq $connectionStatus)
    {
        Write-Host "Connecting to Exchange Online..."
        Connect-ExchangeOnline -ErrorAction "SilentlyContinue" -ShowBanner:$false
        $connectionStatus = Get-ConnectionInformation
        if ($null -eq $connectionStatus)
        {
            Write-Host "Failed to connect to Exchange Online." -ForegroundColor $script:warningColor
            Read-Host "Press Enter to try again"
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
    $connected = Confirm-ConnectedToAzureAD

    while (-not($connected))
    {
        Write-Host "Connecting to Azure AD..." -ForegroundColor $infoColor
        Connect-AzureAD -ErrorAction SilentlyContinue | Out-Null

        $connected = Confirm-ConnectedToAzureAD
        if (-not($connected))
        {
            Write-Warning "Failed to connect to Azure AD."
            Read-Host "Press Enter to try again"
        }
    }
}

function Confirm-ConnectedToAzureAD
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

function TryConnect-JumpCloud
{
    # JCAPIKEY is a global variable set by Connect-JCOnline.
    $connected = ($null -ne $global:JCAPIKEY)

    while (-not($connected))
    {
        $keepGoing = $true
        do
        {
            $apiKey = Read-Host "Enter your JumpCloud API key"
            if ($apiKey -ne "")
            {
                $keepGoing = $false
            }

            $apiKey = $apiKey.Trim()

            if ($apiKey.Length -ne 40)
            {
                Write-Host "API key should be 40 characters." -ForegroundColor $script:warningColor
                $keepGoing = $true
            }
        }
        while ($keepGoing)        
        
        Write-Host "Connecting to JumpCloud..." -ForegroundColor $script:infoColor
        Connect-JCOnline -JumpCloudApiKey $apiKey -Force | Out-Null

        $connected = ($null -ne $global:JCAPIKEY)
        if (-not($connected))
        {
            Write-Host "Failed to connect to JumpCloud." -ForegroundColor $script:warningColor
            Read-Host "Press Enter to try again"
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

# v1
function New-TimeStamp
{
    return Get-Date -Format 'yyyy-MM-dd-hh-mmtt'
}

# v2
function New-TimeStamp
{
    return Get-Date -Format 'yyyy-MM-dd hh:mm tt'
}

# v3
function New-TimeStamp
{
    return Get-Date -Format 'MMMM d, yyyy a\t hh:mm tt'
}

function Get-SimpleTimestamp($dateTimeOb)
{
    return $dateTimeOb | Get-Date -Format 'MMMM d, yyyy a\t hh:mm tt'
}

# Simple timestamp
function Show-TimeStamp
{
    Write-Host ((Get-Date).DateTime) -ForegroundColor $script:infoColor
}

# Timestamp with timezone
function Show-TimeStamp
{
    # UFormat descriptions here: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-date?view=powershell-5.1#notes
    $timestamp = Get-Date -UFormat "%A, %D, %r, UTC %Z"
    Write-Host $timestamp -ForegroundColor $script:infoColor
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

# Version that handles FreshService API rate limits.
function SafelyInvoke-WebRequest($method, $uri, $headers, $body)
{
    try
    {
        $response = Invoke-WebRequest -Method $method -Uri $uri -Headers $headers -Body $body -ErrorVariable "responseError"
    }
    catch
    {
        if ([int]$_.Exception.Response.StatusCode -eq 429)
        {
            $responseHeaders = $_.Exception.Response.Headers
            $secondsToWait = [int]$responseHeaders["Retry-After"]
            Write-Host "API is enforcing rate limits. Waiting $secondsToWait seconds to make the next call." -ForegroundColor $infoColor
            Start-SleepTimer -Seconds $secondsToWait
            $response = SafelyInvoke-WebRequest -Method $method -Uri $uri -Headers $headers -Body $body
            if ($response.Content) { return $response.Content | ConvertFrom-Json }
            return
        }

        Write-Host $responseError[0].Message -ForegroundColor $failColor
        Read-Host "Press Enter to exit"
        exit
    }

    if ($response.Content) { return $response.Content | ConvertFrom-Json }
}

function New-TempPassword
{
    $words = @("red", "orange", "yellow", "green", "blue", "purple", "silver", "gold", "flower", "mushroom", "lake", "river",
        "mountain", "valley", "jungle", "cavern", "rain", "thunder", "lightning", "storm", "fire", "lion", "wolf", "bear", "hawk",
        "dragon", "goblin", "fairy", "wizard", "sun", "moon", "emerald", "ruby", "saphire", "diamond", "treasure", "journey", "voyage",
        "adventure", "quest", "song", "dance", "painting", "magic", "castle", "dungeon", "tower", "sword", "torch", "potion")
    $specialChars = @('!', '@', '#', '$', '%', '^', '&', '*', '-', '+', '=', '?')

    $word1 = $words | Get-Random
    $coinFlip = Get-Random -Maximum 2 # max exclusive
    if ($coinFlip -eq 1) { $word1 = $word1.ToUpper() }
    
    $word2 = $words | Get-Random
    $coinFlip = Get-Random -Maximum 2 # max exclusive
    if ($coinFlip -eq 1) { $word2 = $word2.ToUpper() }

    $word3 = $words | Get-Random
    $coinFlip = Get-Random -Maximum 2 # max exclusive
    if ($coinFlip -eq 1) { $word3 = $word3.ToUpper() }

    $specialChar = $specialChars | Get-Random
    $num = Get-Random -Maximum 100 # max exclusive
    return $word1 + '/' + $word2 + '/' + $word3 + '/' + $specialChar + $num
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

function Append-QueryParams($uri, [Hashtable]$queryParams)
{
    # If URI doesn't end in ? mark, then append ? mark.
    if ($uri[-1] -ne '?') { $uri = $uri + '?' }

    foreach ($pair in $queryParams.GetEnumerator())
    {
        $uri = $uri + [uri]::EscapeDataString($pair.Key) + '=' + [uri]::EscapeDataString($pair.Value) + '&'
    }

    # If URI ends in & sign, remove ending & sign.
    if ($uri[-1] -eq '&') { $uri = $uri.TrimEnd('&') }

    return $uri    
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

function Import-UserCsv
{
    $csvPath = Read-Host "Enter path to user CSV (must be .csv)"
    $csvPath = $csvPath.Trim('"')
    return Import-Csv -Path $csvPath
}

function Confirm-CSVHasCorrectHeaders($importedCSV)
{
    $firstRecord = $importedCSV | Select-Object -First 1
    $validCSV = $true

    if (-not($firstRecord | Get-Member -MemberType NoteProperty -Name "UserPrincipalName"))
    {
        Write-Warning "This CSV file is missing a header called 'UserPrincipalName'."
        $validCSV = $false
    }

    if (-not($validCSV))
    {
        Write-Host "Please make corrections to the CSV."
        Read-Host "Press Enter to exit"
        Exit
    }
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

function Confirm-ValidEmail($email)
{
    return = $email -imatch '^\S+@[\w\.-]+\.\w{2,4}$'
}

function Confirm-ValidBrsEmail($email)
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

function Confirm-FileHasExtension([string]$fileName, [string]$extension)
{
    $actualExtension = [System.IO.Path]::GetExtension($fileName)
    return $actualExtension -ieq $extension.Trim()
}

function Confirm-IsMemberOfGroup($azureUser, $groupUpn)
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

function Confirm-IsMemberOfGroup($userUpn, $groupUpn)
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

# new
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
    $hostWidthInChars = (Get-host).UI.RawUI.BufferSize.Width

    # Truncate title if it's too long.
    if (($separator.length) -gt $hostWidthInChars)
    {
        $separator = $separator.Remove($hostWidthInChars - 5)
        $separator += " "
    }

    # Pad with dashes.
    $separator = "--$($separator.PadRight($hostWidthInChars - 2, "-"))"

    if (-not($noLineBreaks))
    {        
        # Add line breaks.
        $separator = "`n$separator`n"
    }

    Write-Host $separator -ForegroundColor $color
}

# old
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
    if (($separator.length - 6) -gt ((Get-host).UI.RawUI.BufferSize.Width))
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

function Start-SleepTimer($seconds)
{
    for ($i = 0; $i -lt $seconds; $i++)
    {
        Write-Progress -Activity "Waiting..." -Status "$i / $seconds seconds"
        Start-Sleep -Seconds 1
    }
}

function Invoke-GetWithRetry([ScriptBlock]$scriptBlock, $initialDelayInSeconds = 2, $maxRetries = 4)
{
    # API may not have the info we're trying to get yet. This will automatically retry a set amount of times.

    $retryCount = 0
    $delay = $initialDelayInSeconds
    do
    {
        # The call operator (&). Invokes a script block in a new script scope.
        # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators?view=powershell-7.4#call-operator-
        $response = & $scriptBlock

        if ($null -eq $response)
        {
            if ($retryCount -ge 2)
            { 
                Write-Warning "$scriptBlock returned null. Retrying in $delay seconds..."
                Start-SleepTimer -Seconds $delay
            }
            else
            {
                Start-Sleep -Seconds $delay
            }            
            $delay *= 2
            $retryCount++
        }
    }
    while (($null -eq $response) -and ($retryCount -lt $maxRetries))

    if ($retryCount -ge $maxRetries) { Write-Warning "Timed out trying to get a response." }

    return $response
}

function Invoke-ApiCallWithRetry([ScriptBlock]$scriptBlock, $initialDelayInSeconds = 2, $maxRetries = 4)
{
    $retryCount = 0
    $delay = $initialDelayInSeconds
    do
    {
        # The call operator (&). Invokes a script block in a new script scope.
        # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators?view=powershell-7.4#call-operator-
        $response = & $scriptBlock

        if ($null -eq $response)
        {
            if ($retryCount -ge 2)
            { 
                Write-Warning "$scriptBlock returned null. Retrying in $delay seconds..."
                Start-SleepTimer -Seconds $delay
            }
            else
            {
                Start-Sleep -Seconds $delay
            }            
            $delay *= 2
            $retryCount++
        }
    }
    while (($null -eq $response) -and ($retryCount -lt $maxRetries))

    if ($retryCount -ge $maxRetries) { Write-Warning "Timed out trying to get a response." }

    return $response
}

function Install-MSI($msiPath, [switch]$unattended, [switch]$waitUntilDone)
{
    $arguments = @("/i", "`"$msiPath`"", "/promptrestart")
    if ($unattended)
    {
        # Specifies unattended mode, which means it shows a progress bar, but requires no manual inputs.
        $arguments += "/passive"
    }

    if ($waitUntilDone)
    {
        # Using the Wait switch. Script will wait for the install to complete before continuing.
        # Docs on msiexec.exe https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec
        Start-Process "msiexec.exe" -ArgumentList $arguments -NoNewWindow -Wait
    }
    else
    {
        Start-Process "msiexec.exe" -ArgumentList $arguments -NoNewWindow
    }
}

function Log-Info($message, $logPath = ".\logs.txt")
{
    $message = "[$(Get-Date -Format 'yyyy-MM-dd hh:mm tt') I] $message"
    Write-Output $message | Tee-Object -FilePath $logPath -Append | Write-Host -ForegroundColor "DarkCyan"
}

function Log-Success($message, $logPath = ".\logs.txt")
{
    $message = "[$(Get-Date -Format 'yyyy-MM-dd hh:mm tt') S] $message"
    Write-Output $message | Tee-Object -FilePath $logPath -Append | Write-Host -ForegroundColor "Green"
}

function Log-Warning($message, $logPath = ".\logs.txt")
{
    $message = "[$(Get-Date -Format 'yyyy-MM-dd hh:mm tt') W] $message"
    Write-Output $message | Tee-Object -FilePath $logPath -Append | Write-Host -ForegroundColor "Yellow"
}

function Log-Error($message, $logPath = ".\logs.txt")
{
    $message = "[$(Get-Date -Format 'yyyy-MM-dd hh:mm tt') E] $message"
    Write-Output $message | Tee-Object -FilePath $logPath -Append | Write-Host -ForegroundColor "Red"
}

function Invoke-APICallWithRateBackoff([ScriptBlock]$scriptBlock, $initialDelayInSeconds = 2, $maxRetries = 4)
{
    # Some APIs will throw a 429 exception if you run into their rate limits. This will try again after a backoff.
    # Define a script block by wrapping in curly braces. E.g., $scriptBlock = { Invoke-RestMethod -Uri $uri -ErrorAction "Stop" }

    $retryCount = 0
    $delay = $initialDelayInSeconds
    $keepGoing = $true
    while ($keepGoing)
    {
        # The call operator (&). Invokes a script block in a new script scope.
        # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators?view=powershell-7.4#call-operator-
        try 
        {
            $response = & $scriptBlock
        }
        catch 
        {
            if ([int]$_.Exception.Response.StatusCode -eq 429)
            {
                if ($retryCount -ge $maxRetries)
                {
                    Write-Warning "Reached the specified retry max. Moving on."
                    $keepGoing = $false
                    break
                }
                Write-Warning "$scriptBlock is being rate limited. Retrying in $delay seconds..."
                Start-SleepTimer $delay                   
                $delay *= 2
                $retryCount++
                continue
            }
            else
            {
                # If you get any error besides 429, it will throw it back down the call stack, so be sure to handle it!
                throw $_
            }
        }
        $keepGoing = $false
    }    
    return $response
}


