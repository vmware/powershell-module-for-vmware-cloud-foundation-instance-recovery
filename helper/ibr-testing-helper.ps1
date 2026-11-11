$Global:utilityName= "IBR Test Helper"

# This script is run standalone, so provide the globals that Write-LogMessage and the menu breadcrumb expect
# if the host session has not already defined them.
If (!$utilityBuild) {
    $Global:utilityBuild = "1.0"
}
If (!$logMutexName) {
    $Global:logMutexName = "Global\IBRTestingHelperLog"
}
If (!$logFile) {
    $Global:logFile = Join-Path -Path $(If ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }) -ChildPath "log-ibr-testing-helper.log"
}

Function Write-MenuBreadcrumb {
    Param (
        [Parameter(Mandatory=$true)][String]$Version,
        [Parameter(Mandatory=$true)][String]$Submenu,
        [Parameter(Mandatory=$true)][String]$MenuItem
    )
    $E = [char]0x1b
    Write-Host `n "$E[90mVersion $E[96m$Version$E[90m > $E[96m$Submenu$E[90m > $E[96m$MenuItem$E[0m"
}

Function Write-CaughtException {
    <#
        .DESCRIPTION
        Must never itself throw - it runs inside other functions' Catch blocks with no further Try/Catch around
        it, so any error here masks the original error it was trying to report instead of logging it. Guards
        InvocationInfo.Line specifically because Invoke-LoggedCommand re-throws via "throw $caughtError.Exception"
        (a bare Exception, not the original ErrorRecord) - when that's caught further up the stack,
        InvocationInfo.Line on the reconstructed ErrorRecord can come back $null, and calling .trim() on $null
        throws "You cannot call a method on a null-valued expression" - confirmed via a live crash that took down
        the whole session with zero [EXCEPTION] output logged.
    #>
    Param (
        [Parameter (mandatory = $true)] [PSObject]$object
    )
    $lineNumber = $object.InvocationInfo.ScriptLineNumber
    $lineText = If ($object.InvocationInfo.Line) {
        $object.InvocationInfo.Line.trim()
    } else {
        ""
    }
    $errorMessage = If ($object.Exception) {
        $object.Exception.Message
    } else {
        "$object"
    }
    Write-LogMessage -Type EXCEPTION -Message "Error at Script Line $lineNumber"
    Write-LogMessage -Type EXCEPTION -Message "Relevant Command: $lineText"
    Write-LogMessage -Type EXCEPTION -Message "Error Message: $errorMessage"
}

Function Write-LogMessage {
    Param (
        [Parameter (Mandatory = $true)] [AllowEmptyString()] [String]$message,
        [Parameter (Mandatory = $false)] [ValidateSet("INFO", "ERROR", "WARNING", "EXCEPTION","ADVISORY","NOTE","QUESTION","WAIT")] [String]$type = "INFO",
        [Parameter (Mandatory = $false)] [String]$colour,
        [Parameter (Mandatory = $false)] [Switch]$skipnewline,
        [Parameter (Mandatory = $false)] [Switch]$skiplogtofile
    )

    If (!$colour) {
        $colour = "92m" #Green
    }

    If ($type -eq "INFO") {
        $messageColour = "92m" #Green
    } elseIf ($type -in "ERROR","EXCEPTION") {
        $messageColour = "91m" # Red
    } elseIf ($type -in "WARNING","ADVISORY","QUESTION") {
        $messageColour = "93m" #Yellow
    } elseIf ($type -in "NOTE","WAIT") {
        $messageColour = "97m" # White
    }

    If (!$threadTag) {
        $threadTag = "..."; $threadColour = "97m"
    }

    <#
    Reference Colours
    31m Red
    32m Green
    33m Yellow
    36m Cyan
    37m White
    91m Bright Red
    92m Bright Green
    93m Bright Yellow
    95m Bright Magenta
    96m Bright Cyan
    97m Bright White
    #>

    $ESC = [char]0x1b
    $timestampColour = "97m"

    $timeStamp = Get-Date -Format "MM-dd-yyyy_HH:mm:ss"

    $threadTag = $threadTag.toUpper()
    If ($headlessPassed) {
        If ($skipnewline) {
            Write-Host -NoNewline "[$timestamp] [$threadTag] [$type] $message"
        } else {
            Write-Host "[$timestamp] [$threadTag] [$type] $message"
        }
    } else {
        If ($skipnewline) {
            Write-Host -NoNewline "$ESC[${timestampcolour} [$timestamp]$ESC[${threadColour} [$threadTag]$ESC[${messageColour} [$type] $message$ESC[0m"
        } else {
            Write-Host "$ESC[${timestampcolour} [$timestamp]$ESC[${threadColour} [$threadTag]$ESC[${messageColour} [$type] $message$ESC[0m"
        }
    }
    $logContent = '[' + $timeStamp + '] [' +$threadTag + '] ' + $type + ' ' + $message
    If (!$skiplogtofile) {
        $_mutex = New-Object System.Threading.Mutex($false, $logMutexName)
        if ($_mutex.WaitOne(5000)) {
            try {
                Add-Content -path $logFile $logContent
            } finally {
                $_mutex.ReleaseMutex()
            }
        }
    }
}

Function New-TestingMenu {
    Param (
        [Parameter (Mandatory = $false)] [switch]$bannerless
    )
    $submenuTitle = ("IBR Testing Menu")

    $headingItem01 = "IBR Preparation Tasks"
    $menuItem01 = "Download VCF Backups from PTR"
    $menuItem02 = "Download Binaries from VCF Installer"
    $menuItem03 = "Update Variable JSON files"

    $headingItem02 = "IBR Repeat Testing Tasks"
    $menuItem04 = "Snapshot domain hosts"
    $menuItem05 = "Restore domain hosts from snapshot"

    Do {
        Clear-Host

        # Build list of valid menu options
        $validMenuOptions = @("Q")

        if (($headlessPassed) -or ($bannerless)) {
            Write-Host " "; Write-Host -Object $utilityName -ForegroundColor Cyan
        } else {
            Write-Host ""; Write-Ascii -InputObject $utilityName -ForegroundColor Magenta
        }
        Write-Host ""
        Write-Host " PT Version: " -ForegroundColor DarkGray -NoNewline; Write-Host "$utilityBuild" -ForegroundColor Cyan -NoNewline
        Write-Host " | " -ForegroundColor DarkGray -NoNewline; Write-Host "$submenuTitle" -ForegroundColor Cyan

        Write-Host ""; Write-Host -Object " $headingItem01" -ForegroundColor Yellow
        Write-Host -Object " 01. $menuItem01" -ForegroundColor White; $validMenuOptions += "01"
        Write-Host -Object " 02. $menuItem02" -ForegroundColor White; $validMenuOptions += "02"
        Write-Host -Object " 03. $menuItem03" -ForegroundColor White; $validMenuOptions += "03"

        Write-Host ""; Write-Host -Object " $headingItem02" -ForegroundColor Yellow
        Write-Host -Object " 04. $menuItem04" -ForegroundColor White; $validMenuOptions += "04"
        Write-Host -Object " 05. $menuItem05" -ForegroundColor White; $validMenuOptions += "05"

        Write-Host -Object ''
        $MenuInput = if ($clioptions) {
            Get-NextOption
        } else {
            Read-Host -Prompt ' Select Option (or Q to go Quit)'
        }
        $MenuInput = $MenuInput -replace "`t|`n|`r",""
        # Normalize single digit inputs
        If ($MenuInput -match '^\d$') {
            $MenuInput = "0$MenuInput"
        }
        # If invalid input, show error and continue to redraw menu from top of loop
        If (($MenuInput -notin $validMenuOptions) -and ($MenuInput -ine "B")) {
            Write-Host " Invalid option. Please select from the displayed menu options." -ForegroundColor Red
            Start-Sleep -Milliseconds 2500
            Continue
        }
        If ($MenuInput -like "0*") {
            $MenuInput = ($MenuInput -split("0"),2)[1]
        }
        Switch ($MenuInput) {
            01 {
                Clear-Host; Write-MenuBreadcrumb -Version $utilityBuild -Submenu $submenuTitle -MenuItem $menuItem01; Write-Host -Object ''
                Get-VCFBackups -PtrAddress "10.11.10.4"-BackupUsername 'svc-vcf-bck' -BackupPassword 'VMw@re1!' -Destination "F:\VCFIR\backups"
                Wait-AnyKey
            }
            02 {
                Clear-Host; Write-MenuBreadcrumb -Version $utilityBuild -Submenu $submenuTitle -MenuItem $menuItem02; Write-Host -Object ''
                $helperSettingsFile = "F:\VCFIR\scripts\settings-ibr-helper.json"
                If (!(Test-Path -Path $helperSettingsFile)) {
                    Write-LogMessage -Type ERROR -Message "$helperSettingsFile not found"
                } else {
                    $helperSettings = Get-Content -Path $helperSettingsFile -Raw | ConvertFrom-Json
                    Get-VCFInstallerBundleAssets -instanceObject $helperSettings -destinationPath "F:\VCFIR\binaries"
                }
                Wait-AnyKey
            }
            03 {
                Clear-Host; Write-MenuBreadcrumb -Version $utilityBuild -Submenu $submenuTitle -MenuItem $menuItem03; Write-Host -Object ''
                Update-VCFVariableJsonFiles -variablesPath "F:\VCFIR\variables_and_answers" -backupsPath "F:\VCFIR\backups" -binariesPath "F:\VCFIR\binaries"
                Wait-AnyKey
            }
            04 {
                Clear-Host; Write-MenuBreadcrumb -Version $utilityBuild -Submenu $submenuTitle -MenuItem $menuItem04; Write-Host -Object ''
                New-DomainHostSnapshots
                Wait-AnyKey
            }
            05 {
                Clear-Host; Write-MenuBreadcrumb -Version $utilityBuild -Submenu $submenuTitle -MenuItem $menuItem05; Write-Host -Object ''
                Restore-DomainHostSnapshots
                Wait-AnyKey
            }
            Q {
                Clear-Host
                Exit
            }
        }
    }
    Until ($MenuInput -eq 'b')
}

Function Get-VCFInstallerBundleAssets {
    Param (
        [Parameter (Mandatory = $true)] [Object]$instanceObject,
        [Parameter (Mandatory = $false)] [String]$destinationPath = (Get-Location).Path
    )

    Try {
        $bundleRoot = "/nfs/vmware/vcf/nfs-mount/bundle"

        # Best-guess filename patterns - see header comment. First hit wins per file, so
        # order matters if a filename could plausibly match more than one component.
        $componentPatterns = [ordered]@{
            "License Server" = '(?i)(vlcs|lcs[-_.]|license[-_]?server)'
            "SDDC Manager"   = '(?i)sddc[-_]?manager'
            "vCenter"        = '(?i)(vcenter|vcsa)'
            "NSX Manager"    = '(?i)nsx([-_]?t)?[-_]?(unified[-_]?appliance|manager)'
        }

        # Populated per component with whatever filename(s) actually end up in
        # $destinationPath by the end of this run (post vCenter ISO extraction) -
        # used to refresh any breadcrumbs*.ps1 file's stale filename references.
        $finalFileNames = [ordered]@{}
        foreach ($component in $componentPatterns.Keys) {
            $finalFileNames[$component] = @()
        }

        If (!(Test-Path -Path $destinationPath)) {
            New-Item -Path $destinationPath -ItemType Directory -Force | Out-Null
        }

        # Archive any files left from a previous run into archive\<SDDC Manager version>, keeping the
        # recovery tools zip and Veeam ISO in place since they are not re-downloaded below.
        $keepFilePattern = '(?i)(^recovery_tools_python_3_10_11.*\.zip$|^VeeamDataPlatform.*\.iso$)'
        $existingFiles = @(Get-ChildItem -Path $destinationPath -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch $keepFilePattern })
        If ($existingFiles.Count -gt 0) {
            $existingSddcOva = $existingFiles | Where-Object { ($_.Name -match $componentPatterns["SDDC Manager"]) -and ($_.Extension -ieq ".ova") } | Select-Object -First 1
            $archiveVersion = "unknown-version"
            If ($existingSddcOva -and ($existingSddcOva.Name -match '\d+\.\d+\.\d+\.\d+')) {
                $archiveVersion = $Matches[0]
            } else {
                Write-LogMessage -Type WARNING -Message "[$($instanceObject.vcfInstaller.fqdn)] No SDDC Manager OVA found in $destinationPath to derive a version from - archiving to $archiveVersion"
            }
            $archivePath = Join-Path -Path (Join-Path -Path $destinationPath -ChildPath "archive") -ChildPath $archiveVersion
            If (!(Test-Path -Path $archivePath)) {
                New-Item -Path $archivePath -ItemType Directory -Force | Out-Null
            }
            Write-LogMessage -Type INFO -Message "[$($instanceObject.vcfInstaller.fqdn)] Moving $($existingFiles.Count) existing file(s) from $destinationPath to $archivePath"
            $existingFiles | Move-Item -Destination $archivePath -Force
        }

        Write-LogMessage -Type NOTE -Message "[$($instanceObject.vcfInstaller.fqdn)] Retrieving License Server, SDDC Manager, vCenter, and NSX Manager bundle assets from $bundleRoot"

        Do {
            $PSDefaultParameterValues['Test-NetConnection:InformationLevel'] = 'Quiet'
            $testResult = Test-NetConnection -ComputerName $instanceObject.vcfInstaller.ipAddress -Port 22 -WarningAction SilentlyContinue
            If ($testResult -eq $false) {
                Sleep 5
            }
        } Until ($testResult -eq $true)

        Do {
            $qsFingerPrint = (Get-SSHHostKey -ComputerName $instanceObject.vcfInstaller.ipAddress -ErrorAction SilentlyContinue).fingerprint
            If (!$qsFingerPrint) {
                Sleep 5
            }
        } Until ($qsFingerPrint)

        $rootUser = $instanceObject.vcfInstaller.rootUser
        $SecureRootPassword = ConvertTo-SecureString -String $instanceObject.vcfInstaller.rootPassword -AsPlainText -Force
        $mycreds = New-Object System.Management.Automation.PSCredential ($rootUser, $SecureRootPassword)
        $inmem = New-SSHMemoryKnownHost
        New-SSHTrustedHost -KnownHostStore $inmem -HostName $instanceObject.vcfInstaller.ipAddress -FingerPrint $qsFingerPrint | Out-Null

        Do {
            $sshSession = New-SSHSession -ComputerName $instanceObject.vcfInstaller.ipAddress -Credential $mycreds -KnownHost $inmem
        } Until ($sshSession)

        Write-LogMessage -Type INFO -Message "[$($instanceObject.vcfInstaller.fqdn)] Scanning $bundleRoot for OVA/ISO files"
        $scriptCommand = "find $bundleRoot -type f \( -iname '*.ova' -o -iname '*.iso' \)"
        $bundleFiles = (Invoke-SSHCommand -TimeOut 300 -SessionId $sshSession.SessionId -Command $scriptCommand).Output

        If (!$bundleFiles) {
            Write-LogMessage -Type WARNING -Message "[$($instanceObject.vcfInstaller.fqdn)] No OVA/ISO files were found under $bundleRoot"
        } else {
            foreach ($component in $componentPatterns.Keys) {
                $pattern = $componentPatterns[$component]
                $matchedFiles = $bundleFiles | Where-Object { (Split-Path -Path $_ -Leaf) -match $pattern }

                If (!$matchedFiles) {
                    Write-LogMessage -Type WARNING -Message "[$($instanceObject.vcfInstaller.fqdn)] No $component OVA/ISO found under $bundleRoot"
                    continue
                }

                If (@($matchedFiles).count -gt 1) {
                    Write-LogMessage -Type ADVISORY -Message "[$($instanceObject.vcfInstaller.fqdn)] Multiple $component candidates found - downloading all of them: $($matchedFiles -join ', ')"
                }

                foreach ($remoteFile in $matchedFiles) {
                    $fileName = Split-Path -Path $remoteFile -Leaf
                    $localTargetPath = Join-Path -Path $destinationPath -ChildPath $fileName

                    If (Test-Path -Path $localTargetPath) {
                        Write-LogMessage -Type INFO -Message "[$($instanceObject.vcfInstaller.fqdn)] $fileName already present in $destinationPath - skipping download"
                    } else {
                        Write-LogMessage -Type WAIT -Message "[$($instanceObject.vcfInstaller.fqdn)] Downloading $component file $fileName to $destinationPath. This will take several minutes. Please be patient."
                        Get-SCPItem -ComputerName $instanceObject.vcfInstaller.ipAddress -Credential $mycreds -Path $remoteFile -PathType File -Destination $destinationPath -AcceptKey:$true -KnownHost $inmem
                        Write-LogMessage -Type INFO -Message "[$($instanceObject.vcfInstaller.fqdn)] Downloaded $fileName"
                    }

                    If (($component -eq "vCenter") -and ($fileName -match '\.iso$')) {
                        $existingOva = Get-ChildItem -Path $destinationPath -Filter "*.ova" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $pattern } | Select-Object -First 1
                        If ($existingOva) {
                            Write-LogMessage -Type INFO -Message "[$($instanceObject.vcfInstaller.fqdn)] vCenter OVA $($existingOva.Name) already extracted - skipping ISO mount"
                            $finalFileNames[$component] += $existingOva.Name
                            If (Test-Path -Path $localTargetPath) {
                                Remove-Item -Path $localTargetPath -Force
                                Write-LogMessage -Type INFO -Message "[$($instanceObject.vcfInstaller.fqdn)] Removed redundant ISO $fileName"
                            }
                        } else {
                            Write-LogMessage -Type WAIT -Message "[$($instanceObject.vcfInstaller.fqdn)] Mounting $fileName to extract the embedded vCenter OVA"
                            $mountedImage = Mount-DiskImage -ImagePath $localTargetPath -PassThru
                            $mountedVolume = $mountedImage | Get-Volume
                            $mountedOva = Get-ChildItem -Path "$($mountedVolume.DriveLetter):\" -Recurse -Filter "*.ova" -ErrorAction SilentlyContinue | Select-Object -First 1
                            If (!$mountedOva) {
                                Write-LogMessage -Type WARNING -Message "[$($instanceObject.vcfInstaller.fqdn)] No OVA found inside $fileName"
                            } else {
                                Copy-Item -Path $mountedOva.FullName -Destination $destinationPath -Force
                                Write-LogMessage -Type INFO -Message "[$($instanceObject.vcfInstaller.fqdn)] Extracted $($mountedOva.Name) from $fileName"
                                $finalFileNames[$component] += $mountedOva.Name
                            }
                            Dismount-DiskImage -ImagePath $localTargetPath
                            Remove-Item -Path $localTargetPath -Force
                            Write-LogMessage -Type INFO -Message "[$($instanceObject.vcfInstaller.fqdn)] Dismounted and removed $fileName"
                        }
                    } else {
                        $finalFileNames[$component] += $fileName
                    }
                }
            }
        }

        Remove-SSHSession -SessionId $sshSession.SessionId | Out-Null

        Write-LogMessage -Type INFO -Message "[$($instanceObject.vcfInstaller.fqdn)] Checking for breadcrumbs*.ps1 files in $destinationPath to refresh binary filename references"
        $breadcrumbsFiles = Get-ChildItem -Path $destinationPath -Filter "breadcrumbs*.ps1" -File -ErrorAction SilentlyContinue
        $filenameTokenPattern = '[A-Za-z0-9][A-Za-z0-9._-]*\.(?:ova|iso)'

        foreach ($breadcrumbsFile in $breadcrumbsFiles) {
            $originalContent = Get-Content -Path $breadcrumbsFile.FullName -Raw
            $updatedContent = $originalContent

            foreach ($component in $finalFileNames.Keys) {
                $newFileNames = $finalFileNames[$component]
                If (!$newFileNames) {
                    continue
                }

                $pattern = $componentPatterns[$component]
                $existingReferences = @(([regex]::Matches($updatedContent, $filenameTokenPattern) | ForEach-Object { $_.Value } | Where-Object { $_ -match $pattern } | Select-Object -Unique))
                If (!$existingReferences) {
                    continue
                }

                If ($existingReferences.count -eq $newFileNames.count) {
                    for ($i = 0; $i -lt $existingReferences.count; $i++) {
                        If ($existingReferences[$i] -ne $newFileNames[$i]) {
                            $updatedContent = $updatedContent -replace [regex]::Escape($existingReferences[$i]), $newFileNames[$i]
                        }
                    }
                } else {
                    foreach ($oldFileName in $existingReferences) {
                        If ($oldFileName -ne $newFileNames[0]) {
                            $updatedContent = $updatedContent -replace [regex]::Escape($oldFileName), $newFileNames[0]
                        }
                    }
                }
            }

            If ($updatedContent -ne $originalContent) {
                Set-Content -Path $breadcrumbsFile.FullName -Value $updatedContent -NoNewline
                Write-LogMessage -Type INFO -Message "Updated binary filename references in $($breadcrumbsFile.Name)"
            } else {
                Write-LogMessage -Type INFO -Message "No matching filename references needed updating in $($breadcrumbsFile.Name)"
            }
        }

        Write-LogMessage -Type NOTE -Message "[$($instanceObject.vcfInstaller.fqdn)] Bundle asset retrieval complete"
    } Catch {
        Write-CaughtException -object $_
    }
}

Function Get-VCFBackups {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$PtrAddress,
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][String]$BackupUsername = "svc-vcf-bck",
        [Parameter(Mandatory = $false)][String]$BackupPassword = 'VMw@re1!',
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][String]$Destination = "F:\VCFIR\backups"
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"

    # Prompt for password if not supplied
    If (-not $BackupPassword) {
        $BackupPassword = Read-Host -Prompt "Password for ${BackupUsername}@${PtrAddress}"
    }

    # Ensure Posh-SSH is available
    If (-not (Get-Module -Name Posh-SSH -ListAvailable)) {
        Write-Error "Posh-SSH module is not installed. Run: Install-Module -Name Posh-SSH -Scope CurrentUser"
        Exit 1
    }
    Import-Module Posh-SSH -ErrorAction Stop

    # Ensure destination folder exists
    If (-not (Test-Path -Path $Destination)) {
        Write-Host "[INFO] Creating destination folder: $Destination"
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    $securePassword = ConvertTo-SecureString -String $BackupPassword -AsPlainText -Force
    $credential     = New-Object System.Management.Automation.PSCredential ($BackupUsername, $securePassword)

    # Dynamically trust the host key so no interactive prompt is required
    Write-Host "[INFO] Retrieving SSH host key from $PtrAddress"
    $hostKey = Get-SSHHostKey -ComputerName $PtrAddress
    If (-not $hostKey) {
        Write-Error "Unable to retrieve SSH host key from $PtrAddress. Check connectivity and try again."
        Exit 1
    }

    $knownHosts = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $knownHosts -HostName $PtrAddress -FingerPrint $hostKey.fingerprint | Out-Null

    # Open an SSH session to enumerate the top-level entries in /media/backups
    Write-Host "[INFO] Enumerating contents of /media/backups on $PtrAddress"
    $sshSession = New-SSHSession -ComputerName $PtrAddress -Credential $credential -KnownHost $knownHosts
    If (-not $sshSession) {
        Write-Error "Failed to establish SSH session to $PtrAddress."
        Exit 1
    }

    # Use ls -la to distinguish files (leading '-') from directories (leading 'd')
    $listResult = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "ls -la /media/backups"
    Remove-SSHSession -SessionId $sshSession.SessionId | Out-Null

    $remoteEntries = $listResult.Output | Where-Object { $_ -match '^[d-]' -and $_ -notmatch '\s\.$' -and $_ -notmatch '\s\.\.$' } |
        ForEach-Object {
            $parts    = $_ -split '\s+', 9
            $typeChar = $parts[0][0]
            $name     = $parts[-1]
            [PSCustomObject]@{
                Name     = $name
                PathType = if ($typeChar -eq 'd') {
                    'Directory'
                } else {
                    'File'
                }
            }
        }

    If (-not $remoteEntries) {
        Write-Host "[INFO] /media/backups appears to be empty. Nothing to download."
        Exit 0
    }

    # Archive anything already in $Destination so only fresh backups remain at the top level
    $archiveRoot = Join-Path -Path $Destination -ChildPath "archive"
    $existingItems = @(Get-ChildItem -Path $Destination -Force | Where-Object { $_.Name -ne "archive" })
    If ($existingItems.Count -gt 0) {
        $archivePath = Join-Path -Path $archiveRoot -ChildPath (Get-Date -Format "yyyyMMdd-HHmmss")
        Write-Host "[INFO] Moving $($existingItems.Count) existing item(s) in $Destination to $archivePath"
        New-Item -ItemType Directory -Path $archivePath -Force | Out-Null
        $existingItems | Move-Item -Destination $archivePath -Force
    }

    # Download each entry individually so contents land directly in $Destination
    Write-Host "[INFO] Downloading $($remoteEntries.Count) item(s) from /media/backups to $Destination"
    Write-Host "[INFO] This may take some time depending on backup size..."

    Foreach ($entry in $remoteEntries) {
        $remotePath = "/media/backups/$($entry.Name)"
        Write-Host "[INFO] Downloading ($($entry.PathType)): $($entry.Name)"
        Get-SCPItem `
            -ComputerName $PtrAddress `
            -Credential $credential `
            -Path $remotePath `
            -PathType $entry.PathType `
            -Destination $Destination `
            -KnownHost $knownHosts
    }

    Write-Host "[INFO] Download complete. Files are in: $Destination"
    Copy-Item -Path (Join-Path -Path $Destination -ChildPath "credentials\*") -Destination (Join-Path -Path $Destination -ChildPath "sddc-manager-backup\")
}

Function Set-JsonStringValue {
    <#
        .DESCRIPTION
        Text-level replacement of a single top-level string value so the rest of the file keeps its exact
        formatting (ConvertTo-Json would reformat the file and escape characters such as ' and !).
    #>
    Param (
        [Parameter (Mandatory = $true)] [String]$content,
        [Parameter (Mandatory = $true)] [String]$key,
        [Parameter (Mandatory = $true)] [String]$value
    )
    $escapedValue = $value.Replace('\', '\\').Replace('"', '\"')
    $pattern = '("' + [regex]::Escape($key) + '"\s*:\s*)"(?:[^"\\]|\\.)*"'
    $evaluator = [System.Text.RegularExpressions.MatchEvaluator] { Param ($m) $m.Groups[1].Value + '"' + $escapedValue + '"' }
    [regex]::Replace($content, $pattern, $evaluator)
}

Function Update-VCFVariableJsonFiles {
    <#
    .SYNOPSIS
        Aligns the backup/OVA paths and VCF version in the recovery variable JSON files with what is
        actually staged under the backups and binaries folders.
    .DESCRIPTION
        Updates management-domain-recovery-variables-sfo-m01.json and fleet-component-recovery-variables.json
        in $variablesPath. The VCF version (format 9.1.1.0) is parsed from the SDDC Manager OVA file name in
        $binariesPath. The archive subfolders of both staging folders are ignored.
    #>
    Param (
        [Parameter (Mandatory = $false)] [String]$variablesPath = "F:\VCFIR\variables_and_answers",
        [Parameter (Mandatory = $false)] [String]$backupsPath = "F:\VCFIR\backups",
        [Parameter (Mandatory = $false)] [String]$binariesPath = "F:\VCFIR\binaries"
    )

    Try {
        $managementJsonFile = Join-Path -Path $variablesPath -ChildPath "management-domain-recovery-variables-sfo-m01.json"
        $fleetJsonFile = Join-Path -Path $variablesPath -ChildPath "fleet-component-recovery-variables.json"
        foreach ($jsonFile in @($managementJsonFile, $fleetJsonFile)) {
            If (!(Test-Path -Path $jsonFile)) {
                Write-LogMessage -Type ERROR -Message "$jsonFile not found - nothing to update"
                Return
            }
        }

        # Pending replacements per file: json key -> new value
        $managementUpdates = [ordered]@{}
        $fleetUpdates = [ordered]@{}

        # Binaries - OVA file names and VCF version
        $ovaPatterns = [ordered]@{
            sddcManagerOvaFile = '(?i)sddc[-_]?manager'
            vCenterOvaFile     = '(?i)(vcenter|vcsa)'
            nsxManagerOvaFile  = '(?i)nsx([-_]?t)?[-_]?(unified[-_]?appliance|manager)'
        }
        $ovaFiles = @(Get-ChildItem -Path $binariesPath -Filter "*.ova" -File -ErrorAction SilentlyContinue)
        foreach ($key in $ovaPatterns.Keys) {
            $ova = $ovaFiles | Where-Object { $_.Name -match $ovaPatterns[$key] } | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
            If ($ova) {
                $managementUpdates[$key] = $ova.FullName
                Write-LogMessage -Type INFO -Message "Found $key $($ova.FullName)"
            } else {
                Write-LogMessage -Type WARNING -Message "No OVA matching $key found under $binariesPath - leaving existing value"
            }
        }
        If ($managementUpdates.Contains("sddcManagerOvaFile") -and ((Split-Path -Path $managementUpdates["sddcManagerOvaFile"] -Leaf) -match '\d+\.\d+\.\d+\.\d+')) {
            $vcfVersion = $Matches[0]
            $fleetUpdates["VcfVersion"] = $vcfVersion
            Write-LogMessage -Type INFO -Message "Parsed VCF version $vcfVersion from $($managementUpdates["sddcManagerOvaFile"])"
        } else {
            Write-LogMessage -Type WARNING -Message "Unable to parse a VCF version from an SDDC Manager OVA under $binariesPath - leaving VcfVersion unchanged"
        }

        # Backups - SDDC Manager backup archive
        $sddcManagerBackupFolder = Join-Path -Path $backupsPath -ChildPath "sddc-manager-backup"
        $sddcManagerBackupFile = Get-ChildItem -Path $sddcManagerBackupFolder -Filter "*.tar.gz" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "decrypted*" } | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
        If ($sddcManagerBackupFile) {
            $managementUpdates["vcfbackupFilePath"] = $sddcManagerBackupFile.FullName
            Write-LogMessage -Type INFO -Message "Found SDDC Manager backup $($sddcManagerBackupFile.Name)"
        } else {
            Write-LogMessage -Type WARNING -Message "No .tar.gz backup archive found under $sddcManagerBackupFolder - leaving vcfbackupFilePath unchanged"
        }

        # Backups - management vCenter backup set, matched on the vCenter fqdn in the JSON
        # The variable trimming change (085fb83) renamed this key from vCenterFqdn to restoredVcenterFqdn
        $vCenterFqdn = (Get-Content -Path $managementJsonFile -Raw | ConvertFrom-Json).restoredVcenterFqdn
        If ([string]::IsNullOrWhiteSpace($vCenterFqdn)) {
            Write-LogMessage -Type WARNING -Message "restoredVcenterFqdn is empty in $(Split-Path -Path $managementJsonFile -Leaf) - cannot locate the vCenter backup set, leaving vCenterBackupPath unchanged"
            $vCenterBackupSetFolder = $null
        } else {
            $vCenterBackupFolder = Join-Path -Path (Join-Path -Path $backupsPath -ChildPath "vCenter") -ChildPath "sn_$vCenterFqdn"
            $vCenterBackupSetFolder = Get-ChildItem -Path $vCenterBackupFolder -Directory -ErrorAction SilentlyContinue | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
        }
        If ($vCenterBackupSetFolder) {
            # Always detected fresh - the share path must point back at this machine
            $localIpAddress = ([System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) | Where-Object { $_.AddressFamily -eq 'InterNetwork' -and $_.ToString() -notlike '169.254.*' } | Select-Object -First 1)
            If (!$localIpAddress) {
                Write-LogMessage -Type WARNING -Message "Unable to detect this machine's IPv4 address - leaving vCenterBackupPath unchanged"
            } else {
                $driveLetter = $vCenterBackupSetFolder.FullName.Substring(0, 1)
                $shareRelativePath = ($vCenterBackupSetFolder.FullName -replace '^[A-Za-z]:\\', '') -replace '\\', '/'
                $managementUpdates["vCenterBackupPath"] = "$($localIpAddress.ToString())/$driveLetter`$/$shareRelativePath"
                Write-LogMessage -Type INFO -Message "Found vCenter backup set $($vCenterBackupSetFolder.Name) for $vCenterFqdn"
            }
        } elseIf (![string]::IsNullOrWhiteSpace($vCenterFqdn)) {
            Write-LogMessage -Type WARNING -Message "No vCenter backup set found under $vCenterBackupFolder - leaving vCenterBackupPath unchanged"
        }

        # Backups - VCF fleet (VCF Operations / services runtime) archive
        $fleetBackupRoot = Join-Path -Path $backupsPath -ChildPath "vcf\backups"
        $fleetArchiveFile = Get-ChildItem -Path $fleetBackupRoot -Filter "*.base.tgz" -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match '[\\/]vsp[\\/]' } | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
        If ($fleetArchiveFile) {
            $fleetUpdates["LocalArchivePath"] = $fleetArchiveFile.FullName
            Write-LogMessage -Type INFO -Message "Found fleet backup archive $($fleetArchiveFile.Name)"
        } else {
            Write-LogMessage -Type WARNING -Message "No vsp *.base.tgz archive found under $fleetBackupRoot - leaving LocalArchivePath unchanged"
        }

        foreach ($target in @(@{ file = $managementJsonFile; updates = $managementUpdates }, @{ file = $fleetJsonFile; updates = $fleetUpdates })) {
            $originalContent = Get-Content -Path $target.file -Raw
            $updatedContent = $originalContent
            foreach ($key in $target.updates.Keys) {
                $updatedContent = Set-JsonStringValue -content $updatedContent -key $key -value $target.updates[$key]
            }
            If ($updatedContent -ne $originalContent) {
                Set-Content -Path $target.file -Value $updatedContent -NoNewline
                Write-LogMessage -Type INFO -Message "Updated $(Split-Path -Path $target.file -Leaf)"
            } else {
                Write-LogMessage -Type INFO -Message "No changes needed in $(Split-Path -Path $target.file -Leaf)"
            }
        }
    } Catch {
        Write-CaughtException -object $_
    }
}

Function Write-VmTable {
    <#
    .DESCRIPTION
        Prints the VMs found as a table (name and power state) rather than a long comma-separated log line.
    #>
    Param (
        [Parameter (Mandatory = $true)] [Array]$vms
    )

    Write-LogMessage -Type INFO -Message "Found $($vms.Count) VM(s):"
    Write-Host ""
    ($vms | Select-Object @{ Name = "VM Name"; Expression = { $_.Name } }, @{ Name = "Power State"; Expression = { $_.PowerState } } | Format-Table -AutoSize | Out-String).TrimEnd() | Write-Host
    Write-Host ""
}

Function Get-PtrEnvironmentName {
    <#
    .DESCRIPTION
        SSHes to the PTR and returns its hostname minus '-converged-ptr' (the environment name), or $null on failure.
    #>
    Param (
        [Parameter (Mandatory = $false)] [String]$ptrAddress = "10.11.10.4",
        [Parameter (Mandatory = $false)] [String]$ptrUsername = "root",
        [Parameter (Mandatory = $false)] [String]$ptrPassword = 'VMw@re1!'
    )

    $securePassword = ConvertTo-SecureString -String $ptrPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($ptrUsername, $securePassword)
    $hostKey = Get-SSHHostKey -ComputerName $ptrAddress
    If (!$hostKey) {
        Write-LogMessage -Type ERROR -Message "Unable to retrieve SSH host key from $ptrAddress"
        Return $null
    }
    $knownHosts = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $knownHosts -HostName $ptrAddress -FingerPrint $hostKey.fingerprint | Out-Null
    $sshSession = New-SSHSession -ComputerName $ptrAddress -Credential $credential -KnownHost $knownHosts
    If (!$sshSession) {
        Write-LogMessage -Type ERROR -Message "Failed to establish SSH session to $ptrAddress"
        Return $null
    }
    $ptrHostname = ((Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "hostname").Output | Select-Object -First 1).Trim()
    Remove-SSHSession -SessionId $sshSession.SessionId | Out-Null
    $environmentName = $ptrHostname -replace '-converged-ptr', ''
    If (!$environmentName) {
        Write-LogMessage -Type ERROR -Message "Unable to derive an environment name from PTR hostname '$ptrHostname'"
        Return $null
    }
    Write-LogMessage -Type INFO -Message "Environment name: $environmentName"
    Return $environmentName
}

Function Connect-InfrastructureVC {
    <#
    .DESCRIPTION
        Connects to the infrastructure vCenter defined in infrastructure-settings.json. Returns the VIServer
        connection, or $null if the settings file is missing.
    #>
    Param (
        [Parameter (Mandatory = $false)] [String]$settingsFile = "C:\Users\Administrator\Documents\PlatformTools\infrastructure-settings.json"
    )

    If (!(Test-Path -Path $settingsFile)) {
        Write-LogMessage -Type ERROR -Message "$settingsFile not found"
        Return $null
    }
    $infraVc = (Get-Content -Path $settingsFile -Raw | ConvertFrom-Json).infrastructureVC
    If ($infraVc.passwordModel -eq "Secure") {
        Return (Connect-VIServer -Server $infraVc.fqdn -Credential (Get-StoredCredential -Target $infraVc.fqdn) -ErrorAction Stop)
    }
    Return (Connect-VIServer -Server $infraVc.fqdn -User $infraVc.username -Password $infraVc.password -ErrorAction Stop)
}

Function Select-EnvironmentDomain {
    <#
    .DESCRIPTION
        Detects every nested ESX host in the environment (VMs named "<env>-sfo0<n>-<domain>-r01-esx<nn>", excluding any
        ending in '-source'), groups them by the domain parsed from the name, and lets the user choose a domain.
        Returns an object with the VIServer connection, domain code and that domain's VMs, or $null if nothing was
        selected. The caller is responsible for disconnecting the returned connection.
    #>
    $environmentName = Get-PtrEnvironmentName
    If (!$environmentName) {
        Return $null
    }

    $viServer = Connect-InfrastructureVC
    If (!$viServer) {
        Return $null
    }

    $nameRegex = '^' + [regex]::Escape($environmentName) + '-sfo\d+-(?<domain>[a-z]\d+)-r01-esx\d+$'
    $allVms = @(Get-VM -Name "$environmentName-sfo*-r01-esx*" -Server $viServer -ErrorAction SilentlyContinue | Where-Object { ($_.Name -notlike "*-source") -and ($_.Name -match $nameRegex) })
    If ($allVms.Count -eq 0) {
        Write-LogMessage -Type ERROR -Message "No nested ESX hosts found for environment $environmentName on $($viServer.Name)"
        Disconnect-VIServer -Server $viServer -Confirm:$false -ErrorAction SilentlyContinue
        Return $null
    }

    $domainGroups = @($allVms | Group-Object -Property { $null = $_.Name -match $nameRegex; $Matches['domain'] } | Sort-Object -Property Name)
    Write-LogMessage -Type INFO -Message "Found $($allVms.Count) nested host(s) across $($domainGroups.Count) domain(s)"
    Write-Host ""
    Write-Host " Domains in $($environmentName):" -ForegroundColor Yellow
    For ($i = 0; $i -lt $domainGroups.Count; $i++) {
        Write-Host " $($i + 1). $($domainGroups[$i].Name) ($($domainGroups[$i].Count) hosts)" -ForegroundColor White
    }
    Do {
        $choice = Read-Host -Prompt " Select domain"
    } Until (($choice -match '^\d+$') -and ([int]$choice -ge 1) -and ([int]$choice -le $domainGroups.Count))
    $selectedGroup = $domainGroups[[int]$choice - 1]

    Return [PSCustomObject]@{
        ViServer   = $viServer
        DomainCode = $selectedGroup.Name
        Vms        = @($selectedGroup.Group | Sort-Object -Property Name)
    }
}

Function New-DomainHostSnapshots {
    <#
    .SYNOPSIS
        Takes a memory-less, asynchronous snapshot of the nested ESX hosts of a chosen domain.
    .DESCRIPTION
        Detects all nested hosts in the environment, lets the user choose a domain, asks for a snapshot name and
        snapshots every host in that domain.
    #>
    Try {
        $selection = Select-EnvironmentDomain
        If (!$selection) {
            Return
        }

        Try {
            $vms = $selection.Vms
            Write-VmTable -vms $vms

            Do {
                $snapshotName = Read-Host -Prompt " Enter snapshot name"
            } Until (![string]::IsNullOrWhiteSpace($snapshotName))

            foreach ($vm in $vms) {
                Write-LogMessage -Type INFO -Message "Starting snapshot '$snapshotName' of $($vm.Name) (no memory)"
                New-Snapshot -VM $vm -Name $snapshotName -Memory:$false -Quiesce:$false -RunAsync -Confirm:$false | Out-Null
            }
            Write-LogMessage -Type INFO -Message "Snapshot tasks submitted for $($vms.Count) VM(s); they complete asynchronously in vCenter"
        } Finally {
            Disconnect-VIServer -Server $selection.ViServer -Confirm:$false -ErrorAction SilentlyContinue
        }
    } Catch {
        Write-CaughtException -object $_
    }
}

Function Restore-DomainHostSnapshots {
    <#
    .SYNOPSIS
        Reverts the nested ESX hosts of a domain to a user-chosen snapshot and powers them on.
    .DESCRIPTION
        Detects all nested hosts in the environment, lets the user choose a domain, lists the snapshots on the first
        host of that domain for the user to choose from, reverts every host to the snapshot of that name, then
        powers them on.
    #>
    Try {
        $selection = Select-EnvironmentDomain
        If (!$selection) {
            Return
        }

        Try {
            $vms = $selection.Vms
            Write-VmTable -vms $vms

            $snapshots = @(Get-Snapshot -VM $vms[0] | Sort-Object -Property Created -Descending)
            If ($snapshots.Count -eq 0) {
                Write-LogMessage -Type ERROR -Message "No snapshots found on $($vms[0].Name)"
                Return
            }
            Write-Host ""
            Write-Host " Snapshots on $($vms[0].Name):" -ForegroundColor Yellow
            For ($i = 0; $i -lt $snapshots.Count; $i++) {
                Write-Host " $($i + 1). $($snapshots[$i].Name) (created $($snapshots[$i].Created))" -ForegroundColor White
            }
            Do {
                $choice = Read-Host -Prompt " Select snapshot to restore"
            } Until (($choice -match '^\d+$') -and ([int]$choice -ge 1) -and ([int]$choice -le $snapshots.Count))
            $snapshotName = $snapshots[[int]$choice - 1].Name

            $restoredVms = @()
            foreach ($vm in $vms) {
                $snapshot = Get-Snapshot -VM $vm -Name $snapshotName -ErrorAction SilentlyContinue | Sort-Object -Property Created -Descending | Select-Object -First 1
                If (!$snapshot) {
                    Write-LogMessage -Type ERROR -Message "[$($vm.Name)] Snapshot '$snapshotName' not found - skipping"
                    Continue
                }
                Write-LogMessage -Type INFO -Message "[$($vm.Name)] Reverting to snapshot '$snapshotName'"
                Set-VM -VM $vm -Snapshot $snapshot -Confirm:$false | Out-Null
                $restoredVms += $vm
            }

            foreach ($vm in $restoredVms) {
                Write-LogMessage -Type INFO -Message "[$($vm.Name)] Powering on"
                Start-VM -VM $vm -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            }
        } Finally {
            Disconnect-VIServer -Server $selection.ViServer -Confirm:$false -ErrorAction SilentlyContinue
        }
    } Catch {
        Write-CaughtException -object $_
    }
}

Function Reset-NestedHosts {
    Param (
        [Parameter (Mandatory = $true)] [Array]$hostArray
    )
    Connect-VIServer -server vcf-pd-vc01.lvn.broadcom.net -user breakglass@vsphere.local -Password VMw@re1!VMw@re1!
    foreach ($vmName in $nestedhosts) {
        $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
        if (-not $vm) {
            Write-Warning "VM '$vmName' not found. Skipping."
            continue
        }

        $latestSnapshot = Get-Snapshot -VM $vm | Sort-Object -Property Created -Descending | Select-Object -First 1
        if (-not $latestSnapshot) {
            Write-Warning "No snapshots found for '$vmName'. Skipping."
            continue
        }

        Write-Host "Reverting '$vmName' to snapshot '$($latestSnapshot.Name)' (created $($latestSnapshot.Created))..."
        Set-VM -VM $vm -Snapshot $latestSnapshot -Confirm:$false | Out-Null

        Write-Host "Powering on '$vmName'..."
        Start-VM -VM $vm -Confirm:$false | Out-Null
    }
    Disconnect-VIServer * -Confirm:$false
}

Function Reset-WorkloadDomainVMs {

    Connect-VIServer -Server "sfo-m01-vc01.sfo.rainpole.io" -user "administrator@vsphere.local" -Password 'VMw@re1!VMw@re1!'
    $vms = @("sfo-w02-vc01", "sfo-w02-nsx01a","sfo-vcf01")
    foreach ($vmName in $vms) {
        $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
        if (-not $vm) {
            Write-Warning "VM '$vmName' not found. Skipping."
            continue
        }

        $latestSnapshot = Get-Snapshot -VM $vm | Sort-Object -Property Created -Descending | Select-Object -First 1
        if (-not $latestSnapshot) {
            Write-Warning "No snapshots found for '$vmName'. Skipping."
            continue
        }

        Write-Host "Reverting '$vmName' to snapshot '$($latestSnapshot.Name)' (created $($latestSnapshot.Created))..."
        Set-VM -VM $vm -Snapshot $latestSnapshot -Confirm:$false | Out-Null

        Write-Host "Powering on '$vmName'..."
        Start-VM -VM $vm -Confirm:$false | Out-Null
    }
    Disconnect-VIServer * -Confirm:$false
}

New-TestingMenu
