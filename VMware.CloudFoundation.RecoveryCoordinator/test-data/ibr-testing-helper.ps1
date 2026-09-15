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
    $menuItem04 = "Reset sfo-m01-cl01 Nested Hosts"
    $menuItem05 = "Reset sfo-w01-cl01 Nested Hosts and relevant management VMs"
    $menuItem06 = "Reset sfo-w02-cl01 Nested Hosts and relevant management VMs"

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
        Write-Host -Object " 06. $menuItem06" -ForegroundColor White; $validMenuOptions += "06"

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
                Get-VCFBackups -PtrAddress $additionalSettings.userSettings.virtualRouter.public_ip -BackupUsername 'svc-vcf-bck' -BackupPassword 'VMw@re1!' -Destination "F:\VCFIR\current"
                Wait-AnyKey
            }
            02 {
                Clear-Host; Write-MenuBreadcrumb -Version $utilityBuild -Submenu $submenuTitle -MenuItem $menuItem02; Write-Host -Object ''
                Get-VCFInstallerBundleAssets -instanceObject $managementInstanceAObject -destinationPath "F:\VCFIR"
                Wait-AnyKey
            }
            03 {
                Clear-Host; Write-MenuBreadcrumb -Version $utilityBuild -Submenu $submenuTitle -MenuItem $menuItem03; Write-Host -Object ''
                Update-VCFBackupBreadcrumbPaths
                Wait-AnyKey
            }
            04 {
                Clear-Host; Write-MenuBreadcrumb -Version $utilityBuild -Submenu $submenuTitle -MenuItem $menuItem04; Write-Host -Object ''
                $nestedHosts = @("ken-911c5-ibr-osa-sfo01-m01-r01-esx01", "ken-911c5-ibr-osa-sfo01-m01-r01-esx02", "ken-911c5-ibr-osa-sfo01-m01-r01-esx03", "ken-911c5-ibr-osa-sfo01-m01-r01-esx04", "ken-911c5-ibr-osa-sfo02-m01-r01-esx01", "ken-911c5-ibr-osa-sfo02-m01-r01-esx02", "ken-911c5-ibr-osa-sfo02-m01-r01-esx03", "ken-911c5-ibr-osa-sfo02-m01-r01-esx04")
                Reset-NestedHosts -hostArray $nestedHosts
                Wait-AnyKey
            }
            05 {
                Clear-Host; Write-MenuBreadcrumb -Version $utilityBuild -Submenu $submenuTitle -MenuItem $menuItem05; Write-Host -Object ''
                $nestedHosts = @("ken-911c5-ibr-osa-sfo01-w01-r01-esx01", "ken-911c5-ibr-osa-sfo01-w01-r01-esx02", "ken-911c5-ibr-osa-sfo01-w01-r01-esx03", "ken-911c5-ibr-osa-sfo02-w01-r01-esx01", "ken-911c5-ibr-osa-sfo02-w01-r01-esx02", "ken-911c5-ibr-osa-sfo02-w01-r01-esx03")
                Reset-NestedHosts -hostArray $nestedHosts
                Wait-AnyKey
            }
            06 {
                Clear-Host; Write-MenuBreadcrumb -Version $utilityBuild -Submenu $submenuTitle -MenuItem $menuItem06; Write-Host -Object ''
                $nestedHosts = @("ken-911c5-sfo01-w02-r01-esx01", "ken-911c5-sfo01-w02-r01-esx02", "ken-911c5-sfo01-w02-r01-esx03")
                Reset-NestedHosts -hostArray $nestedHosts
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
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][String]$Destination = "F:\VCFIR\current"
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
    Copy-Item -Path "F:\VCFIR\current\credentials\*" -Destination "F:\VCFIR\"
    Copy-Item -Path "F:\VCFIR\current\sddc-manager-backup\vcf*.tar.gz" -Destination "F:\VCFIR\"
}

Function Update-VCFBackupBreadcrumbPaths {
    <#
    .SYNOPSIS
        Refreshes SDDC Manager and vCenter backup path references in breadcrumbs*.ps1
        against the backups actually staged under $destinationPath\current.
    .DESCRIPTION
        The Update-VCFBackupBreadcrumbPaths function locates the newest SDDC Manager
        backup archive under $destinationPath\current\sddc-manager-backup, every
        vCenter backup set folder under $destinationPath\current\vCenter (one per
        vCenter instance found there, keyed by the fqdn embedded in its folder name),
        and the newest credentials backup file per domain under
        $destinationPath\current\credentials (keyed by the domainLabel embedded in its
        filename), then rewrites any breadcrumbs*.ps1 file found in $destinationPath so
        all of their path references point at the current backups.
    .PARAMETER destinationPath
        Local folder containing the "current" backup staging folder and the
        breadcrumbs*.ps1 file(s) to update. Defaults to the current working directory.
    .EXAMPLE
        Update-VCFBackupBreadcrumbPaths
    .EXAMPLE
        Update-VCFBackupBreadcrumbPaths -destinationPath C:\Bundles
    #>

    Param (
        [Parameter (Mandatory = $false)] [String]$destinationPath = (Get-Location).Path
    )

    Try {
        # IP address of the machine this script is running on - always detected fresh,
        # never overridable, since the vCenter backup share path must point back at
        # this machine, not whatever machine a caller might think to pass in.
        $localIpAddress = ([System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) | Where-Object { $_.AddressFamily -eq 'InterNetwork' -and $_.ToString() -notlike '169.254.*' } | Select-Object -First 1).ToString()
        If (!$localIpAddress) {
            Write-LogMessage -Type ERROR -Message "Unable to detect this machine's IPv4 address - cannot build the vCenter backup share path"
            Break
        }

        $currentPath = Join-Path -Path $destinationPath -ChildPath "current"

        If (!(Test-Path -Path $currentPath)) {
            Write-LogMessage -Type WARNING -Message "$currentPath not found - nothing to update"
            Break
        }

        # Every discovered backup becomes one discriminator/newPath pair - SDDC Manager
        # contributes at most one, vCenter contributes one per subfolder found, and
        # credentials contributes one per domainLabel found.
        $backupReplacements = @()

        $sddcManagerBackupFolder = Join-Path -Path $currentPath -ChildPath "sddc-manager-backup"
        If (Test-Path -Path $sddcManagerBackupFolder) {
            $sddcManagerBackupFile = Get-ChildItem -Path $sddcManagerBackupFolder -Filter "*.tar.gz" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "decrypted*" } | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
            If ($sddcManagerBackupFile) {
                $backupReplacements += [PSCustomObject]@{
                    component     = "SDDC Manager"
                    discriminator = '(?i)sddc-manager-backup.*\.tar\.gz$'
                    newPath       = $sddcManagerBackupFile.FullName
                }
                Write-LogMessage -Type INFO -Message "Found SDDC Manager backup $($sddcManagerBackupFile.Name)"
            } else {
                Write-LogMessage -Type WARNING -Message "No .tar.gz backup archive found under $sddcManagerBackupFolder"
            }
        } else {
            Write-LogMessage -Type WARNING -Message "$sddcManagerBackupFolder not found"
        }

        $vCenterBackupRoot = Join-Path -Path $currentPath -ChildPath "vCenter"
        If (Test-Path -Path $vCenterBackupRoot) {
            $vCenterBackupFolders = Get-ChildItem -Path $vCenterBackupRoot -Directory -ErrorAction SilentlyContinue
            If (!$vCenterBackupFolders) {
                Write-LogMessage -Type WARNING -Message "No vCenter backup folders found under $vCenterBackupRoot"
            } else {
                foreach ($vCenterBackupFolder in $vCenterBackupFolders) {
                    $vCenterFqdn = $vCenterBackupFolder.Name -replace '^sn_', ''
                    $nestedBackupSetFolders = Get-ChildItem -Path $vCenterBackupFolder.FullName -Directory -ErrorAction SilentlyContinue
                    $vCenterBackupSetFolder = $nestedBackupSetFolders | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
                    If (!$vCenterBackupSetFolder) {
                        Write-LogMessage -Type WARNING -Message "No backup set folder found nested under $($vCenterBackupFolder.FullName) - skipping $vCenterFqdn"
                        Continue
                    }
                    If (@($nestedBackupSetFolders).Count -gt 1) {
                        Write-LogMessage -Type NOTE -Message "Multiple backup set folders found under $($vCenterBackupFolder.FullName) for $vCenterFqdn - using newest, $($vCenterBackupSetFolder.Name)"
                    }
                    $driveLetter = $vCenterBackupSetFolder.FullName.Substring(0, 1)
                    $shareRelativePath = ($vCenterBackupSetFolder.FullName -replace '^[A-Za-z]:\\', '') -replace '\\', '/'
                    $vCenterBackupSharePath = "$localIpAddress/$driveLetter`$/$shareRelativePath"
                    $backupReplacements += [PSCustomObject]@{
                        component     = "vCenter ($vCenterFqdn)"
                        discriminator = "(?i)vCenter[\\/].*$([regex]::Escape($vCenterFqdn))"
                        newPath       = $vCenterBackupSharePath
                    }
                    Write-LogMessage -Type INFO -Message "Found vCenter backup set $($vCenterBackupSetFolder.Name) for $vCenterFqdn"
                }
            }
        } else {
            Write-LogMessage -Type WARNING -Message "$vCenterBackupRoot not found"
        }

        $credentialsBackupRoot = Join-Path -Path $currentPath -ChildPath "credentials"
        If (Test-Path -Path $credentialsBackupRoot) {
            $credentialsBackupFiles = Get-ChildItem -Path $credentialsBackupRoot -Filter "vcf-credentials-*.json" -File -ErrorAction SilentlyContinue
            If (!$credentialsBackupFiles) {
                Write-LogMessage -Type WARNING -Message "No vcf-credentials-*.json backup files found under $credentialsBackupRoot"
            } else {
                $credentialsByDomain = $credentialsBackupFiles | Group-Object -Property { $_.BaseName -replace '^vcf-credentials-(.+)-\d{8}-\d{6}$', '$1' }
                foreach ($domainGroup in $credentialsByDomain) {
                    $domainLabel = $domainGroup.Name
                    $newestCredentialsFile = $domainGroup.Group | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
                    If ($domainGroup.Group.Count -gt 1) {
                        Write-LogMessage -Type NOTE -Message "Multiple credentials backup files found under $credentialsBackupRoot for domain $domainLabel - using newest, $($newestCredentialsFile.Name)"
                    }
                    $backupReplacements += [PSCustomObject]@{
                        component     = "Credentials ($domainLabel)"
                        discriminator = "(?i)credentials[\\/].*vcf-credentials-$([regex]::Escape($domainLabel))-"
                        newPath       = $newestCredentialsFile.FullName
                    }
                    Write-LogMessage -Type INFO -Message "Found credentials backup $($newestCredentialsFile.Name) for domain $domainLabel"
                }
            }
        } else {
            Write-LogMessage -Type WARNING -Message "$credentialsBackupRoot not found"
        }

        If (!$backupReplacements) {
            Write-LogMessage -Type NOTE -Message "No SDDC Manager, vCenter, or credentials backups found under $currentPath - nothing to update"
            Break
        }

        $breadcrumbsFiles = Get-ChildItem -Path $destinationPath -Filter "breadcrumbs*.ps1" -File -ErrorAction SilentlyContinue
        $quotedLiteralPattern = "(['" + '"' + "])((?:(?!\1).)*?)\1"

        foreach ($breadcrumbsFile in $breadcrumbsFiles) {
            $originalContent = Get-Content -Path $breadcrumbsFile.FullName -Raw
            $updatedContent = $originalContent

            foreach ($replacement in $backupReplacements) {
                $literalMatches = [regex]::Matches($updatedContent, $quotedLiteralPattern) | Where-Object { $_.Groups[2].Value -match $replacement.discriminator }

                foreach ($literalMatch in $literalMatches) {
                    $quoteChar = $literalMatch.Groups[1].Value
                    $oldLiteral = $literalMatch.Value
                    $newLiteral = "$quoteChar$($replacement.newPath)$quoteChar"
                    If ($oldLiteral -ne $newLiteral) {
                        $updatedContent = $updatedContent -replace [regex]::Escape($oldLiteral), $newLiteral
                        Write-LogMessage -Type INFO -Message "[$($breadcrumbsFile.Name)] Updated $($replacement.component) reference to $($replacement.newPath)"
                    }
                }
            }

            If ($updatedContent -ne $originalContent) {
                Set-Content -Path $breadcrumbsFile.FullName -Value $updatedContent -NoNewline
            } else {
                Write-LogMessage -Type INFO -Message "No matching backup path references needed updating in $($breadcrumbsFile.Name)"
            }
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
