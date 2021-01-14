[CmdletBinding(
    SupportsShouldProcess=$True,
    ConfirmImpact='Low',
    DefaultParameterSetName = 'None'
)]
param (
    [String]
    $user         = $env:prtg_linuxuser
    ,
    [String]
    $pass         = $env:prtg_linuxpassword
    ,
    [String]
    $iDrac        = $env:prtg_host
    ,
    [PSCredential]
    $credential
    ,
    [Parameter(Mandatory = $False, ParameterSetName = "VirtualDisk")]
    [String]
    $VirtualDisk
    ,
    [Parameter(Mandatory = $False, ParameterSetName = "PhysicalDisk")]
    [String]
    $PhysicalDisk
    ,
    [Parameter(Mandatory = $False, ParameterSetName = "PhysicalDisks")]
    [Switch]
    $PhysicalDisks
    ,
    [bool]
    $Cached = $true

)
begin {
    # $LogRetention = 30 #days
    $ExecutionTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $script:ScriptPath = split-path $SCRIPT:MyInvocation.MyCommand.Path -parent
    $script:ScriptName =            $SCRIPT:MyInvocation.MyCommand.Name.split(".")[0]
    $host.privatedata.VerboseForegroundColor  = 'DarkYellow'
# TODO errorwhen no host name
    # if (-not (get-PackageProvider | Where-Object {$_.name -eq "NuGet"})){
    #     Write-Output "Installing NuGet"
    #     Install-PackageProvider -Name NuGet -Force | Write-Verbose
    # }
    Function Import-ModuleList{
        PARAM(
            [String[]]$Name,
            [String]$Repository,
            [String]$SourceLocation,
            [String]$InstallationPolicy = "Trusted"
        )
        if (-not (get-PSRepository | Where-Object {$_.Name -eq $Repository})){
            Write-Verbose "Installing $Repository NuGet Repository" -Verbose
            try {
                Register-PSRepository -Name $Repository -SourceLocation $SourceLocation -InstallationPolicy $InstallationPolicy
            } catch {
                $PSCmdlet.ThrowTerminatingError($PSItem)
            }
        }
        Foreach ($Module in $Name) {
            Try {
                Import-Module $Module -ErrorAction Stop
            } catch {
                Write-Verbose "Installing $($Module)" -Verbose
                install-Module -Name $Module -Repository $Repository -Force
                Try {
                    Import-Module $Module -ErrorAction Stop
                } catch {
                    $PSCmdlet.ThrowTerminatingError($PSItem)
                }
            }
        }
    }

    # try {
    #     Import-Module PowerShellLogging
    #     if (Test-Path ("$script:ScriptPath\Logs")){
    #         $LogFile = Enable-LogFile -Path "$script:ScriptPath\Logs\$script:ScriptName.$((get-date).tostring('yyyyMMddHHmm')).log"
    #         Get-ChildItem -Path "$script:ScriptPath\Logs" -Filter "$script:ScriptName.*.log" | Where-Object {(get-date).adddays($LogRetention * -1) -gt $_.LastWriteTime} | Remove-Item -Force
    #     } else {
    #         $LogFile = Enable-LogFile -Path "$script:ScriptPath\$script:ScriptName.log"
    #     }
    # } catch {
    #     Write-Warning "Unable to Enable file based logging"
    #     Write-Host "Caught an exception:" -ForegroundColor Red
    #     Write-Host "Exception Type   : $($_.Exception.GetType().FullName)" -ForegroundColor Red
    #     Write-Host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red

    # }
    Write-Verbose "-------------Start $($myInvocation.InvocationName) : $($ExecutionTimer.Elapsed.ToString()) -----------------"
    Write-Verbose "  From Script:'$($myInvocation.ScriptName)' - At Line:$($myInvocation.ScriptLineNumber) char:$($myInvocation.OffsetInLine)"
    Write-Verbose "  Line '$($myInvocation.Line.Trim())'"
    $myInvocation.BoundParameters.GetEnumerator()  | ForEach-Object { Write-Verbose "  BoundParameter   : '$($_.key)' = '$($_.Value)'" }
    $myInvocation.UnboundArguments | ForEach-Object { Write-Verbose "  UnboundArguments : '$_'" }

    if (test-path("$script:ScriptPath\prtgshell.psm1")) {
        Import-Module "$script:ScriptPath\prtgshell.psm1" -DisableNameChecking
    } else {
        Write-output "<prtg>"
        Write-output "  <error>1</error>"
        Write-output "  <text>Unable to locate prtgshell.psm1</text>"
        Write-output "</prtg>"
        exit
    }

    if ($user) {
        [SecureString] $secpasswd    = (ConvertTo-SecureString $pass -AsPlainText -Force -ErrorAction silent)
        [PSCredential] $credential   = (New-Object System.Management.Automation.PSCredential($user, $secpasswd))
    }

    if ($null -eq $iDrac) {
        Set-PrtgError "iDrac Host Name Not specified"
    }
    if ($null -eq $credential) {
        Set-PrtgError "iDrac Credentials Not specified"
    }

    $DataFile = "$env:ALLUSERSPROFILE\Application data\Paessler\PRTG Network Monitor\Sensordata (NonPersistent)\$script:ScriptName.dat"
    if (-not (Test-Path -PathType Container -path ( Split-Path -Path $DataFile))) {
        $DataFile = "$env:TEMP\$script:ScriptName.dat"
    }
}
process {
    Trap {
        Write-output "<prtg>"
        Write-output "  <error>-1</error>"
        Write-output "  <text>Line: $($_.invocationinfo.PositionMessage)</text>"
        Write-output "</prtg>"
        throw $_
    }

    if (test-Path($DataFile)) {
        Try {
            $Data = Import-Clixml $DataFile
        } Catch {
            $Data = @{
            }
        }
    } else {
        $Data = @{
        }
    }

    if ($null -eq $Data[$iDrac]) {
        $Data[$iDrac] = @{}
        $Data[$iDrac].Refreshed = get-date "1/1/1970"
    }

    if (((Get-Date) - $Data[$iDrac].Refreshed).TotalMinutes -gt 5) {
        Write-Verbose "Refreshing Array Data[$iDrac]" -Verbose
        Try {
            # Import-Module DellPEWSManTools -ErrorAction Stop -Verbose:$false
            Import-ModuleList -Name "DellPEWSManTools" -Repository "IconicIT" -SourceLocation "http://nuget.iconic-it.com/nuget"
        } catch {
            Set-PrtgError $_.exception.Message
        }
        $iDRACSession = New-PEDRACSession -HostName $iDrac -Credential $credential -MaxTimeout 600
        $Data[$iDrac].Refreshed = Get-Date
        $Data[$iDrac].PEVirtualDisk   = Get-PEVirtualDisk  -iDRACSession $iDRACSession -ErrorAction Stop
        $Data[$iDrac].PEEnclosure     = Get-PEEnclosure    -iDRACSession $iDRACSession
        $Data[$iDrac].PEPhysicalDisks = Get-PEPhysicalDisk -iDRACSession $iDRACSession
        Foreach ($PEPhysicalDisk in $Data[$iDrac].PEPhysicalDisks) {
            $Groups = [Regex]::new('Disk\.Bay\.\d+\:Enclosure\.(\S+)\.(\d+)-(\d+):RAID\.\S+\.(\d+)-(\d+)').Matches($PEPhysicalDisk.FQDD).Groups
            $PEPhysicalDisk | Add-Member -NotePropertyName ControllerType -NotePropertyValue $Groups[1].Value
            # $PEPhysicalDisk | Add-Member -NotePropertyName Connector     -NotePropertyValue $Groups[2].Value
            $PEPhysicalDisk | Add-Member -NotePropertyName Enclosure     -NotePropertyValue $Groups[3].Value
            $PEPhysicalDisk | Add-Member -NotePropertyName Controller    -NotePropertyValue $Groups[4].Value
            $Data[$iDrac].PEVirtualDisk | Where-Object {$_.PhysicalDiskIDs -contains $PEPhysicalDisk.InstanceID} | Foreach-Object {
                $PEPhysicalDisk | Add-Member -NotePropertyName VirtualDisk    -NotePropertyValue $_
            }
            $Data[$iDrac].PEEnclosure | Where-Object {$PEPhysicalDisk.InstanceID -match ".*$($_.InstanceID)"} | Foreach-Object {
                $PEPhysicalDisk | Add-Member -NotePropertyName Enclosure2    -NotePropertyValue $_
            }
            # $PEPhysicalDisk | Add-Member -NotePropertyName Slot          -NotePropertyValue $Groups[5].Value
        }
        $Data[$iDrac].PEPhysicalDisks = $Data[$iDrac].PEPhysicalDisks | Sort-Object @{expression={[int]$_.Controller}},@{expression={[int]$_.Enclosure}},@{expression={[int]$_.Slot}}

        $Data | Export-Clixml $DataFile
    }

    $XMLOutput = "<prtg>`n"

    if ($PSCmdlet.ParameterSetName -eq 'None') {
        $Data[$iDrac].PEVirtualDisk | Foreach-Object {
            $XMLOutput += Set-PrtgResult -Channel $_.Name -Value $([int]$_.RollupStatus) -Unit "Status" -sc -ValueLookup "com.dell.idrac.disk.rollupstatus"
        }

    } elseif ($PSCmdlet.ParameterSetName -eq 'VirtualDisk') {
        $Data[$iDrac].PEVirtualDisk | Where-Object {$_.Name -eq $VirtualDisk} | Select-Object Name,
                @{name='PrimaryStatus'               ;expression={$PEPhysicalDiskLookups.PrimaryStatus[         $_.PrimaryStatus]}},
                @{name='RaidStatus'                  ;expression={$PEPhysicalDiskLookups.RaidStatus[            $_.RaidStatus]}},
                OperationName,
                @{name='OperationPercentComplete'    ;expression={[int]$_.OperationPercentComplete}},
                @{name='RAIDTypes'                   ;expression={$PEPhysicalDiskLookups.RAIDTypes[             $_.RAIDTypes]}},
                @{name='ReadCachePolicy'             ;expression={$PEPhysicalDiskLookups.ReadCachePolicy[       $_.ReadCachePolicy]}},
                @{name='RemainingRedundancy'         ;expression={[int]$_.RemainingRedundancy}},
                @{name='RollupStatus'                ;expression={$PEPhysicalDiskLookups.RollupStatus[          $_.RollupStatus]}},
                @{name='WriteCachePolicy'            ;expression={$PEPhysicalDiskLookups.WriteCachePolicy[      $_.WriteCachePolicy]}} | Out-String | Write-Verbose
        $Data[$iDrac].PEVirtualDisk | Where-Object {$_.Name -eq $VirtualDisk} | Foreach-Object {
            $XMLOutput += Set-PrtgResult -Channel 'RollupStatus'             -Value $([int]$_.RollupStatus)             -Unit "Status"  -sc -ValueLookup "com.dell.idrac.disk.rollupstatus"
            $XMLOutput += Set-PrtgResult -Channel 'PrimaryStatus'            -Value $([int]$_.PrimaryStatus)            -Unit "Status"  -sc -ValueLookup "com.dell.idrac.disk.primarystatus"
            $XMLOutput += Set-PrtgResult -Channel 'RaidStatus'               -Value $([int]$_.RaidStatus)               -Unit "Status"  -sc -ValueLookup "com.dell.idrac.disk.raidstatus"
            # $XMLOutput += Set-PrtgResult -Channel 'OperationName'            -Value $([int]$_.OperationName)            -Unit "Status"  -sc -ValueLookup "com.dell.idrac.disk.operationname"
            # $XMLOutput += Set-PrtgResult -Channel 'OperationPercentComplete' -Value $([int]$_.OperationPercentComplete) -Unit "Percent" -sc
            if ($_.OperationName -ne "None") {
                $XMLOutput += Set-PrtgResult -Channel $_.OperationName -Value $([int]$_.OperationPercentComplete) -Unit "Percent" -sc
            }
            $XMLOutput += Set-PrtgResult -Channel 'RAIDTypes'                -Value $([int]$_.RAIDTypes)                -Unit "Status"  -sc -ValueLookup "com.dell.idrac.disk.raidtypes"
            $XMLOutput += Set-PrtgResult -Channel 'ReadCachePolicy'          -Value $([int]$_.ReadCachePolicy)          -Unit "Status"  -sc -ValueLookup "com.dell.idrac.disk.readcachepolicy"

            # TODO: Detect how many sub arrays are in RAID10,50,60 to get acurate
            Switch ([int]$_.RAIDTypes){
                # RAID-1
                4     { $MinRedundancyWarn = 1 ; $MinRedundancyError = 0 }
                # RAID-5
                64    { $MinRedundancyWarn = 1 ; $MinRedundancyError = 0 }
                # RAID-6
                128   { $MinRedundancyWarn = 2 ; $MinRedundancyError = 1 }
                # RAID-10
                2048  { $MinRedundancyWarn = 2 ; $MinRedundancyError = 1 }
                # RAID-50
                8192  { $MinRedundancyWarn = 2 ; $MinRedundancyError = 1 }
                # RAID-60
                16384 { $MinRedundancyWarn = 4 ; $MinRedundancyError = 2 }
                default { $MinRedundancyWarn = 0 }
                }
            $XMLOutput += Set-PrtgResult -Channel 'RemainingRedundancy'      -Value $([int]$_.RemainingRedundancy)      -Unit "Count"   -sc -MinWarn $MinRedundancyWarn -MinError $MinRedundancyError
            $XMLOutput += Set-PrtgResult -Channel 'WriteCachePolicy'         -Value $([int]$_.WriteCachePolicy)         -Unit "Status"  -sc -ValueLookup "com.dell.idrac.disk.writecachepolicy"
            # $XMLOutput += "<text>$($_.OperationName)</text>`n"
        }

    } elseif ($PSCmdlet.ParameterSetName -eq 'PhysicalDisks') {
        $Data[$iDrac].PEPhysicalDisks | Select-Object ControllerType,
                @{name='Controller'                  ;expression={[int]$_.Controller}},
                @{name='EnclosureTag'                ;expression={$_.Enclosure2.ServiceTag}},
                @{name='Enclosure'                   ;expression={[int]$_.Enclosure}},
                @{name='Slot'                        ;expression={[int]$_.Slot}},
                @{name='VirtualDisk'                 ;expression={$_.VirtualDisk.Name}},
                SerialNumber,
                @{name='PredictiveFailureState'      ;expression={$PEPhysicalDiskLookups.PredictiveFailureState[$_.PredictiveFailureState]}},
                @{name='PrimaryStatus'               ;expression={$PEPhysicalDiskLookups.PrimaryStatus[         $_.PrimaryStatus]}},
                @{name='RaidStatus'                  ;expression={$PEPhysicalDiskLookups.RaidStatus[            $_.RaidStatus]}},
                @{name='RollupStatus'                ;expression={$PEPhysicalDiskLookups.RollupStatus[          $_.RollupStatus]}},
                OperationName,
                @{name='OperationPercentComplete';expression={if ($_.OperationName -ne "None") {$_.OperationPercentComplete}}},
                @{name='BusProtocol'                 ;expression={$PEPhysicalDiskLookups.BusProtocol[           $_.BusProtocol]}},
                @{name='HotSpareStatus'              ;expression={$PEPhysicalDiskLookups.HotSpareStatus[        $_.HotSpareStatus]}},
                @{name='RemainingRatedWriteEndurance';expression={if ($_.MediaType -eq "1") {$_.RemainingRatedWriteEndurance}}},
                @{name='SizeInGB'                    ;expression={[int]($_.SizeInBytes/1073741824)}}
    } elseif ($PSCmdlet.ParameterSetName -eq 'PhysicalDisk') {
        $Data[$iDrac].PEPhysicalDisks |
        Where-Object {$_.Controller -eq $PhysicalDisk.Split(":")[0]} |
        Where-Object {$_.Enclosure  -eq $PhysicalDisk.Split(":")[1]} |
        Where-Object {$_.Slot       -eq $PhysicalDisk.Split(":")[2]} |
        Select-Object @{name='Controller2'                  ;expression={[int]$_.Controller}},
                @{name='EnclosureTag'                ;expression={$_.Enclosure2.ServiceTag}},
                @{name='Enclosure3'                   ;expression={[int]$_.Enclosure}},
                @{name='Slot2'                        ;expression={[int]$_.Slot}},
                @{name='VirtualDisk2'                 ;expression={$_.VirtualDisk.Name}},
                @{name='PredictiveFailureState2'      ;expression={$PEPhysicalDiskLookups.PredictiveFailureState[$_.PredictiveFailureState]}},
                @{name='PrimaryStatus2'               ;expression={$PEPhysicalDiskLookups.PrimaryStatus[         $_.PrimaryStatus]}},
                @{name='RaidStatus2'                  ;expression={$PEPhysicalDiskLookups.RaidStatus[            $_.RaidStatus]}},
                @{name='RollupStatus2'                ;expression={$PEPhysicalDiskLookups.RollupStatus[          $_.RollupStatus]}},
                @{name='OperationPercentComplete2';expression={if ($_.OperationName -ne "None") {$_.OperationPercentComplete}}},
                @{name='BusProtocol2'                 ;expression={$PEPhysicalDiskLookups.BusProtocol[           $_.BusProtocol]}},
                @{name='HotSpareStatus2'              ;expression={$PEPhysicalDiskLookups.HotSpareStatus[        $_.HotSpareStatus]}},
                @{name='RemainingRatedWriteEndurance2';expression={if ($_.MediaType -eq "1") {$_.RemainingRatedWriteEndurance}}},
                @{name='SizeInGB'                    ;expression={[int]($_.SizeInBytes/1073741824)}},
                * | Out-String | Write-Verbose
        $Data[$iDrac].PEPhysicalDisks |
                Where-Object {$_.Controller -eq $PhysicalDisk.Split(":")[0]} |
                Where-Object {$_.Enclosure  -eq $PhysicalDisk.Split(":")[1]} |
                Where-Object {$_.Slot       -eq $PhysicalDisk.Split(":")[2]} |
                Foreach-Object {
                    $XMLOutput += Set-PrtgResult -Channel 'RollupStatus'             -Value $([int]$_.RollupStatus)             -Unit "Status"    -sc -ValueLookup "com.dell.idrac.disk.rollupstatus"
                    $XMLOutput += Set-PrtgResult -Channel 'PrimaryStatus'            -Value $([int]$_.PrimaryStatus)            -Unit "Status"    -sc -ValueLookup "com.dell.idrac.disk.primarystatus"
                    $XMLOutput += Set-PrtgResult -Channel 'RaidStatus'               -Value $([int]$_.RaidStatus)               -Unit "Status"    -sc -ValueLookup "com.dell.idrac.disk.raidstatus"
                    if ($_.OperationName -ne "None") {
                        $XMLOutput += Set-PrtgResult -Channel $_.OperationName       -Value $([int]$_.OperationPercentComplete) -Unit "Percent"   -sc -MaxWarn 0
                    }
                    # # $XMLOutput += Set-PrtgResult -Channel 'OperationName'            -Value $([int]$_.OperationName)            -Unit "Status"  -sc -ValueLookup "com.dell.idrac.disk.operationname"
                    $XMLOutput += Set-PrtgResult -Channel 'PredictiveFailureState'   -Value $([int]$_.PredictiveFailureState)   -Unit "Status"    -sc -ValueLookup "com.dell.idrac.disk.predictivefailurestate"
                    $XMLOutput += Set-PrtgResult -Channel 'BusProtocol'              -Value $([int]$_.BusProtocol)              -Unit "Status"    -sc -ValueLookup "com.dell.idrac.disk.busprotocol"
# IF 1 or 2 set default limits to ensure it stays 1 or 2 -----------Setting limit breaks lookup table
                    $XMLOutput += Set-PrtgResult -Channel 'HotSpareStatus'           -Value $([int]$_.HotSpareStatus)           -Unit "Status"    -sc -ValueLookup "com.dell.idrac.disk.hotsparestatus"
                    $XMLOutput += Set-PrtgResult -Channel 'Size'                     -Value $([int64]$_.SizeInBytes)            -Unit "BytesDisk" -sc -VolumeSize  "GigaByte"
                    $XMLOutput += Set-PrtgResult -Channel 'SecurityState'            -Value $([int]$_.SecurityState)            -Unit "Status"    -sc -ValueLookup "com.dell.idrac.disk.securitystate"
                    $XMLOutput += Set-PrtgResult -Channel 'MediaType'                -Value $([int]$_.MediaType)                -Unit "Status"    -sc -ValueLookup "com.dell.idrac.disk.mediatype"
                    $XMLOutput += Set-PrtgResult -Channel 'DriveFormFactor'          -Value $([int]$_.DriveFormFactor)          -Unit "Status"    -sc -ValueLookup "com.dell.idrac.disk.driveformfactor"
                    $XMLOutput += Set-PrtgResult -Channel 'MaxCapableSpeed'          -Value $([int]$_.MaxCapableSpeed)          -Unit "Status"    -sc -ValueLookup "com.dell.idrac.disk.maxcapablespeed"
                    if ($_.MediaType -eq "1") {
                        $XMLOutput += Set-PrtgResult -Channel 'RemainingRatedWriteEndurance' -Value $([int]$_.RemainingRatedWriteEndurance) -Unit "Percent" -sc -MinWarn 20 -MinError 10
                    }

                    $Text  = ""
                    if ($_.Enclosure2.ServiceTag) {
                        $Text += "Enclosure ServiceTag:'$($_.Enclosure2.ServiceTag.trim())' "
                    }
                    if ($_.Model) {
                        $Text += "DiskModel:'$($_.Model)' "
                    }
                    if ($_.SerialNumber) {
                        $Text += "DiskSerial:'$($_.SerialNumber)' "
                    }
                    $Text += "VirtualDisk:'$($_.VirtualDisk.Name)'"
                    $XMLOutput += "<text>$Text</text>`n"
                }

    }
    $XMLOutput += "</prtg>"

    Write-Host $XMLOutput

}
End {
    Write-Verbose "--------------END- $($myInvocation.InvocationName) : $($ExecutionTimer.Elapsed.ToString()) -----------------"
    # $LogFile | Disable-LogFile
}




# | Format-table DeviceDescription, Connector, BusProtocol, Slot, DriveFormFactor, HotSpareStatus, MaxCapableSpeed, MediaType, OperationName, OperationPercentComplete, PrimaryStatus, RaidStatus -a


# foreach ($BusProtocol in $BusProtocols) {
#     write-host $BusProtocol -ForegroundColor Cyan
#     Get-PEPhysicalDisk -iDRACSession $iDRACSession -MediaType 'HDD' -BusProtocol $BusProtocol | Format-table DeviceDescription, Connector, BusProtocol, Slot, DriveFormFactor, HotSpareStatus, MaxCapableSpeed, MediaType, OperationName, OperationPercentComplete, PrimaryStatus, RaidStatus -a
#     Get-PEPhysicalDisk -iDRACSession $iDRACSession -MediaType 'SSD' -BusProtocol $BusProtocol | Format-table DeviceDescription, Connector, BusProtocol, Slot, DriveFormFactor, HotSpareStatus, MaxCapableSpeed, MediaType, OperationName, OperationPercentComplete, PrimaryStatus, RaidStatus -a
# }
<#
BusProtocol                  : 6=BackPlane, 5=Enclosure
Slot                         : Disk #
PredictiveFailureState       : 0=Flase
PrimaryStatus                : 1
RaidStatus                   : 2
RollupStatus                 : 1
SecurityState                : 0
MediaType                    : HDD=0, SSD=1
    # Get-PERAIDEnumeration -iDRACSession $iDRACSession
    $PEPhysicalDiskLookups = [PSCustomObject]@{
        PrimaryStatus = @{
            "0" = "Unknown"
            "1" = "OK"
            "2" = "Degraded"
            "3" = "Error"
            "0x8000" = "DMTF Reserved"
            "0xFFFF" = "Vendor Reserved"
        }
        RollupStatus = @{
            "0" = "Unknown"
            "1" = "OK"
            "2" = "Degraded"
            "3" = "Error"
            "0x8000" = "DMTF Reserved"
            "0xFFFF" = "Vendor Reserved"
        }
        RaidStatus = @{
            "0" = "Unknown"
            "1" = "Ready"
            "2" = "Online"
            "3" = "Foreign"
            "4" = "Offline"
            "5" = "Blocked"
            "6" = "Failed"
            "7" = "Degraded"
            "8" = "Non-RAID"
            "9" = "Missing"
        }
        BusProtocol = @{
            "0" = "Unknown"
            "1" = "SCSI"
            "2" = "PATA"
            "3" = "FIBRE"
            "4" = "USB"
            "5" = "SATA"
            "6" = "SAS"
            "7" = "PCIE"
        }
        HotSpareStatus = @{
            "0" = "No"
            "1" = "Dedicated"
            "2" = "Global"
        }
        PredictiveFailureState = @{
            "0" = "Smart Alert Absent"
            "1" = "Smart Alert Present"
        }
        SecurityState = @{
            "0" = "Not Capable"
            "1" = "Secured"
            "2" = "Locked"
            "3" = "Foreign"
        }
        MediaType = @{
            "0" = "Hard Disk Drive"
            "1" = "Solid State Drive"
        }
        MaxCapableSpeed = @{
            "0" = "Unknown"
            "1" = "1.5Gbs"
            "2" = "3Gbs"
            "3" = "6Gbs"
            "4" = "12Gbs"
        }
        DriveFormFactor = @{
            "0" = "Unknown"
            "1" = "1.8 inch"
            "2" = "2.5 inch"
            "3" = "3.5 inch"
            "4" = "2.5 inch Add-in card"
        }
        RAIDTypes = @{
            "1"     = "No RAID"
            "2"     = "RAID-0"
            "4"     = "RAID-1"
            "64"    = "RAID-5"
            "128"   = "RAID-6"
            "2048"  = "RAID-10"
            "8192"  = "RAID-50"
            "16384" = "RAID-60"
        }
        ReadCachePolicy = @{
            "0"  = "Unknown"
            "16" = "No Read Ahead"
            "32" = "Read Ahead"
            "64" = "AdaptiveRead Ahead"
        }
        WriteCachePolicy = @{
            "0" = "Unknown"
            "1" = "Write Through"
            "2" = "Write Back"
            "4" = "Write Back force"
        }
    }


#>




# Get-PEAvailableDisk -iDRACSession $iDRACSession
        # $DiskType
        # $DiskProtocol
        # $DiskEncrypt



# SIG # Begin signature block
# MIIXpgYJKoZIhvcNAQcCoIIXlzCCF5MCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUQrwNyAB4+7fUpiQKthMgGTdd
# 4K6gghKeMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggTQMIIDuKADAgECAgEHMA0GCSqGSIb3DQEBCwUAMIGDMQswCQYDVQQGEwJVUzEQ
# MA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMR
# R29EYWRkeS5jb20sIEluYy4xMTAvBgNVBAMTKEdvIERhZGR5IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMTEwNTAzMDcwMDAwWhcNMzEwNTAzMDcw
# MDAwWjCBtDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcT
# ClNjb3R0c2RhbGUxGjAYBgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMS0wKwYDVQQL
# EyRodHRwOi8vY2VydHMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS8xMzAxBgNVBAMT
# KkdvIERhZGR5IFNlY3VyZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALngyxDUr3a91JNi6zBkuIEIbMME
# 2WIXji//PmXPj85i5jxSHNoWRUtVq3hrY4NikM4PaWyZyBoUi0zMRTPqiNyeo68r
# /oBhnXlXxM8u9D8wPF1H/JoWvMM3lkFRjhFLVPgovtCMvvAwOB7zsCb4Zkdjbd5x
# JkePOEdT0UYdtOPcAOpFrL28cdmqbwDb280wOnlPX0xH+B3vW8LEnWA7sbJDkdik
# M07qs9YnT60liqXG9NXQpq50BWRXiLVEVdQtKjo++Li96TIKApRkxBY6UPFKrud5
# M68MIAd/6N8EOcJpAmxjUvp3wRvIdIfIuZMYUFQ1S2lOvDvTSS4f3MHSUvsCAwEA
# AaOCARowggEWMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1Ud
# DgQWBBRAwr0njsw0gzCiM9f7bLPwtCyAzjAfBgNVHSMEGDAWgBQ6moUHEGcotu/2
# vQVBbiDBlNoP3jA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmdvZGFkZHkuY29tLzA1BgNVHR8ELjAsMCqgKKAmhiRodHRwOi8vY3JsLmdv
# ZGFkZHkuY29tL2dkcm9vdC1nMi5jcmwwRgYDVR0gBD8wPTA7BgRVHSAAMDMwMQYI
# KwYBBQUHAgEWJWh0dHBzOi8vY2VydHMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS8w
# DQYJKoZIhvcNAQELBQADggEBAAh+bJMQyDi4lqmQS/+hX08E72w+nIgGyVCPpnP3
# VzEbvrzkL9v4utNb4LTn5nliDgyi12pjczG19ahIpDsILaJdkNe0fCVPEVYwxLZE
# nXssneVe5u8MYaq/5Cob7oSeuIN9wUPORKcTcA2RH/TIE62DYNnYcqhzJB61rCIO
# yheJYlhEG6uJJQEAD83EG2LbUbTTD1Eqm/S8c/x2zjakzdnYLOqum/UqspDRTXUY
# ij+KQZAjfVtL/qQDWJtGssNgYIP4fVBBzsKhkMO77wIv0hVU7kQV2Qqup4oz7bEt
# djYm3ATrn/dhHxXch2/uRpYoraEmfQoJpy4Eo428+LwEMAEwggUtMIIEFaADAgEC
# AggIU2wugZfkhDANBgkqhkiG9w0BAQsFADCBtDELMAkGA1UEBhMCVVMxEDAOBgNV
# BAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoTEUdvRGFk
# ZHkuY29tLCBJbmMuMS0wKwYDVQQLEyRodHRwOi8vY2VydHMuZ29kYWRkeS5jb20v
# cmVwb3NpdG9yeS8xMzAxBgNVBAMTKkdvIERhZGR5IFNlY3VyZSBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgLSBHMjAeFw0yMDAyMTgyMTEyNTJaFw0yMzAyMTgyMTEyNTJa
# MG8xCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdGbG9yaWRhMRQwEgYDVQQHEwtUYWxs
# YWhhc3NlZTEbMBkGA1UEChMSSUNPTklDIEdST1VQLCBJTkMuMRswGQYDVQQDExJJ
# Q09OSUMgR1JPVVAsIElOQy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDOOPPNzkLxi9hXM7BbsldN3OWUtE9XSPdRmRvhEc+ICwW4eFvWEhXSkuVlTBkr
# CoMDsD2YnuOTesmMNw7qHK/6OU65ZL2hSggJmhnxtFY1BPfItzPurzaCNaYIZYUa
# ZlhI3f8+07/9TiKEsb9cezolAlWD59pZuKCbRiNuUlXeqbDhbIotqdhu1UEWSUdd
# cJ2HgIOM3qDfzKIECmPw23Bxa+X9tMbLOpt2jZ8xCnEvF7FT0BcmdVJOVQcYGr1H
# AE3jeI2JqOpxSfciC0q7xAM9mhvNlPApvgzbP1VXxpCuu97HljDHzZp5syzcs5Ry
# 9NSJfywSX8bRGBKvAoEDxODpAgMBAAGjggGFMIIBgTAMBgNVHRMBAf8EAjAAMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDA1BgNVHR8ELjAsMCqg
# KKAmhiRodHRwOi8vY3JsLmdvZGFkZHkuY29tL2dkaWcyczUtNS5jcmwwXQYDVR0g
# BFYwVDBIBgtghkgBhv1tAQcXAjA5MDcGCCsGAQUFBwIBFitodHRwOi8vY2VydGlm
# aWNhdGVzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMAgGBmeBDAEEATB2BggrBgEF
# BQcBAQRqMGgwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmdvZGFkZHkuY29tLzBA
# BggrBgEFBQcwAoY0aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBv
# c2l0b3J5L2dkaWcyLmNydDAfBgNVHSMEGDAWgBRAwr0njsw0gzCiM9f7bLPwtCyA
# zjAdBgNVHQ4EFgQU97SPwQlA65NWm/9nnrsbtZ2zvXIwDQYJKoZIhvcNAQELBQAD
# ggEBAKu5unGj3kPkw003TrrwAOewtqbgD9bLMIce1Evx3NTlMzWLD4U/Bwh1Zydb
# IlZg3CB4IZ+q6GJjLPADoESsoct3S+R7w03Z2PBfjz+k1Q6aFPWR7ko99f7GwGUP
# cw98LpvWQEuE2v8iWJeWsY7E7qmn8OScSjE0OwBY5TQDbT2E78woA14g0WHLPrcu
# 8wArO7ynXB7aoLWvCR3NhLKDETSIJuSjnA6+98JeMTWiwrPMTcpK6r34Ex+2EqMs
# aUR3qsVKFqKkEf88IJcXQ14/gMdMLj4jN9Kql5RelkD6lEx90NGAFRJPA8Q5YEZF
# zWnRSaydUSX07rKQoNASoQ63MxwxggRyMIIEbgIBATCBwTCBtDELMAkGA1UEBhMC
# VVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNV
# BAoTEUdvRGFkZHkuY29tLCBJbmMuMS0wKwYDVQQLEyRodHRwOi8vY2VydHMuZ29k
# YWRkeS5jb20vcmVwb3NpdG9yeS8xMzAxBgNVBAMTKkdvIERhZGR5IFNlY3VyZSBD
# ZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMgIICFNsLoGX5IQwCQYFKw4DAhoFAKB4
# MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkE
# MRYEFHtLEaqAfBy6y5ssXQNnt+sshqpbMA0GCSqGSIb3DQEBAQUABIIBACapGiHE
# BK0vOftGuOd1d7PcTNXi8/8K8EbRKAcMGJnrrmPojvpPdYCDTCUhfkPEmOTZeMbh
# HdFuEF8/pvLGxFKy3Dcukr5X4nW2hhu83MhVa+TZnKgPr2/cLgVKWXWZoq4WQky1
# zuc55LeRhnQ5eLSDHupCiwnUdZ8rXT5q4qAbgUbIN+pDPF+QOvJA2ijAGo2CII8e
# 8j0f94HTW9dgYerqBs2/iAg32Xty8GdjiVh7A/tu4CH4uyxk4jQCUCkMaURitZQQ
# eZyybDEEJuGizFjz37W/RJHeN5w1yA2CoaCo43G+1IP/7k/VMOLiPk9yBlXm+Dau
# 9TI8yNLV7YlSBbShggILMIICBwYJKoZIhvcNAQkGMYIB+DCCAfQCAQEwcjBeMQsw
# CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNV
# BAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMgIQDs/0
# OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAxMTI4MDIwMDA3WjAjBgkqhkiG9w0BCQQx
# FgQUcxDrNEPvL8EZybdR8oAMZ1zQlDkwDQYJKoZIhvcNAQEBBQAEggEAjy0bTH2p
# fQmdxoJmkSJ1tvFdKN3Rn2f1HfoEG71LBJN5tkcoVDLvW3PlKZSloxmRzNaP6J96
# YMXEJulOXbsLTCtDMudiw1ibqIcDcmW0ATZHAqUtqdI+GinLu4ez1AmqQSk6+HuN
# g+Tmb7H+3D+oc8gJAxdCQgID6RRn595INBVtDYEh44xFRfRQt+d7MADlJraDRsdO
# fQJIsplPDDz6A2ZBB3OgdYzAhMGTf8epwjohclaNI9foYB50pvbeUV+YIaTzZqLa
# jFBVXCk288tEYxjV7XTmvwdpmVCFNecBuPhRCZmylC2RyNzbWi9HApfG09CjMjc1
# yZzxtnuWZBs50Q==
# SIG # End signature block
