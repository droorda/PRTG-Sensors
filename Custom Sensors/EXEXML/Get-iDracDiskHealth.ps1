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
    ,
    [Alias("IgnoreCertFailures")]
    [switch]
    $IgnoreCertFailure
)
begin {
    # $LogRetention = 30 #days
    $ExecutionTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $script:ScriptPath = split-path $SCRIPT:MyInvocation.MyCommand.Path -parent
    $script:ScriptName =            $SCRIPT:MyInvocation.MyCommand.Name.split(".")[0]
    $host.privatedata.VerboseForegroundColor  = 'DarkYellow'
# TODO error when no host name
    # if (-not (get-PackageProvider | Where-Object {$_.name -eq "NuGet"})){
    #     Write-Output "Installing NuGet"
    #     Install-PackageProvider -Name NuGet -Force | Write-Verbose
    # }
    Function Import-ModuleList {
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
        Import-Module "$script:ScriptPath\prtgshell.psm1" -DisableNameChecking -verbose:$false
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
        Write-Verbose $_ -Verbose
        exit
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
        Write-Verbose "Refreshing Array Data[$iDrac]"
        Try {
            # Import-Module DellPEWSManTools -ErrorAction Stop -Verbose:$false
            if (-not (get-module -Name "DellPEWSManTools")) {
                Import-ModuleList -Name "DellPEWSManTools" -Repository "IconicIT" -SourceLocation "https://nuget.dev.iconic-it.com/nuget"
            }
        } catch {
            Set-PrtgError $_.exception.Message
        }
        Try {
            Write-Verbose "New-PEDRACSession"
            $iDRACSession = New-PEDRACSession -HostName $iDrac -Credential $credential -MaxTimeout 600 -IgnoreCertFailures:$IgnoreCertFailure
            $iDRACSession | Format-List | Out-String | Write-Verbose
        } catch {
            Set-PrtgError $_.exception.Message
        }
        $Data[$iDrac].Refreshed = Get-Date
        Write-Verbose "Get-PEVirtualDisk"
        $Data[$iDrac].PEVirtualDisk   = Get-PEVirtualDisk  -iDRACSession $iDRACSession -ErrorAction Stop
        Write-Verbose "Get-PEEnclosure"
        $Data[$iDrac].PEEnclosure     = Get-PEEnclosure    -iDRACSession $iDRACSession
        Write-Verbose "Get-PEPhysicalDisk"
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
            if (($_.OperationName) -and ($_.OperationName -ne "None")) {
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
        $PEPhysicalDisk = $Data[$iDrac].PEPhysicalDisks |
                Where-Object {$_.Controller -eq $PhysicalDisk.Split(":")[0]} |
                Where-Object {$_.Enclosure  -eq $PhysicalDisk.Split(":")[1]} |
                Where-Object {$_.Slot       -eq $PhysicalDisk.Split(":")[2]}

        if ($PEPhysicalDisk) {
            $PEPhysicalDisk | Select-Object `
                    @{name='Controller2'                  ;expression={[int]$_.Controller}},
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
            $PEPhysicalDisk | Foreach-Object {
                $XMLOutput += Set-PrtgResult -Channel 'RollupStatus'             -Value $([int]$_.RollupStatus)             -Unit "Status"    -sc -ValueLookup "com.dell.idrac.disk.rollupstatus"
                $XMLOutput += Set-PrtgResult -Channel 'PrimaryStatus'            -Value $([int]$_.PrimaryStatus)            -Unit "Status"    -sc -ValueLookup "com.dell.idrac.disk.primarystatus"
                $XMLOutput += Set-PrtgResult -Channel 'RaidStatus'               -Value $([int]$_.RaidStatus)               -Unit "Status"    -sc -ValueLookup "com.dell.idrac.disk.raidstatus"
                if (($_.OperationName) -and ($_.OperationName -ne "None")) {
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
        } else {
            Set-PrtgError "Disk '$PhysicalDisk' Not Found"
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
# MIIM/gYJKoZIhvcNAQcCoIIM7zCCDOsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUSJQupMCN46jvKODeg5i6NZra
# N2OgggoFMIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
# BhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAY
# BgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTExMDUwMzA3MDAwMFoXDTMx
# MDUwMzA3MDAwMFowgbQxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMw
# EQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEt
# MCsGA1UECxMkaHR0cDovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMw
# MQYDVQQDEypHbyBEYWRkeSBTZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0g
# RzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC54MsQ1K92vdSTYusw
# ZLiBCGzDBNliF44v/z5lz4/OYuY8UhzaFkVLVat4a2ODYpDOD2lsmcgaFItMzEUz
# 6ojcnqOvK/6AYZ15V8TPLvQ/MDxdR/yaFrzDN5ZBUY4RS1T4KL7QjL7wMDge87Am
# +GZHY23ecSZHjzhHU9FGHbTj3ADqRay9vHHZqm8A29vNMDp5T19MR/gd71vCxJ1g
# O7GyQ5HYpDNO6rPWJ0+tJYqlxvTV0KaudAVkV4i1RFXULSo6Pvi4vekyCgKUZMQW
# OlDxSq7neTOvDCAHf+jfBDnCaQJsY1L6d8EbyHSHyLmTGFBUNUtpTrw700kuH9zB
# 0lL7AgMBAAGjggEaMIIBFjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
# BjAdBgNVHQ4EFgQUQMK9J47MNIMwojPX+2yz8LQsgM4wHwYDVR0jBBgwFoAUOpqF
# BxBnKLbv9r0FQW4gwZTaD94wNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5nb2RhZGR5LmNvbS8wNQYDVR0fBC4wLDAqoCigJoYkaHR0cDov
# L2NybC5nb2RhZGR5LmNvbS9nZHJvb3QtZzIuY3JsMEYGA1UdIAQ/MD0wOwYEVR0g
# ADAzMDEGCCsGAQUFBwIBFiVodHRwczovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9z
# aXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQAIfmyTEMg4uJapkEv/oV9PBO9sPpyI
# BslQj6Zz91cxG7685C/b+LrTW+C05+Z5Yg4MotdqY3MxtfWoSKQ7CC2iXZDXtHwl
# TxFWMMS2RJ17LJ3lXubvDGGqv+QqG+6EnriDfcFDzkSnE3ANkR/0yBOtg2DZ2HKo
# cyQetawiDsoXiWJYRBuriSUBAA/NxBti21G00w9RKpv0vHP8ds42pM3Z2Czqrpv1
# KrKQ0U11GIo/ikGQI31bS/6kA1ibRrLDYGCD+H1QQc7CoZDDu+8CL9IVVO5EFdkK
# rqeKM+2xLXY2JtwE65/3YR8V3Idv7kaWKK2hJn0KCacuBKONvPi8BDABMIIFLTCC
# BBWgAwIBAgIICFNsLoGX5IQwDQYJKoZIhvcNAQELBQAwgbQxCzAJBgNVBAYTAlVT
# MRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQK
# ExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2NlcnRzLmdvZGFk
# ZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1cmUgQ2Vy
# dGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMjAwMjE4MjExMjUyWhcNMjMwMjE4
# MjExMjUyWjBvMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHRmxvcmlkYTEUMBIGA1UE
# BxMLVGFsbGFoYXNzZWUxGzAZBgNVBAoTEklDT05JQyBHUk9VUCwgSU5DLjEbMBkG
# A1UEAxMSSUNPTklDIEdST1VQLCBJTkMuMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
# MIIBCgKCAQEAzjjzzc5C8YvYVzOwW7JXTdzllLRPV0j3UZkb4RHPiAsFuHhb1hIV
# 0pLlZUwZKwqDA7A9mJ7jk3rJjDcO6hyv+jlOuWS9oUoICZoZ8bRWNQT3yLcz7q82
# gjWmCGWFGmZYSN3/PtO//U4ihLG/XHs6JQJVg+faWbigm0YjblJV3qmw4WyKLanY
# btVBFklHXXCdh4CDjN6g38yiBApj8NtwcWvl/bTGyzqbdo2fMQpxLxexU9AXJnVS
# TlUHGBq9RwBN43iNiajqcUn3IgtKu8QDPZobzZTwKb4M2z9VV8aQrrvex5Ywx82a
# ebMs3LOUcvTUiX8sEl/G0RgSrwKBA8Tg6QIDAQABo4IBhTCCAYEwDAYDVR0TAQH/
# BAIwADATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMCB4AwNQYDVR0f
# BC4wLDAqoCigJoYkaHR0cDovL2NybC5nb2RhZGR5LmNvbS9nZGlnMnM1LTUuY3Js
# MF0GA1UdIARWMFQwSAYLYIZIAYb9bQEHFwIwOTA3BggrBgEFBQcCARYraHR0cDov
# L2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5LzAIBgZngQwBBAEw
# dgYIKwYBBQUHAQEEajBoMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5nb2RhZGR5
# LmNvbS8wQAYIKwYBBQUHMAKGNGh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5j
# b20vcmVwb3NpdG9yeS9nZGlnMi5jcnQwHwYDVR0jBBgwFoAUQMK9J47MNIMwojPX
# +2yz8LQsgM4wHQYDVR0OBBYEFPe0j8EJQOuTVpv/Z567G7Wds71yMA0GCSqGSIb3
# DQEBCwUAA4IBAQCrubpxo95D5MNNN0668ADnsLam4A/WyzCHHtRL8dzU5TM1iw+F
# PwcIdWcnWyJWYNwgeCGfquhiYyzwA6BErKHLd0vke8NN2djwX48/pNUOmhT1ke5K
# PfX+xsBlD3MPfC6b1kBLhNr/IliXlrGOxO6pp/DknEoxNDsAWOU0A209hO/MKANe
# INFhyz63LvMAKzu8p1we2qC1rwkdzYSygxE0iCbko5wOvvfCXjE1osKzzE3KSuq9
# +BMfthKjLGlEd6rFShaipBH/PCCXF0NeP4DHTC4+IzfSqpeUXpZA+pRMfdDRgBUS
# TwPEOWBGRc1p0UmsnVEl9O6ykKDQEqEOtzMcMYICYzCCAl8CAQEwgcEwgbQxCzAJ
# BgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxl
# MRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2Nl
# cnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBT
# ZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzICCAhTbC6Bl+SEMAkGBSsO
# AwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqG
# SIb3DQEJBDEWBBQD3ka+clbDiEgciwYXLRsV+nLM/DANBgkqhkiG9w0BAQEFAASC
# AQBK/Qg43G98kfV1FINatij7JCNlTqxkuS/KcahAS8YT8PI82J/phKtchcg88kEA
# p07BzX+NUKbTRDEAjMQNOoCNSPvPoDVe56wkL6ysuvjOBE1Gue4ZyrJE+Gvi0P8U
# FfiUqFJvK1VYum6Iw1hSpZkVBlQcqH/WH3DDR+TX959zjgbVf4EFAZXKi9PYE7IV
# uzs09SJDTovn7a6vSskHJ46JeciG0RDxs15ZLTHoKCqoGsA2j+iCckGKmz0TzDoJ
# g1g5atk81mi6lxs605GUjmbirBk+5ZI7nPYj+O7ZhpGMxB/WCkekuzRHkx/ed5gg
# aji+dB24fARc+oXGcHSoP/MK
# SIG # End signature block
