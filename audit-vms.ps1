# ==============================
# collect Command Line Arguments (hostname only)

if ($args.count -gt 1) {
  write-host "Too Many Arguments Specified"
  write-host "Syntax:  audit-vms hostname OR fqdn OR ipaddress"
  return
  }
if ($args.count -eq 0) {
  write-host "no target host specified - please specify IP or hostname"
  write-host "Syntax:  audit-vms hostname OR fqdn OR ipaddress"
  return
  }
else {
  $h = $args[0] 
  }


# ==============================
# Is the specified host reachable?

if(!(Test-Connection -Cn $h -BufferSize 16 -Count 1 -ea 0 -quiet))
  {
  write-host "Specified Host "$h" is not reachable, please check hostname or IP address"
  return
  }

$outfile = "audit-"+$h+"-vms.html"

# ==============================
# Check Login

$retry = 1
while ($retry -eq 1) {

$vicreds = get-credential $null
$login = connect-viserver -server $h -credential $vicreds

if ($login.name.length -eq 0) {
    write-host "Login failed, please retry or press Ctrl-C to exit"
    # short pause gives the chance for Ctrl-C
    start-sleep 2
    }
else {
    write-host "Login Successful"
    $login | ft
    $retry=0
    }
}

$vms = get-vm

##########################################################################################
#                                                                                        #
# GLOBAL VARIABLES                                                                       #
#                                                                                        #
##########################################################################################

$h1 =  "<h1>"
$eh1 = "</h1>"
$h2 = "<h2>"
$eh2 = "</h2>"
$pre = "<pre>"
$epre = "</pre>"
$p = "<p>"
$b = "<b>"
$eb = "</b>"

$compliant = "<font color=lime>COMPLIANT</font>"
$notcompliant = "<font color=red>NONCOMPLIANT</font>"
$results= "<b>Results:</b><p>"
$rawdata = "<b>Raw Data:</b><p>" 

$TableCSS = @"
<style>
TABLE {border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
TH {border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #6495ED;}
TD {border-width: 1px;padding: 3px;border-style: solid;border-color: black;}
.odd  { background-color:#ffffff; }
.even { background-color:#dddddd; }
</style>
"@


##########################################################################################
#                                                                                        #
# FUNCTION: Print section header for each check to output file                           #
#                                                                                        #
##########################################################################################

function Print-Header
{
param ( [string]$sectionname )
$fname = "audit.in\"+$sectionname+".html"
$description = get-content -path $fname
out-file -filepath $outfile -inputobject $description -append
# Progress Bar
# write-host -nonewline "."
write-host "Check Completed: ",$sectionname
}

##########################################################################################
#                                                                                        #
# FUNCTION: Fix HTML Converted text back to tags                                         #
#                                                                                        #
##########################################################################################

function fixhtml
{
param ( [string]$htmlcode)

$htmlcode = $htmlcode -replace "&lt;font color=lime&gt;COMPLIANT&lt;/font&gt;" , "<font color=lime>COMPLIANT</font>"
$htmlcode = $htmlcode -replace "&lt;font color=red&gt;NONCOMPLIANT&lt;/font&gt;" , "<font color=red>NONCOMPLIANT</font>"
$htmlcode = $htmlcode -replace "&lt;pre;&gt;" , "<pre>"
$htmlcode = $htmlcode -replace "&lt;/pre;&gt" , "</pre>"
$htmlcode = $htmlcode -replace "&lt;br;&gt" , "<br>"
$htmlcode = $htmlcode -replace "&lt;/br;&gt" , "</br>"

$htmlcode
}

##########################################################################################
#                                                                                        #
# FUNCTION: Get Attached Serial Ports                                                    #
# from http://blogs.vmware.com/PowerCLI/2012/05/working-with-vm-devices-in-powercli.html #
#                                                                                        #
##########################################################################################
Function Get-SerialPort {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        $VM
    )
    Process {
        Foreach ($VMachine in $VM) {
            Foreach ($Device in $VMachine.ExtensionData.Config.Hardware.Device) {
                If ($Device.gettype().Name -eq "VirtualSerialPort"){
                    $Details = New-Object PsObject
                    $Details | Add-Member Noteproperty VM -Value $VMachine
                    $Details | Add-Member Noteproperty Name -Value $Device.DeviceInfo.Label
                    If ($Device.Backing.FileName) { $Details | Add-Member Noteproperty Filename -Value $Device.Backing.FileName }
                    If ($Device.Backing.Datastore) { $Details | Add-Member Noteproperty Datastore -Value $Device.Backing.Datastore }
                    If ($Device.Backing.DeviceName) { $Details | Add-Member Noteproperty DeviceName -Value $Device.Backing.DeviceName }
                    $Details | Add-Member Noteproperty Connected -Value $Device.Connectable.Connected
                    $Details | Add-Member Noteproperty StartConnected -Value $Device.Connectable.StartConnected
                    $Details
                }
            }
        }
    }
}


##########################################################################################
#                                                                                        #
# FUNCTION: Get Attached Parallel Ports                                                  #
# from http://blogs.vmware.com/PowerCLI/2012/05/working-with-vm-devices-in-powercli.html #
#                                                                                        #
##########################################################################################
Function Get-ParallelPort {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        $VM
    )
    Process {
        Foreach ($VMachine in $VM) {
            Foreach ($Device in $VMachine.ExtensionData.Config.Hardware.Device) {
                If ($Device.gettype().Name -eq "VirtualParallelPort"){
                    $Details = New-Object PsObject
                    $Details | Add-Member Noteproperty VM -Value $VMachine
                    $Details | Add-Member Noteproperty Name -Value $Device.DeviceInfo.Label
                    If ($Device.Backing.FileName) { $Details | Add-Member Noteproperty Filename -Value $Device.Backing.FileName }
                    If ($Device.Backing.Datastore) { $Details | Add-Member Noteproperty Datastore -Value $Device.Backing.Datastore }
                    If ($Device.Backing.DeviceName) { $Details | Add-Member Noteproperty DeviceName -Value $Device.Backing.DeviceName }
                    $Details | Add-Member Noteproperty Connected -Value $Device.Connectable.Connected
                    $Details | Add-Member Noteproperty StartConnected -Value $Device.Connectable.StartConnected
                    $Details
                }
            }
        }
    }
}

############ Suppress Error Output ##############
$ErrorActionPreference= 'silentlycontinue'


# ==========================================
# Print Title Block of Audit file
# ==========================================

out-file -filepath $outfile -inputobject $h1, "vSphere Security Benchmark - Virtual Machines",$eh1 
out-file -filepath $outfile -inputobject "Version 2017-1, https://github.com/robvandenbrink/vsphere-hardening-guide",$p -append
out-file -filepath $outfile -inputobject $h2, "Target Host ", $h, $eh2 -append

out-file -filepath $outfile -inputobject (get-date) -append
out-file -filepath $outfile -inputobject $p,"<b>Virtual Machines:</b>" -append
out-file -filepath $outfile -inputobject ($vms | select Name, VMhost, Powerstate `
        | Convertto-html -fragment -precontent $TableCSS ) -append

# ==========================================
# Audit Checks Start Here
# ==========================================

print-header "control-resource-usage"


$result = $vms | Get-VMResourceConfiguration 
Out-File -filepath $outfile -inputobject $rawdata -append
Out-File -filepath $outfile -inputobject ($result | Convertto-html -fragment -precontent $TableCSS ) -append


# ==========================================

print-header "disable-autoinstall"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.autoInstall.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if ($result.value.length -eq 0 -or $result.value.toupper() -eq "TRUE") {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append


# ==========================================

print-header "disable-console-copy"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.copy.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if ($result.value.length -eq 0 -or $result.value.toupper() -eq "TRUE") {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults  | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-console-dnd"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.dnd.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if ($result.value.length -eq 0 -or $result.value.toupper() -eq "TRUE") {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append


# ==========================================

print-header "disable-console-gui-options"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.setGUIOptions.enable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if ($result.value.length -eq 0 -or $result.value.toupper() -eq "TRUE") {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append


# ==========================================

print-header "disable-console-paste"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name "isolation.tools.paste.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if ($result.value.length -eq 0 -or $result.value.toupper() -eq "TRUE") {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-disk-shrinking-shrink"
$vmresults = @()

foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.diskshrink.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $compliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if ($result.value.length -eq 0 -or $result.value.toupper() -eq "FALSE") {
$tempval.Compliance = $notcompliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append



# ==========================================

print-header "disable-disk-shrinking-wiper"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.diskWiper.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $compliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if ($result.value.length -eq 0 -or $result.value.toupper() -eq "TRUE") {
$tempval.Compliance = $notcompliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-hgfs"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.hgfsServerSet.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if ($result.value.length -eq 0 -or $result.value.toupper() -eq "TRUE") {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-independent-nonpersistent"
$vmresults = @()

    $result = $vms | Get-HardDisk
    # account for multiple disks (name parameter)

    foreach ($r in $result) {
        $tempval = new-object psobject;
        $tempval | add-member �membertype NoteProperty �name VM -value $r.parent ;
        $tempval | add-member �membertype NoteProperty �name DiskName -value $r.name ;
        $tempval | add-member �membertype NoteProperty �name Filename -value $r.filename ;
        $tempval | add-member �membertype NoteProperty �name Disktype -value $r.disktype ;
        $tempval | add-member �membertype NoteProperty �name Persistence -value $r.persistence ;
        $tempval | add-member �membertype NoteProperty �name Compliance �Value $compliant ; 


        if (([string]$r.persistence).toupper() -eq "INDEPENDENT-NONPERSISTENT") {
            $tempval.Compliance = $notcompliant
        }
        $vmresults += $tempval
        }
 

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-intervm-vmci"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "vmci0.unrestricted"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $compliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.length -eq 0) -or ($result.value.toupper() -eq "TRUE")) {
$tempval.Compliance = $notcompliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-monitor-control"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.monitor.control.disable" 

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $compliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.length -eq 0) -or ($result.value.toupper() -eq "FALSE")) {
$tempval.Compliance = $notcompliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-unexposed-features-autologon"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.ghi.autologon.disable" 

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.toupper() -eq "TRUE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-unexposed-features-biosbbs"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.bios.bbs.disable" 

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if ($result.value.toupper() -eq "TRUE") {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-unexposed-features-getcreds"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.getCreds.disable" 

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.toupper() -eq "TRUE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-unexposed-features-protocolhandler"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.ghi.launchmenu.change" 

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.toupper() -eq "TRUE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-unexposed-features-shellaction"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.ghi.host.shellAction.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.toupper() -eq "TRUE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-unexposed-features-toporequest"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.dispTopoRequest.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.toupper() -eq "TRUE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-unexposed-features-trashfolderstate"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.trashFolderState.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.toupper() -eq "TRUE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-unexposed-features-trayicon"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.ghi.trayicon.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.toupper() -eq "TRUE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-unexposed-features-unity"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.unity.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.toupper() -eq "TRUE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-unexposed-features-unity-interlock"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.unityInterlockOperation.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.toupper() -eq "TRUE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-unexposed-features-unity-taskbar"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.unity.taskbar.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.toupper() -eq "TRUE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-unexposed-features-unity-unityactive"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.unityActive.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.toupper() -eq "TRUE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-unexposed-features-unity-windowcontents"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.unity.windowContents.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.toupper() -eq "TRUE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-unexposed-features-unitypush"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.unity.push.update.disable" 

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.toupper() -eq "TRUE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-unexposed-features-versionget"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.vmxDnDVersionGet.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.toupper() -eq "TRUE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-unexposed-features-versionset"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.guestDnDVersionSet.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.toupper() -eq "TRUE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disable-vix-messages"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.tools.vixMessage.disable" 

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.toupper() -eq "TRUE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disconnect-devices-floppy"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-FloppyDrive

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.Name ;
$tempval | add-member �membertype NoteProperty �name Device �Value $result.Name ; 
$tempval | add-member �membertype NoteProperty �name State -Value $result.ConnectionState ;
$tempval | add-member �membertype NoteProperty �name Compliance -value $compliant ;


if (($result.State -contains "Connected") -or ($result.State -contains "StartConnected")) {
$tempval.Compliance = $notcompliant
}

$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disconnect-devices-ide"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-CDDrive

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.Name ;
$tempval | add-member �membertype NoteProperty �name Device �Value $result.Name ; 
$tempval | add-member �membertype NoteProperty �name State -Value $result.ConnectionState ;
$tempval | add-member �membertype NoteProperty �name Compliance -value $compliant ;


if (($result.State -contains "Connected") -or ($result.State -contains "StartConnected")) {
$tempval.Compliance = $notcompliant
}

$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disconnect-devices-parallel"

$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-ParallelPort

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.Name ;
$tempval | add-member �membertype NoteProperty �name Device �Value $result.Name ; 
$tempval | add-member �membertype NoteProperty �name State -Value $result.ConnectionState ;
$tempval | add-member �membertype NoteProperty �name Compliance -value $compliant ;


if (($result.State -contains "Connected") -or ($result.State -contains "StartConnected")) {
$tempval.Compliance = $notcompliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disconnect-devices-serial"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-SerialPort

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.Name ;
$tempval | add-member �membertype NoteProperty �name Device �Value $result.Name ; 
$tempval | add-member �membertype NoteProperty �name State -Value $result.ConnectionState ;
$tempval | add-member �membertype NoteProperty �name Compliance -value $compliant ;


if (($result.State -contains "Connected") -or ($result.State -contains "StartConnected")) {
$tempval.Compliance = $notcompliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "disconnect-devices-usb"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-USBDevice

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.Name ;
$tempval | add-member �membertype NoteProperty �name Device �Value $result.Name ; 
$tempval | add-member �membertype NoteProperty �name State -Value $result.ConnectionState ;
$tempval | add-member �membertype NoteProperty �name Compliance -value $compliant ;


if (($result.State -contains "Connected") -or ($result.State -contains "StartConnected")) {
$tempval.Compliance = $notcompliant
}

$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "limit-console-connections-one"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "RemoteDisplay.maxConnections" 

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value -eq 1)) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "limit-console-connections-two"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "RemoteDisplay.maxConnections" 

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value -eq 2)) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "limit-log-number"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "log.keepOld"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value -eq "10")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "limit-log-size"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "log.rotateSize"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value -eq "100000")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "limit-setinfo-size"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "tools.setInfo.sizeLimit"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value -eq "1048576")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "prevent-device-interaction-connect"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.device.connectable.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $compliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.length -eq 0) -or ($result.value.toupper() -eq "FALSE")) {
$tempval.Compliance = $notcompliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "prevent-device-interaction-edit"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "isolation.device.edit.disable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $compliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.length -eq 0) -or ($result.value.toupper() -eq "FALSE")) {
$tempval.Compliance = $notcompliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "restrict-host-info"

$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "tools.guestlib.enableHostInfo"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.length -eq 0) -or ($result.value.toupper() -eq "FALSE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "verify-network-filter"
$vmresults = @()

Out-File -filepath $outfile -inputobject $rawdata -append

foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "ethernet*.filter*.name*"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value "Manually Assess" ; 

if ($result.value.length -eq 0) { $tempval.Compliance = $compliant }

$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "verify-vmsafe-cpumem-agentaddress"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "vmsafe.agentAddress"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value "Manually Assess" ;

if ($result.value.length -eq 0) { $tempval.Compliance = $compliant }

$vmresults += $tempval
}


Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "verify-vmsafe-cpumem-agentport"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "vmsafe.agentPort"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value "Manually Assess" ;

if ($result.value.length -eq 0) { $tempval.Compliance = $compliant }

$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================

print-header "verify-vmsafe-cpumem-enable"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "vmsafe.enable"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name "VMSafe Enabled" $result.value ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value "Manually Assess" ;

if ($result.value.length -eq 0) { $tempval.Compliance = $compliant }

$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append


# ==========================================

print-header "minimize-console-VNC-use"
$vmresults = @()
foreach ($vm in $vms) {
$result = $vm | Get-AdvancedSetting -Name  "RemoteDisplay.vnc.enabled"

$tempval = new-object psobject;
$tempval | add-member �membertype NoteProperty �name VM -value $vm.name ;
$tempval | add-member �membertype NoteProperty �name Compliance �Value $notcompliant ; 
$tempval | add-member �membertype NoteProperty �name "Raw Data" $result.value ;

if (($result.value.length -eq 0) -or ($result.value.toupper() -eq "FALSE")) {
$tempval.Compliance = $compliant
}
$vmresults += $tempval
}

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml ($vmresults | Convertto-html -fragment -precontent $TableCSS) ) -append

# ==========================================


