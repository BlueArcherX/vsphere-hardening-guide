# ==============================
# collect Command Line Arguments (hostname only)

if ($args.count -gt 1) {
  write-host "Too Many Arguments Specified"
  write-host "Syntax:  audit-vnetwork hostname OR fqdn OR ipaddress"
  return
  }
if ($args.count -eq 0) {
  write-host "no target host specified - please specify IP or hostname"
  write-host "Syntax:  audit-vnetwork hostname OR fqdn OR ipaddress"
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

$outfile = "audit-"+$h+"-vnetwork.html"

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


##########################################################################################
#                                                                                        #
# Get List of ESXi hosts from initial vSphere or ESXi connection                         #
#                                                                                        #
##########################################################################################

$esxhosts = get-vmhost -server $h

# if we connected to vcenter:
$vc = $login

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
out-file -filepath $outfile -inputobject $epre -append
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
# FUNCTION: MD5SUM a file                                        #
#                                                                                        #
##########################################################################################

function md5sum
{
param ( [string]$filespec)

$md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
$hash = [System.BitConverter]::ToString($md5.ComputeHash([System.IO.File]::ReadAllBytes($Filespec)))
return $hash
}


##########################################################################################
#                                                                                        #
# FUNCTION: SHA1SUM a file                                        #
#                                                                                        #
##########################################################################################

function sha1sum
{
param ( [string]$filespec)

$sha1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
$hash = [System.BitConverter]::ToString( $sha1.ComputeHash([System.IO.File]::ReadAllBytes($filespec)))
return $hash
}

##########################################################################################
#                                                                                        #
# FUNCTION: Check SSL / TLS Certificate                                                  #
#           https://isc.sans.edu/diary/20645                                             #
#           https://gist.github.com/jstangroome/5945820                                  #
#                                                                                        #
##########################################################################################


function ChkCert
   {
   Param ([string]$ip,[int]$Port)
   $ip
   $port

   $TCPClient = New-Object -TypeName System.Net.Sockets.TCPClient
   try {
      $TcpSocket = New-Object Net.Sockets.TcpClient($ip,$port)
      $tcpstream = $TcpSocket.GetStream()
      $Callback = {param($sender,$cert,$chain,$errors) return $true}
      $SSLStream = New-Object -TypeName System.Net.Security.SSLStream -ArgumentList @($tcpstream, $True, $Callback)
      try {
         $SSLStream.AuthenticateAsClient($ip)
         $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($SSLStream.RemoteCertificate)
         } 
      finally {
         $SSLStream.Dispose()
         }
      }
      finally {
         $TCPClient.Dispose()
         }
      return $Certificate
   }


############ Suppress Error Output ##############
$ErrorActionPreference= 'silentlycontinue'


##########################################################################################
#                                                                                        #
# PRINT TITLE BLOCK                                                                      #
#                                                                                        #
##########################################################################################

# out-file -filepath $outfile -inputobject $pre
out-file -filepath $outfile -inputobject "<title>ESXi Audit Report - ",$h," </title>"
out-file -filepath $outfile -inputobject $h1, "vSphere Security Benchmark - Virtual Networks",$eh1,$p -append
out-file -filepath $outfile -inputobject "Version 2017-1, https://github.com/robvandenbrink/vsphere-hardening-guide",$p -append
out-file -filepath $outfile -inputobject $h2, "Target Host ", $h, $eh2 ,$p -append

out-file -filepath $outfile -inputobject (get-date) -append
out-file -filepath $outfile -inputobject $p,"<b>ESXi Hosts:</b>" -append
out-file -filepath $outfile -inputobject ($esxhosts |Select Name, ConnectionState, PowerState, NumCPU,CpuTotalMhz | Convertto-html -fragment -precontent $TableCSS ) -append

##########################################################################################
#                                                                                        #
# AUDIT CHECKS START HERE                                                                #
#                                                                                        #
##########################################################################################

##########################################################################################
#                                                                                        #
# AUDIT CHECKS - vSwitch                                                                 #
#                                                                                        #
##########################################################################################


# ==========================================
print-header "document-vlans"

$hresults = @()
foreach ($esxh in $esxhosts) {

$result =  $esxh | Get-VirtualPortGroup -Standard | Select virtualSwitch, Name, VlanID
$result | add-member –membertype NoteProperty –name Compliance –Value "MANUAL CHECK" ; 
$result | add-member –membertype NoteProperty –name VMHost –Value $esxh ;

foreach ($swt in $result) {
  if ($swt.name.length  -eq 0) {
  $swt.Compliance = $notcompliant
  }
}
$hresults += $result
}

$complianceresults = $hresults | Select VMHost, VirtualSwitch, Name, VLanId, Compliance | `
    convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# ==========================================
print-header "label-portgroups"

$hresults = @()
foreach ($esxh in $esxhosts) {

$result =  $esxh | Get-VirtualPortGroup
$result | add-member –membertype NoteProperty –name Compliance –Value $compliant ; 
$result | add-member –membertype NoteProperty –name VMHost –Value $esxh ;

foreach ($pgroup in $result) {
  if ($pgroup.name.length  -eq 0) {
  $pgroup.Compliance = $notcompliant
  }
}
$hresults += $result
}

$complianceresults = $hresults | Select VMHost, Name, VlanID, VirtualSwitch,VirtualSwitchName, Compliance | `
    convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# ==========================================
print-header "label-vswitches"

$hresults = @()
foreach ($esxh in $esxhosts) {

$result =  $esxh | Get-VirtualSwitch
$result | add-member –membertype NoteProperty –name Compliance –Value $compliant ; 

# consider the name "vSwitch" with up to 4 numeric digits as not-compliant

foreach ($vswt in $result) {
  if ($vswt.name -match "^vSwitch\d{1,3}$") {
  $vswt.Compliance = $notcompliant
  $hresults += $vswt
  }
}
}

$complianceresults = $hresults | Select VMHost, Name, Compliance | `
    convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append


# ==========================================
print-header "limit-administrator-scope"

# ==========================================
print-header "reject-forged-transmit"

$hresults = @()
foreach ($esxh in $esxhosts) {

$result =  $esxh | Get-VirtualSwitch -Standard | Select VMHost, Name, `
 @{N="MacChanges";E={if ($_.ExtensionData.Spec.Policy.Security.MacChanges) { "Accept" } Else { "Reject"} }}, `
 @{N="PromiscuousMode";E={if ($_.ExtensionData.Spec.Policy.Security.PromiscuousMode) { "Accept" } Else { "Reject"} }}, `
 @{N="ForgedTransmits";E={if ($_.ExtensionData.Spec.Policy.Security.ForgedTransmits) { "Accept" } Else { "Reject"} }}

$result | add-member –membertype NoteProperty –name Compliance –Value $compliant ; 


foreach ($vswt in $result) {
  if($vswt.ForgedTransmits -eq "Accept") {
      $vswt.Compliance = $notcompliant
  }
}

$hresults += $result
}

$complianceresults = $hresults | Select VMHost, Name, ForgedTransmits, Compliance | `
    convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append


# ==========================================
print-header "reject-mac-changes"

$hresults = @()
foreach ($esxh in $esxhosts) {

$result =  $esxh | Get-VirtualSwitch -Standard | Select VMHost, Name, `
 @{N="MacChanges";E={if ($_.ExtensionData.Spec.Policy.Security.MacChanges) { "Accept" } Else { "Reject"} }}, `
 @{N="PromiscuousMode";E={if ($_.ExtensionData.Spec.Policy.Security.PromiscuousMode) { "Accept" } Else { "Reject"} }}, `
 @{N="ForgedTransmits";E={if ($_.ExtensionData.Spec.Policy.Security.ForgedTransmits) { "Accept" } Else { "Reject"} }}

$result | add-member –membertype NoteProperty –name Compliance –Value $compliant ; 


foreach ($vswt in $result) {
  if($vswt.MacChanges -eq "Accept") {
      $vswt.Compliance = $notcompliant
  }
}

$hresults += $result
}

$complianceresults = $hresults | Select VMHost, Name, MacChanges, Compliance | `
    convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# ==========================================
print-header "reject-promiscuous-mode"

$hresults = @()
foreach ($esxh in $esxhosts) {

$result =  $esxh | Get-VirtualSwitch -Standard | Select VMHost, Name, `
 @{N="MacChanges";E={if ($_.ExtensionData.Spec.Policy.Security.MacChanges) { "Accept" } Else { "Reject"} }}, `
 @{N="PromiscuousMode";E={if ($_.ExtensionData.Spec.Policy.Security.PromiscuousMode) { "Accept" } Else { "Reject"} }}, `
 @{N="ForgedTransmits";E={if ($_.ExtensionData.Spec.Policy.Security.ForgedTransmits) { "Accept" } Else { "Reject"} }}

$result | add-member –membertype NoteProperty –name Compliance –Value $compliant ; 


foreach ($vswt in $result) {
  if($vswt.PromiscuousMode -eq "Accept") {
      $vswt.Compliance = $notcompliant
  }
}

$hresults += $result
}

$complianceresults = $hresults | Select VMHost, Name, PromiscuousMode, Compliance | `
    convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append




##########################################################################################
#                                                                                        #
# AUDIT CHECKS - VDS                                                                     #
#                                                                                        #
##########################################################################################


# ==========================================
print-header "document-pvlans"
# also document-vlans-vds
# also label-vdportgroups

$dPortGroups = Get-VirtualPortGroup -Distributed -server $vc

# List all dvSwitches and their Portgroups, VLAN Type and Ids
Foreach ($dPG in $dPortGroups) {
 Switch ((($dPG.ExtensionData.Config.DefaultPortConfig.Vlan).GetType()).Name) {
  VMwareDistributedVirtualSwitchPvlanSpec { 
   $Type = "Private VLAN"
   $VLAN = $dPG.ExtensionData.Config.DefaultPortConfig.Vlan.pVlanID 
  }
  VMwareDistributedVirtualSwitchTrunkVlanSpec { 
   $Type = "VLAN Trunk"
   $VLAN = ($dPG.ExtensionData.Config.DefaultPortConfig.Vlan.VlanID | Select Start, End)
  } 
  VMwareDistributedVirtualSwitchVlanIdSpec { 
   $Type = "VLAN"
   $VLAN = $dPG.ExtensionData.Config.DefaultPortConfig.Vlan.vlanID
  }
  default {
   $Type = (($dPG.ExtensionData.Config.DefaultPortConfig.Vlan).GetType()).Name
   $VLAN = "Unknown"
  }
 }
 $result = $dpg | Select virtualSwitch, Name, @{N="Type";E={$Type}}, @{N="VLanId";E={$VLAN}}
}

$complianceresults = $result | convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append


# ==========================================
print-header "no-unused-dvports"

# Check for the number of free ports on all VDS PortGroups

Function Get-FreeVDSPort {
 Param (
  [parameter(Mandatory=$true,ValueFromPipeline=$true)]
  $VDSPG
 )
 Process {
  $nicTypes = "VirtualE1000","VirtualE1000e","VirtualPCNet32","VirtualVmxnet","VirtualVmxnet2","VirtualVmxnet3" 
  $ports = @{}

  $VDSPG.ExtensionData.PortKeys | Foreach {
   $ports.Add($_,$VDSPG.Name)
  }
 
  $VDSPG.ExtensionData.Vm | Foreach {
      $VMView = Get-View $_
   $nic = $VMView.Config.Hardware.Device | where {$nicTypes -contains $_.GetType().Name -and $_.Backing.GetType().Name -match "Distributed"}
      $nic | where {$_.Backing.Port.PortKey} | Foreach {$ports.Remove($_.Backing.Port.PortKey)}
  }

  ($ports.Keys).Count
 }
}

$dPortGroups = Get-VirtualPortGroup -Distributed -server $vc
$result = @()

foreach ($dPGroup in $dPortGroups) {
$dpg = $dPGroup
$r = Get-FreeVDSPort($dPGroup)
$dpg | add-member –membertype NoteProperty –name FreePorts –Value $r ; 

$Compliance = $notcompliant
if( $r -eq 0) { $Compliance = $compliant }

$dpg | add-member –membertype NoteProperty –name Compliance –Value $Compliance ; 
$result += $dpg

}
Out-File -filepath $outfile -inputobject $epre,$results -append

$complianceresults = $result | select Name,NumPorts,FreePorts,Compliance | convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# ==========================================
print-header "reject-forged-transmit-dvportgroup"

$result = Get-VirtualPortGroup -Distributed | Select Name, `
 @{N="ForgedTransmits";E={if ($_.ExtensionData.Config.DefaultPortConfig.SecurityPolicy.ForgedTransmits.Value) { "Accept" } Else { "Reject"} }}, `
 @{N="Compliance";E={if ($_.ExtensionData.Config.DefaultPortConfig.SecurityPolicy.ForgedTransmits.Value) { $notcompliant } Else { $compliant } }}

Out-File -filepath $outfile -inputobject $epre,$results -append
$complianceresults = $result | convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append


# ==========================================
print-header "reject-mac-change-dvportgroup"

$result = Get-VirtualPortGroup -Distributed | Select Name, `
 @{N="MacChanges";E={if ($_.ExtensionData.Config.DefaultPortConfig.SecurityPolicy.MacChanges.Value) { "Accept" } Else { "Reject"} }}, `
 @{N="Compliance";E={if ($_.ExtensionData.Config.DefaultPortConfig.SecurityPolicy.MacChanges.Value) { $notcompliant } Else { $compliant } }}

Out-File -filepath $outfile -inputobject $epre,$results -append
$complianceresults = $result | convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# ==========================================
print-header "reject-promiscuous-mode-dvportgroup"

$result = Get-VirtualPortGroup -Distributed | Select Name, `
 @{N="PromiscuousMode";E={if ($_.ExtensionData.Config.DefaultPortConfig.SecurityPolicy.AllowPromiscuous.Value) { "Accept" } Else { "Reject"} }}, `
 @{N="Compliance";E={if ($_.ExtensionData.Config.DefaultPortConfig.SecurityPolicy.AllowPromiscuous.Value) { $notcompliant } Else { $compliant } }}

Out-File -filepath $outfile -inputobject $epre,$results -append

$complianceresults = $result | convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append


# ==========================================
print-header "restrict-netflow-usage"

$result2 = @()

$result = Get-VDPortgroup | Select Name, VirtualSwitch, @{Name="NetflowEnabled";Expression={$_.Extensiondata.Config.defaultPortConfig.ipfixEnabled.Value}} 
$result | add-member –membertype NoteProperty –name Compliance –Value $compliant ; 

foreach ($r in $result) {
  if($r.NetflowEnabled -eq "True") {$r.NetflowEnabled = $notcompliant}
  $result2 += $r
}

Out-File -filepath $outfile -inputobject $epre,$results -append

$complianceresults = $result2 | convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# restrict-port-level-overrides
# restrict-portmirror-usage


# ==========================================
print-header "disable-dvportgroup-autoexpand"

$result = Get-VirtualPortGroup -Distributed -server $vc
$result | add-member –membertype NoteProperty –name Compliance –Value $compliant ;

foreach ($dPG in $result) {
  if($dPG.extensiondata.config.autoexpand) {
      $dPG.Compliance = $notcompliant
  }
}


$complianceresults = $result | convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append


# ==========================================
# print-header "restrict-port-level-overrides"

# ==========================================
# print-header "restrict-portmirror-usage" 

# label all vswitches
# get-vdswitch

#label-dvportgroup
#get-vdportgroup



##########################################################################################
#                                                                                        #
# AUDIT CHECKS - VLAN                                                                    #
#                                                                                        #
##########################################################################################

# ==========================================
print-header "no-native-vlan-1"

$hresults = @()
foreach ($esxh in $esxhosts) {

$result =  $esxh | Get-VirtualPortGroup -Standard | Select virtualSwitch, Name, VlanID
$result | add-member –membertype NoteProperty –name VMHost –Value $esxh.Name ; 
$result | add-member –membertype NoteProperty –name Compliance –Value $compliant ; 

foreach ($vswt in $result) {
  if($vswt.VlanID -eq 0) {
      $vswt.Compliance = "MANUALLY VERIFY"
  }
}

$hresults += $result
}

$complianceresults = $hresults | Select VMHost, VirtualSwitch, Name, VLanID, Compliance | `
    convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# ==========================================
print-header "no-reserved-vlans"

# VLANs 1001–1024 and 4094, 3968–4047 

$hresults = @()
foreach ($esxh in $esxhosts) {

$result =  $esxh | Get-VirtualPortGroup -Standard | Select virtualSwitch, Name, VlanID
$result | add-member –membertype NoteProperty –name VMHost –Value $esxh.Name ; 
$result | add-member –membertype NoteProperty –name Compliance –Value $compliant ; 

foreach ($swt in $result) {
  $cval = 0
  if (($swt.VlanID -le 4047) -and ($swt.VlanID -ge 3968)) { $cval +=1 }
  if (($swt.VlanID -le 1024) -and ($swt.VlanID -ge 1001)) { $cval +=1 }
  if ($swt.VlanID -eq 4094) {$cval += 1 }
  if ($cval -eq 0) {$swt.Compliance = $compliant} else {$swt.Compliance = $notcompliant}

  $hresults += $swt
}
}
$complianceresults = $hresults | Select VMHost, VirtualSwitch, Name, VLanID, Compliance | `
    convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# ==========================================
print-header "verify-vlan-id"

$hresults = @()
foreach ($esxh in $esxhosts) {

$result =  $esxh | Get-VirtualPortGroup -Standard | Select virtualSwitch, Name, VlanID
$result | add-member –membertype NoteProperty –name VMHost –Value $esxh.Name ; 
$result | add-member –membertype NoteProperty –name Compliance –Value "Manual Assessment" ; 


$hresults += $result
}

$complianceresults = $hresults | Select VMHost, Name, VlanID, Compliance | `
    convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append


##########################################################################################
#                                                                                        #
# AUDIT CHECKS - Architecture                                                            #
#                                                                                        #
##########################################################################################
# ==========================================
print-header "isolate-mgmt-network-airgap"

# ==========================================
print-header "isolate-mgmt-network-vlan"
# ==========================================
print-header "isolate-storage-network-airgap"
# ==========================================
print-header "isolate-storage-network-vlan"
# ==========================================
print-header "isolate-vmotion-network-airgap"
# ==========================================
print-header "isolate-vmotion-network-vlan"
# ==========================================
print-header "restrict-mgmt-network-access-gateway"
# ==========================================
print-header "restrict-mgmt-network-access-jumpbox"



##########################################################################################
#                                                                                        #
# AUDIT CHECKS - Physical                                                                #
#                                                                                        #
##########################################################################################

# ==========================================
# print-header "enable-portfast"
# ==========================================
print-header "set-non-negotiate"
# ==========================================
print-header "upstream-bpdu-stp"
# ==========================================
# print-header "enable-bpdufilter"
# ==========================================
print-header "verify-vlan-trunk"


