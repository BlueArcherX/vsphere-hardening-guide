# ==============================
# collect Command Line Arguments (hostname only)

if ($args.count -gt 1) {
  write-host "Too Many Arguments Specified"
  write-host "Syntax:  audit-vc hostname OR fqdn OR ipaddress"
  return
  }
if ($args.count -eq 0) {
  write-host "no target host specified - please specify IP or hostname"
  write-host "Syntax:  audit-vc hostname OR fqdn OR ipaddress"
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

$outfile = "audit-"+$h+"-VC.html"

# ==============================
# Are we auditing the localhost or a remote host?
# The variable $runninglocal is used throughout this script 
# ipv4 and ipv6 are both tested

# get the IPs of the host we're testing
$t = (test-connection $h -count 2)[1]
$hip4 = $t.IPV4Address.ipaddresstostring
$hip6 = $t.IPV6Address.ipaddresstostring
$protoaddress = $t.protocoladdress

# get local host ip's (includes both ipv4 and ipv6)
$localips = (Get-WmiObject Win32_NetworkAdapterConfiguration -Computer $env:computername | Where-Object { $_.IpEnabled } | select).ipaddress

if (($localips -contains $hip4) -or ($localips -contains $hip6) -or ($localips -contains $protoaddress) `
     -or ($hip4 -eq "127.0.0.1") -or ($hip6 -eq "::1")) { $runninglocal = $true } else {$runninglocal = $false}


# ==============================
# Check Login

$retry = 1
while ($retry -eq 1) {

# need fully qualified name - user@domain for this login

$vicreds = get-credential $null
$login = connect-viserver -server $h -credential $vicreds

if ($login.name.length -eq 0) {
    write-host "Please be sure to use user@domain for this login"
    write-host "A fully qualified login, with the domain is key for this access"
    write-host "Login failed, please retry or press Ctrl-C to exit"
    # short pause gives the chance for Ctrl-C
    start-sleep 5
    }
else {
    write-host "Login Successful"
    $login | ft
    $retry=0
    }
}
$vc = $login

##########################################################################################
#                                                                                        #
# Get List of ESXi hosts from initial vSphere or ESXi connection                         #
#                                                                                        #
##########################################################################################

$esxhosts = get-vmhost -server $h

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
$br = "<br>"
$ebr = "</br>"

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
write-host "Check In Progress: ",$sectionname
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
$htmlcode = $htmlcode -replace "&lt;br&gt;" , "<br>"
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
out-file -filepath $outfile -inputobject "<title>vCenter Audit Report - ",$h," </title>"
out-file -filepath $outfile -inputobject $h1, "vSphere Security Benchmark - vCenter Host",$eh1,$p -append
out-file -filepath $outfile -inputobject "Version 2017-1, https://github.com/robvandenbrink/vsphere-hardening-guide",$p -append
out-file -filepath $outfile -inputobject $h2, "Target Host: ", $h, $eh2 ,$p -append

out-file -filepath $outfile -inputobject (get-date) -append
out-file -filepath $outfile -inputobject $p,"This script is written for vCenter installed on a Windows Host" -append
out-file -filepath $outfile -inputobject "</br>The next version will account for vCenter Appliances" -append

out-file -filepath $outfile -inputobject $p,"<b>ESXi Hosts:</b>" -append

out-file -filepath $outfile -inputobject ($esxhosts |Select Name, ConnectionState, PowerState, NumCPU, CpuTotalMhz `
       | Convertto-html -fragment -precontent $TableCSS ) -append

##########################################################################################
#                                                                                        #
# AUDIT CHECKS START HERE                                                                #
#                                                                                        #
##########################################################################################

print-header "apply-os-patches"
if (-not $runninglocal) {
$result = ( get-hotfix -computername $vc.name -credential $vicreds ) | select pscomputername, hotfixid, description, installedon
} else {
$result = ( get-hotfix  ) | select pscomputername, hotfixid, description, installedon
}

$lastinstall = ($result | sort installedon)[$result.length-1].installedon

$now =get-date
$latestpatch = ([datetime]$now - [datetime]$lastinstall).days

if ($latestpatch -lt 31) {
   $compliance = $compliant
   }
   else {
   $compliance = $notcompliant
   } 

$statement = $compliance + " Patches last installed " + $latestpatch + " Days ago" + $br

    Out-File -filepath $outfile -inputobject $epre, $results -append
    Out-File -filepath $outfile -inputobject $statement -append

 
    Out-File -filepath $outfile -inputobject $epre,$br, $rawdata,$br -append
    Out-File -filepath $outfile -inputobject ($result | sort hotfixid | Convertto-html -fragment -precontent $TableCSS) -append



# ==========================================

print-header "block-unused-ports"

if (-not $runninglocal) {
#
# remote host
# could do this with psremote, but that requires config change on target host
# user psexec and invoke-expression instead
#

$username = $vicreds.username
$pwd = $vicreds.GetNetworkCredential().password
$pse = "psexec \\" + $h + " -u " + $username + " -p " + $pwd + " "
$rcmd = $pse +  "netsh advfirewall show allprofiles"
$fwprofiles = iex $rcmd
$rcmd = $pse +  "netsh advfirewall firewall show rule all"
$fwrules = iex $rcmd

Out-File -filepath $outfile -inputobject $epre,$b, "Firewall Policies",$eb,$br -append
Out-File -filepath $outfile -inputobject $fwprofiles -append

Out-File -filepath $outfile -inputobject $b,$br "Firewall Rules", $eb,$br -append
Out-File -filepath $outfile -inputobject $fwrules -append


}
else 
{
#
# local host
# user com Firewall object
#

$fw=New-object –comObject HNetCfg.FwPolicy2

$fwprofiles = @(1,2,4) | select @{Name=“Network Type”     ;expression={$fwProfileTypes[$_]}},
                   @{Name=“Firewall Enabled” ;expression={$fw.FireWallEnabled($_)}},
                   @{Name=“Block All Inbound”;expression={$fw.BlockAllInboundTraffic($_)}},
                   @{name=“Default In”       ;expression={$FwAction[$fw.DefaultInboundAction($_)]}},
                   @{Name=“Default Out”      ;expression={$FwAction[$fw.DefaultOutboundAction($_)]}}

$fwrules = $fw.rules | select name, desc, service, localports, remoteports, direction, enabled, action

Out-File -filepath $outfile -inputobject $epre,$b,$br, "Firewall Policies",$eb,$br -append
Out-File -filepath $outfile -inputobject ($fwprofiles | Convertto-html -fragment -precontent $TableCSS) -append

Out-File -filepath $outfile -inputobject $b,$br, "Firewall Rules", $eb,$br -append
Out-File -filepath $outfile -inputobject ($fwrules | Convertto-html -fragment -precontent $TableCSS) -append
}


# ==========================================

# print-header "change-default-password"

# ==========================================

print-header "check-privilege-reassignment"

$result = Get-VIPrivilege -server $vc | select server,name, privilegelist

$final = $result | select server,name , @{Name='Privs';Expression={$_.privilegelist -join "<br>" }}
$f = ( $final | Convertto-html -fragment -precontent $TableCSS ) -replace "&lt;br&gt;" , "<br>"

Out-File -filepath $outfile -inputobject $epre,$b, "Privilege Data:", $eb -append
Out-File -filepath $outfile -inputobject ($f) -append


$result = Get-WinEvent -computername $h -credential $vicreds -FilterHashtable @{logname='application';providername="VMware VirtualCenter Server"} -MaxEvents 1000
$result = $result | select machinename, timecreated, level, leveldisplayname, id, properties.value | where-object {$_.level -lt 4}

Out-File -filepath $outfile -inputobject $epre,$b, "Event Data:", $eb -append
Out-File -filepath $outfile -inputobject ($result | Convertto-html -fragment -precontent $TableCSS) -append

# ==========================================

print-header "config-ntp"


$rcmd1 = "w32tm /query /computer:" + $h + " /status"
$rcmd2 = "w32tm /query /computer:"+$h+" /configuration"

if (-not $runninglocal) {
   $username = $vicreds.username
   $pwd = $vicreds.GetNetworkCredential().password
   $rcmd1 = "psexec \\" + $h + " -u " + $username + " -p " + $pwd + " " + $rcmd1
   $rcmd2 = "psexec \\" + $h + " -u " + $username + " -p " + $pwd + " " + $rcmd2
   }

$result1 = iex $rcmd1
$result2 = iex $rcmd2

Out-File -filepath $outfile -inputobject $epre,$b, "NTP Status:", $eb -append
Out-File -filepath $outfile -inputobject ($pre, $result1) -append

Out-File -filepath $outfile -inputobject $epre,$b, "NTP Configuration:", $eb -append
Out-File -filepath $outfile -inputobject ($pre, $result2) -append



# ==========================================
print-header "disable-datastore-browser"
# print-header "restrict-datastore-web"

$uri = "https://" + $vc.name + "/folder"
$result = invoke-webrequest $uri -credential $vicreds

$compliance = $compliant

if (($result.statuscode -eq 200) -or ($result.statucode -eq 401)) {
   $Compliance = $notcompliant
   }

Out-File -filepath $outfile -inputobject ($pre, $results) -append
Out-File -filepath $outfile -inputobject $compliance  -append

Out-File -filepath $outfile -inputobject ($pre, $rawdata) -append
Out-File -filepath $outfile -inputobject $pre, $result -append


# ==========================================

print-header "disable-mob"

$uri = "https://" + $vc.name + "/mob"
$result = invoke-webrequest $uri -credential $vicreds

$compliance = $compliant

if (($result.statuscode -eq 200) -or ($result.statucode -eq 401)) {
   $Compliance = $notcompliant
   }

Out-File -filepath $outfile -inputobject $epre, $results -append
Out-File -filepath $outfile -inputobject $compliance  -append

Out-File -filepath $outfile -inputobject ($pre, $rawdata) -append
Out-File -filepath $outfile -inputobject $pre, $result -append

# ========================
print-header "install-with-service-account"


if (-not $runninglocal) {
$result = get-wmiobject win32_service -computer $vc.name -credential $vicreds | Where-Object { $_.displayname -like "*VMware*" }
} else {
$result = get-wmiobject win32_service  | Where-Object { $_.displayname -like "*VMware*" }
}
$result | add-member –membertype NoteProperty –name Compliance -value $notcompliant ;

foreach ($s in $result) {
   if ($s.startname -eq "LocalSystem") {
            $s.compliance = $compliant
     }
 if ($s.startname -like "*NetworkService") {
            $s.compliance = $compliant
     }
}

$a = $result | select name, displayname,startmode,status, startname, compliance | Convertto-html -fragment -precontent $TableCSS
$a = fixhtml $a

Out-File -filepath $outfile -inputobject $epre, $results -append
Out-File -filepath $outfile -inputobject $a -append


# ========================
print-header "limit-user-login"

# look for successful and failed logins on vcenter

if (-not $runninglocal) {
$result = Get-WinEvent -computername $h -credential $vicreds -FilterHashtable @{logname='security';id = 4672,4625,4648,4776,4624,680,675,676} -ErrorAction SilentlyContinue -maxevents 25
} else {
$result = Get-WinEvent -FilterHashtable @{logname='security';id = 4672,4625,4648,4776,4624,680,675,676} -ErrorAction SilentlyContinue -maxevents 25
}

$result = $result | select timecreated, id, message | sort timecreated

Out-File -filepath $outfile -inputobject $epre,$b, "Event Data:", $eb -append
Out-File -filepath $outfile -inputobject ($result | Convertto-html -fragment -precontent $TableCSS) -append

# ====================
print-header "monitor-admin-assignment"



$result = Get-VIPrivilege -server $vc | select server,name, privilegelist

$final = $result | select server,name , @{Name='Privs';Expression={$_.privilegelist -join "<br>" }}
$f = ( $final | Convertto-html -fragment -precontent $TableCSS ) -replace "&lt;br&gt;" , "<br>"

Out-File -filepath $outfile -inputobject $epre,$b, "Privilege Data:", $eb -append
Out-File -filepath $outfile -inputobject ($f) -append


$result = Get-WinEvent -computername $h -credential $vicreds -FilterHashtable @{logname='application';providername="VMware VirtualCenter Server"} -MaxEvents 1000
$result = $result | select machinename, timecreated, level, leveldisplayname, id, properties.value | where-object {$_.level -lt 4}

Out-File -filepath $outfile -inputobject $epre,$b, "Event Data:", $eb -append
Out-File -filepath $outfile -inputobject ($result | Convertto-html -fragment -precontent $TableCSS) -append



# ====================

print-header "monitor-certificate-access"
# look for access to audited files on vcenter (certificates)
if (-not $runninglocal) {
$tempval = Get-WinEvent -computername $h -credential $vicreds -FilterHashtable @{logname='security';id = 4663,560,567,568,560}  -ErrorAction SilentlyContinue -maxevents 20
} else {
$tempval = Get-WinEvent -FilterHashtable @{logname='security';id = 4663,560,567,568,560}  -ErrorAction SilentlyContinue -maxevents 20
}

Out-File -filepath $outfile -inputobject $epre,$b, "Event Data:", $eb -append
Out-File -filepath $outfile -inputobject ($result | Convertto-html -fragment -precontent $TableCSS) -append



# =====================
print-header "no-self-signed-certs"
print-header "verify-ssl-certificates"

$sslcert = chkcert $h 443

if ( ($sslcert.issuer).toupper() -like "*VMWARE*") {
   $compliance = $notcompliant
   $result = "Self Signed Certificate"
   }
   else
   { 
   $compliance = $compliant
   $result = "Valid issuer"
   }

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject $br,$compliance,$br -append
Out-File -filepath $outfile -inputobject $br,$result,$br -append

Out-File -filepath $outfile -inputobject $rawdata -append
Out-File -filepath $outfile -inputobject ($sslcert | fl) -append




# =====================

print-header "remove-expired-certificates"
print-header "remove-revoked-certificates"

$sslcert = chkcert $h 443
$now =get-date
 
if ($now -gt $sslcert.notafter) { 
  $compliance = $notcompliant
  }  
  else
  {
  $compliance = $compliant
  }

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject $br,$compliance,$br -append

Out-File -filepath $outfile -inputobject $epre,$rawdata -append
Out-File -filepath $outfile -inputobject $br,"Not Valid After ",$sslcert.notafter,$br -append


# =====================

print-header "remove-failed-install-logs"

$cmd = "dir c:\hs_err_pid*.* /s/b"

if (-not $runninglocal) {
#
# remote host
# could do this with psremote, but that requires config change on target host
# user psexec and invoke-expression instead
#

$username = $vicreds.username
$pwd = $vicreds.GetNetworkCredential().password
$cmd = "psexec \\" + $h + " -u " + $username + " -p " + $pwd + " " + $cmd
}

$result = iex $cmd
if ($result.length -eq 0) {
  $compliance = $compliant
  } else {
  $compliance = $notcompliant
  }



Out-File -filepath $outfile -inputobject ($epre,$results, $br) -append
Out-File -filepath $outfile -inputobject ($compliance, $br) -append

Out-File -filepath $outfile -inputobject ($b,$br, $rawdata, $eb,$br ) -append
Out-File -filepath $outfile -inputobject ($br, $result ) -append



# ===============================
print-header "restrict-admin-privilege"

# ===============================
print-header "restrict-admin-role"

$result = Get-VIPrivilege -server $vc | select server,name,privilegelist
Out-File -filepath $outfile -inputobject $epre, $rawdata -append
Out-File -filepath $outfile -inputobject ($result | Convertto-html -fragment -precontent $TableCSS) -append
# fix this from above priv loop

# =============================
print-header "restrict-certificate-access"


$cmd1 = "cacls `"c:\programdata\vmware\vmware virtualcenter\ssl`""
$cmd2 = "cacls `"C:\Program Files\VMware\Infrastructure\Inventory Service\ssl`""

if (-not $runninglocal) {
   $username = $vicreds.username
   $pwd = $vicreds.GetNetworkCredential().password
   $cmd1 = "psexec \\" + $h + " -u "+ $username + " -p  " + $pwd + " -h " + $cmd1
   $cmd2 = "psexec \\" + $h + " -u "+ $username + " -p  " + $pwd + " -h " + $cmd2 
   }

$result1 = iex $cmd1
$result2 = iex $cmd2

Out-File -filepath $outfile -inputobject $epre, $results,$pre -append
Out-File -filepath $outfile -inputobject ($result1) -append
Out-File -filepath $outfile -inputobject ($result2) -append
Out-File -filepath $outfile -inputobject $p,$epre -append

# ============================
print-header "restrict-guest-control"

$result = get-VIrole -server $vc 

Out-File -filepath $outfile -inputobject $pre, $results -append
Out-File -filepath $outfile -inputobject ($result | select name,  issystem, description, PrivilegeList | Convertto-html -fragment -precontent $TableCSS) -append
# fix this like other privilege loop

# ===================================

print-header "restrict-Linux-clients"
# ===================================

print-header "restrict-network-access"

if (-not $runninglocal) {
#
# remote host
# could do this with psremote, but that requires config change on target host
# user psexec and invoke-expression instead
#

$username = $vicreds.username
$pwd = $vicreds.GetNetworkCredential().password
$pse = "psexec \\" + $h + " -u " + $username + " -p " + $pwd + " "
$fwprofiles = $pse +  "netsh advfirewall show allprofiles"
$tempval = iex $rcmd
$rcmd = $pse +  "netsh advfirewall firewall show rule all"
$fwrules = iex $rcmd

Out-File -filepath $outfile -inputobject $epre,$b, "Firewall Policies",$eb -append
Out-File -filepath $outfile -inputobject $fwprofiles -append

Out-File -filepath $outfile -inputobject $b, "Firewall Rules", $eb -append
Out-File -filepath $outfile -inputobject $fwrules -append


}
else 
{
#
# local host
# user com Firewall object
#

$fw=New-object –comObject HNetCfg.FwPolicy2

$fwprofiles = @(1,2,4) | select @{Name=“Network Type”     ;expression={$fwProfileTypes[$_]}},
                   @{Name=“Firewall Enabled” ;expression={$fw.FireWallEnabled($_)}},
                   @{Name=“Block All Inbound”;expression={$fw.BlockAllInboundTraffic($_)}},
                   @{name=“Default In”       ;expression={$FwAction[$fw.DefaultInboundAction($_)]}},
                   @{Name=“Default Out”      ;expression={$FwAction[$fw.DefaultOutboundAction($_)]}}

$fwrules = $fw.rules | select name, desc, service, localports, remoteports, direction, enabled, action

Out-File -filepath $outfile -inputobject $epre,$b, "Firewall Policies",$eb -append
Out-File -filepath $outfile -inputobject ($fwprofiles | Convertto-html -fragment -precontent $TableCSS) -append

Out-File -filepath $outfile -inputobject $b, "Firewall Rules", $eb -append
Out-File -filepath $outfile -inputobject ($fwrules | Convertto-html -fragment -precontent $TableCSS) -append
}


# ===============================
print-header "restrict-vcs-db-user"

# ===============================

print-header "secure-vcenter-os"

# ===============================
# print-header "secure-vco-file-access"

# ===============================

print-header "thick-client-timeout"

if ($runninglocal) {
   $path = "C:\Program Files` (x86)\VMware\Infrastructure\Virtual Infrastructure Client\Launcher"
   }
else {
   $user = $vicreds.username
   $pwd = $vicreds.GetNetworkCredential().password
   $pse1 = "net use \\" + $h + "\c$ /username:" + $user + " " + $pwd
   $path = "\\" +"$h" +"\c$\Program Files (x86)\VMware\Infrastructure\Virtual Infrastructure Client\Launcher"
   iex $pse1
   }
$path += "\vpxclient.exe.config"
[xml]$vpxd = Get-Content $path 

$rawresult = [int]$vpxd.exe.config.inactivityTimeout

if($rawresult -eq 0) {
  $compliance = $notcompliant 
  } else {
  $compliance = $compliant
  }

Out-File -filepath $outfile -inputobject $pre,$results -append
Out-File -filepath $outfile -inputobject ($compliance, $br," Inactivity Timeout is ", [string]$rawresult, " seconds") -append


# =============================

print-header "use-supported-system"

if ($runninglocal) {
$result = Get-WmiObject Win32_OperatingSystem | select CSName, Caption, CSDVersion
} else {
$result = Get-WmiObject Win32_OperatingSystem -computer $vc.name -credential $vicreds | select CSName, Caption, CSDVersion
}

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject ($result | Convertto-html -fragment -precontent $TableCSS) -append

# =============================

print-header "verify-client-plugins"

# List Plugins Installed
$ServiceInstance = get-view -server $vc serviceinstance
$EM = Get-View -server $vc $ServiceInstance.Content.ExtensionManager

$result = $EM.ExtensionList | Select @{N="Name";E={$_.Description.Label}}, Company, Version, @{N="Summary";E={$_.Description.Summary}}

Out-File -filepath $outfile -inputobject $epre,$br,$results,$br -append
Out-File -filepath $outfile -inputobject ($result | Convertto-html -fragment -precontent $TableCSS) -append


# =============================

print-header "Verify-RDP-encryption"

$cmd = "nmap -p 3389 " + $h + " --script=rdp-enum-encryption"
$rawresult = iex $cmd
if ($rawresult -like "*Encryption level: High*") { 
   $result = $compliant
   }
   else
   { 
   $result = $notcompliant
   }

Out-File -filepath $outfile -inputobject $epre,$results,$br -append
Out-File -filepath $outfile -inputobject ($result) -append

Out-File -filepath $outfile -inputobject $pre,$br,$rawdata -append
Out-File -filepath $outfile -inputobject ($rawresult) -append

# =============================
print-header "use-service-accounts"

if (-not $runninglocal) {
    $services = Get-WmiObject win32_service -computer $h -credential $vicreds | Where-Object {$_.DisplayName -like "*VMware*"}
    } else {
    $services = Get-WmiObject win32_service | Where-Object {$_.DisplayName -like "*VMware*"}
    }

$result = $services | select name,displayname,state,startname 

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject ($result | Convertto-html -fragment -precontent $TableCSS) -append

