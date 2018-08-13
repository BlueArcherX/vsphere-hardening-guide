# ==============================
# collect Command Line Arguments (hostname only)

if ($args.count -gt 1) {
  write-host "Too Many Arguments Specified"
  write-host "Syntax:  audit-esxi hostname OR fqdn OR ipaddress"
  return
  }
if ($args.count -eq 0) {
  write-host "no target host specified - please specify IP or hostname"
  write-host "Syntax:  audit-esxi hostname OR fqdn OR ipaddress"
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

$outfile = "audit-"+$h+"-ESXi.html"

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
out-file -filepath $outfile -inputobject $h1, "vSphere Security Benchmark - ESXi Hosts",$eh1,$br -append

out-file -filepath $outfile -inputobject "Version 2017-1, https://github.com/robvandenbrink/vsphere-hardening-guide",$p -append

out-file -filepath $outfile -inputobject $h2, "Target Host: ", $h, $eh2 ,$p -append

out-file -filepath $outfile -inputobject (get-date) -append
out-file -filepath $outfile -inputobject $p,"<b>ESXi Hosts:</b>" -append

out-file -filepath $outfile -inputobject ($esxhosts |Select Name, ConnectionState, PowerState `
       | Convertto-html -fragment -precontent $TableCSS ) -append

##########################################################################################
#                                                                                        #
# AUDIT CHECKS START HERE                                                                #
#                                                                                        #
##########################################################################################

print-header "apply-patches"

foreach ($esxh in $esxhosts) {
 
    $VMHostName = $esxh.Name
 
    $esxcli = $esxh | Get-EsxCli
    $patches = $esxcli.software.vib.list() | Select-Object @{N="VMHostName"; E={$VMHostName}}, *
    Out-File -filepath $outfile -inputobject $epre, $rawdata -append
    Out-File -filepath $outfile -inputobject ($patches | Convertto-html -fragment -precontent $TableCSS) -append

}


# ==========================================

print-header "config-firewall-access"

foreach ($esxh in $esxhosts) {
    $hostresults = @()
    $VMHostName = $esxh.Name


    # List all services for a host
    $services = Get-VMHost $esxh | Get-VMHostService
    # List the services which are enabled and have rules defined for specific IP ranges to access the service
    $specificrules = Get-VMHost $esxh | Get-VMHostFirewallException | Where {$_.Enabled -and (-not $_.ExtensionData.AllowedHosts.AllIP)}
    # List the services which are enabled and do not have rules defined for specific IP ranges to access the service
    $nonspecificrules = Get-VMHost $esxh | Get-VMHostFirewallException | Where {$_.Enabled -and ($_.ExtensionData.AllowedHosts.AllIP)}


    Out-File -filepath $outfile -inputobject $epre,$b,"Host ", $esxh.name, "HOST Services: ",$eb,$p -append
    Out-File -filepath $outfile -inputobject ($services | select vmhost, key, Label, Policy,Required,Ruleset,Running | `
               convertto-html -fragment -precontent $TableCSS) -append

    Out-File -filepath $outfile -inputobject $p,$b, $esxh.name, " IP Specific Rules: ",$eb,$p -append
    Out-File -filepath $outfile -inputobject ($specificrules | select vmhost,vmhostid,name,enabled,incomingports,outgoingports,protocols,servicerunning | `
               Convertto-html -fragment -precontent $TableCSS) -append

    Out-File -filepath $outfile -inputobject $p,$b,$esxh.name, "IP All Rules: ",$eb,$eb,$p -append
    Out-File -filepath $outfile -inputobject ($nonspecificrules | select vmhost,vmhostid,name,enabled,incomingports,outgoingports,protocols,servicerunning | `
               Convertto-html -fragment -precontent $TableCSS) -append
}

# ==========================================
print-header "config-ntp"

$hresults = @()
foreach ($esxh in $esxhosts) {

$result = $esxh | get-vmhostntpserver 
$status = $esxh | Get-VMHostService |?{$_.key -eq 'ntpd'}

$tempval = new-object psobject;
$tempval | add-member –membertype NoteProperty –name HOST -value $esxh ;
$tempval | add-member –membertype NoteProperty –name Compliance –Value $compliant ; 
$tempval | add-member –membertype NoteProperty –name "NTP Servers" -Value ($result -join "<br>" );

if ($result.count -eq 0) {
$tempval.Compliance = $notcompliant
}
$hresults += $tempval
$servicestatus += $status
}

Out-File -filepath $outfile -inputobject $epre -append

$complianceresults = $hresults | select HOST, Compliance | convertto-html -fragment -precontent $TableCSS
Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

$rawresults = $hresults | select HOST, "NTP Servers" | convertto-html -fragment -precontent $TableCSS
Out-File -filepath $outfile -inputobject $rawdata -append
Out-File -filepath $outfile -inputobject (fixhtml $rawresults) -append

Out-File -filepath $outfile -inputobject $p -append
Out-File -filepath $outfile -inputobject ($servicestatus  | Select vmhost,label,policy,required,running |`
               convertto-html -fragment -precontent $TableCSS) -append

# ==========================================
print-header "config-persistent-logs"

$hresults = @()
foreach ($esxh in $esxhosts) {

$result = $esxh | Get-AdvancedSetting Syslog.global.logDir

$tempval = new-object psobject;
$tempval | add-member –membertype NoteProperty –name HOST -value $esxh ;
$tempval | add-member –membertype NoteProperty –name Compliance –Value $notcompliant ; 
$tempval | add-member –membertype NoteProperty –name "Raw Data" $result ;

if ($result.length -gt 0) {
$tempval.Compliance = $compliant
}
$hresults += $tempval
}

$complianceresults = $hresults | select HOST, Compliance | convertto-html -fragment -precontent $TableCSS
Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

Out-File -filepath $outfile -inputobject $rawdata -append
Out-File -filepath $outfile -inputobject ($hresults | select HOST,"Raw Data"  | `
               convertto-html -fragment -precontent $TableCSS) -append

# ==========================================
print-header "config-snmp"

$hresults = @()
foreach ($esxh in $esxhosts) {

$esxcli = get-esxcli -vmhost $esxh
$result = $esxcli.system.snmp.get()

$tempval = new-object psobject;
$tempval | add-member –membertype NoteProperty –name HOST -value $esxh ;
$tempval | add-member –membertype NoteProperty –name Compliance –Value $compliant ; 
$tempval | add-member –membertype NoteProperty –name "Enable" $result.enable ;
$tempval | add-member –membertype NoteProperty –name "Loglevel" $result.loglevel ;
$tempval | add-member –membertype NoteProperty –name "Port" $result.port ;
$tempval | add-member –membertype NoteProperty –name "Targets" $result.targets ;
$tempval | add-member –membertype NoteProperty –name "v3targets" $result.v3targets ;

if (($result.enable.length -gt 0) -and ($result.enable.toupper() -eq "TRUE")) {
    $tempval.Compliance = $notcompliant
    }
$hresults += $tempval
}

$complianceresults = $hresults | convertto-html -fragment -precontent $TableCSS
Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append


# ==========================================
print-header "create-local-admin"

$hresults = @()
foreach ($esxh in $esxhosts) {
    $result = get-viaccount -server $esxh.name
    $hresults += $result
    }

Out-File -filepath $outfile -inputobject $epre,$rawdata -append
Out-File -filepath $outfile -inputobject ($hresults | Select Server, Name, ID, Description, ShellAccessEnabled | `
         convertto-html -fragment -precontent $TableCSS) -append



# ==========================================
print-header "disable-dcui"

$hresults = @()
foreach ($esxh in $esxhosts) {

$result =  $esxh | Get-VMHostService | Where { $_.key -eq "DCUI" }
$result | add-member –membertype NoteProperty –name Compliance –Value $notcompliant ; 


if (($result.policy.toupper() -eq "OFF") -and ($result.running -eq $false)) {
$result.Compliance = $compliant
}
$hresults += $result
}

$complianceresults = $hresults | Select VMHost, Compliance | convertto-html -fragment -precontent $TableCSS
Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

Out-File -filepath $outfile -inputobject $rawdata -append
Out-File -filepath $outfile -inputobject ($hresults | select VMHost, Key, Policy, Running | `
     convertto-html -fragment -precontent $TableCSS ) -append

# ==========================================
print-header "disable-esxi-shell"

$hresults = @()
foreach ($esxh in $esxhosts) {

$result =  $esxh | Get-VMHostService | where  { $_.key -eq "TSM" } | Select VMHost, Key, Label, Policy, Running, Required
$result | add-member –membertype NoteProperty –name Compliance –Value $notcompliant ; 


if (($result.policy.toupper() -eq "OFF") -and ($result.running -eq $false)) {
$result.Compliance = $compliant
}
$hresults += $result
}

$complianceresults = $hresults | Select VMHost, Compliance | convertto-html -fragment -precontent $TableCSS
Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

$complianceresults = $hresults  | convertto-html -fragment -precontent $TableCSS
Out-File -filepath $outfile -inputobject $rawdata -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# ==========================================
print-header "disable-mob"

$hresults = @()
foreach ($esxh in $esxhosts) {
$uri = "https://" + $esxh.name + "/mob"
$result =  invoke-webrequest $uri -credential $vicreds

$tempval = new-object psobject;
$tempval | add-member –membertype NoteProperty –name VMHost -value $esxh.name ;
$tempval | add-member –membertype NoteProperty –name Compliance –Value $compliant ;

if ( $result.statuscode -eq 200 ) {
  $tempval.Compliance = $notcompliant
  }
$hresults += $tempval
}

$complianceresults = $hresults | Select VMHost, Compliance | convertto-html -fragment -precontent $TableCSS
Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append


# ==========================================

print-header "disable-ssh"

$hresults = @()
foreach ($esxh in $esxhosts) {
$tempval = new-object psobject;
$tempval =  $esxh | Get-VMHostService | Where { $_.key -eq "TSM-SSH" } | Select VMHost, Key, Label, Policy, Running, Required
$tempval | add-member –membertype NoteProperty –name Compliance -value $compliant ;

if (( $tempval.running -eq $true ) -or ( $tempval.Policy.toupper() -eq "ON")) {
  $tempval.Compliance = $notcompliant
  }
$hresults += $tempval
}

$complianceresults = $hresults | Select VMhost, Compliance, Key, Label, Policy, Running, Required `
          | convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append


# ==========================================

print-header "enable-ad-auth"

$hresults = @()
foreach ($esxh in $esxhosts) {

$result =  $esxh | Get-VMHostAuthentication | Select VmHost, Domain, DomainMembershipStatus

$result | add-member –membertype NoteProperty –name Compliance -value $notcompliant ;

# if domain is non-null, then we are a domain member
if ($result.Domain ) {
  $result.Compliance = $compliant
  }
$hresults += $result
}

$complianceresults = $hresults | Select VMhost, Compliance | convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

Out-File -filepath $outfile -inputobject $rawdata -append
Out-File -filepath $outfile -inputobject ($hresults | select VMHost, Domain, DomainMembershipStatus | `
    convertto-html -fragment -precontent $TableCSS ) -append

# ==========================================

# enable-auth-proxy
# moved to vcenter assessment - this check only works when connected via vcenter
# and this script can be run either against vcenter or a standalone host

# ==========================================

print-header "enable-chap-auth"

$hresults = @()
foreach ($esxh in $esxhosts) {

$hbaresult =  $esxh | Get-VMHosthba
$iscsiresult = $esxh | Get-VMHostHba | Where {$_.Type -eq "Iscsi"} | Select VMHost, Device, ChapType, @{N="CHAPName";E={$_.AuthenticationProperties.ChapName}}

if ($iscsiresult ) { 
  if ($iscsiresult.CHAPName.length() -gt 0 ) {
     $iscsiresult | add-member –membertype NoteProperty –name Compliance -value $compliant
     $result = $iscsiresult
     }
     else {      
     $iscsiresult | add-member –membertype NoteProperty –name Compliance -value $notcompliant
     $result = $iscsiresult
     }
  }
  else {
  $result = new-object psobject;
  $result | add-member –membertype NoteProperty –name VMHost -value $esxh.name ;
  $result | add-member –membertype NoteProperty –name Compliance -value " " ;
  }
  
$hresults += $result

}
$complianceresults = $hresults |  convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# ==========================================

# enable-host-profiles
# moved to vcenter assessment - this check only works when connected via vcenter
# and this script can be run either against vcenter or a standalone host

# ==========================================

print-header "enable-lockdown-mode"

$hresults = @()
foreach ($esxh in $esxhosts) {

$result =  $esxh  | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.adminDisabled}}
$result | add-member –membertype NoteProperty –name Compliance -value $notcompliant

if ($result.Lockdown -ne "" ) { 
  $result.Compliance = $compliant
  }
  
$hresults += $result

}
$complianceresults = $hresults | convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append


# ==========================================

# "enable-nfc-ssl"
# moved to vcenter assessment - this check only works when connected via vcenter
# and this script can be run either against vcenter or a standalone host


# ==========================================
print-header "enable-remote-dump"

$hresults = @()
foreach ($esxh in $esxhosts) {
 
$ESXCli = Get-EsxCli -VMHost $esxh
$tempval = $ESXCLI.system.coredump.network.get()

$result = new-object psobject;
$result | add-member –membertype NoteProperty –name VMHost -value $esxh ;
$result | add-member –membertype NoteProperty –name Enabled -value $tempval.Enabled ;
$result | add-member –membertype NoteProperty –name HostVNic -value $tempval.HostVNic ;
$result | add-member –membertype NoteProperty –name NetworkServerIO -value $tempval.NetworkServerIP ;
$result | add-member –membertype NoteProperty –name NetworkServerPort -value $tempval.NetworkServerPort ;
$result | add-member –membertype NoteProperty –name Compliance -value $compliant

if ($result.Enabled -eq $false ) { 
  $result.Compliance = $notcompliant
  }
  
$hresults += $result

}
$complianceresults = $hresults | convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append


# ==========================================
print-header "enable-syslog"

$hresults = @()
foreach ($esxh in $esxhosts) {

 
$tempval = $esxh | Get-AdvancedSetting -Name Syslog.global.logHost
$result = new-object psobject;
$result | add-member –membertype NoteProperty –name VMHost -value $esxh ;
$result | add-member –membertype NoteProperty –name sysloghost -value $tempval.value ;
$result | add-member –membertype NoteProperty –name Compliance -value $notcompliant

if ($result.sysloghost ) { 
  $result.Compliance = $compliant
  }  
$hresults += $result

}
$complianceresults = $hresults | convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append


# ==========================================
print-header "esxi-no-self-signed-certs"

$hresults = @()
foreach ($esxh in $esxhosts) {

$h = $esxh.name
$p = 443
$cert = ChkCert -ip $h -port $p

$result = new-object psobject;
$result | add-member –membertype NoteProperty –name VMHost -value $esxh ;
$result | add-member –membertype NoteProperty –name issuer -value $cert.issuer ;
$result | add-member –membertype NoteProperty –name Compliance -value $compliant

if ($result.issuer.toupper() -like "VMWARE INSTALLER" ) { 
  $result.Compliance = $notcompliant
  }  
$hresults += $result

}
$complianceresults = $hresults | convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# ==========================================
print-header "limit-cim-access"

$hresults = @()
$result = @()
foreach ($esxh in $esxhosts) {

 
$result = get-vmhostaccount -server $esxh.name
$result | add-member –membertype NoteProperty –name Compliance -value $compliant
$result | add-member –membertype NoteProperty –name VMhost -value $esxh

foreach ($r in $result) {
if ($r.shellaccessenabled ) { 
  $r.Compliance = $notcompliant
  } 
} 
$hresults += $result

}
$complianceresults = $hresults | `
      select VMHost, name, Description, ShellAccessEnabled, Server, Compliance | `
      convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# ==========================================
print-header "mask-zone-san"
# manual check

# ==========================================
print-header "remove-authorized-keys"
# manual check

# ==========================================
print-header "remove-revoked-certificates"

$hresults = @()
foreach ($esxh in $esxhosts) {

$h = $esxh.name
$p = 443
$cert = ChkCert -ip $h -port $p

$result = new-object psobject;
$result | add-member –membertype NoteProperty –name VMHost -value $esxh ;
$result | add-member –membertype NoteProperty –name ExpireDate -value $cert.notafter.datetime ;
# this requires Powershell 4 
# $result | add-member –membertype NoteProperty –name ValidCert -value $cert.Verify() ;
$result | add-member –membertype NoteProperty –name Compliance -value $compliant
$now =get-date
 
if ($now.datetime -gt $result.ExpireDate ) { 
  $result.Compliance = $notcompliant
  }  
$hresults += $result

}
$complianceresults = $hresults | convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# ==========================================
# print-header "set-dcui-access"
# manual check

# ==========================================
print-header "set-password-complexity"
# manual check

# ==========================================
print-header "set-shell-interactive-timeout"

$hresults = @()
foreach ($esxh in $esxhosts) {

$result = new-object psobject;
$result | add-member –membertype NoteProperty –name VMHost -value $esxh ;
$tempval = $esxh | Get-AdvancedSetting UserVars.ESXiShellInteractiveTimeOut
$result | add-member –membertype NoteProperty –name ShellIteractiveTimeout -value $tempval.value ;
$result | add-member –membertype NoteProperty –name Compliance -value $compliant ;
 
if ($tempval.value -eq 0 ) { 
  $result.Compliance = $notcompliant
  }  
$hresults += $result
}
$complianceresults = $hresults | convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append


# ==========================================
print-header "set-shell-timeout"

$hresults = @()
foreach ($esxh in $esxhosts) {

$result = new-object psobject;
$tempval = $esxh | Get-AdvancedSetting UserVars.ESXiShellTimeOut
$result | add-member –membertype NoteProperty –name VMHost -value $esxh ;
$result | add-member –membertype NoteProperty –name ShellTimeout -value $tempval.value ;
$result | add-member –membertype NoteProperty –name Compliance -value $compliant ;

 
if ($tempval.value -eq 0 ) { 
  $result.Compliance = $notcompliant
  }  
$hresults += $result
}

$complianceresults = $hresults | convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# ==========================================

print-header "unique-chap-secrets"

$hresults = @()
foreach ($esxh in $esxhosts) {
$result = new-object psobject;

$hbaresult =  $esxh | Get-VMHosthba
$iscsiresult = $esxh | Get-VMHostHba | Where {$_.Type -eq "Iscsi"} | Select VMHost, Device, ChapType, @{N="CHAPName";E={$_.AuthenticationProperties.ChapName}}

if ($iscsiresult ) { 
  if ($iscsiresult.CHAPName.length() -gt 0 ) {
     $iscsiresult | add-member –membertype NoteProperty –name Compliance -value $notcompliant$result = "Manual Assessment"
     }
     else {      
     $iscsiresult | add-member –membertype NoteProperty –name Compliance -value $notcompliant
     $result = $iscsiresult
     }
  }
  else {
  $result = new-object psobject;
  $result | add-member –membertype NoteProperty –name VMHost -value $esxh.name ;
  $result | add-member –membertype NoteProperty –name Compliance -value " " ;
  }
  
$hresults += $result

}
$complianceresults = $hresults |  convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# ==========================================

print-header "verify-acceptance-level-accepted"

$hresults = @()
$hvibresults = @()
foreach ($esxh in $esxhosts) {

# Host Compliance Levels

  $ESXCli = Get-EsxCli -VMHost $esxh
  $result = new-object psobject;
  $result | add-member –membertype NoteProperty –name VMHost -value $esxh.name ;
  $result | add-member –membertype NoteProperty –name HostAcceptanceLevel -value $ESXCLI.software.acceptance.get() ;
  $result | add-member –membertype NoteProperty –name Compliance -value $notcompliant ;

  if(($result.HostAcceptanceLevel -eq "VMwareCertified") -or ($result.HostAcceptanceLevel -eq "VMwareAccepted")) {
      $result.HostAcceptanceLevel = $compliant
      }
  
$hresults += $result

# VIB Compliance Levels
 $ESXCli = Get-EsxCli -VMHost $esxh
 $NCvibs = $ESXCli.software.vib.list() | Where { ($_.AcceptanceLevel -ne "VMwareCertified") -and ($_.AcceptanceLevel -ne "VMwareAccepted") }
 if($NCvibs.count -ne 0) {
     $NCvibs | add-member –membertype NoteProperty –name VMHost -value $esxh.name 
     $NCvibs | add-member –membertype NoteProperty –name Compliance -value $notcompliant 
     $hvibresults += $NCvibs
     }
}

$complianceresults = $hresults |  convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,"<b>Host Compliance Status:</b><p>" -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

if($hvibresults.count -ne 0) {
   $complianceresults = $hresults |  convertto-html -fragment -precontent $TableCSS

   Out-File -filepath $outfile -inputobject $epre,"<b>Out of Compliance VIBs</b><p>" -append
   Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append
   }

# ==========================================

print-header "verify-acceptance-level-certified"

$hresults = @()
$hvibresults = @()
foreach ($esxh in $esxhosts) {

# Host Compliance Levels

  $ESXCli = Get-EsxCli -VMHost $esxh
  $result = new-object psobject;
  $result | add-member –membertype NoteProperty –name VMHost -value $esxh.name ;
  $result | add-member –membertype NoteProperty –name HostAcceptanceLevel -value $ESXCLI.software.acceptance.get() ;
  $result | add-member –membertype NoteProperty –name Compliance -value $notcompliant ;

  if($result.HostAcceptanceLevel -eq "VMwareCertified") {
      $result.HostAcceptanceLevel = $compliant
      }
  
$hresults += $result

# VIB Compliance Levels
 $ESXCli = Get-EsxCli -VMHost $esxh
 $NCvibs = $ESXCli.software.vib.list() | Where { ($_.AcceptanceLevel -ne "VMwareCertified") }
 if($NCvibs.count -ne 0) {
     $NCvibs | add-member –membertype NoteProperty –name VMHost -value $esxh.name 
     $NCvibs | add-member –membertype NoteProperty –name Compliance -value $notcompliant 
     $hvibresults += $NCvibs
     }
}


$complianceresults = $hresults |  convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,"<b>Host Compliance Status:</b><p>" -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

if($hvibresults.count -ne 0) {
   $complianceresults = $hresults |  convertto-html -fragment -precontent $TableCSS

   Out-File -filepath $outfile -inputobject $epre,"<b>Out of Compliance VIBs</b><p>" -append
   Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append
}

# ==========================================

print-header "verify-acceptance-level-supported"

$hresults = @()
$hvibresults = @()
foreach ($esxh in $esxhosts) {

# Host Compliance Levels

  $ESXCli = Get-EsxCli -VMHost $esxh
  $result = new-object psobject;
  $result | add-member –membertype NoteProperty –name VMHost -value $esxh.name ;
  $result | add-member –membertype NoteProperty –name HostAcceptanceLevel -value $ESXCLI.software.acceptance.get() ;
  $result | add-member –membertype NoteProperty –name Compliance -value $notcompliant ;

  if($result.HostAcceptanceLevel -eq "VMwareCertified") {
      $result.HostAcceptanceLevel = $compliant
      }
  
$hresults += $result

# VIB Compliance Levels
 $ESXCli = Get-EsxCli -VMHost $esxh
 $NCvibs = $ESXCli.software.vib.list() | Where { ($_.AcceptanceLevel -ne "VMwareCertified") -and `
              ($_.AcceptanceLevel -ne "VMwareAccepted") -and ($_.AcceptanceLevel -ne "PartnerSupported") }
 if($NCvibs.count -ne 0) {
     $NCvibs | add-member –membertype NoteProperty –name VMHost -value $esxh.name 
     $NCvibs | add-member –membertype NoteProperty –name Compliance -value $notcompliant 
     $hvibresults += $NCvibs
     }
}


$complianceresults = $hresults |  convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,"<b>Host Compliance Status:</b><p>" -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

if($hvibresults.count -ne 0) {
   $complianceresults = $hresults |  convertto-html -fragment -precontent $TableCSS

   Out-File -filepath $outfile -inputobject $epre,"<b>Out of Compliance VIBs</b><p>" -append
   Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append
}

# ==========================================

print-header "verify-admin-group"

$hresults = @()
foreach ($esxh in $esxhosts) {

# Host Compliance Levels

  $tempvalue = $esxh | Get-AdvancedSetting Config.HostAgent.plugins.hostsvc.esxAdminsGroup

  $result = new-object psobject;
  $result | add-member –membertype NoteProperty –name VMHost -value $esxh.name ;
  $result | add-member –membertype NoteProperty –name AdminGroup $tempvalue.value ;
  $result | add-member –membertype NoteProperty –name Compliance -value "Manual Assessment" ;

$hresults += $result

}

$complianceresults = $hresults |  convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# ==========================================

# print-header "verify-config-files"

# This check is not yet implemented in PowerCLI

# ==========================================

print-header "verify-dvfilter-bind"

$hresults = @()
foreach ($esxh in $esxhosts) {

$tempvalue = $esxh | Get-AdvancedSetting Net.DVFilterBindIpAddress
 $result = new-object psobject;
  $result | add-member –membertype NoteProperty –name VMHost -value $esxh.name ;
  $result | add-member –membertype NoteProperty –name DVFilterAddress $tempvalue.value ;
  $result | add-member –membertype NoteProperty –name Compliance -value $notcompliant ;

if ($tempvalue.value.length -eq 0) {
  $result.Compliance = $compliant
 }

$hresults += $result
}

$complianceresults = $hresults |  convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# ==========================================

print-header "verify-install-media"

# ==========================================

print-header "verify-kernel-modules"

$hresults = @()
foreach ($esxh in $esxhosts) {

 $ESXCLI = Get-EsxCli -VMHost $esxh
 $modules = $ESXCLI.system.module.list() 
 foreach ($module in $modules) {
    if($module.name -ne "vmkapei") {
        $result = $ESXCli.system.module.get($module.Name) | Select @{N="VMHost";E={$VMHost}}, Module, `
            License, Modulefile, Version, SignedStatus, SignatureDigest, SignatureFingerPrint
        $result.VMhost = $esxh.name
        $hresults += $result
       }
    }
}

$complianceresults = $hresults |  convertto-html -fragment -precontent $TableCSS

Out-File -filepath $outfile -inputobject $epre,$results -append
Out-File -filepath $outfile -inputobject (fixhtml $complianceresults) -append

# ==========================================

print-header "vmdk-zero-out"
# manual check of work processes and habits

# ==========================================

# print-header "vpxuser-password-age"
# this check moved to vsphere assessment


