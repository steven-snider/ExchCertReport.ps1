<#  
.SYNOPSIS  
	This script reports detailed certificate information on Exchange 2016 servers

.PARAMETER ServerFilter
The name or partial name of the Servers to query valid values such as CONSVR or CONSVR2301

.PARAMETER ReportPath
Directory location to create the HTML report

.NOTES  
  Version      				: 0.5
  Rights Required			: Exchange View Only Admin/Local Server Administrator
  Exchange Version			: 2016/2013 (last tested on Exchange 2016 CU14/Windows 2012R2)
  Authors       			: Steven Snider (stevesn@microsoft.com) with thanks to Jerry Moore, Greg Sheldon, Karthikeyan Santhanam and Dan Sheehan
  Last Update               : Oct 14 2019

.VERSION
  0.1 - Initial Version for connecting Internal Exchange Servers
  0.2 - Added Web bindings and encryption type
  0.3 - Adjusting colors and report output
  0.4 - Adjusting Cert ranges and adding ServerFilter and ReportPath switches
  0.5 - Optimizing speed and multi-threading
	
#>

Param(
   [Parameter(Mandatory=$false)] [string] $ServerFilter="MSGCONSVR",
   [Parameter(Mandatory=$false)] [string] $ReportPath=$env:TEMP

)


If (-Not($UserCredential)) {
    $UserCredential = Get-Credential
}

<#Needs:
1. Option to Generate HTML or Email report
2. Identify Certificate Issues
    a. # certs per server
    b. Missing Cert color coding?
    c. Validate WMSVC Self-Signing and color coding
    d. Validate SMTP Self-Signing
    e. Color Code OAuth Cert
3. Attempt to optimize speed more
#>

#region Verifying Administrator Elevation
Write-Host Verifying User permissions... -ForegroundColor Yellow
Start-Sleep -Seconds 2
#Verify if the Script is running under Admin privileges
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
  [Security.Principal.WindowsBuiltInRole] "Administrator")) 
{
  Write-Warning "You do not have Administrator rights to run this script.`nPlease re-run this script as an Administrator!"
  Write-Host 
  Break
}
#endregion

#region Script Information

Write-Host "--------------------------------------------------------------" -BackgroundColor DarkGreen
Write-Host "Exchange Certificate Report" -ForegroundColor Green
Write-Host "Version: 0.5" -ForegroundColor Green
Write-Host "--------------------------------------------------------------" -BackgroundColor DarkGreen
#endregion

$FileDate = "{0:yyyy_MM_dd-HH_mm_ss}" -f (get-date)

$ServicesFileName = $ReportPath+"\ExCertReport-"+$FileDate+".html"
[Void](New-Item -ItemType file $ServicesFileName -Force)

[string]$search = "(&(objectcategory=computer)(cn=$serverfilter*))"
$ExchangeServers = ([adsisearcher]$search).findall() | ForEach-Object{$_.properties.name} | Sort-Object

$ServersList = @()
$ServersList = $ExchangeServers

If ($serverslist.length -eq 0) {
    Write-Host "Filter returned zero servers.  Please adjust filter and try again." -ForegroundColor Red
    Exit
}

#### Building HTML File ####
Function writeHtmlHeader
{
    param($fileName)
    $date = ( get-date ).ToString('MM/dd/yyyy')
    Add-Content $fileName "<html>"
    Add-Content $fileName "<head>"
    Add-Content $fileName "<meta http-equiv='Content-Type' content='text/html; charset=iso-8859-1'>"
    Add-Content $fileName '<title>Exchange Certificate Report</title>'
    add-content $fileName '<STYLE TYPE="text/css">'
    add-content $fileName  "<!--"
    add-content $fileName  "td {"
    add-content $fileName  "font-family: Segoe UI;"
    add-content $fileName  "font-size: 11px;"
    add-content $fileName  "border-top: 1px solid #1E90FF;"
    add-content $fileName  "border-right: 1px solid #1E90FF;"
    add-content $fileName  "border-bottom: 1px solid #1E90FF;"
    add-content $fileName  "border-left: 1px solid #1E90FF;"
    add-content $fileName  "padding-top: 0px;"
    add-content $fileName  "padding-right: 0px;"
    add-content $fileName  "padding-bottom: 0px;"
    add-content $fileName  "padding-left: 0px;"
    add-content $fileName  "}"
    add-content $fileName  "body {"
    add-content $fileName  "margin-left: 5px;"
    add-content $fileName  "margin-top: 5px;"
    add-content $fileName  "margin-right: 0px;"
    add-content $fileName  "margin-bottom: 10px;"
    add-content $fileName  ""
    add-content $fileName  "table {"
    add-content $fileName  "border: thin solid #000000;"
    add-content $fileName  "}"
    add-content $fileName  "-->"
    add-content $fileName  "</style>"
    add-content $fileName  "</head>"
    add-content $fileName  "<body>"
    add-content $fileName  "<table width='100%'>"
    add-content $fileName  "<tr bgcolor='#336699 '>"
    add-content $fileName  "<td colspan='7' height='25' align='center'>"
    add-content $fileName  "<font face='Segoe UI' color='#FFFFFF' size='4'>Exchange Certificate Report - $date</font>"
    add-content $fileName  "</td>"
    add-content $fileName  "</tr>"
    add-content $fileName  "</table>"
}

Function writeTableHeader
{
    param($fileName)
    Add-Content $fileName "<tr bgcolor=#0099CC>"
    Add-Content $fileName "<td width='5%' align='center'><font color=#FFFFFF>Services</font></td>"
    Add-Content $fileName "<td width='5%' align='center'><font color=#FFFFFF>Binding</font></td>"
    Add-Content $fileName "<td width='15%' align='center'><font color=#FFFFFF>Issuer</font></td>"
    Add-Content $fileName "<td width='15%' align='center'><font color=#FFFFFF>Thumbprint</font></td>"
    Add-Content $fileName "<td width='15%' align='center'><font color=#FFFFFF>Subject Name</font></td>"
    Add-Content $fileName "<td width='5%' align='center'><font color=#FFFFFF>Self Signed</font></td>"
    Add-Content $fileName "<td width='5%' align='center'><font color=#FFFFFF>Cipher</font></td>"
    Add-Content $fileName "<td width='15%' align='center'><font color=#FFFFFF>SAN</font></td>"
    Add-Content $fileName "<td width='5%' align='center'><font color=#FFFFFF>Issue Date</font></td>"
    Add-Content $fileName "<td width='5%' align='center'><font color=#FFFFFF>Expiration Date</font></td>"
    Add-Content $fileName "<td width='10%' align='center'><font color=#FFFFFF>Certificate Age</font></td>"
    Add-Content $fileName "</tr>"
}

Function writeHtmlFooter
{
    param($fileName)
    Add-Content $fileName "</body>"
    Add-Content $fileName "</html>"
}

Function writeServiceInfo
{
    param($fileName,$FriendlyName,$Issuer,$Subject,$Thumbprint,$NotBefore,$NotAfter,[string]$Services,$IsSelfSigned,$Cipher,$CertDomains,$Bind)
    $TimeDiff = New-TimeSpan -Start $NotBefore
    $DaysDiff = $TimeDiff.Days

#write-host $issuer $notbefore $notafter $timediff $DaysDiff
    
     Add-Content $fileName "<tr>"
     Add-Content $fileName "<td align='center'>$Services</td>"
     Add-Content $fileName "<td>$Bind</td>"
     Add-Content $fileName "<td>$Issuer</td>"
     Add-Content $fileName "<td>$Thumbprint</td>"
     Add-Content $fileName "<td>$Subject</td>"

     #determine Self-Signed flag, if Issuer=Subject, then SelfSigned = True
     #  this has to be manually checked since Get-ExchangeCertificate does not return this value when queried remotely
     If ($Issuer -eq $Subject) {
         $IsSelfSigned = "True"
     }
     Else {
         $IsSelfSigned = "False"
     }

     Add-Content $fileName "<td align='center'>$IsSelfSigned</td>"
     If ($Cipher -eq "SHA1") {
        Add-Content $fileName "<td bgcolor='#FBB917' align='center'>$Cipher</td>"
     }
     Else {
        Add-Content $fileName "<td align='center'>$Cipher</td>"
     }
     Add-Content $fileName "<td>$CertDomains</td>"

     Add-Content $fileName "<td align='center'>$NotBefore</td>"
     Add-Content $fileName "<td align='center'>$NotAfter</td>"
     #color code the days depending on age
     if ((730 - $DaysDiff) -lt 0) #cert expired
         {
             Add-Content $fileName "<td bgcolor='#FF0000' align=center>Age Exceeded</td>"
             Add-Content $fileName "</tr>"
         }
     elseif ((730 - $DaysDiff) -lt 180) #cert within 180 days of 2 years age limit
         {
             $Remain = 730 - $DaysDiff
             Add-Content $fileName "<td bgcolor='#FFFF00' align=center>'Non-Compliant in $Remain days'</td>"
             Add-Content $fileName "</tr>"
         }
     else #cert not close to expiring
         {
             Add-Content $fileName "<td bgcolor='#00FF7F' align=center>$DaysDiff</td>"
             Add-Content $fileName "</tr>"
         }
}

Function sendEmail
    { param($from,$to,$subject,$smtphost,$htmlFileName)
        $body = Get-Content $htmlFileName
        $smtp= New-Object System.Net.Mail.SmtpClient $smtphost
        $msg = New-Object System.Net.Mail.MailMessage $from, $to, $subject, $body
        $msg.isBodyhtml = $true
        $smtp.send($msg)
    }

########################### Main Script ###################################
writeHtmlHeader $ServicesFileName


foreach ($Server in $ServersList)
{       
        Add-Content $ServicesFileName "<table width='100%'><tbody>"
        Add-Content $ServicesFileName "<tr bgcolor='#0099CC'>"
        Add-Content $ServicesFileName "<td width='100%' align='center' colSpan=11><font face='segoe ui' color='#FFFFFF' size='2'>$Server</font></td>"
        Add-Content $ServicesFileName "</tr>"
        WriteTableHeader $ServicesFileName
        
        try
        {
#            $ExCerts = Get-ExchangeCertificate -Server $Server
#            Write-Host "Connecting to server: " $server
            $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$Server.contoso.com/PowerShell/ -Authentication Kerberos -Credential $UserCredential
            [Void](Import-PSSession $Session -DisableNameChecking -AllowClobber -commandName Get-ExchangeCertificate)

            
            #Collect Exchange Certificates from each server
            $ExCerts = Invoke-Command -Session $session {Get-ExchangeCertificate |Select-Object Thumbprint,Services,Issuer,IsSelfSigned,CertificateDomains,NotAfter,NotBefore,Subject} 

            #Collect Certificate Binding information for each server's IIS components
            $scriptblock = {
   
                $cert=Get-ChildItem -path cert:\localmachine\my | Select-Object thumbprint, subject, NotAfter, NotBefore, @{n="sa";e={$_.signaturealgorithm.value}}
                $web=get-webbinding | Select-Object protocol, bindinginformation, certificatehash
                foreach ($crt in $cert) {
                #check if cert is bound to something
                $wb=$null;$wbp=$null
                    foreach ($w in $web) {
                        if ($w.certificatehash -eq $crt.Thumbprint) {
                        #$wb=$w.bindinginformation;$wbp=$w.protocol
                            $wb=$w.bindinginformation + "/" + $wb
		        		    $wbp=$w.protocol + "/" + $wbp
                            }
 #                       else {$wb="-";$wbp="-"}
        				
                        }

                   $enc=switch ($crt.sa)
                        {
                            1.2.840.113549.1.1.11 {"SHA256"}
                            1.2.840.113549.1.1.5 {"SHA1"}
                            default {"NotDefinedInScript"}
                        }
                    $data = new-object psobject
                    $data | Add-Member -MemberType NoteProperty -Name "Thumbprint" -Value $crt.Thumbprint
                    $data | Add-Member -MemberType NoteProperty -Name "IISBinding" -Value $wb
                    $data | Add-Member -MemberType NoteProperty -Name "IISProtocol" -Value $wbp
                    $data | Add-Member -MemberType NoteProperty -Name "Algorithm" -Value $crt.sa
                    $data | Add-Member -MemberType NoteProperty -Name "Encryption" -Value $enc
                    $data
 
 
                }
 
            }
 
            $BindingData = Invoke-command -ComputerName $Server -ScriptBlock $scriptblock -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 

        }
        catch
        {
            Write-Host
            Write-Host "Error Connecting to server " $Server ", Please verify connectivity and permissions" -ForegroundColor Red
            Continue
        }
        
        foreach ($item in $ExCerts)
        {
           Foreach ($binding in $BindingData) {
                If ($Item.Thumbprint -eq $Binding.Thumbprint) {
                   $Encryption = $Binding.Encryption
                   $IISBinding = $Binding.IISBinding                }
           
           }
#            writeServiceInfo $ServicesFileName $item.Subject $item.Services $item.Issuer $item.Thumbprint $item.NotBefore $item.NotAfter $item.Services $item.IsSelfSigned $item.CertificateDomains
            writeServiceInfo $ServicesFileName $item.Subject $item.Issuer $item.Subject $item.Thumbprint $item.NotBefore $item.NotAfter $item.Services $item.IsSelfSigned $Encryption $item.CertificateDomains $IISBinding
        }
        
        Add-Content $ServicesFileName "</table>"
}


writeHtmlFooter $ServicesFileName

### Configuring Email Parameters
#sendEmail from@domain.com to@domain.com "Certificates State Report - $Date" SMTPS_SERVER $ServicesFileName

#Closing HTML
writeHtmlFooter $ServicesFileName
Write-Host "`n`nThe File was generated at the following location: $ServicesFileName `n`nOpenning file..." -ForegroundColor Cyan
Invoke-Item $ServicesFileName

Remove-PSSession $Session
