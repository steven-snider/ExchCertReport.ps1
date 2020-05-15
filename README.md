# ExchCertReport.ps1
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
