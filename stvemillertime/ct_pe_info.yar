// #100daysofYARA
// day 3
// stvemillertime
// this size check ruleset is meant to help measure samples in a large corpus
// how many unsigned binaries live in windows 11 system32? what do they look like?

//first we look at the unsigned
/*
yara -r ~/ct_pe_signed.yar ~/W11-FS/ | awk  '{print $1}' | sort | uniq -c |  awk  '{line = sprintf("%*s", ($1*(0.001)), ""); gsub(/ /, "*", line);print $2,$1,line}' 

*/

import "pe"
import "console"
// use this rule to get a quick count of unsigned pes in Windows\System32\
// made private to not show matches
private rule pe_unsigned { condition: pe.number_of_signatures != 0}

// this next rule we can use to take a measurement of what those unsigned files are
// we make the rule private so only the console log shows while it runs
// looks something like this
/*
yara ~/GitHub/100daysofYARA2024/stvemillertime/ct_pe_info.yar ~/w11-vm/Windows/System32/ | sort | uniq -c | sort
1 Herramienta de eliminaci\xf3n de software malintencionado de Microsoft Windows
   1 International Components for Unicode
   1 Microsoft (R) Windows (R) Operating System
   1 Microsoft Malware Protection
   1 Microsoft ODBC Driver 17.7 for SQL Server
   1 Microsoft OneDrive
   1 Microsoft XML Core Services
   1 Microsoft\xa9 ADAL
   1 SQLite
   1 The curl executable
   1 VMware Guest Authentication
   1 VMware HGFS Provider
   1 VMware SVGA 3D (Microsoft Corporation - WDDM)
   1 Windows App Certification Kit
   2 LLVM* OpenMP* Runtime Library
   2 Microsoft Phishing Protection
   2 Microsoft SQL Server
   2 Microsoft\xae DirectX for Windows\xae
   2 Windows\xae Search
   3 Internet Explorer
   3 VMware Tools
   4 Microsoft\xae .NET Framework
   5 Microsoft\xae Skype\x99 Media Stack
   5 Microsoft\xae Visual Studio\xae 2013
   5 Time Travel Debugging
  14 VMware SVGA 3D
  48 Microsoft\xae Visual Studio\xae
 737 Microsoft\xae Windows\xae Operating System
*/

private rule pe_unsigned_version {
    condition:
        pe.number_of_signatures != 0
        and console.log(pe.version_info["ProductName"])
}
// finally, we take the results from the above and use it to create a lazy baseline rule 
// we could use this rule to run over windows/system32 to find unsigned binaries of interest that might be unusual

rule pe_unsigned_uncommon_product_name {
    condition:
        pe.number_of_signatures != 0
    and pe.version_info["ProductName"] != "Herramienta de eliminaci\xf3n de software malintencionado de Microsoft Windows"
    and pe.version_info["ProductName"] != "International Components for Unicode"
    and pe.version_info["ProductName"] != "Microsoft (R) Windows (R) Operating System"
    and pe.version_info["ProductName"] != "Microsoft Malware Protection"
    and pe.version_info["ProductName"] != "Microsoft ODBC Driver 17.7 for SQL Server"
    and pe.version_info["ProductName"] != "Microsoft OneDrive"
    and pe.version_info["ProductName"] != "Microsoft XML Core Services"
    and pe.version_info["ProductName"] != "Microsoft\xa9 ADAL"
    and pe.version_info["ProductName"] != "SQLite"
    and pe.version_info["ProductName"] != "The curl executable"
    and pe.version_info["ProductName"] != "VMware Guest Authentication"
    and pe.version_info["ProductName"] != "VMware HGFS Provider"
    and pe.version_info["ProductName"] != "VMware SVGA 3D (Microsoft Corporation - WDDM)"
    and pe.version_info["ProductName"] != "Windows App Certification Kit"
    and pe.version_info["ProductName"] != "LLVM* OpenMP* Runtime Library"
    and pe.version_info["ProductName"] != "Microsoft Phishing Protection"
    and pe.version_info["ProductName"] != "Microsoft SQL Server"
    and pe.version_info["ProductName"] != "Microsoft\xae DirectX for Windows\xae"
    and pe.version_info["ProductName"] != "Windows\xae Search"
    and pe.version_info["ProductName"] != "Internet Explorer"
    and pe.version_info["ProductName"] != "VMware Tools"
    and pe.version_info["ProductName"] != "Microsoft\xae .NET Framework"
    and pe.version_info["ProductName"] != "Microsoft\xae Skype\x99 Media Stack"
    and pe.version_info["ProductName"] != "Microsoft\xae Visual Studio\xae 2013"
    and pe.version_info["ProductName"] != "Time Travel Debugging"
    and pe.version_info["ProductName"] != "VMware SVGA 3D"
    and pe.version_info["ProductName"] != "Microsoft\xae Visual Studio\xae"
    and pe.version_info["ProductName"] != "Microsoft\xae Windows\xae Operating System"
}