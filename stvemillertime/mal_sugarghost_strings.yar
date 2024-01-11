// #100daysofYARA
// day 8
// stvemillertime
// simple strings rule from sugarghost
// https://blog.talosintelligence.com/new-sugargh0st-rat/
// ee5982a71268c84a5c062095ce135780b8c2ffb1f266c2799173fb0f7bfdd33e 
// not sure what this is, but seems curious, first used FLOSS to get a dump of interesting strings
/*
+-------------------------------------+
| FLOSS STATIC STRINGS: UTF-16LE (77) |
+-------------------------------------+

%C:\
%4d/%02d/%02d %02d:%02d:%02d
%4.2f GB
%4.2f MB
%4.2f KB
%d Bytes
%s%d%d%d%d%d.log
WinSta0\Default
%sd.%s /c "%s"
open
Software\ODBC
2023.8
default
[Up]
[Num Lock]
[Down]
[Right]
[UP]
[Left]
[PageDown]
[End]
[Del]
[PageUp]
[Home]
[Insert]
[Scroll Lock]
[Print Screen]
[WIN]
[CTRL]
[TAB]
[F12]
[F11]
[F10]
[F9]
[F8]
[F7]
[F6]
[F5]
[F4]
[F3]
[F2]
[F1]
[ESC]
]%s (%4d-%02d-%02d %02d:%02d:%02d)
<Enter>
\WinLog.txt
\WinRAR
\SeShutdownPrivilege
System
Security
Application
\WinRAR\~temp.dat
kernel32.dll
SeDebugPrivilege
DISPLAY
default
winsta0
user32.dll
advapi32.dll
WCVideoCap
#32770
2736<Enter>
 ───────────────────── 
  FLOSS STACK STRINGS  
 ───────────────────── 

kernel32.dll
\system32\cmd.exe /c 

*/

import "pe"

rule mal_sugarghost_ee5982_log_strings_plain {
    meta:
        author = "stvemillertime"
        date = "2024-01-09"
        description = "This looks for odd strings from a sample cited in https://blog.talosintelligence.com/new-sugargh0st-rat/"
        sample = "ee5982a71268c84a5c062095ce135780b8c2ffb1f266c2799173fb0f7bfdd33e"
        // this rule is probably not specific enough for "sugarghost" per se, as it likely references code re-used in other families
        // rule quickly and easily generated using https://yaratoolkit.securitybreak.io/ 
    strings:
        // seen in lots of malware including gh0st, icedid, fastcash, hoplight, lazarus-esque and some modified vnc-ish files too
        // ascii vs wide may vary
        $str1 = "%4.2f GB" ascii wide 
        $str2 = "%4.2f MB" ascii wide
        $str3 = "%4.2f KB" ascii wide
        // the ones above are kinda generic, but this one has been seen alongside the others in some gh0strat samples dating back to 2014
        $str4 = "%d Bytes" ascii wide  
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 10MB and
        2 of them //maybe up this to 3 if you're really keen to be more specific
}
rule mal_sugarghost_ee5982_log_strings_xor {
    meta:
        author = "stvemillertime"
        date = "2024-01-09"
        description = "This looks for odd strings from a sample cited in https://blog.talosintelligence.com/new-sugargh0st-rat/"
        sample = "ee5982a71268c84a5c062095ce135780b8c2ffb1f266c2799173fb0f7bfdd33e"
        // this rule is probably not specific enough for "sugarghost" per se, as it likely references code re-used in other families
        // rule quickly and easily generated using https://yaratoolkit.securitybreak.io/ 
    strings:
        // seen in lots of malware including gh0st, icedid, fastcash, hoplight, lazarus-esque and some modified vnc-ish files too
        // ascii vs wide may vary
        $str1 = "%4.2f GB" xor (0x01-0xff)
        $str2 = "%4.2f MB" xor (0x01-0xff)
        $str3 = "%4.2f KB" xor (0x01-0xff)
        // the ones above are kinda generic, but this one has been seen alongside the others in some gh0strat samples dating back to 2014
        $str4 = "%d Bytes" xor (0x01-0xff)
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 10MB and
        2 of them //maybe up this to 3 if you're really keen to be more specific
}
rule mal_sugarghost_ee5982_log_strings_b64 {
    meta:
        author = "stvemillertime"
        date = "2024-01-09"
        description = "This looks for odd strings from a sample cited in https://blog.talosintelligence.com/new-sugargh0st-rat/"
        sample = "ee5982a71268c84a5c062095ce135780b8c2ffb1f266c2799173fb0f7bfdd33e"
        // this rule is probably not specific enough for "sugarghost" per se, as it likely references code re-used in other families
        // rule quickly and easily generated using https://yaratoolkit.securitybreak.io/ 
    strings:
        // seen in lots of malware including gh0st, icedid, fastcash, hoplight, lazarus-esque and some modified vnc-ish files too
        // ascii vs wide may vary
        $str1 = "%4.2f GB" base64 base64wide
        $str2 = "%4.2f MB" base64 base64wide
        $str3 = "%4.2f KB" base64 base64wide
        // the ones above are kinda generic, but this one has been seen alongside the others in some gh0strat samples dating back to 2014
        $str4 = "%d Bytes" base64 base64wide
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 10MB and
        2 of them //maybe up this to 3 if you're really keen to be more specific
}