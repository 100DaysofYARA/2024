import "pe"

rule PE_import_call_xref {
    meta:
        author = "@captainGeech42"
        description = "Look at PE x86 function call and validate the right import is called."
        date = "2024-01-07"
        version = "1"
        DaysofYARA = "7/100"
        hash = "6d0794f5e7ddac69d10c68ec0c6ae3744a1886bec4917e376b7d3a6078d1a410"
    strings:
        $c1 = {
            // .text:100025C6 57                     push    edi             ; dwFlags
            57
            // .text:100025C7 6A 03                  push    3               ; dwService
            6a03
            // .text:100025C9 57                     push    edi             ; lpszPassword
            57
            // .text:100025CA 57                     push    edi             ; lpszUserName
            57
            // .text:100025CB FF 75 0C               push    dword ptr [ebp+nServerPort] ; nServerPort
            ff75??
            // .text:100025CE FF 75 08               push    [ebp+lpszServerName] ; lpszServerName
            ff75??
            // .text:100025D1 FF 35 00 A6 03 10      push    hInternet       ; hInternet
            ff3500[3]
            // .text:100025D7 FF 15 88 82 02         call    ds:InternetConnectA
            ff15

            // last 3 bytes are the .idata rva of the imported function
            // not entirely sure what 15 is... will be doing another one of these
        }
    condition:
        uint16(0) == 0x5a4d and
        uint32(uint32(0x3c)) == 0x00004550 and
        for any imp in pe.import_details : (
            imp.library_name == "WININET.dll" and
            for any func in imp.functions : (
                func.name == "InternetConnectA" and
                uint32(@c1+!c1)&0xffffff == func.rva
            )
        )
}