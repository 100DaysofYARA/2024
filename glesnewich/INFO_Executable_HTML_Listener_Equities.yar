import "pe"

rule INFO_PE_Contains_404_Title
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-16"
        version = "1.0"
        description = "track executable files with equities related to a 404 response page"
        DaysofYARA = "16/100"

    strings:
        $ = "<title>404" ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}

rule INFO_PE_Contains_HTML_Page
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-16"
        version = "1.0"
        description = "track executable files with equities related to HTML"
        DaysofYARA = "16/100"

    strings:
        $ = "<!DOCTYPE" ascii wide
        $ = "<html>" ascii wide
        $ = "<title>" ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}

rule INFO_PE_Contains_NotFound
{
    strings:
        $ = "not found.<" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}


rule INFO_ELF_Contains_404_Title
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-16"
        version = "1.0"
        description = "track executable files with equities related to a 404 response page"
        DaysofYARA = "16/100"

    strings:
        $ = "<title>404" ascii wide
    condition:
        uint32be(0) == 0x7F454C46 and all of them
}

rule INFO_ELF_Contains_HTML_Page
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-16"
        version = "1.0"
        description = "track executable files with equities related to HTML"
        DaysofYARA = "16/100"

    strings:
        $ = "<!DOCTYPE" ascii wide
        $ = "<html>" ascii wide
        $ = "<title>" ascii wide
    condition:
        uint32be(0) == 0x7F454C46 and all of them
}




rule INFO_PE_WSARecv_API
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that reference WSARecv, which may be hooked for passive listening"
        DaysofYARA = "17/100"

    strings:
        $ = "WSARecv" ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}

rule INFO_PE_DeviceIOControl_API
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that reference DeviceIOControl, which may be hooked for passive listening"
        DaysofYARA = "17/100"

    strings:
        $ = "DeviceIOControl" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}

//rule INFO_PE_HttpInitialize_API
//{
//    meta:
//        author = "Greg Lesnewich"
//        date = "2024-01-17"
//        version = "1.0"
//        description = "track executable files that reference HttpInitialize, which may be hooked for passive listening"
//        DaysofYARA = "17/100"
//
//    strings:
//        $ = "HttpInitialize" nocase ascii wide
//    condition:
//        uint16be(0) == 0x4d5a and all of them
//}

rule INFO_PE_HttpReceiveHttpRequest_API
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-18"
        version = "1.0"
        description = "track executable files that reference HttpReceiveHttpRequest, which will be used to handle inbound HTTP requests"
        DaysofYARA = "18/100"

    strings:
        $ = "HttpReceiveHttpRequest" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}


rule INFO_PE_HttpSendHttpResponse_API
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-18"
        version = "1.0"
        description = "track executable files that reference HttpSendHttpResponse, which will be used to respond to inbound HTTP requests"
        DaysofYARA = "18/100"

    strings:
        $ = "HttpSendHttpResponse" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}

rule INFO_PE_HttpSendResponseEntityBody_API
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-18"
        version = "1.0"
        description = "track executable files that reference HttpSendResponseEntityBody, which will be used to respond to inbound HTTP requests"
        DaysofYARA = "18/100"

    strings:
        $ = "HttpSendResponseEntityBody" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}




rule INFO_PE_Port_Slash_Combo
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that include small strings that might indicate port usage "
        DaysofYARA = "17/100"

    strings:
        $ = ":80/" ascii wide
        $ = ":443/" ascii wide
        $regex = /\:[0-9]{2,4}\//ascii wide
    condition:
        uint16be(0) == 0x4d5a and any of them
}


rule INFO_PE_WebServer_References_Apache
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that reference the Apache web server, which might be a fake response page to being probed "
        DaysofYARA = "17/100"

    strings:
        $ = "Apache" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}
rule INFO_PE_WebServer_References_Microsoft_IIS
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that reference the Microsoft-IIS web server, which might be a fake response page to being probed "
        DaysofYARA = "17/100"

    strings:
        $ = "Microsoft-IIS" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}
rule INFO_PE_WebServer_References_OpenResty
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that reference the OpenResty web server, which might be a fake response page to being probed "
        DaysofYARA = "17/100"

    strings:
        $ = "OpenResty" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}
rule INFO_PE_WebServer_References_nginx
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that reference the nginx web server, which might be a fake response page to being probed "
        DaysofYARA = "17/100"

    strings:
        $ = "nginx" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}

rule INFO_PE_WebServer_References_LiteSpeed
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that reference the LiteSpeed web server, which might be a fake response page to being probed "
        DaysofYARA = "17/100"

    strings:
        $ = "LiteSpeed" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}


rule INFO_PE_Imports_NDIS_NetworkInterface
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-20"
        version = "1.0"
        description = "track executable files that import NDIS which is a legitimate driver for the network interface controller."
        DaysofYARA = "20/100"

    condition:
        for any imp in pe.import_details:(
            imp.library_name == "NDIS.SYS"
            )
}

rule INFO_PE_Imports_HardwareAbstractionLayer
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-20"
        version = "1.0"
        description = "track executable files that import hardware abstraction layer (HAL) components"
        DaysofYARA = "20/100"

    condition:
        for any s in ("hal.dll","halacpi.dll","halmacpi.dll"):(
            for any imp in pe.import_details:(
                imp.library_name iequals s
        ))
}
