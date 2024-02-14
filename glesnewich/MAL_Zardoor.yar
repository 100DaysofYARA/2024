import "pe"

rule MAL_Zardoor_Export_MainEntry {

    meta:
        description = "track a consistent export function in combination with tool version info, used by the Zardoor dropper and its embedded backdoor tools"
        author = "Greg Lesnewich"
        date = "2024-02-11"
        version = "1.0"
        reference = "https://blog.talosintelligence.com/new-zardoor-backdoor/"
        DaysOfYara = "42/100"
        hash = "0058d495254bf3760b30b5950d646f9a38506cef8f297c49c3b73c208ab723bf"
        hash = "a99a9f2853ff0ca5b91767096c7f7e977b43e62dd93bde6d79e3407bc01f661d"
        hash = "d267e2a6311fe4e2dfd0237652223add300b9a5233b555e131325a2612e1d7ef"

    condition:
        pe.exports("MainEntry")
        and pe.rich_signature.toolid(241,40116) // C++ Libary UTC1810_CPP from Visual Studio 2013 12.10"
        and pe.rich_signature.toolid(243,40116) // C++ Libary UTC1810_CPP from Visual Studio 2013 12.10"
        and pe.rich_signature.toolid(242,40116) // C++ Libary UTC1810_CPP from Visual Studio 2013 12.10"
        and pe.rich_signature.toolid(259,24123) // C Libary UTC1900_CPP from Visual Studio 2015 14.0.3 RC
        and pe.rich_signature.toolid(261,24123) // C Libary UTC1900_CPP from Visual Studio 2015 14.0.3 RC
        and pe.rich_signature.toolid(260,24123) // C Libary UTC1900_CPP from Visual Studio 2015 14.0.3 RC
        and pe.rich_signature.toolid(147,30729) // Import Library IMPLIB900 from Visual Studio 2008 9.0
        and pe.rich_signature.toolid(1,0) // Visual Studio Resource
        and pe.rich_signature.toolid(265,24215) // Linker from Visual Studio 2008 9.0
        and pe.rich_signature.toolid(256,24215) // Linker from Visual Studio 2008 9.0
        and pe.rich_signature.toolid(255,24210) // CVTRES1400 from Visual Studio 2015 14.0.3
        and pe.rich_signature.toolid(258,24215) // Linker from Visual Studio 2008 9.0
}


rule MAL_Zardoor_Dropper_Resource_TypeString_CODER
{
    meta:
        author = "Greg Lesnewich"
        description = "look for weird typestring included in Zardoor loader called CODER"
        date = "2024-02-12"
        version = "1.0"
        reference = "https://blog.talosintelligence.com/new-zardoor-backdoor/"
        DaysOfYara = "43/100"
        hash = "a99a9f2853ff0ca5b91767096c7f7e977b43e62dd93bde6d79e3407bc01f661d"

    condition:
        for any rsrc in pe.resources:
            (rsrc.type_string == "C\x00O\x00D\x00E\x00R\x00") //CODER
}
