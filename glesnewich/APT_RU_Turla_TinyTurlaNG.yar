import "pe"

rule APT_RU_Turla_TinyTurlaNG_RichHeader {
    meta:
        description = "track TinyTurlaNG based build artifacts & ServiceDLL components"
        author = "Greg Lesnewich"
        date = "2024-02-15"
        version = "1.0"
        reference = "https://blog.talosintelligence.com/tinyturla-next-generation/"
        hash = "d6ac21a409f35a80ba9ccfe58ae1ae32883e44ecc724e4ae8289e7465ab2cf40"
        hash = "267071df79927abd1e57f57106924dd8a68e1c4ed74e7b69403cdcdf6e6a453b"
        DaysOfYARA = "45/100"

    condition:
        pe.exports("ServiceMain")
        and pe.dll_name == "out.dll"
        and pe.rich_signature.toolid(259,27412) == 10 // MASM Visual Studio 2015 14.0
        and pe.rich_signature.toolid(260,27412) == 19 // STDLIB Visual Studio 2015 14.0
        and pe.rich_signature.toolid(261,27412) == 155 //STDLIB Visual Studio 2015 14.0
        and pe.rich_signature.toolid(260,30034) == 14 // STDLIB Visual Studio 2015 14.0
        and pe.rich_signature.toolid(259,30034) == 10 // MASM Visual Studio 2015 14.0
        and pe.rich_signature.toolid(261,30034) >= 70 // STDLIB Visual Studio 2015 14.0
        and pe.rich_signature.toolid(257,27412) >= 6 // IMPORT Visual Studio 2015 14.0
        and pe.rich_signature.toolid(261,30038) >= 7 // STDLIB Visual Studio 2015 14.0
        and pe.rich_signature.toolid(256,30038) == 1 // EXPORT Visual Studio 2015 14.0
        and pe.rich_signature.toolid(255,30038) == 1 // CVTRES Visual Studio 2015 14.0
        and pe.rich_signature.toolid(258,30038) == 1 // LINKER Visual Studio 2015 14.0
}
