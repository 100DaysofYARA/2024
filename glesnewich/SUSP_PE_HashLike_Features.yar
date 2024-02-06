import "pe"

rule SUSP_PE_HashLike_DLL_Name_MD5
{
    meta:
        author = "Greg Lesnewich"
        description = "looking for hashes in weird places"
        date = "2024-02-05"
        version = "1.0"
        DaysOfYara = "36/100"

    condition:
        pe.dll_name matches /[a-z0-9A-Z]{32}.dll/
}

rule SUSP_PE_HashLike_DLL_Name_SHA256
{
    meta:
        author = "Greg Lesnewich"
        description = "looking for hashes in weird places"
        date = "2024-02-05"
        version = "1.0"
        DaysOfYara = "36/100"

    condition:
        pe.dll_name matches /[a-z0-9A-Z]{64}.dll/
}

rule SUSP_PE_HashLike_DLL_Name_SHA1
{
    meta:
        author = "Greg Lesnewich"
        description = "looking for hashes in weird places"
        date = "2024-02-05"
        version = "1.0"
        DaysOfYara = "36/100"

    condition:
        pe.dll_name matches /[a-z0-9A-Z]{40}.dll/
}

rule SUSP_PE_HashLike_Resource_Name_MD5
{
    meta:
        author = "Greg Lesnewich"
        description = "looking for hashes in weird places"
        date = "2024-02-05"
        version = "1.0"
        DaysOfYara = "36/100"

    condition:
        for any rsrc in pe.resources:
        (
            rsrc.name_string matches /([a-z0-9A-Z]{1}\x00){32}/ or
            rsrc.type_string matches /([a-z0-9A-Z]{1}\x00){32}/
        )
}

rule SUSP_PE_HashLike_Resource_Name_SHA1
{
    meta:
        author = "Greg Lesnewich"
        description = "looking for hashes in weird places"
        date = "2024-02-05"
        version = "1.0"
        DaysOfYara = "36/100"

    condition:
        for any rsrc in pe.resources:
        (
            rsrc.name_string matches /([a-z0-9A-Z]{1}\x00){40}/ or
            rsrc.type_string matches /([a-z0-9A-Z]{1}\x00){40}/
        )
}

rule SUSP_PE_HashLike_Resource_Name_SHA256
{
    meta:
        author = "Greg Lesnewich"
        description = "looking for hashes in weird places"
        date = "2024-02-05"
        version = "1.0"
        DaysOfYara = "36/100"

    condition:
        for any rsrc in pe.resources:
        (
            rsrc.name_string matches /([a-z0-9A-Z]{1}\x00){64}/ or
            rsrc.type_string matches /([a-z0-9A-Z]{1}\x00){64}/
        )
}
