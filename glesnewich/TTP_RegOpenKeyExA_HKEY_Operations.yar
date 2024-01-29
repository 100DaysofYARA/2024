import "pe"

rule TTP_RegOpenKeyExA_HKEY_LOCAL_MACHINE_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_LOCAL_MACHINE keys (const 0x80000002) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 02 00 00 80          push    0x80000002 {var_15c_1}  {0x80000002} //HKEY_LOCAL_MACHINE
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6802000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}



rule TTP_RegOpenKeyExA_HKEY_LOCAL_MACHINE_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_LOCAL_MACHINE keys (const 0x80000002) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:

        $reg_open_key_call = {02 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}


rule TTP_RegOpenKeyExA_HKEY_CLASSES_ROOT_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_CLASSES_ROOT keys (const 0x80000000) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 00 00 00 80          push    0x80000000 {var_15c_1}  {0x80000000} //HKEY_CLASSES_ROOT
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6800000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_CLASSES_ROOT_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_CLASSES_ROOT keys (const 0x80000000) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        $reg_open_key_call = {00 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}


rule TTP_RegOpenKeyExA_HKEY_CURRENT_USER_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_CURRENT_USER keys (const 0x80000001) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 01 00 00 80          push    0x80000001 {var_15c_1}  {0x80000001} //HKEY_CURRENT_USER
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6801000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_CURRENT_USER_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_CURRENT_USER keys (const 0x80000001) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:

        $reg_open_key_call = {01 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}


rule TTP_RegOpenKeyExA_HKEY_USERS_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_USERS keys (const 0x80000003) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 01 00 00 80          push    0x80000003 {var_15c_1}  {0x80000003} //HKEY_USERS
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6803000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_USERS_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_USERS keys (const 0x80000003) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:

        $reg_open_key_call = {03 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}


rule TTP_RegOpenKeyExA_HKEY_PERFORMANCE_DATA_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_PERFORMANCE_DATA keys (const 0x80000004) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 01 00 00 80          push    0x80000004 {var_15c_1}  {0x80000004} //HKEY_PERFORMANCE_DATA
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6804000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_PERFORMANCE_DATA_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_PERFORMANCE_DATA keys (const 0x80000004) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:

        $reg_open_key_call = {04 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}
rule TTP_RegOpenKeyExA_HKEY_CURRENT_CONFIG_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_CURRENT_CONFIG keys (const 0x80000005) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 05 00 00 80          push    0x80000005 {var_15c_1}  {0x80000005} //HKEY_CURRENT_CONFIG
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6805000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_CURRENT_CONFIG_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_CURRENT_CONFIG keys (const 0x80000005) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:

        $reg_open_key_call = {05 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}



rule TTP_RegOpenKeyExA_HKEY_DYN_DATA_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_DYN_DATA keys (const 0x80000006) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 06 00 00 80          push    0x80000006 {var_15c_1}  {0x80000006} //HKEY_DYN_DATA
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6806000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_DYN_DATA_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_DYN_DATA keys (const 0x80000006) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:

        $reg_open_key_call = {06 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}


rule TTP_RegOpenKeyExA_HKEY_PERFORMANCE_TEXT_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_PERFORMANCE_TEXT keys (const 0x80000050) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 50 00 00 80          push    0x80000050 {var_15c_1}  {0x80000050} //HKEY_PERFORMANCE_TEXT
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6850000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_PERFORMANCE_TEXT_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_PERFORMANCE_TEXT keys (const 0x80000050) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:

        $reg_open_key_call = {50 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_PERFORMANCE_NLSTEXT_tight {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_PERFORMANCE_NLSTEXT keys (const 0x80000060) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:
        // 1000fdf8  68 60 00 00 80          push    0x80000060 {var_15c_1}  {0x80000060} //HKEY_PERFORMANCE_NLSTEXT
        // 1000fdfd  ff 15 08 80 02 10       call    dword [RegOpenKeyExA]

        $reg_open_key_call = {6860000080ff15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}

rule TTP_RegOpenKeyExA_HKEY_PERFORMANCE_NLSTEXT_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_PERFORMANCE_NLSTEXT keys (const 0x80000060) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:

        $reg_open_key_call = {60 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva // only match last 5 nibbles
                    )
                )
            )
        )
}
