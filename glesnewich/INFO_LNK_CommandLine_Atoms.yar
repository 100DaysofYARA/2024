rule INFO_LNK_File_Ref_wsf {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference .wsf"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = ".wsf" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_js {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference .js"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = ".js" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_hta {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference .hta"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = ".hta" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_vbscript {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference vbscript"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "vbscript" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_javascript {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference javascript"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "javascript" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_7z {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference 7z"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "7z" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_java {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference java"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "java" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_py {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference .py"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = ".py" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_certutil {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference certutil"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "certutil" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_msbuild {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference msbuild"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "msbuild" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_curl {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference curl"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "curl" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_regsvr {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference regsvr"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "regsvr" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_scriptrunner {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference scriptrunner"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "scriptrunner" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_registerocx {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference registerocx"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "registerocx" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_advpackdll {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference advpack.dll"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "advpack.dll" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_shellexec {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference shellexec"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "shellexec" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_set {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference set"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "set" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_exit {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference exit"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "exit" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_copy {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference copy"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "copy" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_xcopy {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference xcopy"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "xcopy" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_echo {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference echo"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "echo" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_findstr {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference findstr"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "findstr" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_call {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference call"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "call" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_attrib {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference attrib"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "attrib" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_cls {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference cls"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "cls" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_rem {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference rem"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "rem" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_goto {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference goto"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "goto" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_msg {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference msg"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "msg" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_app {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference --app="
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "--app=" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_package {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference -package"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "-package" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_getcontent {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference get-content"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "get-content" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_odbcconf {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference odbcconf"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "odbcconf" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_rsp {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference .rsp"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = ".rsp" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_sleep {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference sleep"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "sleep" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_taskkill {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference taskkill"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "taskkill" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_pcalua {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference pcalua"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "pcalua" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_expand {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference expand"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "expand" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_conhost {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference conhost"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "conhost" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_mount {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference mount"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "mount" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_unblock_file {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference unblock-file"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "unblock-file" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_expand_archive {
    meta:
        author = "Greg Lesnewich stolen inspo from @cbecks_2"
        description = "identify LNK with commandlines that reference expand-archive"
        date = "2024-01-31"
        version = "1.0"
        DaysOfYara = "31/100"
    strings:
        $ = "expand-archive" wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}
