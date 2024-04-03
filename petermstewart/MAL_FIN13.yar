rule MAL_FIN13_BLUEAGAVE_PowerShell {
    meta:
        description = "Matches code sample of BLUEAGAVE PowerShell webshell used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-01"
        author = "@petermstewart"
        DaysofYara = "92/100"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "$decode = [System.Web.HttpUtility]::UrlDecode($data.item('kmd'))" ascii wide
        $a2 = "$Out =  cmd.exe /c $decode 2>&1" ascii wide
        $a3 = "$url = 'http://*:" ascii wide

    condition:
        filesize < 5KB and
        all of them
}

rule MAL_FIN13_BLUEAGAVE_Perl {
    meta:
        description = "Matches strings found in BLUEAGAVE Perl webshell used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-02"
        author = "@petermstewart"
        DaysofYara = "93/100"
        ref = "https://www.netwitness.com/wp-content/uploads/FIN13-Elephant-Beetle-NetWitness.pdf"

    strings:
        $a1 = "'[cpuset]';" ascii wide
        $a2 = "$key == \"kmd\"" ascii wide
        $a3 = "SOMAXCONN,"
        $a4 = "(/\\s*(\\w+)\\s*([^\\s]+)\\s*HTTP\\/(\\d.\\d)/)" ascii wide
        $a5 = "s/^\\s+//; s/\\s+$//;" ascii wide

    condition:
        filesize < 5KB and
        all of them
}

rule MAL_FIN13_LATCHKEY {
    meta:
        description = "Matches strings found in LATCHKEY ps2exe loader used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-03"
        author = "@petermstewart"
        DaysofYara = "94/100"
        sha256 = "b23621caf5323e2207d8fbf5bee0a9bd9ce110af64b8f5579a80f2767564f917"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "Unhandeled exception in PS2EXE" wide
        $b1 = "function Out-Minidump" base64wide
        $b2 = "$MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags)" base64wide
        $b3 = "Get-Process lsass | Out-Minidump" base64wide

    condition:
        filesize < 50KB and
        uint16(0) == 0x5a4d and
        all of them
}
