rule MAL_Mythic_Apollo_strings {
    meta:
        description = "Matches strings found in samples of the Windows Apollo agent used by the open-source Mythic framework."
        last_modified = "2024-02-06"
        author = "@petermstewart"
        DaysofYara = "37/100"
        sha256 = "bf3d47335b7c10f655987cfdefecdb2856c0ac90f2f1cedcd67067760a80aa98"
        sha256 = "67b2c1c5d96a7c70b2bc111ace08b35e0db63bef40534dc50a692d46f832d61a"
        ref = "https://github.com/MythicAgents/apollo"

    strings:
        $pdb = "Apollo.pdb"
        $a = "ApolloInterop"
        $b1 = "ApolloTrackerUUID"
        $b2 = "Apollo.Peers.SMB"
        $b3 = "Apollo.Peers.TCP"
        $b4 = "C2ProfileData"
        $b5 = "mythicFileId"
        $b6 = "IMythicMessage"
        $b7 = ".MythicStructs"
        $b8 = ".ApolloStructs"
        $b9 = "Apollo.Api"
        $b10 = "ApolloLogonInformation"

    condition:
        uint16(0) == 0x5a4d and
        ($pdb and #a > 15) or
        ($a and (6 of ($b*)))
}

rule MAL_Mythic_Apfell_strings {
    meta:
        description = "Matches strings found in samples of the macOS Apfell Javascript agent used by the open-source Mythic framework."
        last_modified = "2024-02-07"
        author = "@petermstewart"
        DaysofYara = "38/100"
        sha256 = "8962ad7c608962c637637b9d3aef101a87cfb71873210046d5a49cfa6f47a712"
        ref = "https://github.com/MythicAgents/apfell"

    strings:
        $a1 = "C2.checkin(ip,apfell.pid,apfell.user,ObjC.unwrap(apfell.procInfo.hostName),apfell.osVersion,"
        $a2 = "return this.interval + (this.interval * (this.get_random_int(this.jitter)/100));"
        $a3 = "let info = {'ip':ip,'pid':pid,'user':user,'host':host,'uuid':apfell.uuid, \"os\":os, \"architecture\": arch, \"domain\": domain, \"action\": \"checkin\"};"
        $b1 = "\"user\": apfell.user,"
        $b2 = "\"fullName\": apfell.fullName,"
        $b3 = "\"ips\": apfell.ip,"
        $b4 = "\"hosts\": apfell.host,"
        $b5 = "\"environment\": apfell.environment,"
        $b6 = "\"uptime\": apfell.uptime,"
        $b7 = "\"args\": apfell.args,"
        $b8 = "\"pid\": apfell.pid,"
        $b9 = "\"apfell_id\": apfell.id,"
        $b10 = "\"payload_id\": apfell.uuid"
        $c1 = "-IMPLANT INFORMATION-"
        $c2 = "-Base C2 INFORMATION-"
        $c3 = "-RESTFUL C2 mechanisms -"
        $c4 = "- INSTANTIATE OUR C2 CLASS BELOW HERE IN MAIN CODE-"
        $c5 = "-SHARED COMMAND CODE -"
        $c6 = "-GET IP AND CHECKIN -"
        $c7 = "-MAIN LOOP -"
        $c8 = "//To create your own C2, extend this class and implement the required functions"
        $c9 = "//gets a file from the apfell server in some way"
        $c10 = "//there is a 3rd slash, so we need to splice in the port"
        $c11 = "//generate a time that's this.interval += (this.interval * 1/this.jitter)"
        $c12 = "// now we need to prepend the IV to the encrypted data before we base64 encode and return it"
        $c13 = "// Encrypt our initial message with sessionID and Public key with the initial AES key"
        $c14 = "//depending on the amount of data we're sending, we might need to chunk it"
        $c15 = "//if we do need to decrypt the response though, do that"
        $c16 = "// don't spin out crazy if the connection fails"
        $c17 = "// always round up to account for chunks that are < chunksize;"
        $c18 = "//simply run a shell command via doShellScript and return the response"
        $c19 = "//  so I'll just automatically fix this so it's not weird for the operator"
        $c20 = "//  params should be {\"cmds\": \"cmd1 cmd2 cmd3\", \"file_id\": #}"

    condition:
        (all of ($a*) and 8 of ($b*)) or
        (15 of ($c*))
}

rule MAL_Mythic_Athena_strings {
    meta:
        description = "Matches strings found in samples of the Athena agent used by the open-source Mythic framework."
        last_modified = "2024-02-08"
        author = "@petermstewart"
        DaysofYara = "39/100"
        sha256 = "8075738035ac361d50db2c2112a539acc3f1ad4d4ed5f971b2e18c687fc029da"
        sha256 = "ce66c7487e56722f34e5fd0fea167f9c562a0bbb0d13128b0313e4d3eabff697"
        ref = "https://github.com/MythicAgents/athena"

    strings:
        $a = "Athena"
        $b1 = "\"Athena.Commands\":"
        $b2 = "\"Athena.Forwarders.SMB\":"
        $c1 = "\"cat\":"
        $c2 = "\"drives\":"
        $c3 = "\"get-clipboard\":"
        $c4 = "\"get-localgroup\":"
        $c5 = "\"get-sessions\":"
        $c6 = "\"get-shares\":"
        $c7 = "\"hostname\":"
        $c8 = "\"ifconfig\":"
        $c9 = "\"ls\":"
        $c10 = "\"mkdir\":"
        $c11 = "\"mv\":"
        $c12 = "\"ps\":"
        $c13 = "\"pwd\":"
        $c14 = "\"rm\":"
        $c15 = "\"shell\":"
        $c16 = "\"shellcode\":"
        $c17 = "\"whoami\":"

    condition:
        uint16(0) == 0x5a4d and
        #a > 100 and
        all of ($b*) and
        8 of ($c*)
}
