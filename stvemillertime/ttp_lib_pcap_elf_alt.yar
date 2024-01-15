import "elf"
rule ttp_lib_pcap_elf_alt : ttp {
    meta: 
        author = "stvemillertime"
        note = "usually a pretty good idea to look for executables with pcap functionality, try to tune out some legit stuff"
        desc = "elfs with pcap_ function strings, may indicate use of libpcap"
        ref = "3f26a13f023ad0dcd7f2aa4e7771bba74910ee227b4b36ff72edc5f07336f115" //seaspy
        ref = "427a0860365f15c1408708c2d6ed527e4e12ad917a1fa111d190c6601148a1eb" //messagetap
        ref = "acd07de34cc15f49fd919dc18e695632a08a132fcfc4e9b6292e1a0d45e953e5" //ext4?
        ref = "8a0a9740cf928b3bd1157a9044c6aced0dfeef3aa25e9ff9c93e113cbc1117ee" //fontonlake
    strings:
        $a = "pcap_" nocase
        $b = "pcap_" xor(0x01-0xff)
        $c = "pcap_" base64 base64wide
    condition:
            elf.type == elf.ET_EXEC 
            // if you cant use elf module, try
            // uint32be(0) == 0x7f454c46 and (uint16be(0x10) == 0x0002 or uint8be(0x10) == 0x02)
        and #a + #b + #c > 1
}

/*
ttp_lib_pcap_elf_alt /Users/steve/vx//x_apt/2022/2022.05.07 - BPFDoor - an active Chinese global surveillance tool/Samples/dc8346bf443b7b453f062740d8ae8d8d7ce879672810f4296158f90359dcae3a
ttp_lib_pcap_elf_alt /Users/steve/vx//x_apt/2019/2019.10.31 - Messagetap -  Who’s Reading Your Text Messages/Samples/8D3B3D5B68A1D08485773D70C186D877
ttp_lib_pcap_elf_alt /Users/steve/vx//x_apt/2021/2021.10.19 - A Roaming Threat to Telecommunications Companies/Samples/1852473ca6a0b5d945e989fb65fa481452c108b718f0f6fd7e8202e9d183e707
ttp_lib_pcap_elf_alt /Users/steve/vx//x_apt/2021/2021.10.11 - ESET FontOnLake/Samples/BFCC4E6628B63C92BC46219937EA7582EA6FBB41
ttp_lib_pcap_elf_alt /Users/steve/vx//x_apt/2020/2020.04.28 - Outlaw is Back, a New Crypto-Botnet Targets European Organizations/Samples/d6c230344520dfc21770300bf8364031e10758d223e8281e2b447c3bf1c43d2b
ttp_lib_pcap_elf_alt /Users/steve/vx//x_apt/2020/2020.04.28 - Outlaw is Back, a New Crypto-Botnet Targets European Organizations/Samples/99fa6e718f5f54b1c8bf14e7b73aa0cda6fe9793a958bd4e0a12916755c1ca93
ttp_lib_pcap_elf_alt /Users/steve/vx//x_apt/2020/2020.02.10 - Outlaw Updates/Samples/620635aa9685249c87ead1bb0ad25b096714a0073cfd38a615c5eb63c3761976
ttp_lib_pcap_elf_alt /Users/steve/vx//x_apt/2018/2018.08.16 - Chinese Cyberrespionage Tshinghua University/Samples/acd07de34cc15f49fd919dc18e695632a08a132fcfc4e9b6292e1a0d45e953e5
ttp_lib_pcap_elf_alt /Users/steve/vx//x_apt/2018/2018.08.16 - Chinese Cyberrespionage Tshinghua University/Samples/d08de00e7168a441052672219e717957
ttp_lib_pcap_elf_alt /Users/steve/vx//passive_backdoors/apt41-messagetap-427a0860365f15c1408708c2d6ed527e4e12ad917a1fa111d190c6601148a1eb
ttp_lib_pcap_elf_alt /Users/steve/vx//passive_backdoors/seaspy-unc4841-3f26a13f023ad0dcd7f2aa4e7771bba74910ee227b4b36ff72edc5f07336f115
*/