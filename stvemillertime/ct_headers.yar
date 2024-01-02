//#100daysofYARA
//day 1
//stvemillertime
//this header check ruleset is meant to help measure sample types in a large corpus
//run at command line to some counting yara ~/ct_headers.yar -r ~/corpusfolder/ | awk  '{print $1}' | sort | uniq -c | sort
//results like
/*
   2 head_7z
   2 head_macho
  14 head_gz
  15 head_html
  62 head_elf
 102 head_jpeg
 125 head_gif
 294 head_mscf
 324 head_rtf
 550 head_doc
1368 head_pkzip
12751 head_png
67575 head_mz
127288 head_z_none_of_the_above
*/

rule head_gz { condition: uint16be(0) == 0x1f8b }
rule head_7z { condition: uint16be(0) == 0x377a }
rule head_mz { condition: uint16be(0) == 0x4d5a }
rule head_pkzip { condition: uint16be(0) == 0x504b }
rule head_html { condition: uint32be(0) == 0x3c68746d }
rule head_gif { condition: uint32be(0) == 0x47494638 }
rule head_kwaj { condition: uint32be(0) == 0x4b57414a }
rule head_mscf { condition: uint32be(0) == 0x4d534346  }
rule head_rar { condition: uint32be(0) == 0x52617221 }
rule head_szdd { condition: uint32be(0) == 0x535a4444 }
rule head_rtf { condition: uint32be(0) == 0x7b5c7274 }
rule head_elf { condition: uint32be(0) == 0x7f454c46 }
rule head_png { condition: uint32be(0) == 0x89504e47 }
rule head_doc { condition: uint32be(0) == 0xd0cf11e0 }
rule head_jpeg { condition: uint32be(0) == 0xffd8ffe0 }
rule head_dex { condition: uint32be(0) == 0x6465780a }
rule head_macho { condition: uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca }
rule head_z_none_of_the_above {
    condition: 
        uint16be(0) == 0x1f8b 
    and uint16be(0) == 0x377a 
    and uint16be(0) != 0x4d5a 
    and uint16be(0) != 0x504b 
    and uint32be(0) != 0x3c68746d
    and uint32be(0) != 0x47494638 
    and uint32be(0) != 0x4b57414a
    and uint32be(0) != 0x4d534346
    and uint32be(0) != 0x52617221
    and uint32be(0) != 0x535a4444
    and uint32be(0) != 0x7b5c7274
    and uint32be(0) != 0x7f454c46
    and uint32be(0) != 0x89504e47
    and uint32be(0) != 0xd0cf11e0
    and uint32be(0) != 0xffd8ffe0
    and uint32be(0) != 0x6465780a
    and uint32(0) != 0xfeedface 
    and uint32(0) != 0xcefaedfe 
    and uint32(0) != 0xfeedfacf 
    and uint32(0) != 0xcffaedfe 
    and uint32(0) != 0xcafebabe 
    and uint32(0) != 0xbebafeca 
}