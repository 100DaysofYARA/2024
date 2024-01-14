// #100daysofYARA
// day 13
// stvemillertime
// looking at OT/ICS tailored malware
// these are legit IEC104 protocol strings, but might show up in some malware too


/*

ttp_toolmark_iec104_s_dt /Users/steve/vx//x_apt/2022/2022.04.12 - Cyberattack by Sandworm Group (UAC-0082) on energy facilities of Ukraine using malicious programs INDUSTROYER2 and CADDYWIPER/Samples/d69665f56ddef7ad4e71971f06432e59f1510a7194386e5f0e8926aea7b88e00
0x8654:$b6: STARTDT
0x8660:$b6: STARTDT
0x866c:$s2: STOPDT
0x8678:$s2: STOPDT
ttp_toolmark_iec104_s_dt /Users/steve/vx//x_apt/2022/2022.04.27 - Industroyer2 - Nozomi Networks Labs Analyzes the IEC 104 Payload/Samples/d69665f56ddef7ad4e71971f06432e59f1510a7194386e5f0e8926aea7b88e00
0x8654:$b6: STARTDT
0x8660:$b6: STARTDT
0x866c:$s2: STOPDT
0x8678:$s2: STOPDT
ttp_toolmark_iec104_s_dt /Users/steve/vx//x_apt/2022/2022.04.27 - Industroyer2 - Nozomi Networks Labs Analyzes the IEC 104 Payload/Samples/7907dd95c1d36cf3dc842a1bd804f0db511a0f68f4b3d382c23a3c974a383cad
0x1d408:$b6: STARTDT
0x1d414:$b6: STARTDT
0x1d420:$s2: STOPDT
0x1d42c:$s2: STOPDT
ttp_toolmark_iec104_s_dt /Users/steve/vx//x_apt/2017/2017.06.12 - CRASHOVERRIDE - Analysis of the Threat to Electric Grid Operations/Samples/94488f214b165512d2fc0438a581f5c9e3bd4d4c
0x1d408:$b6: STARTDT
0x1d414:$b6: STARTDT
0x1d420:$s2: STOPDT
0x1d42c:$s2: STOPDT
ttp_toolmark_iec104_s_dt /Users/steve/vx//ics_tailored/industroyer-7907dd95c1d36cf3dc842a1bd804f0db511a0f68f4b3d382c23a3c974a383cad
0x1d408:$b6: STARTDT
0x1d414:$b6: STARTDT
0x1d420:$s2: STOPDT
0x1d42c:$s2: STOPDT
ttp_toolmark_iec104_s_dt /Users/steve/vx//ics_tailored/cosmicenergy-lightwork-740e0d2fba550308344b2fb0e5ecfebdd09329bdcfaa909d3357ad4fe5552532
0x12846:$b6: STARTDT
0x1d1fa:$b6: STARTDT


*/

import "pe"
rule ttp_toolmark_iec104_s_dt {
    meta: 
        author = "stvemillertime"
        desc = "This rule looks for IEC104 protocol strings, often seen in anything that has IEC104 compatibility. Will be noisy on ICS/OT related files. Might find some malware, just maybe."
        ref = "740e0d2fba550308344b2fb0e5ecfebdd09329bdcfaa909d3357ad4fe5552532" // INDUSTROYER?
        ref = "7907dd95c1d36cf3dc842a1bd804f0db511a0f68f4b3d382c23a3c974a383cad" // INDUSTROYER
        ref = "d69665f56ddef7ad4e71971f06432e59f1510a7194386e5f0e8926aea7b88e00" // ?
    strings:
        $a1 = "startdt" nocase ascii wide fullword
        $a2 = "stopdt" nocase ascii wide fullword
    condition:
            uint16be(0) == 0x4d5a
        and pe.number_of_signatures == 0
        and all of them
}