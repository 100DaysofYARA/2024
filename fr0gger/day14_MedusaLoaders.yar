rule Loader_Medusa_Driver_ASMGuard
{
    meta:
        author = "Thomas Roccia | @fr0gger_"
        date = "2024-01-14"
        description = "100DaysOfYara | Medusa Ransomware driver loader hunting based on report | no hash"
        source = "https://unit42.paloaltonetworks.com/medusa-ransomware-escalation-new-leak-site/"
    strings:
        $fakeUPX = { 30 34 0A 55 50 58 21 00 5F 30 78 30 30 31 34 39 33 32 }
        $str1 = "ASM_Guard" fullword
    condition:
        uint16(0) == 0x5a4d and
        filesize < 500KB and
        $fakeUPX and $str1
}