rule MAL_PE_SHADOWPAD_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to find POISONPLUG DLLs."

        DaysofYARA  = "25/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-31"
        version     = "1.0"

        hash = "efda9964cc50d05f1caca65de0c7c0ea7393935028f39be32e34a0b351f0d946"
        hash = "8b3dd9df1275b9e6d05a88b93b7f1355b0dd666955e26078c168f35cfe1c8354"
        hash = "be2ea86af841a647da131bb6a9c1b428a8d0b9b539592d67c73f3d11095c4a91"
        hash = "168a82871b19d4eee6818e6a6628ebd6181af6878b02b74a6f54792258451b82"
        hash = "1e394ad81c7ddbc99360583959f4fbfc6685f174ba47970341d4005b9590655f"

    strings:
        $ = {89056C2F02004805000B00008BCD890D422F0200483BD073454883C20948834AF7FF66C742FF000A4489720366C7422F000AC642310A4489724744887243488B052D2F02004883C258488D4AF74805000B0000483BC872C58B0DF82E020066443974}

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and uint16(uint32(0x3C)+0x18) == 0x20b
        and (uint16(uint32(0x3C)+0x16) & 0x2000) == 0x2000
        and all of them
}
