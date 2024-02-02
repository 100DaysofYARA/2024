rule APT_EQGRP_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to detect shared event name string across samples Observed in at least PEDDLECHEAP."
        reference   = "https://docs.google.com/spreadsheets/d/1-iFBlQH-41vDWv3QXiPb2s9RnWvRKojCAalAOCAKjfk/edit?pli=1#gid=0"

        DaysofYARA  = "27/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-31"
        version     = "1.0"

        hash        = "aa32b47a6019ea27a86a3267908e9a9dda2e8df549d9549539ff8913c8186a55"
        hash        = "0a5c21bb343199c3fc9df48e8bcfe185f235ac0d292dd9f45225321359a97f44"
        hash        = "2931c14bac0f48b2def6a8160d86b0ce9ee2ff78e70a28e73801ea5d77f29aa9"

    strings:
        $ = "*.pq-r)>w134k^="

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and uint16(uint32(0x3C)+0x18) == 0x10b
        and all of them
        and filesize < 1MB
}
