import "lnk"

rule MAL_LNK_MAC_ADDRESS_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule matching on LNK files based on the host MAC address."
        reference   = "https://blog.nviso.eu/2017/04/04/tracking-threat-actors-through-lnk-files/"

        DaysofYARA  = "5/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-05"
        version     = "1.0"

    condition:
        lnk.is_lnk
        and lnk.has_tracker_data == 1
        and (
            lnk.tracker_data.droid_birth_file_identifier endswith "\x00PV\xae\x90\x0e"
            or lnk.tracker_data.droid_file_identifier endswith "\x00PV\xae\x90\x0e"
        )
}
