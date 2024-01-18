// yara-x

import "lnk"

rule Hunting_LNK_powershell_encoded {
    meta:
        author = "@captainGeech42"
        description = "Look for LNK files that execute powershell with a base64 encoded command. Requires yara-x"
        date = "2024-01-15"
        version = "1"
        DaysofYARA = "15/100"
        hash = "ccbc8330ca084289cb472ad6f22f39e5177ba66119a5bf6f45cd92c28d976799"
    condition:
        lnk.is_lnk and
        (
            lnk.relative_path icontains "powershell" and
            lnk.cmd_line_args icontains "-e"
        ) or (
            lnk.cmd_line_args istartswith "powershell" and
            lnk.cmd_line_args icontains " -e"
        )
}