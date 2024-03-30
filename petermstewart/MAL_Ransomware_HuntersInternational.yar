rule MAL_HuntersInternational_strings {
    meta:
        description = "Matches strings found in Hunters International ransomware samples."
        last_modified = "2024-03-30"
        author = "@petermstewart"
        DaysofYara = "90/100"
        sha256 = "c4d39db132b92514085fe269db90511484b7abe4620286f6b0a30aa475f64c3e"

    strings:
        $a1 = "windows_encrypt/src/main.rs"
        $a2 = "skipped, reserve dir"
        $a3 = "skipped, min size:"
        $a4 = "skipped, symlink:"
        $a5 = "skipped, reserved file:"
        $a6 = "skipped, reserved extension:"
        $a7 = "got, dir:"
        $a8 = "encrypting"

    condition:
        uint16(0) == 0x5a4d and
        all of them
}
