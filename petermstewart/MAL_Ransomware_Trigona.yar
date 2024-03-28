rule MAL_Trigona_strings {
    meta:
        description = "Matches strings found in Trigona ransomware samples."
        last_modified = "2024-03-28"
        author = "@petermstewart"
        DaysofYara = "88/100"
        sha256 = "fb128dbd4e945574a2795c2089340467fcf61bb3232cc0886df98d86ff328d1b"
        sha256 = "d743daa22fdf4313a10da027b034c603eda255be037cb45b28faea23114d3b8a"

    strings:
        $a1 = "how_to_decrypt" wide
        $b1 = "nolocal"
        $b2 = "nolan"
        $b3 = "shutdown"
        $b4 = "random_file_system"
        $b5 = "fullmode"
        $b6 = "erasemode"
        $b7 = "network_scan_finished"
        $b8 = "is_testing"

    condition:
        uint16(0) == 0x5a4d and
        $a1 and
        4 of ($b*)
}
