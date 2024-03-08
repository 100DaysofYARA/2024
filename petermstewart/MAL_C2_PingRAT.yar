rule MAL_PingRAT_client_strings {
    meta:
        description = "Matches strings found in the PingRAT client binary and source code."
        last_modified = "2024-03-08"
        author = "@petermstewart"
        DaysofYara = "68/100"
        sha256 = "51bcb9d9b2e3d8292d0666df573e1a737cc565c0e317ba18cb57bd3164daa4bf"
        ref = "https://github.com/umutcamliyurt/PingRAT"

    strings:
        $a1 = "(Virtual) Network Interface (e.g., eth0)"
        $a2 = "Destination IP address"
        $a3 = "[+] ICMP listener started!"
        $b1 = "golang.org/x/net/icmp"
        $b2 = "golang.org/x/net/ipv4"
        $b3 = "os/exec"

    condition:
        all of them
}
