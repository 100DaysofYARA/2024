rule PUP_Cloudflare_tunnel_strings {
    meta:
        description = "Matches strings found in Cloudflare Tunnel client binaries, often abused by threat actors."
        last_modified = "2024-03-21"
        author = "@petermstewart"
        DaysofYara = "81/100"
        sha256 = "92ec16e1226249fcb7f07691a3e6d8fbb0f4482c786c4cff51b4ecab3e1a3a86"
        sha256 = "05cead663a846504ca20d73abede2e97c7cae59b3975fb6dbe89840d57abc5d7"
        ref = "https://github.com/cloudflare/cloudflared"

    strings:
        $a1 = "cloudflared connects your machine or user identity to Cloudflare's global network"
        $a2 = "Use Cloudflare Tunnel to expose private services to the Internet or to Cloudflare connected private users."
        $a3 = "[global options] [command] [command options]"

    condition:
        all of them
}
