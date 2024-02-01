rule APT_EQGRP_SUCTIONCHAR_BVP47_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Code overlap between EQGRP SUCTIONCHAR and BVP47."

        reference   = "https://github.com/x0rz/EQGRP"
        reference   = "https://www.virustotal.com/gui/collection/43334ea6fbd9e71384d7c3c299f6a7472b35d6930b95caedd25764f09513ca60"
        reference   = "https://www.virustotal.com/gui/collection/alienvault_62165a9098875d0f12e0d0a8"

        DaysofYARA  = "23/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-31"
        version     = "1.0"

        hash        = "7989032a5a2baece889100c4cfeca81f1da1241ab47365dad89107e417ce7bac"
        hash        = "81479e151a090288793a4c449f70a94a7a285dfd86178f2d407d1915536c0105"
        hash        = "df79815b6fa50dfdd626be2d20a9e5d0741e4ceed4fd49da9f62ef4ecbc127a7"

    strings:
        $ = {3C2489D1BAA12FB844C1E90669C1E8030000034DE029C369DB40420F006945E4E803000001C389D8F7EA89D8C1F81FC1FA1C29C28D0C0A69D200CA9A3B8D45D0894D}

    condition:
        uint32(0) == 0x464c457f
        and all of them
}
