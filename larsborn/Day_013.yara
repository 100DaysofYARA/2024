rule Rand_Constants
{
    meta:
        description = "Constant from rand() implementation"
        author = "@larsborn"
        date = "2020-12-13"
        reference = "https://en.wikipedia.org/wiki/Linear_congruential_generator"
        example_hash_msvcrt = "d66d08f27ad113bb55b157af9563989182cda0aa02f693d512d581ad0fd70d1a"
        example_hash_badnews = "f65eeb136e23d06b54b15834ad15d4bcd2cd51af9e8c134da32da02bdcb68996"
        example_hash_alfonso_stealer = "92175f70c2e1472fcb742e9dc4939a48da8ae6f02d0177a2387be4235b0b1b23"
        example_hash_zlob = "00b50968469c9e22f63d2166d9f952a18edb0bc8e7fa5b7816c85ad68f7099c7"
        example_hash_flawed_ammy = "06df4a5fda733594ce5225118badf6747890ec3a37fe2c59854a54622a809814"
        example_hash_hamweq = "4eb33ce768def8f7db79ef935aabf1c712f78974237e96889e1be3ced0d7e619"
        example_hash_matanbuchus = "60f030597c75f9df0f7a494cb5432b600d41775cfe5cf13006c1448fa3a68d8d"
        example_hash_meteor_express = "2aa6e42cb33ec3c132ffce425a92dfdb5e29d8ac112631aec068c8a78314d49b"
        example_hash_ned_dl = "0fe796e1b7db725115a7de7ee8a56540f838305356b5de2f24de0883300e2c23"
        example_hash_outsider_ransomware = "37110e8ec09ea76a961e4bcf5aa07ffdcb265cca4f28ec52a80bab29f8d236e9"
        example_hash_olympic_destroyer = "3e27b6b287f0b9f7e85bfe18901d961110ae969d58b44af15b1d75be749022c2"
        example_hash_revil = "cebadaf95ea4de56b7cda20d417b030af7d5ca7657d1670c8acecb49f6e29c78"
        example_hash_shamoon = "7dad0b3b3b7dd72490d3f56f0a0b1403844bb05ce2499ef98a28684fbccc07b4"
        example_hash_warzone = "167e5d4485a57ba84504d0c62cf8e9481d39c1e59cca0a4f90b3f3c607ae3a4e"

        DaysofYARA = "13/100"
    strings:
        $lcg_a = { fd 43 03 00 }
        $lcg_c = { c3 9e 26 00 }
        $lcg_mod = { ff 7f 00 00 }
    condition:
        all of them
}
