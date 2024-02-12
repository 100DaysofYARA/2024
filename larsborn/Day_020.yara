rule StrelaStealer_XorKey {
    meta:
        description = "Multi-purpose Xor-Key observed in StrelaStealer"
        author = "@larsborn"
        date = "2024-02-10"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.strelastealer"
        example_hash = "6e8a3ffffd2f7a91f3f845b78dd90011feb80d30b4fe48cb174b629afa273403"
        example_hash = "8b0d8651e035fcc91c39b3260c871342d1652c97b37c86f07a561828b652e907"

        DaysofYARA = "20/100"
    strings:
        $ = "4f3855aa-af7e-4fd2-b04e-55e63653d2f7"
    condition:
        any of them
}
