rule StrelaStealer_PdbPath {
    meta:
        description = "PDB path fragments present in some StrelaStealer samples"
        author = "@larsborn"
        date = "2024-02-10"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.strelastealer"
        example_hash = "6e8a3ffffd2f7a91f3f845b78dd90011feb80d30b4fe48cb174b629afa273403"
        example_hash = "8b0d8651e035fcc91c39b3260c871342d1652c97b37c86f07a561828b652e907"

        DaysofYARA = "19/100"
    strings:
        $ = "C:\\Users\\Serhii\\"
        $ = "\\StrelaDLLCompile\\"
        $ = "StrelaDLLCompile.pdb"
    condition:
        any of them
}
