rule PolyglotJavascriptDropper {
    meta:
        description = "Polyglot (JavaScript/Batch) loader stage in a drop-chain resulting in StrelaStealer"
        author = "@larsborn"
        date = "2023-06-23"
        reference = "https://medium.com/@avaen/malware-analysis-digital-forensic-strela-stealer-9a3c3402c6bf"
        reference = "https://youtu.be/MC6SXCJ7pEs?si=U36OXSXeEd7HqPZf&t=900"
        example_hash = "1b7235d0223274eafd9b93d62cb33908a1af5b3d2c2970e322b3e31ddee5c29a"

        DaysofYARA = "18/100"
    strings:
        $ = "*/WScript[\"Cr"
        $ = "4d 5a 90 00 03 00 00 00"
    condition:
        all of them
}
