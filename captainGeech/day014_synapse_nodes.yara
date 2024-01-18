rule Hunting_Synapse_Nodes {
    meta:
        author = "@captainGeech42"
        description = "Look for Synapse nodes files"
        date = "2024-01-14"
        version = "2"
        DaysofYARA = "14/100"
    strings:
        // msgpack'd node iden, which is then followed by the tags
        $iden = /iden\xd9@[0-9a-f]{64}/
    condition:
        $iden
}