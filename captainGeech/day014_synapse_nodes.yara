rule Hunting_Synapse_Nodes {
    meta:
        author = "@captainGeech42"
        description = "Look for Synapse nodes files"
        date = "2024-01-14"
        version = "1"
        DaysofYARA = "14/100"
    strings:
        // msgpack'd node iden, which is then followed by the tags
        $iden = /iden.@[0-9a-f]{64}\xa4tags/
    condition:
        $iden
}