rule fileformat_leveldb {
    meta:
        description = "LeveDB database format"
        author = "@larsborn"
        created_at = "2022-01-15"
        reference = "https://github.com/google/leveldb/blob/master/doc/table_format.md"

        DaysofYARA = "4/100"
    condition:
        // file ends in { 57 fb 80 8b 24 75 47 db }
        uint32(filesize - 8) == 0x8b80fb57 and uint32(filesize - 4) == 0xdb477524
}
