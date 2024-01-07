rule deflate_copyright {
    meta:
        description = "Copyright string of the deflate algorithm"
        author = "@larsborn"
        created_at = "2023-05-09"
        reference = "https://github.com/commontk/zlib/blob/master/deflate.c"
        example_hash_01 = "fbe103fac45abe4e3638055a3cac5e7009166f626cf2d3049fb46f3b53c1057f"

        DaysofYARA = "5/100"
    strings:
        $ = " deflate 1.2.3 Copyright 1995-2005 Jean-loup Gailly "
    condition:
        all of them
}
