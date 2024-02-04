rule salsa20
{
    meta:
        description = "Nothing-up-my-sleeve number used in the Salsa20 stream cipher"
        author = "@larsborn"
        author = "@huettenhain"
        date = "2020-08-23"
        reference = "https://en.wikipedia.org/wiki/Salsa20"
        example_hash_abcbot = "1fc59a86915eca78dbe0f90c7e0ee3fac6f7e5160c26a04330bf3858f7e5c1f2"
        example_hash_egregor = "d893f26330906bedcad2627f41135f0fda65bc4dfe1f4186cd60d4546469b3c3"
        example_hash_netwalker = "de04d2402154f676f757cf1380671f396f3fc9f7dbb683d9461edd2718c4e09d"
        example_hash_revil = "12d8bfa1aeb557c146b98f069f3456cc8392863a2f4ad938722cd7ca1a773b39"
        example_hash_stealth_worker = "f48628472e35ac54f2b0b42583dfa04ae62ae644ba036dad5abf7efc545393c9"
        example_hash_xaynnalc = "b277fb8b666f8b5c179ddac940fad90a3e38b23170931e1226dd1676404dbfec"

        DaysofYARA = "15/100"
    strings:
        $ = "expand 32-byte k"
        $ = "expand 16-byte k"
    condition:
        any of them
}
