## quine*

\* this is not a real quine due to `console` module limitations. however, i spent a while on this and its still kinda fun))

```
$ yara -s day010_quine.yara day010_quine.yara 2>/dev/null | python -c 'import sys;l=sys.stdin.readlines()[1:];l=sorted(l,key=lambda x: int(x.split(":")[0],0));print("\n".join([x.split(":",2)[2].split(r"\x")[0][1:] for x in l]))'
rule quine {
    strings:
        $pat1 = / {4}(strings|condition|).{1,3}\n/
        $pat2 = /^rule.{1,10}\n/
        $pat3 = /}\n$/
        $pat4 = / {8}\$?(pat|all).{1,40}\n/
    condition:
        all of them
}
```

```
$ cat day010_quine.yara | md5sum
b1e457bbea580782ff46940e7cc78a16  -

$ yara -s day010_quine.yara day010_quine.yara 2>/dev/null | python -c 'import sys;l=sys.stdin.readlines()[1:];l=sorted(l,key=lambda x: int(x.split(":")[0],0));print("\n".join([x.split(":",2)[2].split(r"\x")[0][1:] for x in l]))' | md5sum -
b1e457bbea580782ff46940e7cc78a16  -
```