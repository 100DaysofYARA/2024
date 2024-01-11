rule quine {
    strings:
        $pat1 = / {4}(strings|condition|).{1,3}\n/
        $pat2 = /^rule.{1,10}\n/
        $pat3 = /}\n$/
        $pat4 = / {8}\$?(pat|all).{1,40}\n/
    condition:
        all of them
}
