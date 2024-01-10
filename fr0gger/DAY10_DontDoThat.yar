rule DontDoThatNoReally
{
    meta:
        author = "Thomas Roccia | @fr0gger_"
        date = "2024-01-10"
        description = "#100daysofYara | regex experiment that will slow down the scanning"
        source = "https://stackoverflow.com/questions/9315647/regex-credit-card-number-tests"
    strings:
        $Amex = /3[47][0-9]{13}/
        $BCGlobal = /(6541|6556)[0-9]{12}/
        $CarteBlanche = /389[0-9]{11}/
        $DinersClub = /^3(0[0-5]|[68][0-9])[0-9]{11}$/
        $Discover = /65[4-9][0-9]{13}|64[4-9][0-9]{13}|6011[0-9]{12}|(622(12[6-9]|1[3-9][0-9]|[2-8][0-9][0-9]|9[01][0-9]|92[0-5])[0-9]{10})/
        $InstaPayment = /63[7-9][0-9]{13}/
        $JCB = /(2131|1800|35\d{3})\d{11}/
        $KoreanLocal = /9[0-9]{15}/
        $Laser = /(6304|6706|6709|6771)[0-9]{12,15}/
        $Maestro = /(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}/
        $Mastercard = /(5[1-5][0-9]{14}|2(22[1-9][0-9]{12}|2[3-9][0-9]{13}|[3-6][0-9]{14}|7[0-1][0-9]{13}|720[0-9]{12}))/
        $Solo = /(6334|6767)[0-9]{12}|(6334|6767)[0-9]{14}|(6334|6767)[0-9]{15}/
        $UnionPay = /(62[0-9]{14,17})/
        $Visa = /4[0-9]{12}([0-9]{3})?/
        $VisaMaster = /(4[0-9]{12}([0-9]{3})?|5[1-5][0-9]{14})/
    condition:
        any of them
}
