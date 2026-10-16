rule FakeGPT_Extension_Credential_Stealer
{
    meta:
        description = "Strings seen in the FakeGPT lab extension (credential and keystroke theft, AES, image beacon)"
        author      = "Muhammad Umer Imran"
        date        = "2026-10-16"
        reference   = "CyberDefenders FakeGPT lab, static analysis"
        note        = "Hunting aid built from observed strings; test before any production use"

    strings:
        $f1 = "exfiltrateCredentials" ascii
        $f2 = "exfiltrateData" ascii
        $k1 = "SuperSecretKey123" ascii
        $u1 = "elshaheedy.com/collect" ascii nocase
        $t1 = "'keystroke'" ascii

    condition:
        2 of them
}
