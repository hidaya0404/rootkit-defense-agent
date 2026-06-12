rule Suspicious_Linux_Rootkit_Indicators
{
    meta:
        description = "Detects simple suspicious Linux/rootkit-like indicators"
        author = "M4 Rootkit Defense Agent"
        project = "Rootkit Defense Agent"

    strings:
        $s1 = "/etc/ld.so.preload"
        $s2 = "insmod"
        $s3 = "rmmod"
        $s4 = "hide_process"
        $s5 = "rootkit"
        $s6 = "persistence"
        $s7 = "/etc/crontab"
        $s8 = "/lib/modules"

    condition:
        any of them
}
