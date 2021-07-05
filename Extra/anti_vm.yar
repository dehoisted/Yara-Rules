rule anti_vm {
    meta:
        description = "Checks for vm names and paths used to detect virtual machines"
        type = "Anti VM/Debug"
    strings:
       $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
       $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
       $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" nocase
       $s4 = "SYSTEM\\CurrentControlSet\\Control\\SystemInformation" nocase
       $s5 = "virtualbox" nocase
       $s6 = "vmware" nocase
       $s7 = "innotek gmbh"
       $s8 = "SystemManufacturer"
       $s9 = "SystemProductName"
       $vbox = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase ascii wide
    condition:
        any of them
}

rule anti_debug {
    meta:
        description = "Detects tools for analyzing files/anti debug tools"
        type = "Anti VM/Debug"
    strings:
        $f1 = "procmon.exe" nocase
        $f2 = "processmonitor.exe" nocase
        $f3 = "wireshark.exe" nocase
        $f4 = "fiddler.exe" nocase
        $f5 = "ollydbg.exe" nocase
        $f6 = "winhex.exe" nocase
        $f7 = "processhacker.exe" nocase
        $ex1 = "CheckRemoteDebuggerPresent"
        $ex2 = "IsDebuggerPresent"
        $ex3 = "IsDebugged"
    condition:
        any of them
}
