rule Discord_Token_Logger {
    meta:
        description = "Detects discord token logger"
        type = "Malware/Gather Info"
    strings:
        $path1 = "\\Discord\\Local Storage\\leveldb"
        $path2 = "\\Lightcord\\Local Storage\\leveldb"
        $path3 = "\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb"
        $path4 = "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb"
        $lb = "\\Local Storage\\leveldb"
        $webhook = "https://discord.com/api/webhooks"
    condition:
        any of them
}
