# Yara-Rules
Useful Yara rules that I made/use

# Yara Info
Documentation: https://virustotal.github.io/yara/                                                                                                               

Source code: https://github.com/virustotal/yara                                                                                                                   

Official download/release: https://github.com/virustotal/yara/releases

# Usage
Example of using yara (command line): 
``` 
yara64 --print-meta --print-strings --print-stats rules\upx.yara apps\app.exe
```
                                                                                                                                                                  
                                                                                                                                                                  
Personally I use Yara with ImHex by putting all .yar files in "C:\Program Files\ImHex\yara"
It should look like this when a condition is met: ![image](https://user-images.githubusercontent.com/75084509/124402788-7f468a80-dd00-11eb-96e5-7fc80c2be011.png)

# ImHex Info
Documentation: https://github.com/WerWolv/ImHex/wiki/Pattern-Language-Guide                                                                                       

Source code: https://github.com/WerWolv/ImHex                                                                                                                     

Official download/release: https://github.com/WerWolv/ImHex/releases
