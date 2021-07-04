// If something is detected here, it doesn't automatically mean the file is malware of course

import "pe"

rule IsPE32
{
    meta:
	   description = "Checks if architecture is 64 bit"
       type = "PECheck"
	condition:
		uint16(0) == 0x5A4D and
		uint16(uint32(0x3C)+0x18) == 0x010B
}

rule IsPE64
{
    meta:
	   description = "Checks if architecture is 64 bit"
       type = "PECheck"
	condition:
		uint16(0) == 0x5A4D and
		uint16(uint32(0x3C)+0x18) == 0x020B
}

rule NATIVE_DLL
{
	meta:
	   description = "Checks if file is a native DLL"
	condition:
		uint16(0) == 0x5A4D and
		(uint16(uint32(0x3C)+0x16) & 0x2000) == 0x2000

}

rule DOTNET_EXE
{
    meta:
	   type = "DOTNET"
	condition:
		pe.imports("mscoree.dll", "_CorExeMain")
}

rule DOTNET_DLL
{
    meta:
	   type = "DOTNET"
	condition:
		pe.imports("mscoree.dll", "_CorDllMain")
}