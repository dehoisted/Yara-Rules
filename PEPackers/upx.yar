rule upx {
    meta:
        description = "Detect a basic UPX packed file"
		type = "PEPacker"
    strings:
        $mz = "MZ"
        $upx1 = {55505830000000}
        $upx2 = {55505831000000}
        $upx_sig = "UPX!"

    condition:
        $mz at 0 and $upx1 in (0..1024) and $upx2 in (0..1024) and $upx_sig in (0..1024)
}

rule upx_2 {
	meta:
		description = "Detect a packed UPX file, sample 2"
		type = "PEPacker"
		extra_info = "Just in case it was packed with a different version of UPX that doesn't follow the rules shown above"
	strings:
	$UPX0 = "UPX0"
	$UPX1 = "UPX1"

	condition:
		$UPX0 and $UPX1
}

rule bpx {
	meta:
		description = "Detect hex edited UPX files"
		type = "PEPacker"
		extra = "Editing UPX0 to BPX0 makes the file non decompressable, hence why people do this"
	strings:
		$BPX0 = "BPX0"
		$BPX1 = "BPX1"
	condition:
	    $BPX0 and $BPX1 
}