rule MAL_Loader_KrustyLoader_strings {
	meta:
		description = "Matches strings found in KrustyLoader malware samples."
		last_modified = "2024-03-25"
		author = "@petermstewart"
		DaysofYara = "85/100"
		sha256 = "030eb56e155fb01d7b190866aaa8b3128f935afd0b7a7b2178dc8e2eb84228b0"
		ref = "https://www.synacktiv.com/en/publications/krustyloader-rust-malware-linked-to-ivanti-connectsecure-compromises"

	strings:
		$a1 = "|||||||||||||||||||||||||||||||||||"
		$a2 = "/proc/self/exe"
		$a3 = "/tmp/"
		$a4 = "TOKIO_WORKER_THREADS"

	condition:
		uint32(0) == 0x464c457f and
		all of them
}
