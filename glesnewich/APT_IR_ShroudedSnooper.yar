import "pe"

rule APT_IR_ShroudedSnooper_XORd_Config_In_Data_Sect
{
	meta:
		author = "Greg Lesnewich"
		description = "track ShroudedSnooper toolset based on repeated XOR encoded .data section "
		date = "2023-10-02"
		version = "1.0"
		DaysofYARA = "7/100"
		HTTPSnoop_hash = "3875ed58c0d42e05c83843b32ed33d6ba5e94e18ffe8fb1bf34fd7dedf3f82a7"
		HTTPSnoop_hash = "7495c1ea421063845eb8f4599a1c17c105f700ca0671ca874c5aa5aef3764c1c"
		HTTPSnoop_hash = "c5b4542d61af74cf7454d7f1c8d96218d709de38f94ccfa7c16b15f726dc08c0"
		PipeSnoop_hash = "9117bd328e37be121fb497596a2d0619a0eaca44752a1854523b8af46a5b0ceb"
		PipeSnoop_hash = "e1ad173e49eee1194f2a55afa681cef7c3b8f6c26572f474dec7a42e9f0cdc9d"
		reference = "https://blog.talosintelligence.com/introducing-shrouded-snooper/"

	condition:
		for any sect in pe.sections:
		(
			sect.name == ".data" and
			uint8(sect.raw_data_offset) == uint8(sect.raw_data_offset + 4) and
			uint32be(sect.raw_data_offset) != 0x0 and
			(
				//HTTPSnoop Variant
				(
					uint8(sect.raw_data_offset+0x40) ^ uint8be(sect.raw_data_offset) == 0x2f and
					uint8(sect.raw_data_offset+0x42) ^ uint8be(sect.raw_data_offset) == 0x2f and
					uint8(sect.raw_data_offset+0x41) == uint8be(sect.raw_data_offset)
				) or
				( //PipeSnoop Variant
					uint8(sect.raw_data_offset+0x34) ^ uint8be(sect.raw_data_offset) == 0x5c and
					uint8(sect.raw_data_offset+0x36) ^ uint8be(sect.raw_data_offset) == 0x5c and
					uint8(sect.raw_data_offset+0x38) ^ uint8be(sect.raw_data_offset) == 0x2e and
					uint8(sect.raw_data_offset+0x35) == uint8be(sect.raw_data_offset)
					)
			)
			)
}
