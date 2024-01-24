rule INFO_KCP_MZ_FILE {
	meta:
		version = "1"
		date = "1/17/24"
		modified = "1/17/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "https://github.com/skywind3000/kcp/blob/master/ikcp.c"
		author = "@x0rc1sm"
		description = "taking print and log reference from KCP, trying to find other implementations"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "N/A"
		hash = ""
		hash = ""
		hash = ""
	strings:
		$kcp1 = "[RO] %ld bytes" //ikcp_log(kcp, IKCP_LOG_OUTPUT, "[RO] %ld bytes", (long)size)
		$kcp2 = "[RI] %d bytes" //ikcp_log(kcp, IKCP_LOG_INPUT, "[RI] %d bytes", (int)size);
		$kcp3 = "recv sn=%lu" //ikcp_log(kcp, IKCP_LOG_RECV, "recv sn=%lu", (unsigned long)seg->sn);
		$kcp4 = "input ack: sn=%lu rtt=%ld rto=%ld" //ikcp_log(kcp, IKCP_LOG_IN_ACK, "input ack: sn=%lu rtt=%ld rto=%ld", (unsigned
		$kcp5 = "input psh: sn=%lu ts=%lu" //ikcp_log(kcp, IKCP_LOG_IN_DATA, "input psh: sn=%lu ts=%lu", (unsigned long)sn,
		$kcp6 = "input probe" //ikcp_log(kcp, IKCP_LOG_IN_PROBE, "input probe");
		$kcp7 = "input wins: %lu" //ikcp_log(kcp, IKCP_LOG_IN_WINS, "input wins: %lu", (unsigned long)(wnd));
		$kcp8 = "snd(buf=%d, queue=%d)\\n" // printf("snd(buf=%d, queue=%d)\n", kcp->nsnd_buf, kcp->nsnd_que);
		$kcp9 = "rcv(buf=%d, queue=%d)\\n" // printf("rcv(buf=%d, queue=%d)\n", kcp->nrcv_buf, kcp->nrcv_que);
		$kcp10 = "rcv_nxt=%lu\\n" // printf("rcv_nxt=%lu\n"
		$kcp11 = "rcvbuf" //ikcp_qprint("rcvbuf"
	condition:
		uint16(0) == 0x5a4d and 5 of them
}
