#!/bin/bash
diff -w -B  <(./trace trace_files/smallTCP.pcap) \
   trace_files/smallTCP.out
diff -w -B <(./trace trace_files/ArpTest.pcap) \
   trace_files/ArpTest.out
diff -w -B <(./trace trace_files/Http.pcap) \
   trace_files/Http.out
diff -w -B <(./trace trace_files/IP_bad_checksum.pcap) \
    trace_files/IP_bad_checksum.out
diff -w -B <(./trace trace_files/largeMix2.pcap) trace_files/largeMix2.out
diff -w -B <(./trace trace_files/largeMix.pcap) trace_files/largeMix.out
diff -w -B <(./trace trace_files/PingTest.pcap) trace_files/PingTest.out
diff -w -B <(./trace trace_files/TCP_bad_checksum.pcap) \
    trace_files/TCP_bad_checksum.out
diff -w -B <(./trace trace_files/UDPfile.pcap) \
   trace_files/UDPfile.out
