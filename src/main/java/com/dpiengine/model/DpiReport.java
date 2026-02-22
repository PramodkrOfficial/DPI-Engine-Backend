package com.dpiengine.model;

import java.util.Map;
import java.util.List;

/**
 * Final report produced after processing a PCAP file.
 * Equivalent to the console output in the C++ versions.
 */
public class DpiReport {

    public long totalPackets;
    public long totalBytes;
    public long tcpPackets;
    public long udpPackets;
    public long forwarded;
    public long dropped;

    /** Per-app packet count */
    public Map<AppType, Long> appStats;

    /** SNIs detected and their mapped AppType */
    public Map<String, AppType> detectedSnis;

    /** Per-flow summary (optional, for REST API) */
    public List<FlowSummary> flows;

    public record FlowSummary(
        String srcIp,
        int    srcPort,
        String dstIp,
        int    dstPort,
        String protocol,
        String appType,
        String sni,
        boolean blocked,
        long packets,
        long bytes
    ) {}
}
