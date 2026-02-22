package com.dpiengine.model;

import java.util.Objects;

/**
 * Uniquely identifies a network connection/flow.
 * Equivalent to the C++ FiveTuple struct in types.h
 *
 * A "flow" is identified by:
 *   srcIp, dstIp, srcPort, dstPort, protocol
 */
public class FiveTuple {

    public final long   srcIp;    // stored as unsigned 32-bit (use long)
    public final long   dstIp;
    public final int    srcPort;  // 0-65535
    public final int    dstPort;
    public final short  protocol; // 6=TCP, 17=UDP

    public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, short protocol) {
        this.srcIp    = srcIp;
        this.dstIp    = dstIp;
        this.srcPort  = srcPort;
        this.dstPort  = dstPort;
        this.protocol = protocol;
    }

    /** Returns the source IP as a dotted-decimal string */
    public String srcIpString() {
        return ipToString(srcIp);
    }

    /** Returns the destination IP as a dotted-decimal string */
    public String dstIpString() {
        return ipToString(dstIp);
    }

    public static String ipToString(long ip) {
        return ((ip >> 24) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 8)  & 0xFF) + "." +
               ( ip        & 0xFF);
    }

    /**
     * Parse dotted-decimal IP into an unsigned 32-bit long.
     */
    public static long parseIp(String dotted) {
        String[] parts = dotted.split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Bad IP: " + dotted);
        long result = 0;
        for (String part : parts) {
            result = (result << 8) | (Integer.parseInt(part) & 0xFF);
        }
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple t)) return false;
        return srcIp == t.srcIp && dstIp == t.dstIp &&
               srcPort == t.srcPort && dstPort == t.dstPort &&
               protocol == t.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        return srcIpString() + ":" + srcPort + " → " + dstIpString() + ":" + dstPort +
               " [" + (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "proto=" + protocol) + "]";
    }
}
