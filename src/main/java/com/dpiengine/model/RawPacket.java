package com.dpiengine.model;

/**
 * Raw bytes read directly from a PCAP file.
 * Equivalent to the raw packet structs used in pcap_reader.h
 */
public class RawPacket {

    /** Timestamp in microseconds since epoch */
    public long timestampUs;

    /** Original length of the packet on the wire */
    public int originalLength;

    /** Actual bytes captured (may be truncated to snaplen) */
    public byte[] data;

    public RawPacket(long timestampUs, int originalLength, byte[] data) {
        this.timestampUs    = timestampUs;
        this.originalLength = originalLength;
        this.data           = data;
    }
}
