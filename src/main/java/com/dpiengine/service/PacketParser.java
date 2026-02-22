package com.dpiengine.service;

import com.dpiengine.model.ParsedPacket;
import com.dpiengine.model.RawPacket;
import org.springframework.stereotype.Service;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Parses raw packet bytes into structured protocol fields.
 * Direct Java port of packet_parser.cpp
 *
 * Handles:
 *   Ethernet → IPv4 → TCP / UDP
 *
 * Packet layout (Ethernet + IPv4 + TCP):
 *   [0-5]   Destination MAC
 *   [6-11]  Source MAC
 *   [12-13] EtherType (0x0800 = IPv4)
 *   [14]    IP version+IHL
 *   [15]    DSCP
 *   [16-17] Total length
 *   [18-19] Identification
 *   [20-21] Flags + Fragment offset
 *   [22]    TTL
 *   [23]    Protocol
 *   [24-25] Header checksum
 *   [26-29] Source IP
 *   [30-33] Destination IP
 *   [34-35] TCP/UDP source port
 *   [36-37] TCP/UDP destination port
 *   ...
 */
@Service
public class PacketParser {

    private static final int ETH_HEADER_LEN  = 14;
    private static final int MIN_IP_HEADER   = 20;
    private static final int MIN_TCP_HEADER  = 20;
    private static final int UDP_HEADER_LEN  = 8;

    private static final int ETHERTYPE_IPV4 = 0x0800;
    private static final int PROTO_TCP      = 6;
    private static final int PROTO_UDP      = 17;

    /**
     * Parse a raw packet.
     *
     * @param raw the raw bytes from the PCAP
     * @return ParsedPacket with all decoded fields, or null if packet is too small / unsupported
     */
    public ParsedPacket parse(RawPacket raw) {
        byte[] data = raw.data;
        if (data.length < ETH_HEADER_LEN) return null;

        ParsedPacket pkt = new ParsedPacket();
        pkt.raw = raw;

        // --- Ethernet Header ---
        pkt.dstMac = macToString(data, 0);
        pkt.srcMac = macToString(data, 6);
        pkt.etherType = readUint16(data, 12);

        if (pkt.etherType != ETHERTYPE_IPV4) {
            return pkt; // Non-IPv4 – return partial
        }

        // --- IPv4 Header ---
        int ipStart = ETH_HEADER_LEN;
        if (data.length < ipStart + MIN_IP_HEADER) return pkt;

        pkt.hasIp    = true;
        pkt.ipVersion = (data[ipStart] >> 4) & 0x0F;
        int ihl      = (data[ipStart] & 0x0F) * 4;  // IP header length in bytes
        pkt.ttl      = data[ipStart + 8] & 0xFF;
        pkt.protocol = data[ipStart + 9] & 0xFF;
        pkt.srcIp    = readUint32(data, ipStart + 12);
        pkt.dstIp    = readUint32(data, ipStart + 16);

        int transportStart = ipStart + ihl;

        // --- TCP Header ---
        if (pkt.protocol == PROTO_TCP) {
            if (data.length < transportStart + MIN_TCP_HEADER) return pkt;

            pkt.hasTcp   = true;
            pkt.srcPort  = readUint16(data, transportStart);
            pkt.dstPort  = readUint16(data, transportStart + 2);
            pkt.seqNum   = readUint32(data, transportStart + 4);
            pkt.ackNum   = readUint32(data, transportStart + 8);
            int dataOffset = ((data[transportStart + 12] >> 4) & 0x0F) * 4;
            pkt.tcpFlags = data[transportStart + 13] & 0xFF;

            pkt.payloadOffset = transportStart + dataOffset;
            pkt.payloadLength = data.length - pkt.payloadOffset;
            if (pkt.payloadLength > 0) {
                pkt.payload = new byte[pkt.payloadLength];
                System.arraycopy(data, pkt.payloadOffset, pkt.payload, 0, pkt.payloadLength);
            }

        // --- UDP Header ---
        } else if (pkt.protocol == PROTO_UDP) {
            if (data.length < transportStart + UDP_HEADER_LEN) return pkt;

            pkt.hasUdp  = true;
            pkt.srcPort = readUint16(data, transportStart);
            pkt.dstPort = readUint16(data, transportStart + 2);

            pkt.payloadOffset = transportStart + UDP_HEADER_LEN;
            pkt.payloadLength = data.length - pkt.payloadOffset;
            if (pkt.payloadLength > 0) {
                pkt.payload = new byte[pkt.payloadLength];
                System.arraycopy(data, pkt.payloadOffset, pkt.payload, 0, pkt.payloadLength);
            }
        }

        return pkt;
    }

    // ---- helpers ----

    private static String macToString(byte[] data, int offset) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
            data[offset]   & 0xFF, data[offset+1] & 0xFF,
            data[offset+2] & 0xFF, data[offset+3] & 0xFF,
            data[offset+4] & 0xFF, data[offset+5] & 0xFF);
    }

    /** Read an unsigned 16-bit big-endian integer */
    static int readUint16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    /** Read an unsigned 32-bit big-endian integer (returned as long) */
    static long readUint32(byte[] data, int offset) {
        return ((long)(data[offset]   & 0xFF) << 24) |
               ((long)(data[offset+1] & 0xFF) << 16) |
               ((long)(data[offset+2] & 0xFF) << 8)  |
               ((long)(data[offset+3] & 0xFF));
    }
}
