package com.dpiengine.model;

/**
 * Parsed fields extracted from a raw packet.
 * Equivalent to ParsedPacket in packet_parser.h
 */
public class ParsedPacket {

    // --- Ethernet ---
    public String srcMac  = "";
    public String dstMac  = "";
    public int    etherType = 0;   // 0x0800 = IPv4

    // --- IPv4 ---
    public boolean hasIp   = false;
    public int     ipVersion = 0;
    public int     ttl       = 0;
    public int     protocol  = 0;  // 6=TCP, 17=UDP
    public long    srcIp     = 0;  // unsigned 32-bit stored in long
    public long    dstIp     = 0;

    // --- TCP ---
    public boolean hasTcp    = false;
    public int     srcPort   = 0;
    public int     dstPort   = 0;
    public long    seqNum    = 0;
    public long    ackNum    = 0;
    public int     tcpFlags  = 0;  // SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04

    // --- UDP ---
    public boolean hasUdp    = false;
    // srcPort / dstPort shared with TCP field

    // --- Payload ---
    public byte[]  payload        = new byte[0];
    public int     payloadOffset  = 0;  // byte offset into RawPacket.data
    public int     payloadLength  = 0;

    // Reference back to raw
    public RawPacket raw;

    public FiveTuple toFiveTuple() {
        return new FiveTuple(srcIp, dstIp, srcPort, dstPort, (short) protocol);
    }

    public boolean isSyn()   { return (tcpFlags & 0x02) != 0; }
    public boolean isAck()   { return (tcpFlags & 0x10) != 0; }
    public boolean isFin()   { return (tcpFlags & 0x01) != 0; }
    public boolean isRst()   { return (tcpFlags & 0x04) != 0; }
}
