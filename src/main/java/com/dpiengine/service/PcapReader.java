package com.dpiengine.service;

import com.dpiengine.model.RawPacket;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads PCAP files and returns raw packets.
 * Direct Java port of pcap_reader.cpp
 *
 * PCAP Global Header (24 bytes):
 *   magic_number  (4)  – 0xa1b2c3d4 (big-endian) or 0xd4c3b2a1 (little-endian)
 *   version_major (2)
 *   version_minor (2)
 *   thiszone      (4)  – GMT offset
 *   sigfigs       (4)  – timestamp accuracy
 *   snaplen       (4)  – max packet size
 *   network       (4)  – link type (1 = Ethernet)
 *
 * PCAP Packet Header (16 bytes):
 *   ts_sec   (4)
 *   ts_usec  (4)
 *   incl_len (4)  – bytes in file
 *   orig_len (4)  – original length
 */
@Service
public class PcapReader {

    private static final int MAGIC_BIG    = 0xa1b2c3d4;
    private static final int MAGIC_LITTLE = 0xd4c3b2a1;
    private static final int GLOBAL_HEADER_SIZE = 24;
    private static final int PACKET_HEADER_SIZE = 16;

    /**
     * Read all packets from a PCAP byte array (e.g. uploaded file).
     *
     * @param pcapBytes raw bytes of the .pcap file
     * @return ordered list of RawPackets
     * @throws IOException if the data is not a valid PCAP
     */
    public List<RawPacket> readAll(byte[] pcapBytes) throws IOException {
        ByteBuffer buf = ByteBuffer.wrap(pcapBytes);

        // --- Read & validate Global Header ---
        if (pcapBytes.length < GLOBAL_HEADER_SIZE) {
            throw new IOException("File too small to be a valid PCAP");
        }

        int magic = buf.getInt(); // read as big-endian first

        ByteOrder order;
        if (magic == MAGIC_BIG) {
            order = ByteOrder.BIG_ENDIAN;
        } else if (Integer.reverseBytes(magic) == MAGIC_BIG) {
            order = ByteOrder.LITTLE_ENDIAN;
            buf.order(ByteOrder.LITTLE_ENDIAN);
        } else {
            throw new IOException("Not a valid PCAP file (bad magic number)");
        }

        buf.order(order);

        // Skip the rest of the global header (we re-read with correct byte order)
        buf.position(0);
        buf.order(order);
        buf.getInt();  // magic_number (already read)
        buf.getShort(); // version_major
        buf.getShort(); // version_minor
        buf.getInt();   // thiszone
        buf.getInt();   // sigfigs
        int snaplen = buf.getInt(); // max packet size
        buf.getInt();   // network / link type

        List<RawPacket> packets = new ArrayList<>();

        // --- Read packets ---
        while (buf.remaining() >= PACKET_HEADER_SIZE) {
            long tsSec  = buf.getInt() & 0xFFFFFFFFL;
            long tsUsec = buf.getInt() & 0xFFFFFFFFL;
            int  inclLen = buf.getInt();
            int  origLen = buf.getInt();

            if (inclLen < 0 || inclLen > snaplen + 65536) {
                throw new IOException("Invalid packet length: " + inclLen);
            }
            if (buf.remaining() < inclLen) {
                break; // truncated file – stop reading
            }

            byte[] data = new byte[inclLen];
            buf.get(data);

            long timestampUs = tsSec * 1_000_000L + tsUsec;
            packets.add(new RawPacket(timestampUs, origLen, data));
        }

        return packets;
    }

    /**
     * Write a list of raw packets back to PCAP format (big-endian).
     * Used to write the filtered output PCAP.
     */
    public byte[] writeAll(List<RawPacket> packets) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // Global header (big-endian)
        dos.writeInt(MAGIC_BIG);
        dos.writeShort(2);          // version major
        dos.writeShort(4);          // version minor
        dos.writeInt(0);            // thiszone
        dos.writeInt(0);            // sigfigs
        dos.writeInt(65535);        // snaplen
        dos.writeInt(1);            // network = Ethernet

        for (RawPacket pkt : packets) {
            long tsSec  = pkt.timestampUs / 1_000_000L;
            long tsUsec = pkt.timestampUs % 1_000_000L;

            dos.writeInt((int) tsSec);
            dos.writeInt((int) tsUsec);
            dos.writeInt(pkt.data.length);
            dos.writeInt(pkt.originalLength);
            dos.write(pkt.data);
        }

        dos.flush();
        return baos.toByteArray();
    }
}
