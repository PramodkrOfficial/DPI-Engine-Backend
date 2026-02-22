package com.dpiengine.service;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the SNI (Server Name Indication) hostname from TLS Client Hello packets,
 * and the Host header from plain HTTP requests.
 *
 * Direct Java port of sni_extractor.cpp
 *
 * TLS ClientHello wire layout that we navigate:
 *
 *   [0]      Content Type = 0x16 (Handshake)
 *   [1-2]    Legacy Record Version
 *   [3-4]    Record Length
 *   [5]      Handshake Type = 0x01 (ClientHello)
 *   [6-8]    Handshake Length (3 bytes)
 *   [9-10]   Client Version
 *   [11-42]  Client Random (32 bytes)
 *   [43]     Session ID Length  (N)
 *   [44..44+N-1]  Session ID
 *   [44+N .. 44+N+1]  Cipher Suites Length (C)
 *   [44+N+2 .. 44+N+2+C-1]  Cipher Suites
 *   [44+N+2+C]  Compression Methods Length (M)
 *   [44+N+3+C .. 44+N+3+C+M-1]  Compression Methods
 *   [44+N+3+C+M .. +1]  Extensions Length (E)
 *   … Extensions …
 *
 *   Each Extension:
 *     [0-1]  Type
 *     [2-3]  Length
 *     [4+]   Data
 *
 *   SNI Extension (Type = 0x0000):
 *     [0-1]  SNI List Length
 *     [2]    SNI Type (0x00 = host_name)
 *     [3-4]  SNI Length
 *     [5+]   SNI value (ASCII)
 */
@Service
public class SniExtractor {

    private static final int TLS_CONTENT_HANDSHAKE = 0x16;
    private static final int TLS_HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXT_SNI = 0x0000;

    /**
     * Try to extract the SNI from a TLS Client Hello payload.
     *
     * @param payload TCP payload bytes
     * @return the SNI hostname, or empty if not found / not a Client Hello
     */
    public Optional<String> extractTlsSni(byte[] payload) {
        if (payload == null || payload.length < 43) return Optional.empty();

        // Check TLS record type
        if ((payload[0] & 0xFF) != TLS_CONTENT_HANDSHAKE) return Optional.empty();

        // Check handshake type
        if ((payload[5] & 0xFF) != TLS_HANDSHAKE_CLIENT_HELLO) return Optional.empty();

        try {
            int offset = 43; // start of Session ID Length

            // Skip Session ID
            if (offset >= payload.length) return Optional.empty();
            int sessionLen = payload[offset] & 0xFF;
            offset += 1 + sessionLen;

            // Skip Cipher Suites
            if (offset + 2 > payload.length) return Optional.empty();
            int cipherLen = readUint16(payload, offset);
            offset += 2 + cipherLen;

            // Skip Compression Methods
            if (offset + 1 > payload.length) return Optional.empty();
            int compLen = payload[offset] & 0xFF;
            offset += 1 + compLen;

            // Extensions
            if (offset + 2 > payload.length) return Optional.empty();
            int extTotalLen = readUint16(payload, offset);
            offset += 2;

            int extEnd = offset + extTotalLen;
            if (extEnd > payload.length) extEnd = payload.length;

            // Iterate extensions
            while (offset + 4 <= extEnd) {
                int extType = readUint16(payload, offset);
                int extLen  = readUint16(payload, offset + 2);
                offset += 4;

                if (extType == EXT_SNI) {
                    // SNI extension found
                    // [0-1] SNI List Length
                    // [2]   SNI Type (0 = hostname)
                    // [3-4] Hostname Length
                    // [5..] Hostname bytes
                    if (offset + 5 > extEnd) return Optional.empty();

                    // skip SNI list length (2) + SNI type (1)
                    int sniLen = readUint16(payload, offset + 3);
                    int sniStart = offset + 5;

                    if (sniStart + sniLen > payload.length) return Optional.empty();

                    String sni = new String(payload, sniStart, sniLen, StandardCharsets.US_ASCII);
                    return Optional.of(sni);
                }

                offset += extLen;
            }

        } catch (ArrayIndexOutOfBoundsException e) {
            // Malformed / truncated packet
        }

        return Optional.empty();
    }

    /**
     * Try to extract the Host header value from an HTTP/1.x request.
     * Equivalent to HTTPHostExtractor::extract() in sni_extractor.cpp
     *
     * @param payload TCP payload bytes
     * @return the Host value (without port), or empty if not HTTP
     */
    public Optional<String> extractHttpHost(byte[] payload) {
        if (payload == null || payload.length < 16) return Optional.empty();

        String text = new String(payload, StandardCharsets.US_ASCII);

        // Quick check for HTTP methods
        if (!text.startsWith("GET ")    && !text.startsWith("POST ") &&
            !text.startsWith("HEAD ")   && !text.startsWith("PUT ")  &&
            !text.startsWith("DELETE ") && !text.startsWith("CONNECT ")) {
            return Optional.empty();
        }

        // Search for "Host:" header (case-insensitive)
        int hostIdx = text.toLowerCase().indexOf("\nhost:");
        if (hostIdx == -1) {
            hostIdx = text.toLowerCase().indexOf("\r\nhost:");
        }
        if (hostIdx == -1) return Optional.empty();

        // Find the colon after "Host"
        int colonIdx = text.indexOf(':', hostIdx);
        if (colonIdx == -1) return Optional.empty();

        // Extract value up to end of line
        int valueStart = colonIdx + 1;
        int lineEnd    = text.indexOf('\n', valueStart);
        if (lineEnd == -1) lineEnd = text.length();

        String host = text.substring(valueStart, lineEnd).strip();

        // Strip port if present (e.g. "example.com:8080")
        int portColon = host.lastIndexOf(':');
        if (portColon != -1) {
            String potentialPort = host.substring(portColon + 1);
            if (potentialPort.matches("\\d+")) {
                host = host.substring(0, portColon);
            }
        }

        return host.isEmpty() ? Optional.empty() : Optional.of(host);
    }

    /** Read big-endian unsigned 16-bit int */
    private static int readUint16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }
}
