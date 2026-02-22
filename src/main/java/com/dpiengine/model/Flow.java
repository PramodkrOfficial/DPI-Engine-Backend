package com.dpiengine.model;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Represents a tracked network flow/connection.
 * Equivalent to the C++ Flow struct used in main_working.cpp and dpi_mt.cpp
 */
public class Flow {

    public final FiveTuple tuple;

    /** SNI extracted from the TLS Client Hello (or HTTP Host header) */
    public volatile String sni = "";

    /** Classified application type */
    public volatile AppType appType = AppType.UNKNOWN;

    /** Whether this flow has been blocked by a rule */
    public volatile boolean blocked = false;

    /** Total packets seen on this flow */
    public final AtomicLong packetCount = new AtomicLong(0);

    /** Total bytes seen on this flow */
    public final AtomicLong byteCount = new AtomicLong(0);

    /** Whether we have already attempted SNI extraction */
    public volatile boolean sniAttempted = false;

    public Flow(FiveTuple tuple) {
        this.tuple = tuple;
    }

    @Override
    public String toString() {
        return "Flow{" + tuple + ", app=" + appType +
               ", sni='" + sni + "', blocked=" + blocked +
               ", pkts=" + packetCount + "}";
    }
}
