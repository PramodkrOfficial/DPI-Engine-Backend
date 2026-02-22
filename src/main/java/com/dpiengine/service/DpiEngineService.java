package com.dpiengine.service;

import com.dpiengine.model.*;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import com.dpiengine.model.AppType;
import com.dpiengine.model.DpiReport;
import com.dpiengine.model.FiveTuple;
import com.dpiengine.model.Flow;
import com.dpiengine.model.RawPacket;


import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;


/**
 * Main DPI orchestrator.
 *
 * This is a Java/Spring Boot port of BOTH versions from the C++ project:
 *
 *   • processSingleThreaded()   → equivalent to main_working.cpp  (simple, sequential)
 *   • processMultiThreaded()    → equivalent to dpi_mt.cpp        (LB + FP thread pools)
 *
 * The multi-threaded path mirrors the C++ architecture:
 *   Reader → LB threads → FP threads → output queue → writer
 *
 * Consistent hashing is used (hash(5-tuple) % numFPs) so every packet of the
 * same flow always ends up on the same FastPath thread – exactly like the C++ version.
 */
@Service
public class DpiEngineService {

    private final PcapReader        pcapReader;
    private final PacketParser      packetParser;
    private final SniExtractor      sniExtractor;
    private final RuleManager       ruleManager;
    private final ConnectionTracker connectionTracker;

    public DpiEngineService(PcapReader pcapReader,
                            PacketParser packetParser,
                            SniExtractor sniExtractor,
                            RuleManager ruleManager,
                            ConnectionTracker connectionTracker) {
        this.pcapReader        = pcapReader;
        this.packetParser      = packetParser;
        this.sniExtractor      = sniExtractor;
        this.ruleManager       = ruleManager;
        this.connectionTracker = connectionTracker;
    }

    // =========================================================================
    // PUBLIC API
    // =========================================================================

    /**
     * Process a PCAP file using the simple single-threaded approach.
     * Equivalent to main_working.cpp
     *
     * @param pcapBytes  raw bytes of the input PCAP
     * @return DpiResult with the filtered PCAP bytes and a report
     */
    public DpiResult processSingleThreaded(byte[] pcapBytes) throws IOException {
        connectionTracker.clear();
        List<RawPacket> allPackets = pcapReader.readAll(pcapBytes);

        AtomicLong totalBytes = new AtomicLong();
        AtomicLong tcpPkts   = new AtomicLong();
        AtomicLong udpPkts   = new AtomicLong();
        AtomicLong dropped   = new AtomicLong();
        AtomicLong forwarded = new AtomicLong();

        List<RawPacket> outputPackets = new ArrayList<>();

        for (RawPacket raw : allPackets) {
            totalBytes.addAndGet(raw.data.length);

            ParsedPacket pkt = packetParser.parse(raw);
            if (pkt == null || !pkt.hasIp) {
                // Non-IP: forward without inspection
                outputPackets.add(raw);
                forwarded.incrementAndGet();
                continue;
            }

            if (pkt.hasTcp) tcpPkts.incrementAndGet();
            if (pkt.hasUdp) udpPkts.incrementAndGet();

            FiveTuple tuple = pkt.toFiveTuple();
            Flow flow       = connectionTracker.getOrCreate(tuple);
            flow.packetCount.incrementAndGet();
            flow.byteCount.addAndGet(raw.data.length);

            // --- SNI / Host extraction (only once per flow) ---
            if (!flow.sniAttempted && pkt.payloadLength > 5) {
                flow.sniAttempted = true;

                Optional<String> sni = Optional.empty();

                // TLS (HTTPS) – port 443 or any port with TLS signature
                if (pkt.dstPort == 443 || pkt.dstPort == 8443 ||
                    isTlsClientHello(pkt.payload)) {
                    sni = sniExtractor.extractTlsSni(pkt.payload);
                }

                // HTTP – port 80 or explicit HTTP methods
                if (sni.isEmpty() && (pkt.dstPort == 80 || pkt.dstPort == 8080)) {
                    sni = sniExtractor.extractHttpHost(pkt.payload);
                }

                if (sni.isPresent()) {
                    flow.sni     = sni.get();
                    flow.appType = AppType.fromSni(flow.sni);

                    // Determine HTTPS/HTTP if still UNKNOWN
                    if (flow.appType == AppType.UNKNOWN) {
                        flow.appType = (pkt.dstPort == 443 || pkt.dstPort == 8443)
                                       ? AppType.HTTPS : AppType.HTTP;
                    }
                } else {
                    // Port-based heuristic
                    if (flow.appType == AppType.UNKNOWN) {
                        flow.appType = portHeuristic(pkt.dstPort);
                    }
                }
            }

            // --- Blocking decision ---
            if (!flow.blocked) {
                flow.blocked = ruleManager.isBlocked(tuple.srcIp, flow.appType, flow.sni);
            }

            if (flow.blocked) {
                dropped.incrementAndGet();
            } else {
                forwarded.incrementAndGet();
                outputPackets.add(raw);
            }
        }

        byte[] outputPcap = pcapReader.writeAll(outputPackets);
        DpiReport report  = buildReport(allPackets.size(), totalBytes.get(),
                                        tcpPkts.get(), udpPkts.get(),
                                        forwarded.get(), dropped.get());

        return new DpiResult(outputPcap, report);
    }

    /**
     * Process a PCAP using the multi-threaded architecture.
     * Equivalent to dpi_mt.cpp (LoadBalancer + FastPath thread pools).
     *
     * @param pcapBytes raw bytes of the input PCAP
     * @param numLbs    number of Load Balancer threads (default 2)
     * @param numFps    number of Fast Path threads per LB (default 2, total = numLbs * numFps)
     */
    public DpiResult processMultiThreaded(byte[] pcapBytes, int numLbs, int numFps)
            throws IOException, InterruptedException {

        connectionTracker.clear();
        List<RawPacket> allPackets = pcapReader.readAll(pcapBytes);

        int totalFps = numLbs * numFps;

        // Per-FP flow tables (same FP always handles same flow = consistent hashing)
        @SuppressWarnings("unchecked")
        Map<FiveTuple, Flow>[] fpFlowTables = new ConcurrentHashMap[totalFps];
        for (int i = 0; i < totalFps; i++) fpFlowTables[i] = new ConcurrentHashMap<>();

        // Output queue (FP → writer)
        BlockingQueue<RawPacket> outputQueue = new LinkedBlockingQueue<>();

        // Per-FP stats
        AtomicLong[] fpDropped   = new AtomicLong[totalFps];
        AtomicLong[] fpForwarded = new AtomicLong[totalFps];
        AtomicLong[] fpProcessed = new AtomicLong[totalFps];
        for (int i = 0; i < totalFps; i++) {
            fpDropped[i]   = new AtomicLong();
            fpForwarded[i] = new AtomicLong();
            fpProcessed[i] = new AtomicLong();
        }

        // Per-FP input queues (LB feeds these)
        @SuppressWarnings("unchecked")
        BlockingQueue<ParsedPacket>[] fpQueues = new LinkedBlockingQueue[totalFps];
        for (int i = 0; i < totalFps; i++) fpQueues[i] = new LinkedBlockingQueue<>();

        // --- FastPath threads ---
        ExecutorService fpExecutor = Executors.newFixedThreadPool(totalFps);
        CountDownLatch fpDone = new CountDownLatch(totalFps);

        for (int fpIdx = 0; fpIdx < totalFps; fpIdx++) {
            final int fi = fpIdx;
            fpExecutor.submit(() -> {
                Map<FiveTuple, Flow> myFlows = fpFlowTables[fi];
                BlockingQueue<ParsedPacket> myQueue = fpQueues[fi];

                try {
                    while (true) {
                        ParsedPacket pkt = myQueue.poll(100, TimeUnit.MILLISECONDS);
                        if (pkt == null) {
                            // Check if we are done
                            if (myQueue.isEmpty()) break;
                            continue;
                        }

                        fpProcessed[fi].incrementAndGet();

                        FiveTuple tuple = pkt.toFiveTuple();
                        Flow flow = myFlows.computeIfAbsent(tuple, Flow::new);
                        flow.packetCount.incrementAndGet();
                        flow.byteCount.addAndGet(pkt.raw.data.length);

                        // SNI extraction
                        if (!flow.sniAttempted && pkt.payloadLength > 5) {
                            flow.sniAttempted = true;
                            Optional<String> sni = Optional.empty();

                            if (pkt.dstPort == 443 || pkt.dstPort == 8443 ||
                                isTlsClientHello(pkt.payload)) {
                                sni = sniExtractor.extractTlsSni(pkt.payload);
                            }
                            if (sni.isEmpty() && (pkt.dstPort == 80 || pkt.dstPort == 8080)) {
                                sni = sniExtractor.extractHttpHost(pkt.payload);
                            }

                            if (sni.isPresent()) {
                                flow.sni     = sni.get();
                                flow.appType = AppType.fromSni(flow.sni);
                                if (flow.appType == AppType.UNKNOWN) {
                                    flow.appType = (pkt.dstPort == 443 || pkt.dstPort == 8443)
                                                   ? AppType.HTTPS : AppType.HTTP;
                                }
                            } else {
                                if (flow.appType == AppType.UNKNOWN)
                                    flow.appType = portHeuristic(pkt.dstPort);
                            }
                        }

                        // Blocking decision
                        if (!flow.blocked) {
                            flow.blocked = ruleManager.isBlocked(
                                tuple.srcIp, flow.appType, flow.sni);
                        }

                        if (flow.blocked) {
                            fpDropped[fi].incrementAndGet();
                        } else {
                            fpForwarded[fi].incrementAndGet();
                            outputQueue.put(pkt.raw);
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    fpDone.countDown();
                    // Copy local flows into shared tracker for reporting
                    myFlows.values().forEach(f -> connectionTracker.getOrCreate(f.tuple));
                }
            });
        }

        // --- LB threads feed FP queues ---
        // LBs just do consistent hashing and dispatch
        int[] lbDispatch = new int[numLbs];

        for (RawPacket raw : allPackets) {
            ParsedPacket pkt = packetParser.parse(raw);
            if (pkt == null || !pkt.hasIp) {
                // Non-IP: go directly to output
                outputQueue.put(raw);
                continue;
            }

            FiveTuple tuple   = pkt.toFiveTuple();
            int lbIdx         = Math.abs(tuple.hashCode()) % numLbs;
            int fpLocalIdx    = Math.abs(tuple.hashCode() >> 1) % numFps;
            int fpGlobalIdx   = lbIdx * numFps + fpLocalIdx;

            lbDispatch[lbIdx]++;
            fpQueues[fpGlobalIdx].put(pkt);
        }

        // Signal FP threads that input is exhausted (drain wait)
        fpDone.await(30, TimeUnit.SECONDS);
        fpExecutor.shutdownNow();

        // Drain remaining output queue
        List<RawPacket> outputPackets = new ArrayList<>();
        outputQueue.drainTo(outputPackets);

        // Aggregate stats
        long totalBytes  = allPackets.stream().mapToLong(p -> p.data.length).sum();
        long tcpPkts     = allPackets.stream()
                                     .map(packetParser::parse)
                                     .filter(p -> p != null && p.hasTcp).count();
        long udpPkts     = allPackets.stream()
                                     .map(packetParser::parse)
                                     .filter(p -> p != null && p.hasUdp).count();
        long totalDropped   = Arrays.stream(fpDropped).mapToLong(AtomicLong::get).sum();
        long totalForwarded = Arrays.stream(fpForwarded).mapToLong(AtomicLong::get).sum();

        // Merge FP flow tables into tracker for report
        for (Map<FiveTuple, Flow> ft : fpFlowTables) {
            ft.forEach((k, v) -> connectionTracker.getOrCreate(k));
        }

        byte[] outputPcap = pcapReader.writeAll(outputPackets);
        DpiReport report  = buildReport(allPackets.size(), totalBytes,
                                        tcpPkts, udpPkts,
                                        totalForwarded, totalDropped);

        return new DpiResult(outputPcap, report);
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    /**
     * Check if bytes look like a TLS ClientHello without caring about port.
     * Allows detection of TLS on non-standard ports.
     */
    private boolean isTlsClientHello(byte[] payload) {
        return payload != null && payload.length > 5 &&
               (payload[0] & 0xFF) == 0x16 &&
               (payload[5] & 0xFF) == 0x01;
    }

    /** Port-based app heuristic when no SNI is available */
    private AppType portHeuristic(int dstPort) {
        return switch (dstPort) {
            case 80, 8080, 8000 -> AppType.HTTP;
            case 443, 8443      -> AppType.HTTPS;
            case 53             -> AppType.DNS;
            default             -> AppType.UNKNOWN;
        };
    }

    private DpiReport buildReport(long totalPkts, long totalBytes,
                                  long tcpPkts, long udpPkts,
                                  long forwarded, long dropped) {
        DpiReport report = new DpiReport();
        report.totalPackets = totalPkts;
        report.totalBytes   = totalBytes;
        report.tcpPackets   = tcpPkts;
        report.udpPackets   = udpPkts;
        report.forwarded    = forwarded;
        report.dropped      = dropped;

        // App stats
        Map<AppType, Long> appStats = new HashMap<>();
        Map<String, AppType> detectedSnis = new LinkedHashMap<>();
        List<DpiReport.FlowSummary> flowSummaries = new ArrayList<>();

        for (Flow flow : connectionTracker.allFlows()) {
            appStats.merge(flow.appType, flow.packetCount.get(), Long::sum);

            if (!flow.sni.isEmpty()) {
                detectedSnis.put(flow.sni, flow.appType);
            }

            FiveTuple t = flow.tuple;
            flowSummaries.add(new DpiReport.FlowSummary(
                t.srcIpString(), t.srcPort,
                t.dstIpString(), t.dstPort,
                t.protocol == 6 ? "TCP" : t.protocol == 17 ? "UDP" : "OTHER",
                flow.appType.name(),
                flow.sni,
                flow.blocked,
                flow.packetCount.get(),
                flow.byteCount.get()
            ));
        }

        report.appStats     = appStats;
        report.detectedSnis = detectedSnis;
        report.flows        = flowSummaries;

        return report;
    }

    // =========================================================================
    // RESULT RECORD
    // =========================================================================

    public record DpiResult(byte[] filteredPcap, DpiReport report) {}
}
