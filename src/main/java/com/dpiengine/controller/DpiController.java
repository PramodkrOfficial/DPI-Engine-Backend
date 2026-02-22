package com.dpiengine.controller;

import com.dpiengine.model.AppType;
import com.dpiengine.model.DpiReport;
import com.dpiengine.service.DpiEngineService;
import com.dpiengine.service.RuleManager;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * REST API for the DPI Engine.
 *
 * Endpoints:
 *
 *   POST /api/analyze
 *     Upload a PCAP file, get back a JSON report.
 *
 *   POST /api/filter
 *     Upload a PCAP file, get back a filtered PCAP file (blocked packets removed).
 *
 *   POST /api/filter/threaded
 *     Same as /filter but uses the multi-threaded processing pipeline.
 *
 *   GET  /api/rules
 *     View current blocking rules.
 *
 *   POST /api/rules/ip/{ip}
 *     Block a source IP address.
 *
 *   DELETE /api/rules/ip/{ip}
 *     Unblock a source IP address.
 *
 *   POST /api/rules/app/{app}
 *     Block an application type (e.g. YOUTUBE, FACEBOOK).
 *
 *   DELETE /api/rules/app/{app}
 *     Unblock an application type.
 *
 *   POST /api/rules/domain/{domain}
 *     Block any SNI containing this substring.
 *
 *   DELETE /api/rules/domain/{domain}
 *     Unblock a domain substring.
 *
 *   DELETE /api/rules
 *     Clear all rules.
 */
@RestController
@RequestMapping("/api")
public class DpiController {

    private final DpiEngineService dpiEngine;
    private final RuleManager      ruleManager;

    public DpiController(DpiEngineService dpiEngine, RuleManager ruleManager) {
        this.dpiEngine   = dpiEngine;
        this.ruleManager = ruleManager;
    }

    // =========================================================================
    // ANALYZE / FILTER ENDPOINTS
    // =========================================================================

    /**
     * Upload a PCAP and receive a JSON analysis report.
     *
     * Example:
     *   curl -F "file=@capture.pcap" http://localhost:8080/api/analyze
     */
    @PostMapping(value = "/analyze", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<DpiReport> analyze(
            @RequestParam("file") MultipartFile file
    ) throws IOException {
        byte[] bytes = file.getBytes();
        DpiEngineService.DpiResult result = dpiEngine.processSingleThreaded(bytes);
        return ResponseEntity.ok(result.report());
    }

    /**
     * Upload a PCAP, receive a filtered PCAP (blocked packets removed).
     *
     * Example:
     *   curl -F "file=@capture.pcap" http://localhost:8080/api/filter --output filtered.pcap
     */
    @PostMapping(value = "/filter", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<byte[]> filter(
            @RequestParam("file") MultipartFile file
    ) throws IOException {
        byte[] bytes  = file.getBytes();
        DpiEngineService.DpiResult result = dpiEngine.processSingleThreaded(bytes);

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"filtered.pcap\"")
                .body(result.filteredPcap());
    }

    /**
     * Same as /filter but uses the multi-threaded pipeline (dpi_mt.cpp equivalent).
     *
     * @param lbs number of Load Balancer threads (default 2)
     * @param fps number of Fast Path threads per LB (default 2)
     */
    @PostMapping(value = "/filter/threaded", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<byte[]> filterThreaded(
            @RequestParam("file")          MultipartFile file,
            @RequestParam(value = "lbs", defaultValue = "2") int lbs,
            @RequestParam(value = "fps", defaultValue = "2") int fps
    ) throws IOException, InterruptedException {
        byte[] bytes  = file.getBytes();
        DpiEngineService.DpiResult result = dpiEngine.processMultiThreaded(bytes, lbs, fps);

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"filtered_mt.pcap\"")
                .body(result.filteredPcap());
    }

    // =========================================================================
    // RULE MANAGEMENT ENDPOINTS
    // =========================================================================

    @GetMapping("/rules")
    public ResponseEntity<Map<String, Object>> getRules() {
        Set<String> blockedIps = ruleManager.getBlockedIps().stream()
                .map(ip -> ((ip >> 24) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "."
                         + ((ip >> 8) & 0xFF) + "." + (ip & 0xFF))
                .collect(Collectors.toSet());

        return ResponseEntity.ok(Map.of(
                "blockedIps",     blockedIps,
                "blockedApps",    ruleManager.getBlockedApps(),
                "blockedDomains", ruleManager.getBlockedDomains()
        ));
    }

    @PostMapping("/rules/ip/{ip}")
    public ResponseEntity<String> blockIp(@PathVariable String ip) {
        ruleManager.blockIp(ip);
        return ResponseEntity.ok("Blocked IP: " + ip);
    }

    @DeleteMapping("/rules/ip/{ip}")
    public ResponseEntity<String> unblockIp(@PathVariable String ip) {
        ruleManager.unblockIp(ip);
        return ResponseEntity.ok("Unblocked IP: " + ip);
    }

    @PostMapping("/rules/app/{app}")
    public ResponseEntity<String> blockApp(@PathVariable String app) {
        AppType type = AppType.valueOf(app.toUpperCase());
        ruleManager.blockApp(type);
        return ResponseEntity.ok("Blocked app: " + type);
    }

    @DeleteMapping("/rules/app/{app}")
    public ResponseEntity<String> unblockApp(@PathVariable String app) {
        AppType type = AppType.valueOf(app.toUpperCase());
        ruleManager.unblockApp(type);
        return ResponseEntity.ok("Unblocked app: " + type);
    }

    @PostMapping("/rules/domain/{domain}")
    public ResponseEntity<String> blockDomain(@PathVariable String domain) {
        ruleManager.blockDomain(domain);
        return ResponseEntity.ok("Blocked domain substring: " + domain);
    }

    @DeleteMapping("/rules/domain/{domain}")
    public ResponseEntity<String> unblockDomain(@PathVariable String domain) {
        ruleManager.unblockDomain(domain);
        return ResponseEntity.ok("Unblocked domain substring: " + domain);
    }

    @DeleteMapping("/rules")
    public ResponseEntity<String> clearRules() {
        ruleManager.clearAll();
        return ResponseEntity.ok("All rules cleared");
    }
}
