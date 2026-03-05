package com.dpiengine;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

/**
 * DPI Engine - Deep Packet Inspection System
 * Spring Boot port of the C++ packet analyzer project by perryvegehan.
 * <a href="https://github.com/perryvegehan/Packet_analyzer">...</a>
 * Architecture mirrors the original:
 *   - PcapReader       ← pcap_reader.cpp
 *   - PacketParser     ← packet_parser.cpp
 *   - SniExtractor     ← sni_extractor.cpp
 *   - RuleManager      ← rule_manager.h
 *   - ConnectionTracker← connection_tracker.h
 *   - DpiEngineService ← main_working.cpp + dpi_mt.cpp
 *   - DpiController    ← REST API wrapper (new in Java version)
 */
@SpringBootApplication
@RestController
public class DpiEngineApplication {

    public static void main(String[] args) {
        SpringApplication.run(DpiEngineApplication.class, args);
    }

    @GetMapping("/status")
    Map<String, Object> status() {
        return Map.of(
                "service", "DPI Engine",
                "status", "running",
                "timestamp", Instant.now()
        );
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of(
                "engine", "healthy",
                "status", "running",
                "timestamp", Instant.now()
        );
    }
}
