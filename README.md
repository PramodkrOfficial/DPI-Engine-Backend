# DPI Engine — Spring Boot Port

Java/Spring Boot port of [perryvegehan/Packet_analyzer](https://github.com/perryvegehan/Packet_analyzer).

> **Only the language has changed** — all logic, architecture, and behaviour are faithful translations of the original C++ code.

---

## Architecture Mapping

| C++ file | Java equivalent |
|---|---|
| `pcap_reader.cpp` | `PcapReader.java` |
| `packet_parser.cpp` | `PacketParser.java` |
| `sni_extractor.cpp` | `SniExtractor.java` |
| `types.h / types.cpp` | `AppType.java`, `FiveTuple.java`, `Flow.java` |
| `rule_manager.h` | `RuleManager.java` |
| `connection_tracker.h` | `ConnectionTracker.java` |
| `main_working.cpp` | `DpiEngineService.processSingleThreaded()` |
| `dpi_mt.cpp` | `DpiEngineService.processMultiThreaded()` |
| *(new)* | `DpiController.java` — REST API |

---

## Building

```bash
./mvnw clean package -DskipTests
java -jar target/dpi-engine-2.0.0.jar
```

Or with Maven installed:
```bash
mvn clean package -DskipTests
java -jar target/dpi-engine-2.0.0.jar
```

---

## REST API

### Analyze a PCAP (JSON report)
```bash
curl -F "file=@capture.pcap" http://localhost:8080/api/analyze
```

### Filter a PCAP (download filtered PCAP, single-threaded)
```bash
curl -F "file=@capture.pcap" http://localhost:8080/api/filter --output filtered.pcap
```

### Filter a PCAP (multi-threaded — mirrors dpi_mt.cpp)
```bash
curl -F "file=@capture.pcap" \
     -F "lbs=2" -F "fps=2" \
     http://localhost:8080/api/filter/threaded --output filtered_mt.pcap
```

### Rule Management
```bash
# View current rules
curl http://localhost:8080/api/rules

# Block an IP
curl -X POST http://localhost:8080/api/rules/ip/192.168.1.50

# Block an app
curl -X POST http://localhost:8080/api/rules/app/YOUTUBE

# Block a domain substring
curl -X POST http://localhost:8080/api/rules/domain/tiktok

# Unblock
curl -X DELETE http://localhost:8080/api/rules/ip/192.168.1.50
curl -X DELETE http://localhost:8080/api/rules/app/YOUTUBE
curl -X DELETE http://localhost:8080/api/rules/domain/tiktok

# Clear all rules
curl -X DELETE http://localhost:8080/api/rules
```

---

## What the DPI Engine Does

1. **Reads** a PCAP file (Wireshark / tcpdump capture)
2. **Parses** Ethernet → IPv4 → TCP/UDP headers
3. **Inspects** TLS Client Hello to extract the SNI (domain name) — even for HTTPS traffic
4. **Classifies** each flow as YouTube, Facebook, Netflix, etc.
5. **Applies** blocking rules (by IP, app type, or domain substring)
6. **Outputs** a filtered PCAP with blocked packets removed + a JSON report

---

## Supported App Types

`YOUTUBE`, `FACEBOOK`, `TWITTER`, `INSTAGRAM`, `TIKTOK`, `NETFLIX`,
`AMAZON`, `MICROSOFT`, `APPLE`, `GITHUB`, `CLOUDFLARE`, `TWITCH`,
`DISCORD`, `REDDIT`, `LINKEDIN`, `WHATSAPP`, `TELEGRAM`, `ZOOM`,
`DROPBOX`, `GOOGLE`, `HTTP`, `HTTPS`, `DNS`, `UNKNOWN`

---

## Requirements

- Java 17+
- Maven 3.8+ (or use the included `mvnw` wrapper)
