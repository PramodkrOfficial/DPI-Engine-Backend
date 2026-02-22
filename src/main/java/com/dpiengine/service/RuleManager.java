package com.dpiengine.service;

import com.dpiengine.model.AppType;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * Manages blocking rules (IP, app type, domain substring).
 * Direct Java port of rule_manager.h in the C++ multi-threaded version.
 *
 * Thread-safe so it can be shared across FastPath worker threads.
 */
@Service
public class RuleManager {

    /** Source IPs that should be blocked */
    private final Set<Long> blockedIps = new CopyOnWriteArraySet<>();

    /** Application types that should be blocked */
    private final Set<AppType> blockedApps = new CopyOnWriteArraySet<>();

    /**
     * Domain substrings to block.
     * Any SNI containing one of these strings (case-insensitive) is blocked.
     */
    private final Set<String> blockedDomains = new CopyOnWriteArraySet<>();

    // ---- Rule management ----

    public void blockIp(String dotted) {
        blockedIps.add(parseIp(dotted));
    }

    public void unblockIp(String dotted) {
        blockedIps.remove(parseIp(dotted));
    }

    public void blockApp(AppType app) {
        blockedApps.add(app);
    }

    public void unblockApp(AppType app) {
        blockedApps.remove(app);
    }

    /** Block any SNI containing this substring (e.g. "tiktok", "facebook") */
    public void blockDomain(String substring) {
        blockedDomains.add(substring.toLowerCase());
    }

    public void unblockDomain(String substring) {
        blockedDomains.remove(substring.toLowerCase());
    }

    public void clearAll() {
        blockedIps.clear();
        blockedApps.clear();
        blockedDomains.clear();
    }

    // ---- Decision ----

    /**
     * Return true if a packet/flow should be blocked.
     * Equivalent to RuleManager::isBlocked() in rule_manager.cpp
     *
     * @param srcIp   source IP (unsigned 32-bit in long)
     * @param appType classified app
     * @param sni     SNI hostname (may be empty)
     */
    public boolean isBlocked(long srcIp, AppType appType, String sni) {
        if (blockedIps.contains(srcIp))   return true;
        if (blockedApps.contains(appType)) return true;

        if (sni != null && !sni.isEmpty()) {
            String lower = sni.toLowerCase();
            for (String domain : blockedDomains) {
                if (lower.contains(domain)) return true;
            }
        }

        return false;
    }

    // ---- Getters for reporting ----

    public Set<Long>    getBlockedIps()     { return blockedIps; }
    public Set<AppType> getBlockedApps()    { return blockedApps; }
    public Set<String>  getBlockedDomains() { return blockedDomains; }

    private static long parseIp(String dotted) {
        String[] parts = dotted.split("\\.");
        long result = 0;
        for (String p : parts) result = (result << 8) | (Integer.parseInt(p) & 0xFF);
        return result;
    }
}
