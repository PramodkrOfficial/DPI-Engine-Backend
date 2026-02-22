package com.dpiengine.service;

import com.dpiengine.model.Flow;
import com.dpiengine.model.FiveTuple;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Maintains per-flow state across packets.
 * Equivalent to the flow table (map<FiveTuple, Flow>) used in the C++ DPI engine.
 *
 * In the multi-threaded C++ version, each FastPath thread had its OWN flow table
 * (consistent hashing ensured the same flow always went to the same FP thread).
 *
 * In this Spring Boot port, a single ConcurrentHashMap provides thread safety.
 * The multi-threaded version (DpiEngineService) mirrors the C++ architecture
 * using Java's ExecutorService.
 */
@Service
public class ConnectionTracker {

    private final Map<FiveTuple, Flow> flows = new ConcurrentHashMap<>();

    /**
     * Get the existing flow for a 5-tuple, or create a new one.
     * Equivalent to flows[tuple] in the C++ code.
     */
    public Flow getOrCreate(FiveTuple tuple) {
        return flows.computeIfAbsent(tuple, Flow::new);
    }

    /**
     * Look up a flow without creating it.
     */
    public Flow get(FiveTuple tuple) {
        return flows.get(tuple);
    }

    public Collection<Flow> allFlows() {
        return Collections.unmodifiableCollection(flows.values());
    }

    public int flowCount() {
        return flows.size();
    }

    public void clear() {
        flows.clear();
    }
}
