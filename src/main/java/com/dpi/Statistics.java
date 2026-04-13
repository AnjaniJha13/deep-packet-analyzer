package com.dpi;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.ConcurrentHashMap;

public class Statistics {

    public static AtomicInteger totalPackets = new AtomicInteger(0);
    public static AtomicInteger tcpPackets = new AtomicInteger(0);
    public static AtomicInteger udpPackets = new AtomicInteger(0);
    public static AtomicInteger forwarded = new AtomicInteger(0);
    public static AtomicInteger dropped = new AtomicInteger(0);

    public static ConcurrentHashMap<String, AtomicInteger> appCount = new ConcurrentHashMap<>();

    public static void incrementApp(String app) {
        appCount.putIfAbsent(app, new AtomicInteger(0));
        appCount.get(app).incrementAndGet();
    }
}