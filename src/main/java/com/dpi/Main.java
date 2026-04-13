package com.dpi;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.ConcurrentHashMap;

public class Main {

    private static final String BORDER =
            "+-----+--------+-------------------+-------------------+-------+------------------+-------+-----------+";

    static AtomicInteger total = new AtomicInteger(0);
    static AtomicInteger forwarded = new AtomicInteger(0);
    static AtomicInteger dropped = new AtomicInteger(0);

    static ConcurrentHashMap<String, AtomicInteger> appStats = new ConcurrentHashMap<>();

    public static void main(String[] args) {

        String file = "input.pcap";

        try {
            PcapHandle handle = Pcaps.openOffline(file);

            System.out.println("\n===================== DEEP PACKET ANALYZER =====================\n");
            System.out.println(BORDER);
            System.out.printf("| %-3s | %-6s | %-17s | %-17s | %-5s | %-16s | %-5s | %-9s |\n",
                    "No", "Proto", "Source IP", "Destination IP",
                    "Port", "Application", "Size", "Action");
            System.out.println(BORDER);

            Packet packet;

            while ((packet = handle.getNextPacket()) != null) {

                int id = total.incrementAndGet();

                String protocol = "Unknown";
                String srcIp = "-";
                String dstIp = "-";
                String port = "-";
                String application = "Unknown";
                String action = "FORWARDED";

                int size = packet.length();

                if (packet.contains(IpV4Packet.class)) {
                    IpV4Packet ip = packet.get(IpV4Packet.class);
                    srcIp = ip.getHeader().getSrcAddr().getHostAddress();
                    dstIp = ip.getHeader().getDstAddr().getHostAddress();
                }

                if (packet.contains(TcpPacket.class)) {
                    protocol = "TCP";
                    TcpPacket tcp = packet.get(TcpPacket.class);
                    port = String.valueOf(tcp.getHeader().getDstPort().valueAsInt());

                    if (port.equals("443")) {
                        application = "HTTPS";

                        // Basic SNI detection (raw payload check)
                        if (packet.getPayload() != null) {
                            String payload = new String(packet.getPayload().getRawData());

                            if (payload.toLowerCase().contains("youtube")) {
                                application = "YouTube";
                                action = "BLOCKED";
                            }
                        }
                    }
                }

                else if (packet.contains(UdpPacket.class)) {
                    protocol = "UDP";
                    UdpPacket udp = packet.get(UdpPacket.class);
                    port = String.valueOf(udp.getHeader().getDstPort().valueAsInt());

                    if (packet.contains(DnsPacket.class)) {
                        DnsPacket dns = packet.get(DnsPacket.class);
                        if (!dns.getHeader().getQuestions().isEmpty()) {
                            String domain = dns.getHeader()
                                    .getQuestions()
                                    .get(0)
                                    .getQName()
                                    .getName();

                            application = "DNS";

                            if (domain.toLowerCase().contains("youtube")) {
                                application = "YouTube";
                                action = "BLOCKED";
                            }
                        }
                    }
                }

                if (action.equals("BLOCKED")) dropped.incrementAndGet();
                else forwarded.incrementAndGet();

                appStats.putIfAbsent(application, new AtomicInteger(0));
                appStats.get(application).incrementAndGet();

                System.out.printf("| %-3d | %-6s | %-17s | %-17s | %-5s | %-16s | %-5d | %-9s |\n",
                        id, protocol, srcIp, dstIp, port,
                        application, size, action);
            }

            System.out.println(BORDER);

            printDashboard();

            handle.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void printDashboard() {

        System.out.println("\n================ ENTERPRISE DASHBOARD =================");
        System.out.println("Total Packets  : " + total.get());
        System.out.println("Forwarded      : " + forwarded.get());
        System.out.println("Dropped        : " + dropped.get());

        System.out.println("\nApplication Breakdown:");

        appStats.forEach((app, count) -> {
            double percent = (count.get() * 100.0) / total.get();
            System.out.printf("%-10s : %-5d (%.2f%%)\n",
                    app, count.get(), percent);
        });

        System.out.println("=======================================================\n");
    }
}