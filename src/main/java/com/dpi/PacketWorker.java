package com.dpi;

import org.pcap4j.packet.*;
import java.util.concurrent.BlockingQueue;

public class PacketWorker implements Runnable {

    private BlockingQueue<Packet> queue;
    private int workerId;

    public PacketWorker(BlockingQueue<Packet> queue, int id) {
        this.queue = queue;
        this.workerId = id;
    }

    @Override
    public void run() {

        try {
            while (true) {

                Packet packet = this.queue.take();
                Statistics.totalPackets.incrementAndGet();

                String application = "Unknown";
                boolean blocked = false;

                if (packet.contains(TcpPacket.class)) {
                    Statistics.tcpPackets.incrementAndGet();
                    TcpPacket tcp = packet.get(TcpPacket.class);

                    int port = tcp.getHeader().getDstPort().valueAsInt();

                    if (port == 443) {
                        application = "HTTPS";

                        // 🔥 SNI Extraction
                        if (tcp.getPayload() != null) {
                            byte[] raw = tcp.getPayload().getRawData();
                            String data = new String(raw);

                            if (data.contains("youtube")) {
                                blocked = true;
                                application = "YouTube";
                            }
                        }
                    }
                }

                else if (packet.contains(UdpPacket.class)) {
                    Statistics.udpPackets.incrementAndGet();

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
                                blocked = true;
                                application = "YouTube";
                            }
                        }
                    }
                }

                if (blocked) {
                    Statistics.dropped.incrementAndGet();
                } else {
                    Statistics.forwarded.incrementAndGet();
                }

                Statistics.incrementApp(application);

                System.out.println("Worker " + this.workerId + " processed packet → " + application);
            }
        } catch (Exception ignored) {}
    }
}