package com.dpi;

import org.pcap4j.packet.Packet;
import java.util.concurrent.BlockingQueue;

public class LoadBalancer {

    private BlockingQueue<Packet>[] workers;
    private int index = 0;

    public LoadBalancer(BlockingQueue<Packet>[] workers) {
        this.workers = workers;
    }

    public void dispatch(Packet packet) throws InterruptedException {
        this.workers[this.index].put(packet);
        this.index = (this.index + 1) % this.workers.length;
    }
}