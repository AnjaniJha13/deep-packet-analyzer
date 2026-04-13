# 🚀 Deep Packet Analyzer (Java)

A multithreaded Deep Packet Inspection (DPI) engine built using Java and Pcap4J to analyze, classify, and filter network traffic from PCAP files.

---

## 🔥 Features

- 📦 PCAP file parsing
- 🌐 TCP / UDP packet analysis
- 🔍 DNS inspection (domain extraction)
- 🔐 HTTPS detection with basic SNI parsing
- 🚫 Rule-based blocking (e.g., YouTube)
- ⚙️ Multithreading with load balancing
- 📊 Tabular packet visualization
- 📈 Enterprise-style dashboard with statistics

---

## 🛠 Tech Stack

- Java
- Maven
- Pcap4J
- Npcap (Windows)

---

## 📊 Sample Output
+-----+--------+-------------------+-------------------+-------+------------------+-------+-----------+
| No | Proto | Source IP | Destination IP | Port | Application | Size | Action |
+-----+--------+-------------------+-------------------+-------+------------------+-------+-----------+
| 1 | UDP | 192.168.1.1 | 192.168.1.2 | 53 | DNS | 70 | FORWARDED |
| 2 | TCP | 192.168.1.1 | 142.250.183.14 | 443 | YouTube | 512 | BLOCKED |


---

## 🧠 Architecture
PCAP Reader → Load Balancer → Worker Threads → DPI Engine → Rule Engine → Dashboard


---

## ▶️ How to Run

```bash
mvn compile
mvn exec:java

---

### 3️⃣ Save and close

---

### 4️⃣ Push it to GitHub

```bash
git add README.md
git commit -m "Added professional README"
git push
