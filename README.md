# PQC TLS 1.3 Telemetry Parser

**Author:** Huy Doan

**Project:** *Agility at the Boundary: Modeling Protection State Degradation during Hybrid Classical-Quantum TLS 1.3 Session Negotiation*

## Overview

This repository contains the telemetry extraction engine (`telemetry_parser.py`) for our research on Post-Quantum Cryptography (PQC) integration within TLS 1.3. This script is designed to process raw network traffic captures (`.pcap`/`.pcapng`) generated from our testbed.

Its function is to automatically parsing hybrid handshake packets to evaluate performance friction and map the degradation of cryptographic protection states under injected network impairments.

## Features & Extracted Metrics

The script utilizes `pyshark` (a Python wrapper for `tshark`) to inspect the TLS and TCP layers, extracting 4 evaluation metrics required for our dataset:

### Injected Parameters
* **Injected Latency, Loss, & Jitter:** Automatically parsed from the filename (e.g., `hybrid_L100_J20_P5.pcap`).

### Observed Metrics (from PCAP)
1. **Handshake Completion Time (Latency):** Calculates the precise delta (in milliseconds) between the initial `TCP SYN` and the client's `TLS Finished` message.
2. **Observed Network RTT:** Measures the actual network round-trip time calculated from the initial `TCP SYN` to `TCP SYN-ACK` handshake.
3. **Observed Jitter:** Calculates the standard deviation of packet inter-arrival times, capturing the impact of jitter on the packet stream.
4. **IP Fragmentation Rate:** Inspects IPv4 `flags_mf` and `frag_offset` to count fragmented packets caused by oversized PQC payloads exceeding standard MTU limits.
5. **TCP Retransmissions:** Analyzes TCP flags to count physical packet retransmissions, validating the impact of network packet loss.

## Usage Instructions

1. **Prepare Captures:** Place all testbed network capture files into a directory named `captures/` in the same folder as the script. Ensure filenames follow the taxonomy `scenario_L[latency]_J[jitter]_P[loss].pcap` (e.g., `hybrid_L100_J20_P5.pcap`).
2. **Execute Parser:**
```bash
python3 telemetry_parser.py
```
3. **Output:** The script will process all captures in bulk and generate a structured `raw_dataset.csv` file, ready to be loaded into Pandas or DuckDB for data visualization and Markov state-transition modeling.
