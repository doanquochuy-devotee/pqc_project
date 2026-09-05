# PQC TLS 1.3 Telemetry Parser

**Author:** Huy Doan

**Project:** *Agility at the Boundary: Modeling Protection State Degradation during Hybrid Classical-Quantum TLS 1.3 Session Negotiation*

## Overview

This repository contains the core telemetry extraction engine (`telemetry_parser.py`) for our research on Post-Quantum Cryptography (PQC) integration within TLS 1.3. As part of Phase 2 of the project, this script is designed to process raw network traffic captures (`.pcap`/`.pcapng`) generated from our isolated Docker/Mininet testbed.

Its primary function is to strictly fulfill the data engineering mandate of the project: automatically parsing hybrid handshake packets to evaluate performance friction and mathematically map the degradation of cryptographic protection states under injected network impairments.

## Core Features & Extracted Metrics

The script utilizes `pyshark` (a Python wrapper for `tshark`) to inspect the TLS and TCP layers, extracting the exact 4 evaluation metrics required for our dataset:

1. **Handshake Completion Time (Latency):** Calculates the precise RTT (in milliseconds) delta between the initial `TCP SYN` and the client's `TLS Finished` (Record Type 22) message.
2. **Packet Loss (TCP Retransmissions):** Analyzes TCP flags to count physical packet retransmissions, validating the actual impact of the `netem` packet loss injection.
3. **Fragmentation Rate:** Inspects the IPv4 `flags_mf` and `frag_offset` to count fragmented packets caused by oversized PQC payloads exceeding standard MTU limits.
4. **Negotiated Cryptographic State:** Deep-inspects the `ServerHello` (Handshake Type 2) `key_share` extension to classify the session's final protection state:
* **$S_1$ (Hybrid/PQC):** Successful negotiation of quantum-safe groups (e.g., `p256_mlkem768`, group ID `1113`/`0x0459`).
* **$S_2$ (Fallback):** Degradation to classical cryptography (e.g., ECDHE X25519, group ID `29`).
* **$S_F$ (Failure):** Connection timeout or fatal handshake alert.


## Current Status

**Testing Phase:** The script has been successfully validated against a preliminary real-world sample (`hybrid_L100_P5.pcap`). The parser accurately captured state degradation ($S_2$ fallback to Group 29) alongside 9 TCP retransmissions, confirming its readiness to process the full batch of experimental captures from the network team.

## Usage Instructions

1. **Prepare Captures:** Place all testbed network capture files (`.pcap` or `.pcapng`) into a directory named `captures/` in the same folder as the script. Ensure filenames follow the taxonomy `hybrid_L[latency]_P[loss].pcap` (e.g., `hybrid_L100_P5.pcap`) so the script can auto-label the injected variables.
2. **Execute Parser:**
```bash
python3 telemetry_parser.py

```

3. **Output:** The script will process all captures in bulk and generate a structured `raw_dataset.csv` file. This dataset is fully sanitized, sorted, and ready to be loaded into Pandas or DuckDB for data visualization and Markov state-transition modeling.