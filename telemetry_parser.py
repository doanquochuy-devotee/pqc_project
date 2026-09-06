"""
Agility at the Boundary: PQC TLS 1.3 Telemetry Parser
--------------------------------------------------
Author: Huy Doan
Objective: Extract handshake completion time, IP fragmentation counts,
           and negotiated cryptographic states from raw PCAP files.
"""

import os
import re
import glob
import pyshark
import pandas as pd
import numpy as np
import asyncio
import warnings

# --- WARNING FILTERS & MONKEY PATCH ---
warnings.filterwarnings("ignore", category=DeprecationWarning)

try:
    asyncio.get_event_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

def parse_pcap_files(pcap_dir, output_csv):
    """
    Scans the directory for PCAP files, extracts TLS/TCP telemetry, and writes a unified CSV.
    """
    pcap_files = glob.glob(os.path.join(pcap_dir, "*.pcap")) + glob.glob(os.path.join(pcap_dir, "*.pcapng"))
    
    if not pcap_files:
        print(f"[!] No PCAP files found in directory: {pcap_dir}")
        print("[*] Please ensure you have placed your test captures there.")
        return False

    print(f"[*] Found {len(pcap_files)} file(s) for parsing.")
    dataset = []

    for filepath in pcap_files:
        filename = os.path.basename(filepath)
        print(f"\n[+] Analyzing: {filename}")

        # --- 1. PARSE INJECTED IMPAIRMENTS FROM FILENAME (INDEPENDENT VARIABLES) ---
        # Supports regex variations: 
        # - hybrid_L100_P5.pcap -> Latency=100ms, Jitter=0ms, Loss=5%
        # - hybrid_L100_J10_P5.pcap -> Latency=100ms, Jitter=10ms, Loss=5%
        latency_injected = 0
        jitter_injected = 0
        loss_injected = 0
        
        # Check for Latency and Loss
        lat_match = re.search(r"[Ll](\d+)", filename)
        loss_match = re.search(r"[Pp](\d+)", filename)
        jit_match = re.search(r"[Jj](\d+)", filename)
        
        if lat_match:
            latency_injected = int(lat_match.group(1))
        if loss_match:
            loss_injected = int(loss_match.group(1))
        if jit_match:
            jitter_injected = int(jit_match.group(1))
            
        print(f"    -> Injected Metrics (Design Parameters): Latency = {latency_injected}ms, Jitter = {jitter_injected}ms, Loss = {loss_injected}%")

        # --- 2. INITIALIZE TELEMETRY METRICS (DEPENDENT VARIABLES) ---
        tcp_syn_time = None
        tcp_syn_ack_time = None
        tls_finished_time = None
        fragment_count = 0
        tcp_retransmissions = 0
        negotiated_state = "SF"  # Default to 'SF' (Connection Failure / Timeout)
        negotiated_group = "Unknown"
        
        packet_timestamps = []  # To calculate empirical jitter from packet inter-arrival times

        # --- 3. EXECUTE PYSHARK PACKET SCAN ---
        cap = pyshark.FileCapture(
            filepath, 
            display_filter="tcp",
            keep_packets=False  # Crucial for memory management on local macOS
        )

        try:
            for packet in cap:
                # Store sniff timestamp for packet-level statistics
                sniff_time_sec = float(packet.sniff_time.timestamp())
                packet_timestamps.append(sniff_time_sec)

                # A. Track IP Fragmentation (Evaluating IPv4 layer flags)
                if "IP" in packet:
                    try:
                        flags_mf = int(packet.ip.flags_mf) if hasattr(packet.ip, "flags_mf") else 0
                        frag_offset = int(packet.ip.frag_offset) if hasattr(packet.ip, "frag_offset") else 0
                        
                        if flags_mf == 1 or frag_offset > 0:
                            fragment_count += 1
                    except (ValueError, AttributeError):
                        pass

                # B. Record TCP SYN, SYN-ACK and TCP Retransmissions
                if "TCP" in packet:
                    try:
                        # 1. Count TCP Retransmissions (Empirical Packet Loss Impact)
                        if hasattr(packet.tcp, "analysis_retransmission"):
                            tcp_retransmissions += 1
                        
                        # 2. Track SYN and SYN-ACK to calculate pure network Round Trip Time (RTT)
                        flags = int(packet.tcp.flags, 16)
                        if (flags & 0x002):  # SYN is present
                            if not (flags & 0x010):  # ACK is not present -> Client TCP SYN
                                if tcp_syn_time is None:
                                    tcp_syn_time = sniff_time_sec
                            else:  # ACK is present -> Server TCP SYN-ACK
                                if tcp_syn_ack_time is None:
                                    tcp_syn_ack_time = sniff_time_sec
                    except (ValueError, AttributeError):
                        pass

                # C. Evaluate Cryptographic Handshake Messages
                if "TLS" in packet:
                    try:
                        # Parse ServerHello (Handshake Type = 2) to identify negotiated group
                        if hasattr(packet.tls, "handshake_type") and packet.tls.handshake_type == "2":
                            if hasattr(packet.tls, "handshake_extensions_key_share_group"):
                                group_id = str(packet.tls.handshake_extensions_key_share_group)
                                negotiated_group = group_id
                                
                                # 0x1113 (4371) or 0x0459 (1113) represents PQ/Hybrid groups (p256_mlkem768)
                                if "1113" in group_id or "mlkem" in group_id.lower() or "0x0459" in group_id.lower():
                                    negotiated_state = "S1"  # Successful Hybrid Quantum-Safe Negotiation
                                else:
                                    negotiated_state = "S2"  # Degraded to Classical (e.g., ECDHE)
                        
                        # Detect Handshake Finished / Encrypted Handshake Message from Client (Record Type = 22)
                        if hasattr(packet.tls, "record_content_type") and packet.tls.record_content_type == "22":
                            tls_finished_time = sniff_time_sec
                            
                    except AttributeError:
                        pass

        except Exception as e:
            print(f"    [!] Parsing error on packet stream: {e}")
        finally:
            cap.close()

        # --- 4. DATA METRIC SYNTHESIS & EMPIRICAL CALCULATIONS ---
        
        # A. Handshake Completion Time (End-to-End Handshake Latency)
        if tcp_syn_time and tls_finished_time and negotiated_state != "SF":
            handshake_time_ms = (tls_finished_time - tcp_syn_time) * 1000.0
            if handshake_time_ms < 0:
                handshake_time_ms = np.nan
                negotiated_state = "SF"
        else:
            handshake_time_ms = np.nan
            negotiated_state = "SF"  # Handshake timeout / failure

        # B. Pure Observed Network RTT (First TCP SYN -> Server SYN-ACK)
        if tcp_syn_time and tcp_syn_ack_time:
            observed_rtt_ms = (tcp_syn_ack_time - tcp_syn_time) * 1000.0
        else:
            observed_rtt_ms = np.nan

        # C. Empirical Packet-to-Packet Jitter (Standard Deviation of Inter-Arrival Times)
        if len(packet_timestamps) > 1:
            # Calculate the time interval between consecutive packets in milliseconds
            deltas = np.diff(packet_timestamps) * 1000.0
            # Standard deviation represents packet delay variation (Jitter)
            observed_jitter_ms = np.std(deltas)
        else:
            observed_jitter_ms = np.nan

        print(f"    -> Results: State = {negotiated_state} | Handshake Time = {handshake_time_ms:.2f} ms")
        print(f"                Observed RTT = {observed_rtt_ms:.2f} ms | Observed Jitter = {observed_jitter_ms:.2f} ms")
        print(f"                Fragments = {fragment_count} | TCP Retransmissions = {tcp_retransmissions}")

        # Append structured telemetry row containing both Design and Empirical parameters
        dataset.append({
            "Latency_Injected": latency_injected,
            "Jitter_Injected": jitter_injected,
            "Packet_Loss_Injected": loss_injected,
            "Handshake_Completion_Time_ms": handshake_time_ms,
            "Observed_Network_RTT_ms": observed_rtt_ms,
            "Observed_Jitter_ms": observed_jitter_ms,
            "IP_Fragmentation_Count": fragment_count,
            "TCP_Retransmissions": tcp_retransmissions,
            "Final_Negotiated_State": negotiated_state,
            "Negotiated_Group": negotiated_group
        })

    # --- 5. COMPILE AND EXPORT CLEAN DATASET ---
    df = pd.DataFrame(dataset)
    df = df.sort_values(by=["Latency_Injected", "Jitter_Injected", "Packet_Loss_Injected"])
    df.to_csv(output_csv, index=False)
    print(f"\n[+] Processing Complete! Dataset successfully exported to: {output_csv}")
    return True

if __name__ == "__main__":
    CURRENT_DIR = os.path.dirname(os.path.abspath(__file__)) if "__file__" in locals() else os.getcwd()
    CAPTURE_DIR = os.path.join(CURRENT_DIR, "captures")
    OUTPUT_FILE = os.path.join(CURRENT_DIR, "raw_dataset.csv")

    if not os.path.exists(CAPTURE_DIR):
        os.makedirs(CAPTURE_DIR)
        print(f"[*] Created empty '{CAPTURE_DIR}' folder.")
    else:
        parse_pcap_files(CAPTURE_DIR, OUTPUT_FILE)
