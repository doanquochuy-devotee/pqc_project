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

# --- EVENT LOOP HOTFIX FOR PYTHON 3.10+ ---
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

        # --- 1. PARSE INJECTED IMPAIRMENTS FROM FILENAME ---
        latency_injected = 0
        loss_injected = 0
        
        match = re.search(r"[Ll](\d+)_?[Pp](\d+)", filename)
        if match:
            latency_injected = int(match.group(1))
            loss_injected = int(match.group(2))
            print(f"    -> Detected Injected Faults: Latency = {latency_injected}ms, Loss = {loss_injected}%")
        else:
            print(f"    -> [Warning] Filename does not match 'L[ms]_P[%]' pattern. Defaulting metrics to 0.")

        # --- 2. INITIALIZE TELEMETRY METRICS ---
        tcp_syn_time = None
        tls_finished_time = None
        fragment_count = 0
        tcp_retransmissions = 0
        negotiated_state = "SF"  # Default to 'SF' (Connection Failure / Timeout)
        negotiated_group = "Unknown"

        # --- 3. EXECUTE PYSHARK PACKET SCAN ---
        # Note: We filter for "tcp" which naturally includes "tls" traffic
        cap = pyshark.FileCapture(
            filepath, 
            display_filter="tcp",
            keep_packets=False  # Crucial for memory management on local macOS
        )

        try:
            for packet in cap:
                # A. Track IP Fragmentation (Evaluating IPv4 layer flags)
                if "IP" in packet:
                    try:
                        flags_mf = int(packet.ip.flags_mf) if hasattr(packet.ip, "flags_mf") else 0
                        frag_offset = int(packet.ip.frag_offset) if hasattr(packet.ip, "frag_offset") else 0
                        
                        if flags_mf == 1 or frag_offset > 0:
                            fragment_count += 1
                    except (ValueError, AttributeError):
                        pass

                # B. Record High-Resolution Timestamp of the First TCP SYN & Count Retransmissions
                if "TCP" in packet:
                    try:
                        # 1. Count TCP Retransmissions (Empirical Packet Loss Impact)
                        if hasattr(packet.tcp, "analysis_retransmission"):
                            tcp_retransmissions += 1
                        
                        # 2. Track initial SYN packet
                        flags = int(packet.tcp.flags, 16)
                        if (flags & 0x002) and not (flags & 0x010):  # SYN=1, ACK=0
                            if tcp_syn_time is None:
                                tcp_syn_time = float(packet.sniff_time.timestamp())
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
                            tls_finished_time = float(packet.sniff_time.timestamp())
                            
                    except AttributeError:
                        pass

        except Exception as e:
            print(f"    [!] Parsing error on packet stream: {e}")
        finally:
            cap.close()

        # --- 4. CALCULATE HIGH-RESOLUTION TIME DELTA ---
        if tcp_syn_time and tls_finished_time and negotiated_state != "SF":
            handshake_time_ms = (tls_finished_time - tcp_syn_time) * 1000.0
            if handshake_time_ms < 0:
                handshake_time_ms = np.nan
                negotiated_state = "SF"
        else:
            handshake_time_ms = np.nan
            negotiated_state = "SF"  # Handshake timeout / failure

        print(f"    -> Results: State = {negotiated_state} | Handshake Time = {handshake_time_ms:.2f} ms | Fragments = {fragment_count} | TCP Retransmissions = {tcp_retransmissions}")

        # Append structured telemetry row
        dataset.append({
            "Latency_Injected": latency_injected,
            "Packet_Loss_Injected": loss_injected,
            "Handshake_Completion_Time_ms": handshake_time_ms,
            "IP_Fragmentation_Count": fragment_count,
            "TCP_Retransmissions": tcp_retransmissions,
            "Final_Negotiated_State": negotiated_state,
            "Negotiated_Group": negotiated_group
        })

    # --- 5. COMPILE AND EXPORT CLEAN DATASET ---
    df = pd.DataFrame(dataset)
    df = df.sort_values(by=["Latency_Injected", "Packet_Loss_Injected"])
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
