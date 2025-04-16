# Evasive DNS Tunneling Client (AES + Base32 + Timing)

## ⚠️ Disclaimer & Important Notes ⚠️

* **EDUCATIONAL USE ONLY:** This script demonstrates DNS tunneling techniques for **academic and research purposes** within controlled, isolated laboratory environments.
* **REQUIRES CONTROLLED SERVER:** This is only the **client-side** script. It sends data encoded within DNS queries. To make this work, you **MUST** have a DNS server (e.g., running on Kali Linux in your lab) configured to receive and log queries for the specified `TARGET_DOMAIN` (e.g., `exfil.lab`) or specifically designed to decode this traffic. Without the server component, this script only sends queries into the void (or to the specified IP).
* **DETECTION IS LIKELY:** DNS tunneling is a well-understood technique. Modern security solutions (NGFW, IPS, DNS Firewalls, DNS Monitoring Tools, SIEMs) often have signatures and behavioral analysis rules specifically designed to detect it. Factors like high query volume to a single domain, queries with high entropy or unusual encoding (like Base32), non-existent domain (NXDOMAIN) responses, and direct resolver usage can all trigger alerts.
* **INSECURE KEY:** The AES key is hardcoded in this script for simplicity. In any real scenario, this is insecure. Secure key distribution is necessary.
* **ETHICAL USE:** Unauthorized data exfiltration or network abuse is illegal and unethical. Use responsibly within your authorized lab setting.

## Description

This Python script acts as a client for DNS tunneling. It takes data, encrypts it using AES-GCM, encodes the encrypted result using Base32 (for DNS label safety), splits it into manageable chunks, adds sequence numbers, and then sends each chunk as part of a subdomain in DNS A-record queries to a designated DNS server. Random delays are added between queries to make the traffic less predictable.

The primary goal is to demonstrate how DNS (a typically allowed protocol on port 53) *could* be abused to exfiltrate small amounts of data, potentially bypassing firewalls that block other protocols but allow DNS lookups.

## Features

* **AES-GCM Encryption:** Encrypts the payload data, hiding the content and providing integrity.
* **Base32 Encoding:** Encodes the encrypted binary data into DNS-safe characters (A-Z, 2-7). Slightly less common signature than Base64.
* **Chunking & Sequencing:** Splits data into chunks suitable for DNS labels and adds sequence numbers (`<seq_num>.<chunk>.<domain>`) for potential reassembly on the server side.
* **Variable Timing:** Introduces randomized delays between DNS queries to potentially evade simple rate-based detection.
* **Configurable:** Target domain, DNS server IP, chunk size, and timing delays are configurable.
* **Direct Resolver Use (Lab Focus):** Configured to send queries directly to a specified IP address, simplifying closed lab setups where external DNS might be blocked or the target domain isn't globally resolvable.

## Requirements

* **Python 3:** Script is written for Python 3.x.
* **Libraries:** Install on the client machine (Victim1):
    ```bash
    pip install dnspython pycryptodome
    ```
* **Controlled DNS Server:** A DNS server (e.g., on Kali) configured to receive/log queries for the `TARGET_DOMAIN`. This setup is **not** covered by this script.

## Setup

1.  **Install Dependencies:** Run `pip install dnspython pycryptodome` on Victim1.
2.  **Configure Script:**
    * Edit `evasive_dns_tunnel_client.py`.
    * Set `TARGET_DOMAIN` to the domain your Kali DNS server is authoritative for (e.g., `exfil.lab`).
    * Set `DNS_SERVER_IP` to the IP address of your Kali machine running the DNS server.
    * **CRITICAL:** Set the `AES_KEY` variable. This **must** match the key used by your server-side logic (if any) to decrypt the data. Remember this hardcoded key is insecure.
    * Adjust `CHUNK_LABEL_SIZE`, `MIN_DELAY`, `MAX_DELAY` if needed.
3.  **Setup Kali DNS Server:** Configure a DNS server on Kali (e.g., `dnsmasq`, `bind9`, or a custom script) to log all queries received for `TARGET_DOMAIN` or to actively process them (decode Base32, decrypt AES, reassemble). Standard DNS servers will likely just return NXDOMAIN but log the query.
4.  **Payload:** Modify the `secret_data` variable in the `if __name__ == '__main__':` block to contain the data you want to exfiltrate for the test.

## Usage

1.  **Start DNS Server:** Ensure your DNS server is running on Kali and logging queries for the `TARGET_DOMAIN`.
2.  **Run Client Script:** On Victim1, execute:
    ```bash
    python3 evasive_dns_tunnel_client.py
    ```
3.  **Monitor Server Logs:** Observe the logs on your Kali DNS server. You should see incoming A-record queries for subdomains like `1.[b32_chunk1].exfil.lab`, `2.[b32_chunk2].exfil.lab`, etc. The sequence of Base32 chunks represents the AES-encrypted (Nonce+Tag+Ciphertext) original data.

## How It Works

1.  **Encryption:** The `secret_data` is encrypted using AES-GCM with the hardcoded `AES_KEY`. This outputs `Nonce + Tag + Ciphertext`.
2.  **Encoding:** The binary encrypted result is encoded using Base32, producing a string of uppercase letters and digits (2-7). Padding (`=`) is typically stripped.
3.  **Chunking:** The Base32 string is split into smaller pieces (`chunks`), each no larger than `CHUNK_LABEL_SIZE`.
4.  **Query Construction:** For each `chunk`, a DNS query domain is formed: `<sequence_number>.<chunk>.<TARGET_DOMAIN>`.
5.  **Resolution:** The script configures `dnspython` to use the specified `DNS_SERVER_IP` directly.
6.  **Transmission:** It iterates through the chunks, waits for a random delay, and sends a DNS A-record query for the constructed domain using `resolver.resolve()`. Errors (like timeouts or NXDOMAIN) are generally ignored/logged as the goal is just to get the *query* logged by the controlled server.

## Evasion Considerations & Limitations

* **Payload Confidentiality:** AES effectively hides the content of the exfiltrated data from passive network observers *without* the key.
* **Encoding Obscurity:** Base32 is slightly less common than Base64 in DNS tunneling, potentially bypassing very basic Base64-specific signatures. However, any non-standard encoding or high entropy in DNS labels is suspicious.
* **Timing:** Random delays disrupt uniform traffic patterns, potentially evading simple rate limits or frequency analysis. "Low and slow" (large delays) enhances this but reduces speed.
* **DNS Inspection:** **Major Limitation.** Advanced firewalls/IPS/DNS security tools inspect DNS traffic specifically. They can detect:
    * High volume of unique subdomains queried under a single parent domain.
    * Queries for long, random-looking subdomains (high entropy).
    * Specific encoding patterns (Base64, Base32, Hex).
    * Anomalous query types (e.g., excessive TXT queries, or A/AAAA queries for clearly non-hostname data).
    * Clients bypassing designated internal/ISP resolvers (if direct resolver use is detected).
* **Server-Side:** Assumes a working, controlled DNS server for logging/processing. Reassembly logic is needed on the server.
* **Limited Bandwidth:** DNS tunneling is typically very slow due to query overhead and label size limits.

This enhanced script adds layers compared to basic Base64 tunneling but remains vulnerable to detection by sophisticated DNS monitoring and security platforms. It serves best as an educational tool to understand the principles and challenges of protocol abuse for data exfiltration.