# HIP-VPLS with IPsec Authentication Header (AH)

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.6+-blue.svg)](https://python.org)
[![RFC 7401](https://img.shields.io/badge/RFC-7401-green.svg)](https://tools.ietf.org/html/rfc7401)
[![RFC 4302](https://img.shields.io/badge/RFC-4302-green.svg)](https://tools.ietf.org/html/rfc4302)

## About

This repository contains an implementation of VPLS based on the Host Identity Protocol (HIP) with **IPsec Authentication Header (AH)** as the data plane security mechanism.

## Introduction

Host Identity Protocol (HIP) is a layer 3.5 solution initially designed to split the dual role of the IP address: locator and identifier. Using the HIP protocol, one can solve not only mobility problems but also establish authenticated secure channels.

This repository contains a comprehensive implementation of **HIP-VPLS with IPsec AH data plane**, providing:

- **Authentication without encryption** - Inner packets remain visible for debugging
- **RFC 4302 compliant** AH implementation
- **Wireshark-friendly** packet captures
- **HMAC-based integrity** protection
- **Backward compatible** with existing HIP infrastructure

### Key Features

- **IPsec Authentication Header (AH)**: Provides authentication and integrity without encryption
- **HIP Base Exchange**: Complete HIP BEX implementation for secure channel establishment
- **VPLS Functionality**: Layer 2 VPN services over HIP-secured tunnels
- **Mininet Integration**: Ready-to-use simulation environment

### Technical Implementation

The implementation uses **IPsec AH (Protocol 0x33)** instead of ESP for the data plane, ensuring:
- Authentication and integrity protection via HMAC
- Unencrypted payload for network visibility and debugging
- RFC 4302 compliance
- Seamless integration with existing HIP key material

## Development Status

The development is ongoing with Linux as the target system. The implementation is tested using the Mininet simulation environment and provides comprehensive debugging capabilities for troubleshooting data plane issues.

## Quick Start

### Prerequisites

- Linux operating system (Ubuntu 18.04+ recommended)
- Python 3.6 or higher
- Mininet network emulator
- Root privileges for network operations

### Installation

1. **Clone the repository:**
   ```bash
   cd ~
   git clone https://github.com/strangebit-io/hip-vpls-ah.git
   cd hip-vpls-ah
   ```

2. **Deploy the topology:**
   ```bash
   sudo bash deploy.sh
   ```

   If the deployment script is not available, start the topology manually:
   ```bash
   sudo python3 hipls-mn.py
   ```

### Network Topology

The setup consists of:
- **2 HIP routers** (r1, r2) forming the VPLS backbone
- **3 switches** (s1, s2, s5) connecting hosts and routers
- **2 hosts** (h1, h2) that are topology-agnostic

```
h1 ---- s1 ---- r1 ---- s5 ---- r2 ---- s2 ---- h2
     192.168.1.100  192.168.3.1  192.168.3.2  192.168.1.101
```

**Network Details:**
- **h1**: `192.168.1.100/24` → default route via `192.168.1.1` (r1)
- **h2**: `192.168.1.101/24` → default route via `192.168.1.2` (r2)
- **r1-eth0**: `192.168.1.1/24` (host-facing interface)
- **r1-eth1**: `192.168.3.1/29` (backbone interface)
- **r2-eth0**: `192.168.1.2/24` (host-facing interface)
- **r2-eth1**: `192.168.3.2/29` (backbone interface)

### Testing the Implementation

1. **Start the topology:**
   ```bash
   sudo python3 hipls-mn.py
   ```

2. **Wait for HIP Base Exchange (BEX):**
   The BEX should complete in a few seconds. You'll see authentication and key establishment messages in the logs.

3. **Test connectivity with IPsec AH:**
   ```bash
   mininet> h1 ping h2
   ```

4. **Monitor HIP operations:**
   ```bash
   tail -f router1/hipls.log
   ```

### IPsec AH Packet Capture

One of the key advantages of using AH instead of ESP is **packet visibility**. Capture and analyze AH-protected traffic:

```bash
# Capture packets between routers (AH protocol 0x33)
mininet> r2 tcpdump -n -i r2-eth1 -w hip-ah-capture.pcap

# View AH packets in real-time
mininet> r1 tcpdump -n -i r1-eth1 proto 51
```

**Wireshark Analysis:**
- Inner packets (ICMP, ARP, etc.) are **fully visible** and unencrypted
- AH headers show SPI, sequence numbers, and ICV for authentication
- No decryption needed - packets are human-readable

### Debugging Commands

**View switch port status:**
```bash
mininet> s1 ovs-ofctl show "s1"
mininet> s2 ovs-ofctl show "s2"
mininet> s5 ovs-ofctl show "s5"
```

**Monitor AH authentication:**
```bash
# Look for AH-specific debug messages
grep "AH packet" router1/hipls.log
grep "authentication successful" router1/hipls.log
```

**Check HIP state:**
```bash
# Monitor HIP Base Exchange
grep "BEX" router*/hipls.log

# Check Security Association status
grep "SA" router*/hipls.log
```

## Technical Details

### IPsec Authentication Header (AH) Implementation

This implementation uses **IPsec AH (RFC 4302)** instead of ESP for several advantages:

| Feature | ESP | AH (This Implementation) |
|---------|-----|--------------------------|
| **Encryption** | ✅ Yes | ❌ No |
| **Authentication** | ✅ Yes | ✅ Yes |
| **Packet Visibility** | ❌ Encrypted | ✅ Fully Visible |
| **Debugging** | ❌ Difficult | ✅ Easy |
| **Wireshark Analysis** | ❌ Requires Decryption | ✅ Native Support |

### AH Packet Structure

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Next Header   |  Payload Len  |          RESERVED             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Security Parameters Index (SPI)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number Field                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                Integrity Check Value-ICV (variable)          |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Protected Payload (Unencrypted)           |
~                                                               ~
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Key Components

- **Protocol Number**: `0x33` (AH) instead of `0x32` (ESP)
- **Authentication**: HMAC-based Integrity Check Value (ICV)
- **Visibility**: Payload remains unencrypted for analysis
- **Security**: Authentication and anti-replay protection maintained

### Modified Files

| File | Purpose | Changes |
|------|---------|---------|
| `router*/hiplib/packets/IPSec.py` | AH packet implementation | Added `AHPacket` class with RFC 4302 compliance |
| `router*/hiplib/hlib.py` | Packet processing | Replaced ESP encryption with AH authentication |
| `router*/hiplib/databases/SA.py` | Security associations | Maintained compatibility, AES unused for AH |

## Troubleshooting

### Common Issues

**1. Ping fails after BEX completion**
```bash
# Check AH authentication
grep "authentication failed" router*/hipls.log

# Verify packet creation
grep "Creating AH packet" router*/hipls.log

# Check ICV calculation
grep "ICV" router*/hipls.log
```

**2. Packets not visible in Wireshark**
```bash
# Ensure AH protocol (51) is being used
tcpdump -n proto 51

# Check for ESP packets (should be none)
tcpdump -n proto 50
```

**3. Authentication failures**
```bash
# Verify HMAC key consistency
grep "HMAC" router*/hipls.log

# Check sequence numbers
grep "Sequence" router*/hipls.log
```

### Debug Messages

Key log messages to monitor:

- `"Creating AH packet for data plane"` - Outgoing packet creation
- `"Processing incoming AH packet"` - Incoming packet processing
- `"AH authentication successful!"` - ICV verification passed
- `"Invalid ICV in AH packet"` - Authentication failure

### Performance Considerations

- **CPU Usage**: AH has lower CPU overhead than ESP (no encryption)
- **Bandwidth**: Slightly higher overhead due to AH header (12+ bytes)
- **Latency**: Reduced latency compared to ESP (no encryption/decryption)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## References

- [RFC 7401 - Host Identity Protocol Version 2 (HIPv2)](https://tools.ietf.org/html/rfc7401)
- [RFC 4302 - IP Authentication Header](https://tools.ietf.org/html/rfc4302)
- [RFC 4303 - IP Encapsulating Security Payload (ESP)](https://tools.ietf.org/html/rfc4303)
- [RFC 4423 - Host Identity Protocol (HIP) Architecture](https://tools.ietf.org/html/rfc4423)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Host Identity Protocol research community
- Mininet development team
- IPsec protocol designers