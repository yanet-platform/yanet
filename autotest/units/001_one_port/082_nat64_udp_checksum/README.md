# NAT64 UDP Checksum RFC Compliance Test

This test verifies the correct handling of UDP checksums during NAT64 translation,
specifically addressing RFC compliance for checksum handling.

## Test Scenarios

1. **IPv6→IPv4 Translation with Standard Checksum**
   - Input: IPv6 UDP packet with auto-calculated checksum 
   - Expected: IPv4 UDP packet with properly recalculated checksum
   - Validates: Basic NAT64 functionality with `yanet_udp_checksum_v6_to_v4` function

2. **IPv6→IPv4 Translation with 0xffff Checksum**
   - Input: IPv6 UDP packet with checksum = 0xffff
   - Expected: IPv4 UDP packet with correctly calculated checksum
   - Validates: `yanet_udp_checksum_v6_to_v4` function with 0xffff input handling

3. **IPv4→IPv6 Translation with Valid Checksum**
   - Input: IPv4 UDP packet with valid calculated checksum
   - Expected: IPv6 UDP packet with properly recalculated checksum
   - Validates: Normal checksum recalculation for IPv4→IPv6 translation

4. **IPv4→IPv6 Translation with Zero Checksum**  
   - Input: IPv4 UDP packet with checksum = 0x0000 (allowed in IPv4)
   - Expected: IPv6 UDP packet with correctly calculated checksum (required in IPv6)
   - Validates: `yanet_udp_checksum_v4_to_v6` function with proper checksum calculation for zero-checksum packets

## RFC References

- RFC 768: UDP checksum = 0 means no checksum computed (IPv4 only)
- RFC 2460: UDP checksum is mandatory in IPv6 (must not be zero)
- RFC 6145: NAT64 checksum translation rules
