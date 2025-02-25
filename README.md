Data Link Layer Switch Implementation

This program implements a data link layer switch using a C-based shared library (dlink.so) for handling raw Ethernet frames. It provides functions for initializing the switch, sending, and receiving frames across network interfaces using ctypes for C-Python interoperability. This implementation allows direct communication at the data link layer, making it suitable for packet forwarding, VLAN processing, and custom network switching.

Features

Switch Initialization (init()): Initializes the switch by parsing command-line arguments and returns the number of available network interfaces. This function ensures that the library is correctly loaded and that the network interfaces are ready for frame transmission and reception.

Frame Reception (recv_from_any_link()): Listens for Ethernet frames on any network interface and returns the received data along with the frame length. This function enables the switch to process incoming traffic dynamically.

Frame Transmission (send_to_link()): Sends an Ethernet frame to a specified network interface, ensuring direct frame forwarding based on predefined rules or switching logic.

MAC Address Retrieval (get_switch_mac()): Extracts the MAC address of the switch by querying the first available network interface. This is useful for managing VLANs and implementing MAC-based filtering.

Interface Name Retrieval (get_interface_name()): Retrieves the name of a given network interface, aiding in debugging and dynamic network configuration.

Implementation Details

ctypes-based C Library Integration: Uses Python’s ctypes to call C functions from dlink.so, enabling efficient low-level networking operations.

Raw Socket Communication: Works directly with Ethernet frames, bypassing higher-layer protocols to allow precise packet manipulation and forwarding.

Memory Management & Safety: Ensures safe buffer handling using ctypes.create_string_buffer and proper memory allocation techniques to prevent overflows.

Multi-Interface Support: Allows handling multiple network interfaces, making it adaptable for advanced switching mechanisms.

Synchronized Transmission & Reception: Provides real-time frame processing to maintain network integrity and prevent packet loss.

Use Cases

This implementation is ideal for:

Custom Network Switching: Enables the development of software-defined networking (SDN) applications.

VLAN Management: Can be extended to support VLAN tagging and filtering.

Packet Monitoring & Filtering: Provides direct access to raw Ethernet frames for traffic analysis and network security applications.
