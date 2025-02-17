#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name



root_port = -1
root_path_cost = -1
root_bridge_ID = -1
own_bridge_ID = -1

port_state = {}
trunk_ports = []

destination_mac = bytes([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00])

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)


def read_switch_info(switch_id):
    config_path = 'configs/switch{}.cfg'.format(switch_id)

    try:
        with open(config_path) as cfg_file:
            switch_data = cfg_file.readlines()
        return ''.join(switch_data)
    except IOError:
        return None


def is_unicast(dest_mac):
    return (int(dest_mac[:2], 16)) % 2 == 0

def create_bdpu_package(sender_bridge_ID, port, root_path_cost, root_bridge_ID):
    # Start by building the Ethernet frame and BPDU header
    ethernet_header = create_ethernet_header()
    bpdu_header = create_bpdu_header()
    bpdu_config = create_bpdu_config(sender_bridge_ID, port, root_path_cost, root_bridge_ID)

    # Construct the final package
    LLC_LENGTH = 38
    return ethernet_header + bpdu_header + bpdu_config


def create_bpdu_header():
    # BPDU header contains STP identifier and control field
    STP = b"\x42"
    CONTROL = 3
    
    # Create logical link using struct.pack (equivalent to bytes concatenation in the original)
    bytes_logical_link = STP + STP + struct.pack('>B', CONTROL)  # CONTROL as a single byte

    # BPDU header format with 2 bytes reserved, followed by 1 byte zero for configuration
    ZERO = 0
    # Use struct.pack to add reserved bytes
    bytes_BPDU_header = struct.pack('>H', ZERO) + struct.pack('>B', ZERO) + struct.pack('>B', ZERO)

    return bytes_logical_link + bytes_BPDU_header

def create_ethernet_header():
    global destination_mac
    # Ethernet frame starts with destination MAC address, source MAC address, and LLC header
    return destination_mac + get_switch_mac() + struct.pack('!H', 38)  # LLC length


def create_bpdu_config(sender_bridge_ID, port, root_path_cost, root_bridge_ID):
    ZERO = 0

    # Start BPDU configuration packet with a reserved byte
    bytes_BPDU_CONFIG = struct.pack('>B', ZERO)
    # Append root bridge ID, root path cost, and sender bridge ID
    bytes_BPDU_CONFIG += struct.pack('>Q', int(root_bridge_ID))
    bytes_BPDU_CONFIG += struct.pack('>I', int(root_path_cost))
    bytes_BPDU_CONFIG += struct.pack('>Q', int(sender_bridge_ID))

    # STP timing constants
    BPDU_MESSAGE_LIFETIME = 1
    BPDU_HELLO_TIME = 2
    FORWARD_DELAY = 15
    MAX_AGE = 20

    # Append port number and STP timing constants
    bytes_BPDU_CONFIG += struct.pack('>H', port)
    bytes_BPDU_CONFIG += struct.pack('>H', BPDU_MESSAGE_LIFETIME)
    bytes_BPDU_CONFIG += struct.pack('>H', MAX_AGE)
    bytes_BPDU_CONFIG += struct.pack('>H', BPDU_HELLO_TIME)
    bytes_BPDU_CONFIG += struct.pack('>H', FORWARD_DELAY)

    return bytes_BPDU_CONFIG


def send_bdpu_every_sec():
    global root_path_cost, root_bridge_ID, own_bridge_ID

    while True:
        # Check if the switch is the root bridge
        if root_bridge_ID != -1 and root_path_cost != -1 and own_bridge_ID == root_bridge_ID:
            root_path_cost = 0
            root_bridge_ID = own_bridge_ID

            # Send BPDU packet from each trunk port
            for current_port in trunk_ports:
                source_bridge_ID = own_bridge_ID
                bpdu_data = create_bdpu_package(source_bridge_ID, current_port, root_path_cost, root_bridge_ID)
                send_to_link(current_port, 52, bpdu_data)

        time.sleep(1)


def handle_BDPU_packet_received(BPDU_root_bridge_ID, BPDU_sender_path_cost, interface_from, BPDU_sender_bridge_ID):
    global root_bridge_ID, own_bridge_ID, root_path_cost, root_port
    weWereRootBridge = (root_bridge_ID == own_bridge_ID)

    # Check if the received BPDU has a lower root bridge ID, indicating a new root bridge
    if BPDU_root_bridge_ID < int(root_bridge_ID):
        handle_new_root_bridge(BPDU_root_bridge_ID, BPDU_sender_path_cost, interface_from, weWereRootBridge)
    # If BPDU root ID matches current root bridge ID, update path cost and root port if necessary
    elif BPDU_root_bridge_ID == root_bridge_ID:
        handle_same_root_bridge(BPDU_sender_path_cost, interface_from)
    # Ignore packets sent by this bridge itself
    elif BPDU_sender_bridge_ID == own_bridge_ID:
        handle_sender_is_own_bridge(interface_from)
    else:
        return

    # Update designated ports for the current root bridge
    set_designated_ports_for_root_bridge()


def handle_new_root_bridge(BPDU_root_bridge_ID, BPDU_sender_path_cost, interface_from, weWereRootBridge):
    global root_bridge_ID, root_path_cost, root_port, port_state, trunk_ports

    # Set the interface as the root port and update the path cost and root bridge ID
    root_port = interface_from
    root_path_cost = BPDU_sender_path_cost + 10
    root_bridge_ID = BPDU_root_bridge_ID

    # If this bridge was previously the root, block other ports except the root port
    if weWereRootBridge:
        block_non_root_ports()

    # Update root port state to designated if currently blocked
    if port_state[root_port] == 'BLOCKED':
        port_state[root_port] = 'DESIGNATED'

    # Send BPDU packets from each trunk port
    send_bdpu_to_trunk_ports()



def block_non_root_ports():
    global port_state, root_port, trunk_ports
    # Block all trunk ports except the root port
    for i in trunk_ports:
        if i != root_port:
            port_state[i] = 'BLOCKED'


def send_bdpu_to_trunk_ports():
    global root_bridge_ID, root_path_cost, own_bridge_ID, trunk_ports
    # Send BPDU packet from each trunk port
    for port in trunk_ports:
        package = create_bdpu_package(own_bridge_ID, port, root_path_cost, root_bridge_ID)
        send_to_link(port, len(package), package)


def handle_same_root_bridge(BPDU_sender_path_cost, interface_from):
    global root_path_cost, root_port, port_state

    # Check if received BPDU is from a different interface or if path cost is higher
    if interface_from != root_port or BPDU_sender_path_cost + 10 >= root_path_cost:
        # Update port state to designated if not the root port and path cost is higher
        if interface_from != root_port:
            if BPDU_sender_path_cost > root_path_cost:
                if port_state[interface_from] == 'BLOCKED':
                    port_state[interface_from] = 'DESIGNATED'
    else:
        # Update root path cost to new value if received from root port
        root_path_cost = BPDU_sender_path_cost + 10


def handle_sender_is_own_bridge(interface_from):
    global port_state
    # Block port if the packet is sent by this bridge itself
    port_state[interface_from] = 'BLOCKED'



def set_designated_ports_for_root_bridge():
    global root_bridge_ID, own_bridge_ID, port_state, trunk_ports
    # Set all trunk ports as designated if this bridge is the root bridge
    if own_bridge_ID == root_bridge_ID:
        for port in trunk_ports:
            port_state[port] = 'DESIGNATED'


def extract_BDPU_packet_info(data):
    root_bridge_offset = 22
    path_cost_offset = 30
    sender_bridge_offset = 34

    # Extract root bridge ID from packet data at the specified offset
    BPDU_root_bridge_ID = struct.unpack_from('>Q', data[root_bridge_offset:root_bridge_offset + 8])[0]
    # Extract sender path cost from packet data at the specified offset
    BDPU_sender_path_cost = struct.unpack_from('>I', data[path_cost_offset:path_cost_offset + 4])[0]
    # Extract sender bridge ID from packet data at the specified offset
    BPDU_sender_bridge_ID = struct.unpack_from('>Q', data[sender_bridge_offset:sender_bridge_offset + 8])[0]

    return [int(BPDU_root_bridge_ID), int(BDPU_sender_path_cost), int(BPDU_sender_bridge_ID)]




def main():
    global root_path_cost, root_bridge_ID, own_bridge_ID
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    
    vlan_mac_table = []
    for i in interfaces:
        vlan_mac_table.append({})

    file_data = read_switch_info(switch_id).split('\n')
    switch_priority = file_data[0]

    interface_types_dict = {}

    for i in interfaces:
        line_split = file_data[i + 1].split(' ')
        if len(line_split) == 2:
            interface_types_dict[line_split[0]] = line_split[1]
            # set all ports to blocking (STP)
            if line_split[1] == 'T':
                trunk_ports.append(i)
                port_state[i] = 'BLOCKED'

    root_path_cost = 0
    own_bridge_ID =  switch_priority
    root_bridge_ID = own_bridge_ID
    
 
    # initialise
    if own_bridge_ID == root_bridge_ID:
        for port in trunk_ports:
            port_state[port] = 'DESIGNATED'
    
    
    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()


    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)
        
        if dest_mac == destination_mac:
            BPDU_root_bridge_ID, BPDU_sender_path_cost, BPDU_sender_bridge_ID = extract_BDPU_packet_info(data)
            handle_BDPU_packet_received(BPDU_root_bridge_ID, BPDU_sender_path_cost, interface, BPDU_sender_bridge_ID)
            continue

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]


        # TODO: Implement forwarding with learning
        # TODO: Implement VLAN support
        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, length, data)


        cameFromTrunk = False
        
        if interface_types_dict[get_interface_name(interface)] == 'T':
            cameFromTrunk = True
        else:
            vlan_id = int(interface_types_dict[get_interface_name(interface)])

        if(cameFromTrunk == True and port_state[interface] == 'BLOCKED'):
            continue
        
        vlan_mac_table[vlan_id][src_mac] = interface
            
        if is_unicast(dest_mac):
            if dest_mac in vlan_mac_table[vlan_id]:
                if interface_types_dict[get_interface_name(vlan_mac_table[vlan_id][dest_mac])] != 'T' or port_state[vlan_mac_table[vlan_id][dest_mac]] == 'BLOCKED':
                    if cameFromTrunk == False:
                        send_to_link(vlan_mac_table[vlan_id][dest_mac], length, data)
                    else:
                        send_to_link(vlan_mac_table[vlan_id][dest_mac], length - 4, data[slice(0, 12)] + data[slice(16, None)])
                else:
                    if cameFromTrunk == False:
                        send_to_link(vlan_mac_table[vlan_id][dest_mac], length + 4, data[slice(0, 12)] + create_vlan_tag(vlan_id) + data[slice(12, None)])
                    else:
                        send_to_link(vlan_mac_table[vlan_id][dest_mac], length, data)
                    
            else:
                for aux in interfaces:
                    if aux != interface:
                        if interface_types_dict[get_interface_name(aux)] != 'T' or port_state[aux] == 'BLOCKED':
                            if interface_types_dict[get_interface_name(aux)] == str(vlan_id):
                                if cameFromTrunk == False:
                                    send_to_link(aux, length, data)
                                else:
                                    send_to_link(aux, length - 4, data[slice(0, 12)] + data[slice(16, None)])
                        else:
                            if cameFromTrunk == False:
                                send_to_link(aux, length + 4, data[slice(0, 12)] + create_vlan_tag(vlan_id) + data[slice(12, None)])
                            else:
                                send_to_link(aux, length, data)
        else:
            for aux in interfaces:
                if aux != interface:
                    if interface_types_dict[get_interface_name(aux)] != 'T' or port_state[aux] == 'BLOCKED':
                        if interface_types_dict[get_interface_name(aux)] == str(vlan_id):
                            if cameFromTrunk == False:
                                send_to_link(aux, length, data)
                            else:
                                send_to_link(aux, length - 4, data[slice(0, 12)] + data[slice(16, None)])
                    else:
                        if cameFromTrunk == False:
                            send_to_link(aux, length + 4, data[slice(0, 12)] + create_vlan_tag(vlan_id) + data[slice(12, None)])
                        else:
                            send_to_link(aux, length, data)

if __name__ == "__main__":
    main()