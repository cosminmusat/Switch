#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

# Type(dest_mac, src_mac, root_bridge_ID, root_path_cost, sender_bridge_ID) = [bytes, bytes, int, int, int]
# Each BPDU packet is 52 bytes long
def computeBPDU(dest_mac, src_mac, root_bridge_ID, root_path_cost, sender_bridge_ID):
    dest_mac = int.from_bytes(dest_mac, byteorder='big')
    src_mac = int.from_bytes(src_mac, byteorder='big')
    return (
        dest_mac.to_bytes(6, byteorder='big') +
        src_mac.to_bytes(6, byteorder='big') +
        bytes([0x00, 0x26, 0x42, 0x42, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00]) +
        root_bridge_ID.to_bytes(8, byteorder='big') +
        root_path_cost.to_bytes(4, byteorder='big') +
        sender_bridge_ID.to_bytes(8, byteorder='big') +
        bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    )

# Bytes 17 and 18 are the bytes for protocol identifier
def isPacketBPDU(packet):
    if packet[17] == 0x00 and packet[18] == 0x00:
        return True
    return False

# Extract the useful information from BPDU packet
def parse_bpdu(bpdu):
    root_bridge_ID = int.from_bytes(bpdu[22:30], byteorder='big')
    root_path_cost = int.from_bytes(bpdu[30:34], byteorder='big')
    sender_bridge_ID = int.from_bytes(bpdu[34:42], byteorder='big')
    return root_bridge_ID, root_path_cost, sender_bridge_ID

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

def send_bdpu_every_sec(VLAN, switch_priority, stop_event):
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    while not stop_event.is_set():
        
        # MAC multicast destination address for BPDU
        dest_mac = bytes([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00])
        src_mac = get_switch_mac()

        # Switch is Root Bridge therefore root_bridge_ID is the switches' priority and so on
        bpdu = computeBPDU(dest_mac, src_mac, switch_priority, 0, switch_priority)
        for i in interfaces:
            vlan_dest = VLAN[get_interface_name(i)]
            if vlan_dest == "T":
                send_to_link(i, bpdu, 52)
        time.sleep(1)

def main():
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    switch_cfg_path = "configs/switch" + switch_id + ".cfg"

    # Initialising switch priority
    switch_priority = -1
    # VLAN map
    # VLAN[INTERFACE_NAME] = VLAN_NO/TRUNK
    VLAN = dict()

    with open(switch_cfg_path, 'r') as file:
        switch_priority = int(file.readline().strip())

        lines = file.readlines()[0:]
        for line in lines:
            if line.strip():
                interface_name, vlan = map(str.strip, line.split(' ', 1))
                if vlan == "T":
                    VLAN[interface_name] = vlan
                else:
                    VLAN[interface_name] = int(vlan)

    # CAM table of the switch and VLAN map of every interface on each switch
    # CAM[MAC_ADDR] = INTERFACE_NO
    CAM = dict()

    # Map of each port's state
    # LB[NAME_OF_INTERFACE] = TRUE or FALSE 
    # True means port is in listening state
    # False means port is in blocking state
    LB = dict()
    
    # Initialise switch
    for i in interfaces:
        vlan_dest = VLAN[get_interface_name(i)]
        if vlan_dest == "T":
            LB[get_interface_name(i)] = False
        else:
            # Set access ports to listening
            LB[get_interface_name(i)] = True

    own_bridge_ID = switch_priority
    root_bridge_ID = own_bridge_ID
    root_path_cost = 0
    # No root port yet
    root_port = -1
            
    if own_bridge_ID == root_bridge_ID:
        for i in interfaces:
            LB[get_interface_name(i)] = True

    stop_event = threading.Event()
    thread = threading.Thread(target=lambda: send_bdpu_every_sec(VLAN, switch_priority, stop_event))
    thread.start()

    while True:

        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        if isPacketBPDU(data):
            
            # Extract useful information from BPDU
            bpdu_root_bridge_ID, bpdu_root_path_cost, bpdu_sender_bridge_ID = parse_bpdu(data)

            if bpdu_root_bridge_ID < root_bridge_ID:

                # Used to check if switch was root bridge before
                former_root_bridge_ID = root_bridge_ID
                
                root_bridge_ID = bpdu_root_bridge_ID
                root_path_cost = bpdu_root_path_cost + 10
                root_port = interface
                # This switch is no longer root bridge so signal thread function to stop sending BPDUs
                stop_event.set()
                thread.join()

                # Setting all ports to blocking except for root port and access ports
                if former_root_bridge_ID == switch_priority:
                    for i in interfaces:
                        vlan_dest = VLAN[get_interface_name(i)]
                        if i != root_port and not vlan_dest != "T":
                            LB[get_interface_name(i)] = False
                
                # Set root port to listening if it is blocking
                if LB[get_interface_name(root_port)] == False:
                    LB[get_interface_name(root_port)] = True

                new_bpdu = computeBPDU(bytes([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00]), get_switch_mac(), root_bridge_ID, root_path_cost, own_bridge_ID)

                # Forward BPDU to the other ports
                for i in interfaces:
                    if i != interface:
                        send_to_link(i, new_bpdu, 52)

            elif bpdu_root_bridge_ID == root_bridge_ID:

                if interface == root_port and bpdu_root_path_cost + 10 < root_path_cost:
                    root_path_cost = bpdu_root_path_cost + 10
                
                elif interface != root_port:
                    if bpdu_root_path_cost > root_path_cost:
                        if LB[get_interface_name(interface)] == False:
                            LB[get_interface_name(interface)] = True
                
            elif bpdu_sender_bridge_ID == own_bridge_ID:
                LB[get_interface_name(interface)] = False
            
            if own_bridge_ID == root_bridge_ID:
                for i in interfaces:
                    LB[get_interface_name(i)] = True
            continue

        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Ignore packets received on ports in blocking state
        if LB[get_interface_name(interface)] == False:
            continue

        # Learn the new source
        CAM[src_mac] = interface

        vlan_src = VLAN[get_interface_name(interface)]

        if vlan_src == "T":
            # Remove 802.1Q tag for the time being
            data = data[:12] + data[16:]
            length = length - 4
            # If port is access vlan_src = vlan_id but here port is trunk so vlan_id needs to be assigned to vlan_src
            vlan_src = vlan_id

        if int(dest_mac[1], 16) % 2 is 0:
            # Destination address is unicast

            # Check if the port that the packet is about to go through is listening and look for destination MAC in the switches' CAM table
            if dest_mac in CAM.keys() and LB[get_interface_name(CAM[dest_mac])] == True:
                # Switch knows where destination is
                vlan_dest = VLAN[get_interface_name(CAM[dest_mac])]
                
                if vlan_dest == "T":
                    # Link is trunk vlan so apply 802.1Q tag
                    vlan_tag = create_vlan_tag(vlan_src)
                    data = data[:12] + vlan_tag + data[12:]
                    length = length + 4
                    send_to_link(CAM[dest_mac], data, length)

                elif vlan_src == vlan_dest:
                    # Same vlan so no need to apply 802.1Q tag
                    send_to_link(CAM[dest_mac], data, length)

            else:
                # Switch either does not know where destination is or port is blocking
                for intf in interfaces:
                    # Don't send the packet on source port and check if the port that the packet is about to go through is listening
                    if intf != interface and LB[get_interface_name(intf)] == True:
                        vlan_dest = VLAN[get_interface_name(intf)]

                        if vlan_dest == "T":
                            # Link is trunk vlan so apply 802.1Q tag
                            vlan_tag = create_vlan_tag(vlan_src)
                            # Insert the tag into the data and change length
                            data = data[:12] + vlan_tag + data[12:]
                            length = length + 4
                            send_to_link(intf, data, length)
                            # Same packet will be used for the following iterations so remove 802.1Q tag for the time being and change the length
                            data = data[:12] + data[16:]
                            length = length - 4

                        elif vlan_src == vlan_dest:
                            # Same vlan so no need to apply 802.1Q tag
                            send_to_link(intf, data, length)
        else:
            # Destination address is multicast/broadcast
            for intf in interfaces:
                # Don't send the packet on source port and check if the port that the packet is about to go through is listening
                if intf != interface and LB[get_interface_name(intf)] == True:
                    vlan_dest = VLAN[get_interface_name(intf)]

                    if vlan_dest == "T":
                        # Link is trunk vlan so apply 802.1Q tag
                        vlan_tag = create_vlan_tag(vlan_src)
                        # Insert the tag into the data and change length
                        data = data[:12] + vlan_tag + data[12:]
                        length = length + 4
                        send_to_link(intf, data, length)
                        # Same packet will be used for the following iterations so remove 802.1Q tag for the time being and change the length
                        data = data[:12] + data[16:]
                        length = length - 4

                    elif vlan_src == vlan_dest:
                        # Same vlan so no need to apply 802.1Q tag
                        send_to_link(intf, data, length)

if __name__ == "__main__":
    main()