# ModBus MITM

This project implements a Man-In-The-Middle (MITM) attack on Modbus TCP communication using Scapy. It captures, modifies, delays, and replays Modbus packets based on user-defined parameters.

## Usage

To run the script, use the following command:

```sh
sudo python3 mitm_modbus.py --rxif <RX_INTERFACE> --txif <TX_INTERFACE> --srcmac <SRC_MAC> --dstmac <DST_MAC> --delay <DELAY> --modif <MODIFICATION> --replay <REPLAY> --pcap <PCAP_FILE>
```

### Example Commands

```sh
sudo python3 mitm_modbus.py --rxif eth0 --txif eth1 --srcmac_n 00:30:a7:32:cb:52 00:1e:06:37:a1:a0 00:0e:c6:64:68:ee --dstmac_n 00:1e:06:37:a1:a0 00:0e:c6:64:68:ee --delay 0 --modif None --replay None
sudo python3 mitm_modbus.py --rxif eth0 --txif eth1 --srcmac 00:30:a7:34:0a:67 18:31:bf:cf:28:69 --delay 0 --modif None --replay None
sudo python3 mitm_modbus.py --rxif eth1 --txif eth0 --srcmac 00:30:a7:32:cb:52 --delay 0 --modif None --replay None
sudo python3 mitm_modbus.py --rxif eth1 --txif eth0 --srcmac 00:30:a7:32:cb:52 --delay 0.0 --modif None --replay "['send_with_delay',0.5]"
```

## Arguments

- `--rxif`: List of RX interface names (default: ['eno1'])
- `--txif`: List of TX interface names (default: ['eno1'])
- `--srcmac`: List of source MAC addresses to sniff (default: [])
- `--dstmac`: List of destination MAC addresses to sniff (default: [])
- `--srcmac_n`: List of source MAC addresses not to sniff (default: [])
- `--dstmac_n`: List of destination MAC addresses not to sniff (default: [])
- `--delay`: Delay time to put in the path of packets (default: 0)
- `--modif`: Modification to be done on the packet (default: None)
- `--replay`: Replay packet instruction (default: None)
- `--pcap`: Name of the pcap file to read (default: None)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.