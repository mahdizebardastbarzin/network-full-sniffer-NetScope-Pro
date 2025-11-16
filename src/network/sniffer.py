"""
Network Sniffer Module

This module provides functionality for capturing and processing network packets.

ماژول شبکه اسنیفر
این ماژول قابلیت ضبط و پردازش بسته‌های شبکه را فراهم می‌کند.
"""

import platform
import socket
import time
import threading
from datetime import datetime
from collections import deque
import psutil
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
import netifaces as ni

class NetworkSniffer:
    """
    Network sniffer class for capturing and analyzing network traffic
    
    کلاس شبکه اسنیفر برای ضبط و تحلیل ترافیک شبکه
    """
    
    def __init__(self, max_packets=1000):
        """Initialize the network sniffer
        
        مقداردهی اولیه شبکه اسنیفر
        
        Args:
            max_packets (int): Maximum number of packets to store in memory
                               حداکثر تعداد بسته‌های ذخیره شده در حافظه
        """
        self.max_packets = max_packets
        self.packets = deque(maxlen=max_packets)
        self.new_packets = deque()
        self.sniffing = False
        self.sniffer_thread = None
        self.interface = None
        self.filter = None
        self.lock = threading.Lock()
    
    def get_network_interfaces(self):
        """Get list of available network interfaces with friendly names
        
        دریافت لیست رابط‌های شبکه در دسترس با نام‌های خوانا
        
        Returns:
            list: List of dictionaries containing interface information
                  لیستی از دیکشنری‌های حاوی اطلاعات رابط‌های شبکه
        """
        interfaces = []
        
        try:
            # Get all network interfaces
            for iface, addrs in psutil.net_if_addrs().items():
                try:
                    # Skip loopback and non-physical interfaces
                    if iface.startswith(('lo', 'Loopback', 'Teredo', 'isatap', 'Microsoft')):
                        continue
                        
                    # Get IP address
                    ip = next((addr.address for addr in addrs if addr.family == socket.AF_INET), 'N/A')
                    # Get MAC address
                    mac = next((addr.address for addr in addrs if addr.family == psutil.AF_LINK), '00:00:00:00:00:00')
                    
                    # Get interface status
                    stats = psutil.net_if_stats().get(iface, None)
                    status = 'Up' if stats and stats.isup else 'Down'
                    
                    # Get friendly name for Windows
                    if platform.system() == 'Windows':
                        try:
                            import wmi
                            c = wmi.WMI()
                            iface_name = iface
                            for interface in c.Win32_NetworkAdapter(NetEnabled=True):
                                if interface.NetConnectionID == iface or interface.NetConnectionID == iface.replace('_', ' '):
                                    iface_name = interface.Description
                                    break
                        except:
                            iface_name = iface
                    else:
                        iface_name = iface
                    
                    # Skip interfaces without IP (unless they're active)
                    if ip == 'N/A' and status != 'Up':
                        continue
                        
                    interfaces.append({
                        'name': iface,
                        'friendly_name': iface_name,
                        'ip': ip,
                        'mac': mac,
                        'status': status
                    })
                except Exception as e:
                    continue
                    
            # Sort interfaces: active first, then by name
            interfaces.sort(key=lambda x: (x['status'] != 'Up', x['friendly_name']))
                    
        except Exception as e:
            print(f"Error getting network interfaces: {str(e)}")
            # Fallback to basic interface list
            for iface in ni.interfaces():
                interfaces.append({
                    'name': iface,
                    'friendly_name': iface,
                    'ip': 'N/A',
                    'mac': '00:00:00:00:00:00',
                    'status': 'Down'
                })
        
        return interfaces
    
    def start_sniffing(self, iface_index=0, filter_exp=None):
        """Start packet sniffing on the specified interface
        
        شروع ضبط بسته‌ها در رابط شبکه مشخص شده
        
        Args:
            iface_index (int): Index of the network interface to use
                              اندیس رابط شبکه مورد استفاده
            filter_exp (str): BPF filter expression
                             عبارت فیلتر BPF
        """
        if self.sniffing:
            return
        
        interfaces = self.get_network_interfaces()
        if not interfaces or iface_index >= len(interfaces):
            raise ValueError("Invalid network interface index")
        
        self.interface = interfaces[iface_index]['name']
        self.filter = filter_exp
        self.sniffing = True
        
        # Start sniffing in a separate thread
        self.sniffer_thread = threading.Thread(
            target=self._sniff_thread,
            daemon=True
        )
        self.sniffer_thread.start()
    
    def stop_sniffing(self):
        """Stop packet sniffing
        
        توقف ضبط بسته‌ها
        """
        self.sniffing = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=2.0)
        self.sniffer_thread = None
    
    def is_sniffing(self):
        """Check if sniffing is active
        
        بررسی فعال بودن حالت ضبط بسته‌ها
        
        Returns:
            bool: True if sniffing is active, False otherwise
                  در صورتی که ضبط فعال باشد True و در غیر این صورت False
        """
        return self.sniffing
    
    def clear_packets(self):
        """Clear captured packets
        
        پاک کردن بسته‌های ضبط شده
        """
        with self.lock:
            self.packets.clear()
            self.new_packets.clear()
    
    def get_packets(self):
        """Get all captured packets
        
        دریافت تمام بسته‌های ضبط شده
        
        Returns:
            list: List of captured packets
                  لیست بسته‌های ضبط شده
        """
        with self.lock:
            return list(self.packets)
    
    def get_new_packets(self):
        """Get newly captured packets since last call
        
        دریافت بسته‌های جدید از آخرین فراخوانی
        
        Returns:
            list: List of new packets
                  لیست بسته‌های جدید
        """
        with self.lock:
            new_packets = list(self.new_packets)
            self.new_packets.clear()
            return new_packets
    
    def get_protocol_counts(self):
        """Get counts of different protocols in captured packets
        
        دریافت تعداد بسته‌های هر پروتکل در بسته‌های ضبط شده
        
        Returns:
            dict: Dictionary with protocol names as keys and counts as values
                  دیکشنری با نام پروتکل‌ها به عنوان کلید و تعداد به عنوان مقدار
        """
        protocol_counts = {}
        with self.lock:
            for packet in self.packets:
                protocol = packet.get('protocol', 'Other')
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
        # Sort by count (descending)
        return dict(sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True))
        with self.lock:
            new_packets = list(self.new_packets)
            self.new_packets.clear()
            return new_packets
    
    def _sniff_thread(self):
        """Internal method for packet sniffing in a separate thread
        
        متد داخلی برای ضبط بسته‌ها در یک رشته جداگانه
        """
        try:
            # Set promiscuous mode based on platform
            promisc = platform.system() != 'Windows'
            
            # Start sniffing
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                filter=self.filter,
                store=0,
                promisc=promisc,
                stop_filter=lambda x: not self.sniffing
            )
        except Exception as e:
            print(f"Error in sniffing thread: {str(e)}")
        finally:
            self.sniffing = False
    
    def _packet_handler(self, packet):
        """Handle captured packets
        
        مدیریت بسته‌های ضبط شده
        
        Args:
            packet: The captured packet
                    بسته ضبط شده
        """
        if not self.sniffing:
            return
        
        try:
            # Extract packet information
            packet_info = self._extract_packet_info(packet)
            if not packet_info:
                return
            
            # Add timestamp
            packet_info['timestamp'] = time.time()
            packet_info['time'] = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            
            # Add to packet lists
            with self.lock:
                self.packets.append(packet_info)
                self.new_packets.append(packet_info)
                
        except Exception as e:
            print(f"Error processing packet: {str(e)}")
    
    def _extract_packet_info(self, packet):
        """Extract relevant information from a packet
        
        استخراج اطلاعات مربوطه از یک بسته
        
        Args:
            packet: The packet to extract information from
                    بسته‌ای که اطلاعات از آن استخراج می‌شود
                    
        Returns:
            dict: Dictionary containing packet information
                  دیکشنری حاوی اطلاعات بسته
        """
        packet_info = {
            'source': '',
            'destination': '',
            'protocol': 'Unknown',
            'length': len(packet),
            'info': '',
            'raw': packet
        }
        
        # Ethernet layer
        if Ether in packet:
            eth = packet[Ether]
            packet_info['src_mac'] = eth.src
            packet_info['dst_mac'] = eth.dst
            
            # IP layer
            if IP in packet:
                ip = packet[IP]
                packet_info['source'] = ip.src
                packet_info['destination'] = ip.dst
                packet_info['protocol'] = ip.proto
                
                # TCP
                if TCP in packet:
                    tcp = packet[TCP]
                    packet_info['protocol'] = 'TCP'
                    packet_info['sport'] = tcp.sport
                    packet_info['dport'] = tcp.dport
                    packet_info['flags'] = self._get_tcp_flags(tcp.flags)
                    packet_info['info'] = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} [{packet_info['flags']}]"
                
                # UDP
                elif UDP in packet:
                    udp = packet[UDP]
                    packet_info['protocol'] = 'UDP'
                    packet_info['sport'] = udp.sport
                    packet_info['dport'] = udp.dport
                    packet_info['info'] = f"{ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}"
                
                # ICMP
                elif ICMP in packet:
                    icmp = packet[ICMP]
                    packet_info['protocol'] = 'ICMP'
                    packet_info['type'] = icmp.type
                    packet_info['code'] = icmp.code
                    packet_info['info'] = f"Type: {icmp.type}, Code: {icmp.code}"
                
                # Other IP protocols
                else:
                    packet_info['info'] = f"{ip.proto}"
            
            # ARP
            elif ARP in packet:
                arp = packet[ARP]
                packet_info['protocol'] = 'ARP'
                packet_info['source'] = arp.psrc
                packet_info['destination'] = arp.pdst
                packet_info['operation'] = 'who-has' if arp.op == 1 else 'is-at'
                packet_info['info'] = f"{arp.op}: {arp.psrc} -> {arp.pdst}"
            
            # Other Ethernet protocols
            else:
                packet_info['protocol'] = 'Ethernet'
                packet_info['info'] = f"EtherType: 0x{eth.type:04x}"
        
        return packet_info
    
    def _get_tcp_flags(self, flags):
        """Convert TCP flags to string representation
        
        تبدیل پرچم‌های TCP به نمایش متنی
        
        Args:
            flags: TCP flags value
                   مقدار پرچم‌های TCP
                   
        Returns:
            str: String representation of TCP flags
                 نمایش متنی پرچم‌های TCP
        """
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        if flags & 0x40: flag_names.append('ECE')
        if flags & 0x80: flag_names.append('CWR')
        
        return ', '.join(flag_names) if flag_names else 'None'
