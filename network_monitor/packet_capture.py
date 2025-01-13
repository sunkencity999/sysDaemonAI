import os
import logging
from PyQt6.QtCore import QThread, pyqtSignal
import psutil
from scapy.all import sniff, AsyncSniffer, get_if_list, conf, ETH_P_ALL, TCP, UDP
from scapy.utils import PcapWriter
from datetime import datetime
import traceback

class PacketCaptureThread(QThread):
    packet_received = pyqtSignal(dict)
    capture_complete = pyqtSignal()
    error_signal = pyqtSignal(str)
    status_signal = pyqtSignal(str)

    def __init__(self, interface, filter_text="", packet_count=1000):
        super().__init__()
        self.interface = interface
        self.filter_text = filter_text
        self.packet_count = packet_count
        self.running = True
        self.captured_count = 0
        self.sniffer = None
        self.logger = logging.getLogger(__name__)

    def run(self):
        """Run packet capture"""
        try:
            # Check for root privileges first
            if os.geteuid() != 0:
                raise PermissionError("Packet capture requires root privileges")

            # Log start of capture
            self.logger.info(f"Starting capture on interface {self.interface}")
            self.status_signal.emit("Initializing capture...")
            
            # Get system interfaces
            psutil_ifaces = list(psutil.net_if_addrs().keys())
            scapy_ifaces = get_if_list()
            
            self.logger.debug(f"Available interfaces - psutil: {psutil_ifaces}, scapy: {scapy_ifaces}")
            
            # Validate interface
            if not self.interface:
                raise ValueError("No interface specified")

            # First try exact match
            if self.interface in scapy_ifaces:
                self.logger.info(f"Using exact interface match: {self.interface}")
            else:
                # Try case-insensitive match
                for iface in scapy_ifaces:
                    if self.interface.lower() == iface.lower():
                        self.interface = iface
                        self.logger.info(f"Found case-insensitive match: {self.interface}")
                        break
                else:
                    # Try partial match
                    matches = [iface for iface in scapy_ifaces if self.interface.lower() in iface.lower()]
                    if len(matches) == 1:
                        self.interface = matches[0]
                        self.logger.info(f"Found partial match: {self.interface}")
                    elif len(matches) > 1:
                        raise ValueError(f"Multiple interfaces match {self.interface}: {matches}")
                    else:
                        raise ValueError(f"Interface {self.interface} not found in available interfaces: {scapy_ifaces}")

            def packet_callback(packet):
                if not self.running:
                    return True  # Stop sniffing
                
                try:
                    packet_info = {
                        'timestamp': packet.time,
                        'length': len(packet),
                        'protocol': 'Unknown'
                    }

                    if TCP in packet:
                        packet_info['protocol'] = 'TCP'
                        packet_info['src_port'] = packet[TCP].sport
                        packet_info['dst_port'] = packet[TCP].dport
                        packet_info['flags'] = packet[TCP].flags
                    elif UDP in packet:
                        packet_info['protocol'] = 'UDP'
                        packet_info['src_port'] = packet[UDP].sport
                        packet_info['dst_port'] = packet[UDP].dport

                    if hasattr(packet, 'src') and hasattr(packet, 'dst'):
                        packet_info['src'] = packet.src
                        packet_info['dst'] = packet.dst

                    self.packet_received.emit(packet_info)
                    self.captured_count += 1
                    
                    if self.captured_count % 100 == 0:
                        progress = min(100, int((self.captured_count / self.packet_count) * 100))
                        self.status_signal.emit(f"Captured {self.captured_count} packets ({progress}%)")

                    return self.captured_count < self.packet_count
                
                except Exception as e:
                    self.error_signal.emit(f"Error processing packet: {str(e)}")
                    return False

            # Start async sniffer
            self.status_signal.emit("Starting packet capture...")
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=packet_callback,
                filter=self.filter_text if self.filter_text else None,
                store=0
            )
            
            # Start sniffing and wait for completion
            self.sniffer.start()
            
            # Wait for completion or stop
            while self.running and self.captured_count < self.packet_count:
                self.msleep(100)
                if self.sniffer and not self.sniffer.running:
                    break

            self.status_signal.emit("Capture complete")
            self.capture_complete.emit()

        except Exception as e:
            error_msg = f"Capture error: {str(e)}\n{traceback.format_exc()}"
            self.logger.error(error_msg)
            self.error_signal.emit(str(e))
        finally:
            self.cleanup()

    def stop(self):
        """Stop the packet capture"""
        self.running = False
        self.cleanup()

    def cleanup(self):
        """Clean up sniffer resources"""
        try:
            if self.sniffer:
                if self.sniffer.running:
                    self.sniffer.stop()
                self.sniffer = None
        except Exception as e:
            self.logger.error(f"Error cleaning up sniffer: {str(e)}")
        finally:
            self.status_signal.emit("Capture stopped")
