#!/usr/bin/env python3

import os
import json
import socket
import logging
import threading
import time
import netifaces
from datetime import datetime

class AgentServer:
    def __init__(self, port=5775):
        self.port = port
        self.agents = {}  # Dictionary to store connected agents
        self.running = True
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        log_dir = os.path.expanduser('~/.sysdaemon/logs')
        os.makedirs(log_dir, exist_ok=True)
        
        self.logger = logging.getLogger('AgentServer')
        self.logger.setLevel(logging.INFO)
        
        # File handler
        fh = logging.FileHandler(os.path.join(log_dir, 'server.log'))
        fh.setLevel(logging.INFO)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)
        
    def get_ip_address(self):
        """Get the server's IP address"""
        try:
            # Try to get the primary interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                interface = gateways['default'][netifaces.AF_INET][1]
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    return addrs[netifaces.AF_INET][0]['addr']
            
            # Fallback: try all interfaces
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr['addr']
                        if not ip.startswith('127.'):
                            return ip
                            
            return '127.0.0.1'  # Fallback to localhost
            
        except Exception as e:
            self.logger.error(f"Error getting IP address: {e}")
            return '127.0.0.1'
            
    def get_broadcast_addresses(self):
        """Get broadcast addresses for all network interfaces"""
        broadcast_addrs = []
        try:
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:  # Has IPv4
                    for addr in addrs[netifaces.AF_INET]:
                        if 'broadcast' in addr:
                            broadcast_addrs.append(addr['broadcast'])
            return broadcast_addrs
        except Exception as e:
            self.logger.error(f"Error getting broadcast addresses: {e}")
            return ['127.0.0.1']  # Fallback to localhost
            
    def broadcast_presence(self):
        """Broadcast server presence for agent discovery"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind to all interfaces on a random port
        sock.bind(('0.0.0.0', 0))
        
        server_info = {
            'type': 'sysdaemon_server',
            'ip': self.get_ip_address(),
            'port': self.port
        }
        
        while self.running:
            try:
                # Get all broadcast addresses
                broadcast_addrs = self.get_broadcast_addresses()
                
                # Try sending to each broadcast address
                for addr in broadcast_addrs:
                    try:
                        sock.sendto(json.dumps(server_info).encode(), (addr, 5776))
                    except Exception as e:
                        self.logger.debug(f"Failed to send to {addr}: {e}")
                        
                time.sleep(5)  # Broadcast every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Error broadcasting presence: {e}")
                time.sleep(1)
                
    def handle_client(self, client_sock, client_addr):
        """Handle individual client connections"""
        try:
            # Receive initial handshake
            data = client_sock.recv(4096)
            if not data:
                return
                
            agent_info = json.loads(data.decode())
            agent_id = f"{agent_info['hostname']}_{client_addr[0]}"
            
            self.agents[agent_id] = {
                'info': agent_info,
                'addr': client_addr,
                'sock': client_sock,
                'last_seen': time.time(),
                'metrics': {}
            }
            
            self.logger.info(f"New agent connected: {agent_id}")
            
            # Handle incoming metrics
            while self.running:
                try:
                    data = client_sock.recv(4096)
                    if not data:
                        break
                        
                    metrics = json.loads(data.decode())
                    self.agents[agent_id]['metrics'] = metrics
                    self.agents[agent_id]['last_seen'] = time.time()
                    
                except json.JSONDecodeError as e:
                    self.logger.error(f"Error decoding metrics from {agent_id}: {e}")
                except Exception as e:
                    self.logger.error(f"Error receiving metrics from {agent_id}: {e}")
                    break
                    
        except Exception as e:
            self.logger.error(f"Error handling client {client_addr}: {e}")
            
        finally:
            client_sock.close()
            if agent_id in self.agents:
                del self.agents[agent_id]
                self.logger.info(f"Agent disconnected: {agent_id}")
                
    def cleanup_inactive_agents(self):
        """Remove inactive agents"""
        while self.running:
            try:
                current_time = time.time()
                inactive_agents = [
                    agent_id for agent_id, agent in self.agents.items()
                    if current_time - agent['last_seen'] > 300  # 5 minutes timeout
                ]
                
                for agent_id in inactive_agents:
                    agent = self.agents[agent_id]
                    agent['sock'].close()
                    del self.agents[agent_id]
                    self.logger.info(f"Removed inactive agent: {agent_id}")
                    
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error cleaning up inactive agents: {e}")
                time.sleep(5)
                
    def start(self):
        """Start the agent server"""
        try:
            # Start broadcast thread
            broadcast_thread = threading.Thread(target=self.broadcast_presence, daemon=True)
            broadcast_thread.start()
            
            # Start cleanup thread
            cleanup_thread = threading.Thread(target=self.cleanup_inactive_agents, daemon=True)
            cleanup_thread.start()
            
            # Start listening for connections
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(('', self.port))
            server_sock.listen(5)
            
            self.logger.info(f"Server started on port {self.port}")
            
            while self.running:
                try:
                    client_sock, client_addr = server_sock.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_sock, client_addr),
                        daemon=True
                    )
                    client_thread.start()
                    
                except Exception as e:
                    self.logger.error(f"Error accepting client connection: {e}")
                    time.sleep(1)
                    
        except Exception as e:
            self.logger.error(f"Error starting server: {e}")
            
        finally:
            self.running = False
            server_sock.close()
            
    def stop(self):
        """Stop the agent server"""
        self.running = False
        for agent in self.agents.values():
            try:
                agent['sock'].close()
            except:
                pass
        self.agents.clear()
        
    def get_agents(self):
        """Get list of connected agents"""
        return self.agents
