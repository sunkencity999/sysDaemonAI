#!/usr/bin/env python3
import psutil
import time
from datetime import datetime, timedelta
import statistics
from typing import Dict, List, Optional, Tuple, Any
import logging
import os
import subprocess
from collections import deque
import gc

class PerformanceMonitor:
    # Maximum number of raw data points to keep (5 minutes worth at 1 second intervals)
    MAX_RAW_HISTORY = 300
    # Maximum number of aggregated data points to keep (24 hours worth at 5 minute intervals)
    MAX_AGG_HISTORY = 288
    # Interval for aggregating data (5 minutes)
    AGGREGATION_INTERVAL = 300

    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        # Use deque with maxlen for automatic size management
        self.raw_bandwidth_history = deque(maxlen=self.MAX_RAW_HISTORY)
        self.aggregated_bandwidth_history = deque(maxlen=self.MAX_AGG_HISTORY)
        self.latency_history = {}
        self.process_stats = {}
        self.last_bandwidth_check = None
        self.last_bytes_sent = 0
        self.last_bytes_recv = 0
        self.last_aggregation_time = datetime.now()
        
        self.metrics_history = {
            'cpu': [],
            'memory': [],
            'disk': [],
            'network': [],
            'processes': []
        }
        self.history_limit = 1000  # Keep last 1000 measurements
        self.sampling_interval = 5  # seconds
        self.anomaly_detection_enabled = True
        self.baseline_periods = {
            'hour': 60 * 60,    # 1 hour in seconds
            'day': 24 * 60 * 60,  # 1 day in seconds
            'week': 7 * 24 * 60 * 60  # 1 week in seconds
        }
        
        # Initialize prometheus metrics if available
        try:
            from prometheus_client import Counter, Gauge, Histogram
            self.prometheus_enabled = True
            
            # Create Prometheus metrics
            self.cpu_usage_gauge = Gauge('system_cpu_usage_percent', 'System CPU usage percentage')
            self.memory_usage_gauge = Gauge('system_memory_usage_percent', 'System memory usage percentage')
            self.disk_usage_gauge = Gauge('system_disk_usage_percent', 'System disk usage percentage')
            self.network_bytes_sent = Counter('system_network_bytes_sent', 'Total bytes sent')
            self.network_bytes_recv = Counter('system_network_bytes_received', 'Total bytes received')
            self.latency_histogram = Histogram('system_latency_seconds', 'System latency in seconds')
        except ImportError:
            self.prometheus_enabled = False
            self.logger.warning("Prometheus client not available. Metrics export disabled.")
    
    def _aggregate_bandwidth_data(self) -> None:
        """Aggregate bandwidth data older than AGGREGATION_INTERVAL into 5-minute averages"""
        current_time = datetime.now()
        
        # Only aggregate if enough time has passed
        if (current_time - self.last_aggregation_time).total_seconds() < self.AGGREGATION_INTERVAL:
            return
            
        try:
            # Convert raw data to list of (timestamp, upload, download) tuples
            raw_data = [(datetime.fromisoformat(entry["timestamp"]), 
                        entry["upload"], 
                        entry["download"]) for entry in self.raw_bandwidth_history]
            
            if not raw_data:
                return
                
            # Group data by 5-minute intervals
            interval_start = raw_data[0][0]
            current_interval = []
            aggregated_data = []
            
            for timestamp, upload, download in raw_data:
                if (timestamp - interval_start).total_seconds() < self.AGGREGATION_INTERVAL:
                    current_interval.append((upload, download))
                else:
                    if current_interval:
                        # Calculate averages for the interval
                        avg_upload = statistics.mean(u for u, _ in current_interval)
                        avg_download = statistics.mean(d for _, d in current_interval)
                        aggregated_data.append({
                            "timestamp": interval_start.isoformat(),
                            "upload": avg_upload,
                            "download": avg_download,
                            "samples": len(current_interval)
                        })
                    # Start new interval
                    interval_start = timestamp
                    current_interval = [(upload, download)]
            
            # Add any remaining data
            if current_interval:
                avg_upload = statistics.mean(u for u, _ in current_interval)
                avg_download = statistics.mean(d for _, d in current_interval)
                aggregated_data.append({
                    "timestamp": interval_start.isoformat(),
                    "upload": avg_upload,
                    "download": avg_download,
                    "samples": len(current_interval)
                })
            
            # Update aggregated history
            self.aggregated_bandwidth_history.extend(aggregated_data)
            
            # Clear old raw data
            old_time = current_time - timedelta(minutes=5)
            self.raw_bandwidth_history = deque(
                (entry for entry in self.raw_bandwidth_history 
                 if datetime.fromisoformat(entry["timestamp"]) > old_time),
                maxlen=self.MAX_RAW_HISTORY
            )
            
            # Update last aggregation time
            self.last_aggregation_time = current_time
            
            # Trigger garbage collection after major data cleanup
            gc.collect()
            
        except Exception as e:
            self.logger.error(f"Error aggregating bandwidth data: {str(e)}")
            
    def get_bandwidth_usage(self) -> Dict:
        """Get current bandwidth usage in bytes/second"""
        current_time = time.time()
        counters = psutil.net_io_counters()
        
        if self.last_bandwidth_check is None:
            self.last_bandwidth_check = current_time
            self.last_bytes_sent = counters.bytes_sent
            self.last_bytes_recv = counters.bytes_recv
            return {"upload": 0, "download": 0}
            
        time_delta = current_time - self.last_bandwidth_check
        
        # Calculate bandwidth
        upload_speed = (counters.bytes_sent - self.last_bytes_sent) / time_delta
        download_speed = (counters.bytes_recv - self.last_bytes_recv) / time_delta
        
        # Update last values
        self.last_bandwidth_check = current_time
        self.last_bytes_sent = counters.bytes_sent
        self.last_bytes_recv = counters.bytes_recv
        
        # Store in raw history
        self.raw_bandwidth_history.append({
            "timestamp": datetime.now().isoformat(),
            "upload": upload_speed,
            "download": download_speed
        })
        
        # Trigger data aggregation
        self._aggregate_bandwidth_data()
        
        return {
            "upload": upload_speed,
            "download": download_speed,
            "upload_human": self._humanize_bytes(upload_speed),
            "download_human": self._humanize_bytes(download_speed)
        }
    
    def get_process_network_stats(self) -> List[Dict]:
        """Get network statistics for all processes"""
        process_stats = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                # Get process connections
                connections = proc.connections()
                if not connections:
                    continue
                
                stats = {
                    "pid": proc.pid,
                    "name": proc.name(),
                    "cpu_percent": proc.cpu_percent(),
                    "memory_percent": proc.memory_percent(),
                    "connection_count": len(connections),
                    "connections": [
                        {
                            "local_addr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                            "remote_addr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                            "status": c.status
                        }
                        for c in connections
                    ]
                }
                
                # Try to get IO counters, but don't fail if unavailable
                try:
                    io_counters = proc.io_counters()
                    stats.update({
                        "bytes_sent": io_counters.write_bytes,
                        "bytes_recv": io_counters.read_bytes
                    })
                except (psutil.AccessDenied, AttributeError):
                    stats.update({
                        "bytes_sent": 0,
                        "bytes_recv": 0
                    })
                
                process_stats.append(stats)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
        self.process_stats = {p["pid"]: p for p in process_stats}
        return process_stats
    
    def get_system_metrics(self) -> Dict:
        """Get system metrics with proper error handling"""
        metrics = {}
        try:
            metrics['cpu_percent'] = psutil.cpu_percent(interval=1)
            vm = psutil.virtual_memory()
            metrics['memory_percent'] = vm.percent
            metrics['memory_available'] = vm.available
            metrics['memory_total'] = vm.total
            
            disk = psutil.disk_usage('/')
            metrics['disk_percent'] = disk.percent
            metrics['disk_free'] = disk.free
            metrics['disk_total'] = disk.total
            
        except psutil.Error as e:
            self.logger.error(f"Error getting system metrics: {e}")
            metrics['error'] = str(e)
            
        return metrics
    
    def get_comprehensive_system_metrics(self) -> Dict:
        """Get comprehensive system metrics with enhanced error handling"""
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'cpu': self._get_cpu_metrics(),
            'memory': self._get_memory_metrics(),
            'disk': self._get_disk_metrics(),
            'network': self._get_network_metrics(),
            'processes': self._get_process_metrics()
        }
        
        # Update metrics history
        for key in self.metrics_history:
            if key in metrics:
                self.metrics_history[key].append({
                    'timestamp': metrics['timestamp'],
                    'data': metrics[key]
                })
                # Maintain history limit
                if len(self.metrics_history[key]) > self.history_limit:
                    self.metrics_history[key].pop(0)
        
        # Export to Prometheus if enabled
        if self.prometheus_enabled:
            self._export_to_prometheus(metrics)
        
        return metrics
    
    def _get_cpu_metrics(self) -> Dict:
        """Get detailed CPU metrics"""
        try:
            cpu_times = psutil.cpu_times_percent()
            cpu_freq = psutil.cpu_freq()
            cpu_stats = psutil.cpu_stats()
            
            return {
                'total_usage': psutil.cpu_percent(interval=None),
                'per_cpu': psutil.cpu_percent(interval=None, percpu=True),
                'times_percent': {
                    'user': cpu_times.user,
                    'system': cpu_times.system,
                    'idle': cpu_times.idle,
                    'iowait': getattr(cpu_times, 'iowait', 0),
                },
                'frequency': {
                    'current': cpu_freq.current if cpu_freq else 0,
                    'min': cpu_freq.min if cpu_freq else 0,
                    'max': cpu_freq.max if cpu_freq else 0
                },
                'stats': {
                    'ctx_switches': cpu_stats.ctx_switches,
                    'interrupts': cpu_stats.interrupts,
                    'soft_interrupts': cpu_stats.soft_interrupts,
                    'syscalls': cpu_stats.syscalls
                }
            }
        except Exception as e:
            self.logger.error(f"Error getting CPU metrics: {str(e)}")
            return {'error': str(e)}
    
    def _get_memory_metrics(self) -> Dict:
        """Get detailed memory metrics"""
        try:
            virtual = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            return {
                'virtual': {
                    'total': virtual.total,
                    'available': virtual.available,
                    'used': virtual.used,
                    'free': virtual.free,
                    'percent': virtual.percent,
                    'active': getattr(virtual, 'active', 0),
                    'inactive': getattr(virtual, 'inactive', 0),
                    'buffers': getattr(virtual, 'buffers', 0),
                    'cached': getattr(virtual, 'cached', 0),
                    'shared': getattr(virtual, 'shared', 0)
                },
                'swap': {
                    'total': swap.total,
                    'used': swap.used,
                    'free': swap.free,
                    'percent': swap.percent,
                    'sin': swap.sin,
                    'sout': swap.sout
                }
            }
        except Exception as e:
            self.logger.error(f"Error getting memory metrics: {str(e)}")
            return {'error': str(e)}
            
    def _get_disk_metrics(self) -> Dict:
        """Get detailed disk metrics"""
        try:
            # Get disk partitions
            partitions = psutil.disk_partitions(all=False)
            disk_data = {}
            
            for partition in partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_data[partition.mountpoint] = {
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'opts': partition.opts,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    }
                except (PermissionError, OSError) as e:
                    self.logger.warning(f"Could not get disk usage for {partition.mountpoint}: {str(e)}")
                    continue
            
            # Get disk I/O statistics
            try:
                io_counters = psutil.disk_io_counters()
                if io_counters:
                    disk_data['io_stats'] = {
                        'read_bytes': io_counters.read_bytes,
                        'write_bytes': io_counters.write_bytes,
                        'read_count': io_counters.read_count,
                        'write_count': io_counters.write_count,
                        'read_time': io_counters.read_time,
                        'write_time': io_counters.write_time
                    }
            except Exception as e:
                self.logger.warning(f"Could not get disk I/O statistics: {str(e)}")
                disk_data['io_stats'] = {'error': str(e)}
            
            return disk_data
            
        except Exception as e:
            self.logger.error(f"Error getting disk metrics: {str(e)}")
            return {'error': str(e)}

    def _get_network_metrics(self) -> Dict:
        """Get detailed network metrics"""
        try:
            # Get network I/O counters
            net_io = psutil.net_io_counters()
            
            # Get current bandwidth usage
            bandwidth = self.get_bandwidth_usage()
            
            # Get network interfaces
            interfaces = {}
            for interface, stats in psutil.net_if_stats().items():
                try:
                    addrs = psutil.net_if_addrs().get(interface, [])
                    addresses = []
                    for addr in addrs:
                        addresses.append({
                            'address': addr.address,
                            'netmask': addr.netmask,
                            'broadcast': getattr(addr, 'broadcast', None),
                            'ptp': getattr(addr, 'ptp', None)
                        })
                    
                    interfaces[interface] = {
                        'isup': stats.isup,
                        'duplex': stats.duplex,
                        'speed': stats.speed,
                        'mtu': stats.mtu,
                        'addresses': addresses
                    }
                except Exception as e:
                    self.logger.warning(f"Error getting details for interface {interface}: {str(e)}")
                    continue
            
            # Get network connections
            connections = []
            try:
                for conn in psutil.net_connections(kind='inet'):
                    connections.append({
                        'fd': conn.fd,
                        'family': conn.family,
                        'type': conn.type,
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    })
            except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
                self.logger.warning(f"Limited access to network connections: {str(e)}")
            
            return {
                'io_counters': {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv,
                    'errin': net_io.errin,
                    'errout': net_io.errout,
                    'dropin': net_io.dropin,
                    'dropout': net_io.dropout
                },
                'bandwidth': bandwidth,
                'interfaces': interfaces,
                'connections': connections,
                'connection_count': len(connections)
            }
            
        except Exception as e:
            self.logger.error(f"Error getting network metrics: {str(e)}")
            return {'error': str(e)}

    def _get_process_metrics(self) -> Dict:
        """Get detailed process metrics"""
        try:
            processes = []
            total_threads = 0
            total_fds = 0
            total_connections = 0
            
            # Get all processes
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'status', 
                                          'num_threads', 'num_fds', 'create_time', 'ppid']):
                try:
                    # Get process info
                    pinfo = proc.info
                    
                    # Get CPU and memory percentages separately with error handling
                    try:
                        cpu_percent = proc.cpu_percent()
                        memory_percent = proc.memory_percent()
                    except (psutil.AccessDenied, AttributeError):
                        cpu_percent = 0
                        memory_percent = 0
                    
                    # Get memory info
                    try:
                        mem_info = proc.memory_info()
                    except (psutil.AccessDenied, AttributeError):
                        mem_info = None
                    
                    # Get IO counters (might fail due to permissions)
                    try:
                        io_counters = proc.io_counters()
                        io_stats = {
                            'read_bytes': io_counters.read_bytes,
                            'write_bytes': io_counters.write_bytes,
                            'read_count': io_counters.read_count,
                            'write_count': io_counters.write_count
                        }
                    except (psutil.AccessDenied, AttributeError):
                        io_stats = {
                            'read_bytes': 0,
                            'write_bytes': 0,
                            'read_count': 0,
                            'write_count': 0
                        }
                    
                    # Get network connections (might fail due to permissions)
                    try:
                        connections = proc.connections()
                        conn_count = len(connections)
                        total_connections += conn_count
                    except (psutil.AccessDenied, AttributeError):
                        conn_count = 0
                    
                    # Update totals with safe access
                    total_threads += pinfo.get('num_threads', 0)
                    if 'num_fds' in pinfo and pinfo['num_fds'] is not None:
                        total_fds += pinfo['num_fds']
                    
                    # Create process entry with safe dictionary access
                    process = {
                        'pid': pinfo.get('pid', 0),
                        'name': pinfo.get('name', ''),
                        'username': pinfo.get('username', ''),
                        'cmdline': pinfo.get('cmdline', []),
                        'cpu_percent': cpu_percent,
                        'memory_percent': memory_percent,
                        'status': pinfo.get('status', ''),
                        'num_threads': pinfo.get('num_threads', 0),
                        'num_fds': pinfo.get('num_fds', 0),
                        'create_time': pinfo.get('create_time', 0),
                        'ppid': pinfo.get('ppid', 0),
                        'memory': {
                            'rss': getattr(mem_info, 'rss', 0) if mem_info else 0,
                            'vms': getattr(mem_info, 'vms', 0) if mem_info else 0,
                            'shared': getattr(mem_info, 'shared', 0) if mem_info else 0,
                            'text': getattr(mem_info, 'text', 0) if mem_info else 0,
                            'data': getattr(mem_info, 'data', 0) if mem_info else 0
                        },
                        'io': io_stats,
                        'connections': conn_count
                    }
                    
                    processes.append(process)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Sort processes by CPU usage
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            
            return {
                'process_count': len(processes),
                'thread_count': total_threads,
                'fd_count': total_fds,
                'connection_count': total_connections,
                'top_processes': processes[:10],  # Only return top 10 processes
                'processes': processes,  # Full list for detailed analysis
                'summary': {
                    'running': len([p for p in processes if p['status'] == 'running']),
                    'sleeping': len([p for p in processes if p['status'] == 'sleeping']),
                    'stopped': len([p for p in processes if p['status'] == 'stopped']),
                    'zombie': len([p for p in processes if p['status'] == 'zombie'])
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error getting process metrics: {str(e)}")
            return {'error': str(e)}
    
    def detect_anomalies(self, current_metrics: Dict) -> List[Dict]:
        """Detect anomalies in system metrics using statistical analysis"""
        anomalies = []
        
        if not self.anomaly_detection_enabled:
            return anomalies
        
        try:
            # CPU Usage Anomaly Detection
            cpu_history = [m['data']['total_usage'] for m in self.metrics_history['cpu']]
            if cpu_history:
                mean = statistics.mean(cpu_history)
                stdev = statistics.stdev(cpu_history) if len(cpu_history) > 1 else 0
                current_cpu = current_metrics['cpu']['total_usage']
                
                if abs(current_cpu - mean) > (2 * stdev):  # Outside 2 standard deviations
                    anomalies.append({
                        'type': 'cpu_usage_anomaly',
                        'severity': 'high' if abs(current_cpu - mean) > (3 * stdev) else 'medium',
                        'message': f'Abnormal CPU usage detected: {current_cpu:.1f}% (Mean: {mean:.1f}%, StdDev: {stdev:.1f}%)'
                    })
            
            # Memory Usage Anomaly Detection
            memory_history = [m['data']['virtual']['percent'] for m in self.metrics_history['memory']]
            if memory_history:
                mean = statistics.mean(memory_history)
                stdev = statistics.stdev(memory_history) if len(memory_history) > 1 else 0
                current_memory = current_metrics['memory']['virtual']['percent']
                
                if abs(current_memory - mean) > (2 * stdev):
                    anomalies.append({
                        'type': 'memory_usage_anomaly',
                        'severity': 'high' if abs(current_memory - mean) > (3 * stdev) else 'medium',
                        'message': f'Abnormal memory usage detected: {current_memory:.1f}% (Mean: {mean:.1f}%, StdDev: {stdev:.1f}%)'
                    })
            
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {str(e)}")
        
        return anomalies
    
    def _export_to_prometheus(self, metrics: Dict):
        """Export metrics to Prometheus if enabled"""
        try:
            if not self.prometheus_enabled:
                return
                
            # Update CPU metrics
            cpu_metrics = metrics.get('cpu', {})
            if isinstance(cpu_metrics, dict) and 'total_usage' in cpu_metrics:
                self.cpu_usage_gauge.set(cpu_metrics['total_usage'])
            
            # Update Memory metrics
            memory_metrics = metrics.get('memory', {}).get('virtual', {})
            if isinstance(memory_metrics, dict) and 'percent' in memory_metrics:
                self.memory_usage_gauge.set(memory_metrics['percent'])
            
            # Calculate disk usage percentage
            disk_metrics = metrics.get('disk', {})
            if isinstance(disk_metrics, dict):
                total_size = 0
                used_size = 0
                for mount_data in disk_metrics.values():
                    if isinstance(mount_data, dict) and 'total' in mount_data and 'used' in mount_data:
                        total_size += mount_data['total']
                        used_size += mount_data['used']
                
                if total_size > 0:
                    disk_percent = (used_size / total_size) * 100
                    self.disk_usage_gauge.set(disk_percent)
            
            # Update network counters if available
            network_metrics = metrics.get('network', {})
            if isinstance(network_metrics, dict):
                if 'bytes_sent' in network_metrics:
                    self.network_bytes_sent.inc(network_metrics['bytes_sent'])
                if 'bytes_recv' in network_metrics:
                    self.network_bytes_recv.inc(network_metrics['bytes_recv'])
                
        except Exception as e:
            self.logger.error(f"Error exporting to Prometheus: {str(e)}")
    
    def get_performance_report(self) -> Dict:
        """Generate a comprehensive performance report"""
        bandwidth = self.get_bandwidth_usage()
        system_metrics = self.get_system_metrics()
        process_stats = self.get_process_network_stats()
        
        # Calculate bandwidth statistics from both raw and aggregated data
        if self.raw_bandwidth_history or self.aggregated_bandwidth_history:
            # Get recent statistics from raw data
            recent_upload_speeds = [entry["upload"] for entry in self.raw_bandwidth_history]
            recent_download_speeds = [entry["download"] for entry in self.raw_bandwidth_history]
            
            # Get historical statistics from aggregated data
            historical_upload_speeds = [entry["upload"] for entry in self.aggregated_bandwidth_history]
            historical_download_speeds = [entry["download"] for entry in self.aggregated_bandwidth_history]
            
            # Combine recent and historical data
            all_upload_speeds = recent_upload_speeds + historical_upload_speeds
            all_download_speeds = recent_download_speeds + historical_download_speeds
            
            bandwidth_stats = {
                "recent": {
                    "upload_avg": statistics.mean(recent_upload_speeds) if recent_upload_speeds else 0,
                    "upload_max": max(recent_upload_speeds) if recent_upload_speeds else 0,
                    "download_avg": statistics.mean(recent_download_speeds) if recent_download_speeds else 0,
                    "download_max": max(recent_download_speeds) if recent_download_speeds else 0,
                    "timespan": "5 minutes"
                },
                "historical": {
                    "upload_avg": statistics.mean(historical_upload_speeds) if historical_upload_speeds else 0,
                    "upload_max": max(historical_upload_speeds) if historical_upload_speeds else 0,
                    "download_avg": statistics.mean(historical_download_speeds) if historical_download_speeds else 0,
                    "download_max": max(historical_download_speeds) if historical_download_speeds else 0,
                    "timespan": "24 hours"
                },
                "overall": {
                    "upload_avg": statistics.mean(all_upload_speeds) if all_upload_speeds else 0,
                    "upload_max": max(all_upload_speeds) if all_upload_speeds else 0,
                    "download_avg": statistics.mean(all_download_speeds) if all_download_speeds else 0,
                    "download_max": max(all_download_speeds) if all_download_speeds else 0
                }
            }
        else:
            bandwidth_stats = {
                "recent": {
                    "upload_avg": 0,
                    "upload_max": 0,
                    "download_avg": 0,
                    "download_max": 0,
                    "timespan": "5 minutes"
                },
                "historical": {
                    "upload_avg": 0,
                    "upload_max": 0,
                    "download_avg": 0,
                    "download_max": 0,
                    "timespan": "24 hours"
                },
                "overall": {
                    "upload_avg": 0,
                    "upload_max": 0,
                    "download_avg": 0,
                    "download_max": 0
                }
            }
        
        return {
            "timestamp": datetime.now().isoformat(),
            "current_bandwidth": bandwidth,
            "bandwidth_stats": bandwidth_stats,
            "system_metrics": system_metrics,
            "process_stats": process_stats,
            "latency_stats": {
                host: {
                    "current": history[-1]["latency"] if history else None,
                    "avg": statistics.mean([h["latency"] for h in history]) if history else None,
                    "max": max([h["latency"] for h in history]) if history else None,
                    "min": min([h["latency"] for h in history]) if history else None
                }
                for host, history in self.latency_history.items()
            },
            "memory_usage": {
                "raw_history_size": len(self.raw_bandwidth_history),
                "aggregated_history_size": len(self.aggregated_bandwidth_history),
                "total_entries": len(self.raw_bandwidth_history) + len(self.aggregated_bandwidth_history)
            }
        }
    
    def measure_latency(self, host: str) -> Optional[float]:
        """Measure network latency to a specific host"""
        try:
            if os.name == 'nt':  # Windows
                ping_param = '-n'
            else:  # Unix/Linux/MacOS
                ping_param = '-c'
            
            # Use subprocess instead of os.system for better control and security
            cmd = ['ping', ping_param, '1', '-W', '1', host]
            start_time = time.time()
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            end_time = time.time()
            
            if result.returncode == 0:
                latency = (end_time - start_time) * 1000  # Convert to milliseconds
                
                # Store in history
                if host not in self.latency_history:
                    self.latency_history[host] = []
                self.latency_history[host].append({
                    "timestamp": datetime.now().isoformat(),
                    "latency": float(latency)  # Ensure latency is stored as float
                })
                
                # Keep last hour of history
                self.latency_history[host] = self.latency_history[host][-3600:]
                
                return latency
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error measuring latency to {host}: {str(e)}")
            return None
    
    @staticmethod
    def _humanize_bytes(bytes_per_sec: float) -> str:
        """Convert bytes per second to human readable format"""
        for unit in ['B/s', 'KB/s', 'MB/s', 'GB/s']:
            if bytes_per_sec < 1024.0:
                return f"{bytes_per_sec:.2f} {unit}"
            bytes_per_sec /= 1024.0
        return f"{bytes_per_sec:.2f} TB/s"
