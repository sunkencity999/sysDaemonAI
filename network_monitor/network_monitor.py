#!/usr/bin/env python3
import json
import logging
from logging_config import ContextLogger, setup_logging
from datetime import datetime, timedelta
import threading
import queue
import requests
import psutil
import schedule
from plyer import notification
import pandas as pd
from scapy.all import *
from threat_detector import ThreatDetector
from performance_monitor import PerformanceMonitor
from alert_manager import AlertManager
from auto_responder import AutoResponder
from database import DatabaseManager
from async_database import AsyncDatabaseManager
from backup_manager import BackupManager
from advanced_config import AdvancedConfig
from ip_blacklist_manager import IPBlacklistManager
from cache_manager import CacheManager, cached_result
from llm_analyzer import LLMAnalyzer
import statistics
from config import OLLAMA_CONFIG, PERFORMANCE_CONFIG, NOTIFICATION_CONFIG, LOG_CONFIG
import asyncio
from typing import Optional, Dict, Any
from network_utils import NetworkManager, OllamaCache, batch_processor
from async_utils import AsyncTaskManager, ConnectionPool, TaskPriority, cpu_bound, run_in_process
import uuid
import subprocess

class NetworkMonitor:
    def __init__(self, gui_confirmation_callback=None, async_db_manager: Optional[AsyncDatabaseManager] = None):
        # Initialize logging
        setup_logging(app_name='network_monitor')
        self.logger = ContextLogger('network_monitor')
        
        # Initialize configuration
        self.config = AdvancedConfig()
        
        # Create logs directory if it doesn't exist
        self.logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
        os.makedirs(self.logs_dir, exist_ok=True)
        
        # Initialize database manager
        self.db_manager = async_db_manager if async_db_manager else DatabaseManager()
        
        # Ensure log files exist with proper permissions
        self.ensure_log_files()
        
        # Initialize async components
        self.async_db = async_db_manager
        
        self.setup_logging()
        self.connection_history = []
        self.analysis_queue = asyncio.Queue()
        self.baseline = {}
        
        # Initialize Ollama configuration
        self.model = OLLAMA_CONFIG.get('model', 'mistral')  # Default model
        self.ollama_retries = OLLAMA_CONFIG.get('retries', 3)  # Default retries
        self.ollama_retry_delay = OLLAMA_CONFIG.get('retry_delay', 1)  # Default retry delay in seconds
        self.ollama_timeout = OLLAMA_CONFIG.get('timeout', 30)  # Default timeout in seconds
        self.ollama_base_url = OLLAMA_CONFIG.get('base_url', 'http://localhost:11434')
        self.ollama_health_url = f"{self.ollama_base_url}{OLLAMA_CONFIG.get('health_endpoint', '/api/version')}"
        self.ollama_generate_url = f"{self.ollama_base_url}{OLLAMA_CONFIG.get('generate_endpoint', '/api/generate')}"
        
        # Initialize backup manager
        self.backup_manager = BackupManager()
        self.backup_manager.start()
        
        # Initialize IP blacklist manager
        self.ip_blacklist_manager = IPBlacklistManager()
        
        # Initialize core components
        self.threat_detector = ThreatDetector(self.logger, self.ip_blacklist_manager)
        self.performance_monitor = PerformanceMonitor(self.logger)
        self.alert_manager = AlertManager(self.logger)
        self.auto_responder = AutoResponder(self.logger, gui_confirmation_callback)
        
        # Initialize LLM analyzer
        self.llm_analyzer = LLMAnalyzer(self.logger)
        
        # Initialize network utilities
        self.network_manager = NetworkManager(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=3,
            cache_ttl=300,
            cache_maxsize=1000
        )
        
        # Initialize Ollama cache
        self.ollama_cache = OllamaCache(
            ttl=3600,  # Cache Ollama responses for 1 hour
            maxsize=1000
        )
        
        # Initialize async utilities
        self.task_manager = AsyncTaskManager()
        self.connection_pool = ConnectionPool(min_size=10, max_size=100)
        
        # Create event loop for async operations
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        # Initialize async components in a separate thread
        self._init_thread = threading.Thread(target=self._init_async_components)
        self._init_thread.start()
        self._init_thread.join()  # Wait for initialization to complete
        
        # Initialize monitored hosts for performance tracking
        self.monitored_hosts = ['8.8.8.8', '1.1.1.1']  # Default hosts to measure latency
        self.performance_history = []
        
        # Load baseline if exists
        self.load_baseline()
        
        # Schedule daily report and performance monitoring
        schedule.every().day.at("23:59").do(self.generate_daily_report)
        schedule.every(1).minutes.do(self.update_performance_metrics)
    
    def _init_async_components(self):
        """Initialize async components in a separate thread."""
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._start_async_components())
    
    async def _start_async_components(self):
        """Start all async components."""
        await self.task_manager.start()
        await self.connection_pool.start()
    
    async def _stop_async_components(self):
        """Stop all async components."""
        await self.task_manager.stop()
        await self.connection_pool.stop()
    
    def ensure_log_files(self):
        """Ensure all necessary log files exist with proper permissions"""
        log_files = {
            'network_monitor.log': '',
            'connections.json': '[]',
            'baseline.json': '{}'
        }
        
        for filename, initial_content in log_files.items():
            file_path = os.path.join(self.logs_dir, filename)
            if not os.path.exists(file_path):
                with open(file_path, 'w') as f:
                    f.write(initial_content)
                os.chmod(file_path, 0o666)  # Set read/write permissions
                
        self.logger.info("Log files initialized")

    def setup_logging(self):
        log_file = os.path.join(self.logs_dir, 'network_monitor.log')
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Logging system initialized")

    def load_baseline(self):
        baseline_file = os.path.join(self.logs_dir, 'baseline.json')
        if os.path.exists(baseline_file):
            try:
                with open(baseline_file, 'r') as f:
                    self.baseline = json.load(f)
            except json.JSONDecodeError:
                self.logger.error("Failed to load baseline file")
                
    def get_current_connections(self):
        """Get current network connections"""
        try:
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                try:
                    # Only process connections that have a local address
                    if not hasattr(conn, 'laddr') or not conn.laddr:
                        continue

                    # Get process information
                    process = psutil.Process(conn.pid) if conn.pid else None
                    process_name = process.name() if process else "Unknown"

                    # Format addresses safely
                    local_address = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "unknown:0"
                    remote_address = "0.0.0.0:0"  # Default for no remote address
                    
                    # Only set remote address if it exists
                    if hasattr(conn, 'raddr') and conn.raddr:
                        remote_address = f"{conn.raddr.ip}:{conn.raddr.port}"

                    connections.append({
                        'local_address': local_address,
                        'remote_address': remote_address,
                        'status': conn.status,
                        'pid': conn.pid,
                        'process': process_name
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError) as e:
                    self.logger.debug(f"Skipping connection due to error: {str(e)}")
                    continue
            return connections
        except psutil.AccessDenied:
            self.logger.warning("Access denied getting connections, trying with sudo")
            return []
        except Exception as e:
            self.logger.error(f"Error getting connections: {str(e)}")
            return []

    def _get_connections_internal(self):
        """Internal method to get connections without sudo"""
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            try:
                # Only process connections that have a local address
                if not hasattr(conn, 'laddr') or not conn.laddr:
                    continue

                # Get process information
                process = psutil.Process(conn.pid) if conn.pid else None
                process_name = process.name() if process else "Unknown"

                # Format addresses safely
                local_address = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "unknown:0"
                remote_address = "0.0.0.0:0"  # Default for no remote address
                
                # Only set remote address if it exists
                if hasattr(conn, 'raddr') and conn.raddr:
                    remote_address = f"{conn.raddr.ip}:{conn.raddr.port}"

                connections.append({
                    'local_address': local_address,
                    'remote_address': remote_address,
                    'status': conn.status,
                    'pid': conn.pid,
                    'process': process_name
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError) as e:
                self.logger.debug(f"Skipping connection due to error: {str(e)}")
                continue
        return connections

    def analyze_with_llm(self, data):
        """Enhanced LLM analysis with improved error handling and retry logic"""
        if not self.check_ollama_health():
            self.logger.error("Ollama service is not available")
            return None

        prompt = f"""
Analyze the following network monitoring data and provide insights:
{json.dumps(data, indent=2)}

Format your response as:
- Summary: Brief overview
- Findings: List any suspicious or notable items
- Risk Level: Low/Medium/High
- Recommendations: If any actions needed

Focus on actionable insights and clear security implications."""

        retries = 0
        while retries < self.ollama_retries:
            try:
                response = requests.post(
                    self.ollama_base_url,
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False
                    },
                    timeout=self.ollama_timeout
                )
                
                if response.status_code == 200:
                    analysis = response.json().get('response')
                    if analysis:
                        self.logger.info(f"LLM Analysis completed successfully")
                        return analysis
                    else:
                        self.logger.error("Empty response from Ollama API")
                elif response.status_code == 404:
                    self.logger.error(f"Model '{self.model}' not found. Please ensure it is installed.")
                    return None
                elif response.status_code == 500:
                    self.logger.error("Internal server error from Ollama API")
                else:
                    self.logger.error(f"Failed to get LLM response: {response.status_code}")
                
            except requests.exceptions.Timeout:
                self.logger.error(f"Request timeout after {self.ollama_timeout} seconds")
            except requests.exceptions.ConnectionError:
                self.logger.error("Failed to connect to Ollama service")
            except Exception as e:
                self.logger.error(f"Unexpected error communicating with Ollama: {str(e)}")
            
            retries += 1
            if retries < self.ollama_retries:
                time.sleep(self.ollama_retry_delay)
        
        self.logger.error(f"Failed to get LLM analysis after {self.ollama_retries} attempts")
        return None

    def analyze_with_ollama(self, data: str, model: str = "llama2") -> str:
        """Analyze data using Ollama with connection pooling."""
        try:
            # Check cache first
            cached_response = self.ollama_cache.get_cached_response(
                model=model,
                prompt=data
            )
            
            if cached_response:
                self.logger.debug("Using cached Ollama response")
                return cached_response
            
            # Ensure data is a string
            if isinstance(data, bytes):
                data = data.decode('utf-8')
            elif not isinstance(data, str):
                data = str(data)
            
            # Create a synchronous request using the network manager
            response = self.network_manager.request(
                method="POST",
                url=f"{OLLAMA_CONFIG['base_url']}/api/generate",
                data={
                    "model": model,
                    "prompt": data
                },
                compress=True
            )
            
            if response.status_code == 200:
                result = response.json()['response']
                # Cache the response
                self.ollama_cache.cache_response(
                    model=model,
                    prompt=data,
                    response=result
                )
                return result
            else:
                self.logger.error(f"Ollama request failed: {response.status_code}")
                return ""
                
        except Exception as e:
            self.logger.error(f"Error in Ollama analysis: {str(e)}")
            return ""
    
    async def analyze_with_ollama_async(self, data: str, model: str = "llama2") -> str:
        """Async version of Ollama analysis."""
        try:
            # Check cache first
            cached_response = self.ollama_cache.get_cached_response(
                model=model,
                prompt=data
            )
            
            if cached_response:
                self.logger.debug("Using cached Ollama response")
                return cached_response
            
            # Ensure data is a string
            if isinstance(data, bytes):
                data = data.decode('utf-8')
            elif not isinstance(data, str):
                data = str(data)
            
            # Use connection pool for Ollama requests
            async with self.connection_pool.acquire() as session:
                async with session.post(
                    f"{OLLAMA_CONFIG['base_url']}/api/generate",
                    json={
                        "model": model,
                        "prompt": data
                    }
                ) as response:
                    if response.status == 200:
                        result = (await response.json())['response']
                        # Cache the response
                        self.ollama_cache.cache_response(
                            model=model,
                            prompt=data,
                            response=result
                        )
                        return result
                    else:
                        self.logger.error(f"Ollama request failed: {response.status}")
                        return ""
                    
        except Exception as e:
            self.logger.error(f"Error in Ollama analysis: {str(e)}")
            return ""
    
    async def check_ollama_health_async(self) -> bool:
        """Check Ollama service health asynchronously with caching."""
        cache_key = "ollama_health"
        cached_status = self.cache_manager.get_api_response("health", cache_key)
        if cached_status is not None:
            return cached_status

        for attempt in range(self.ollama_retries):
            try:
                async with self.connection_pool.get() as session:
                    async with session.get(self.ollama_health_url) as response:
                        is_healthy = response.status == 200
                        self.cache_manager.cache_api_response("health", cache_key, is_healthy, ttl=60)
                        if is_healthy:
                            self.logger.info("Ollama service is available")
                        else:
                            self.logger.warning(f"Ollama service returned status: {response.status}")
                        return is_healthy
            except Exception as e:
                self.logger.warning(f"Ollama connection failed (attempt {attempt + 1}/{self.ollama_retries}): {str(e)}")
                if attempt < self.ollama_retries - 1:
                    await asyncio.sleep(self.ollama_retry_delay)

        self.logger.error("Ollama service is not available after all retries")
        return False

    def check_ollama_health(self) -> bool:
        """Synchronous wrapper for checking Ollama service health."""
        if hasattr(self, 'loop') and self.loop.is_running():
            # If we're in an async context, use asyncio.run_coroutine_threadsafe
            future = asyncio.run_coroutine_threadsafe(self.check_ollama_health_async(), self.loop)
            try:
                return future.result(timeout=self.ollama_timeout)
            except Exception as e:
                self.logger.error(f"Error checking Ollama health: {str(e)}")
                return False
        else:
            # If we're not in an async context, use requests
            for attempt in range(self.ollama_retries):
                try:
                    response = requests.get(self.ollama_health_url, timeout=self.ollama_timeout)
                    is_healthy = response.status_code == 200
                    if is_healthy:
                        self.logger.info("Ollama service is available")
                    else:
                        self.logger.warning(f"Ollama service returned status code: {response.status_code}")
                    return is_healthy
                except Exception as e:
                    self.logger.warning(f"Ollama connection failed (attempt {attempt + 1}/{self.ollama_retries}): {str(e)}")
                    if attempt < self.ollama_retries - 1:
                        time.sleep(self.ollama_retry_delay)
            
            self.logger.error("Ollama service is not available after all retries")
            return False

    def analyze_connections(self):
        """Analyze and log network connections"""
        self.logger.info("Starting connection analysis thread...")
        while True:
            try:
                connections = self.get_current_connections()
                if connections:
                    self.connection_history.extend(connections)
                    
                    # Save connections to log file
                    log_file = os.path.join(self.logs_dir, 'connections.json')
                    try:
                        with open(log_file, 'a') as f:
                            for conn in connections:
                                json_line = json.dumps(conn)
                                f.write(json_line + '\n')
                        self.logger.info(f"Logged {len(connections)} new connections to {log_file}")
                    except Exception as e:
                        self.logger.error(f"Error writing to connections log: {str(e)}")
                    
                    # Analyze with LLM if we have meaningful connections
                    meaningful_connections = [
                        conn for conn in connections 
                        if conn.get('remote_ip') and conn.get('remote_port')
                    ]
                    if meaningful_connections:
                        self.logger.info(f"Analyzing {len(meaningful_connections)} meaningful connections")
                        analysis = self.analyze_with_llm(meaningful_connections)
                        if analysis and "attention" in analysis.lower():
                            self.show_notification(
                                "Unusual Network Activity Detected",
                                analysis[:100] + "..." if len(analysis) > 100 else analysis
                            )
                else:
                    self.logger.debug("No new connections detected")
                
                # Update baseline every hour
                current_hour = datetime.now().hour
                if not hasattr(self, 'last_baseline_hour') or current_hour != self.last_baseline_hour:
                    self.update_baseline()
                    self.last_baseline_hour = current_hour
                
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                self.logger.error(f"Error in connection analysis: {str(e)}")
                time.sleep(5)

    def update_baseline(self):
        """Update baseline with improved metrics"""
        try:
            df = pd.DataFrame(self.connection_history[-1000:])  # Use last 1000 connections
            if not df.empty:
                self.baseline = {
                    'timestamp': datetime.now().isoformat(),
                    'metrics': {
                        'common_ips': df['remote_ip'].value_counts().head(50).to_dict(),
                        'common_ports': df['remote_port'].value_counts().head(50).to_dict(),
                        'common_statuses': df['status'].value_counts().to_dict(),
                        'connection_frequency': {
                            'hourly_avg': len(df) / 24,  # Assuming data spans 24 hours
                            'total_unique_ips': len(df['remote_ip'].unique()),
                            'total_unique_ports': len(df['remote_port'].unique())
                        }
                    },
                    'history': self.baseline.get('history', [])[-10:]  # Keep last 10 baseline updates
                }
                
                # Add current baseline to history
                self.baseline['history'].append({
                    'timestamp': datetime.now().isoformat(),
                    'metrics': self.baseline['metrics'].copy()
                })
                
                # Save baseline to file
                baseline_file = os.path.join(self.logs_dir, 'baseline.json')
                with open(baseline_file, 'w') as f:
                    json.dump(self.baseline, f, indent=2)
                self.logger.info("Baseline updated successfully")
            else:
                self.logger.warning("No connection data available for baseline update")
        except Exception as e:
            self.logger.error(f"Error updating baseline: {str(e)}")

    def update_performance_metrics(self):
        """Update performance metrics and store in history"""
        try:
            current_metrics = {
                'timestamp': datetime.now(),
                'cpu': {
                    'total_usage': psutil.cpu_percent(interval=1),
                    'per_cpu': psutil.cpu_percent(interval=1, percpu=True),
                    'load_avg': psutil.getloadavg()
                },
                'memory': {
                    'total': psutil.virtual_memory().total,
                    'available': psutil.virtual_memory().available,
                    'percent': psutil.virtual_memory().percent,
                    'used': psutil.virtual_memory().used,
                    'free': psutil.virtual_memory().free
                },
                'disk': {
                    'total': psutil.disk_usage('/').total,
                    'used': psutil.disk_usage('/').used,
                    'free': psutil.disk_usage('/').free,
                    'percent': psutil.disk_usage('/').percent
                },
                'network': {
                    'connections': len(psutil.net_connections()),
                    'bytes_sent': psutil.net_io_counters().bytes_sent,
                    'bytes_recv': psutil.net_io_counters().bytes_recv,
                    'packets_sent': psutil.net_io_counters().packets_sent,
                    'packets_recv': psutil.net_io_counters().packets_recv
                }
            }

            # Store in performance history
            self.performance_history.append(current_metrics)
            
            # Keep only last 24 hours of data
            cutoff_time = datetime.now() - timedelta(hours=24)
            self.performance_history = [
                metrics for metrics in self.performance_history 
                if metrics['timestamp'] > cutoff_time
            ]
            
            # Log significant changes
            self._log_performance_changes(current_metrics)
            
            # Record metrics to database
            self.record_metrics(current_metrics)
            
            return current_metrics
            
        except Exception as e:
            self.logger.error(f"Error updating performance metrics: {str(e)}")
            return None

    def _log_performance_changes(self, current_data):
        """Log significant changes in performance metrics"""
        if not self.performance_history[:-1]:  # No previous data
            return
            
        prev_data = self.performance_history[-2]
        
        # Check CPU usage
        if current_data['cpu']['total_usage'] > 90:
            self.logger.warning(f"High CPU usage: {current_data['cpu']['total_usage']}%")
            
        # Check memory usage
        if current_data['memory']['percent'] > 90:
            self.logger.warning(f"High memory usage: {current_data['memory']['percent']}%")
            
        # Check bandwidth spikes
        curr_bandwidth = current_data['network']
        if curr_bandwidth['bytes_sent'] > prev_data['network']['bytes_sent'] * 2:
            self.logger.warning(f"Upload bandwidth spike: {curr_bandwidth['bytes_sent']}")
        if curr_bandwidth['bytes_recv'] > prev_data['network']['bytes_recv'] * 2:
            self.logger.warning(f"Download bandwidth spike: {curr_bandwidth['bytes_recv']}")
    
    def get_performance_stats(self):
        """Get current performance statistics"""
        if not self.performance_history:
            return None
        return self.performance_history[-1]
    
    def get_performance_summary(self):
        """Get a summary of performance metrics over time"""
        if not self.performance_history:
            return None
            
        # Calculate averages and trends
        cpu_usage = [d['cpu']['total_usage'] for d in self.performance_history]
        memory_usage = [d['memory']['percent'] for d in self.performance_history]
        bandwidth_up = [d['network']['bytes_sent'] for d in self.performance_history]
        bandwidth_down = [d['network']['bytes_recv'] for d in self.performance_history]
        
        return {
            "time_range": {
                "start": self.performance_history[0]['timestamp'],
                "end": self.performance_history[-1]['timestamp']
            },
            "cpu": {
                "avg": statistics.mean(cpu_usage),
                "max": max(cpu_usage),
                "min": min(cpu_usage)
            },
            "memory": {
                "avg": statistics.mean(memory_usage),
                "max": max(memory_usage),
                "min": min(memory_usage)
            },
            "bandwidth": {
                "upload": {
                    "avg": self.performance_monitor._humanize_bytes(statistics.mean(bandwidth_up)),
                    "max": self.performance_monitor._humanize_bytes(max(bandwidth_up)),
                    "min": self.performance_monitor._humanize_bytes(min(bandwidth_up))
                },
                "download": {
                    "avg": self.performance_monitor._humanize_bytes(statistics.mean(bandwidth_down)),
                    "max": self.performance_monitor._humanize_bytes(max(bandwidth_down)),
                    "min": self.performance_monitor._humanize_bytes(min(bandwidth_down))
                }
            },
            "latency": {
                host: {
                    "current": history[-1]["latency"] if history else None,
                    "avg": statistics.mean([h["latency"] for h in history]) if history else None
                }
                for host, history in self.performance_monitor.latency_history.items()
            }
        }

    def generate_daily_report(self):
        """Generate a comprehensive daily report using the LLM"""
        try:
            current_time = datetime.now()
            today = current_time.strftime('%Y-%m-%d')
            report_file = os.path.join(self.logs_dir, f'daily_report_{today}.txt')
            
            # Collect today's statistics
            today_connections = [
                conn for conn in self.connection_history 
                if datetime.fromisoformat(conn['timestamp']).strftime('%Y-%m-%d') == today
            ]
            
            # Prepare statistics
            stats = {
                'total_connections': len(today_connections),
                'unique_ips': len(set(conn['remote_ip'] for conn in today_connections if conn.get('remote_ip'))),
                'unique_ports': len(set(conn['remote_port'] for conn in today_connections if conn.get('remote_port'))),
                'connection_statuses': {},
                'hourly_distribution': {},
                'top_ips': {},
                'top_ports': {}
            }
            
            # Calculate detailed statistics
            for conn in today_connections:
                # Status counts
                status = conn.get('status')
                if status:
                    stats['connection_statuses'][status] = stats['connection_statuses'].get(status, 0) + 1
                
                # Hourly distribution
                hour = datetime.fromisoformat(conn['timestamp']).strftime('%H')
                stats['hourly_distribution'][hour] = stats['hourly_distribution'].get(hour, 0) + 1
                
                # Top IPs and ports
                if conn.get('remote_ip'):
                    stats['top_ips'][conn['remote_ip']] = stats['top_ips'].get(conn['remote_ip'], 0) + 1
                if conn.get('remote_port'):
                    stats['top_ports'][conn['remote_port']] = stats['top_ports'].get(conn['remote_port'], 0) + 1
            
            # Sort and limit top items
            stats['top_ips'] = dict(sorted(stats['top_ips'].items(), key=lambda x: x[1], reverse=True)[:10])
            stats['top_ports'] = dict(sorted(stats['top_ports'].items(), key=lambda x: x[1], reverse=True)[:10])
            
            # Get LLM analysis of the day's activity
            daily_analysis = self.analyze_with_llm(today_connections[-100:])  # Analyze last 100 connections
            
            # Create the report content
            report_content = f"""Network Activity Report for {today}
{'=' * 50}

Summary Statistics:
- Total Connections: {stats['total_connections']}
- Unique IPs: {stats['unique_ips']}
- Unique Ports: {stats['unique_ports']}

Connection Status Distribution:
{json.dumps(stats['connection_statuses'], indent=2)}

Top 10 Remote IPs:
{json.dumps(stats['top_ips'], indent=2)}

Top 10 Remote Ports:
{json.dumps(stats['top_ports'], indent=2)}

Hourly Connection Distribution:
{json.dumps(stats['hourly_distribution'], indent=2)}

AI Analysis of Recent Activity:
{daily_analysis if daily_analysis else "No AI analysis available"}

Generated at: {current_time.strftime('%Y-%m-%d %H:%M:%S')}
"""
            # Save the report
            with open(report_file, 'w') as f:
                f.write(report_content)
                
            self.logger.info(f"Daily report generated: {report_file}")
            
            # Show notification
            self.show_notification(
                "Daily Network Report Generated",
                f"Network activity report for {today} is now available."
            )
            
            return report_file
        except Exception as e:
            self.logger.error(f"Error generating daily report: {str(e)}")
            return None

    def start(self):
        """Start the network monitor"""
        self.logger.info("Starting Network Monitor...")
        
        # Ensure the logs directory exists
        os.makedirs(self.logs_dir, exist_ok=True)
        
        # Clear or initialize the connections log
        connections_file = os.path.join(self.logs_dir, 'connections.json')
        try:
            with open(connections_file, 'w') as f:
                f.write('')  # Clear the file
            self.logger.info(f"Initialized connections log: {connections_file}")
        except Exception as e:
            self.logger.error(f"Error initializing connections log: {str(e)}")
        
        # Create a thread for connection analysis
        analysis_thread = threading.Thread(target=self.analyze_connections)
        analysis_thread.daemon = True
        analysis_thread.start()
        self.logger.info("Started connection analysis thread")
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Shutting down Network Monitor...")

    def record_metrics(self, metrics):
        """Record system metrics to database"""
        try:
            if not hasattr(self, 'db_manager'):
                self.logger.warning("Database manager not initialized, skipping metrics recording")
                return
                
            if hasattr(self, 'metrics_batch'):
                self.add_to_metrics_batch(metrics)
            else:
                # Convert process iterator to list length
                process_count = sum(1 for _ in psutil.process_iter())
                
                self.db_manager.add_system_metrics(
                    cpu=metrics['cpu']['total_usage'],
                    memory=metrics['memory']['percent'],
                    disk=metrics['disk']['percent'],
                    network=metrics['network']['bytes_sent'] + metrics['network']['bytes_recv'],
                    process_count=process_count
                )
        except Exception as e:
            self.logger.error(f"Error recording metrics: {str(e)}")
        
    def record_connection(self, connection_data):
        """Record network connection to database"""
        if self.async_db:
            self.add_to_network_batch(connection_data)
        else:
            self.db_manager.add_network_connection(
                src_ip=connection_data['src'],
                dst_ip=connection_data['dst'],
                src_port=connection_data['sport'],
                dst_port=connection_data['dport'],
                protocol=connection_data['proto'],
                bytes_sent=connection_data.get('bytes_sent', 0),
                bytes_received=connection_data.get('bytes_recv', 0),
                status=connection_data.get('status', 'UNKNOWN'),
                threat_level=connection_data.get('threat_level')
            )

    def get_active_connections(self) -> list[dict[str, any]]:
        """Get list of active network connections with process information"""
        connections = []
        try:
            # Try to get connections with sudo if available
            try:
                connections_list = psutil.net_connections(kind='inet')
            except psutil.AccessDenied:
                self.logger.warning("Access denied getting connections, trying with sudo")
                # Return empty list if we can't get connections
                return []
                
            for conn in connections_list:
                try:
                    # Skip connections without addresses
                    if not conn.laddr:
                        continue
                        
                    # Get process information
                    process = psutil.Process(conn.pid) if conn.pid else None
                    process_name = process.name() if process else "Unknown"
                    
                    # Format addresses
                    laddr = conn.laddr
                    raddr = conn.raddr if conn.raddr else ('0.0.0.0', 0)
                    
                    connection_info = {
                        'local_address': f"{laddr.ip}:{laddr.port}",
                        'remote_address': f"{raddr[0]}:{raddr[1]}",
                        'status': conn.status,
                        'pid': conn.pid or 0,
                        'process': process_name,  # Changed from process_name to process
                        'threat_level': 0.0  # Add default threat level
                    }
                    
                    # Only check for threats if we have a valid remote address
                    if raddr[0] != '0.0.0.0':
                        try:
                            is_malicious = self.threat_detector.is_malicious_ip(raddr[0])
                            if is_malicious:
                                connection_info['threat_level'] = 0.8  # Set high threat level
                                # Use alert manager to show notification with cooldown
                                self.alert_manager.show_notification(
                                    title="Malicious Connection Detected",
                                    message=(
                                        f"Process: {process_name}\n"
                                        f"Remote IP: {raddr[0]}\n"
                                        f"Port: {raddr[1]}\n"
                                        f"Status: {conn.status}"
                                    ),
                                    alert_type='malicious_connection',
                                    identifier=f"{raddr[0]}:{process_name}"  # Use IP and process as identifier
                                )
                                
                                self.logger.warning(f"Malicious connection detected from {raddr[0]} by process {process_name}")
                                
                                # Record the threat
                                threat_data = {
                                    'timestamp': datetime.now().isoformat(),
                                    'process_name': process_name,
                                    'remote_ip': raddr[0],
                                    'remote_port': raddr[1],
                                    'connection_status': conn.status,
                                    'threat_type': 'malicious_ip'
                                }
                                try:
                                    self.db_manager.record_threat(threat_data)
                                except Exception as e:
                                    self.logger.error(f"Failed to record threat: {str(e)}")
                        except Exception as e:
                            self.logger.error(f"Error checking for threats: {str(e)}")
                    
                    connections.append(connection_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError) as e:
                    self.logger.debug(f"Skipping connection due to error: {str(e)}")
                    continue
                    
            return connections
            
        except Exception as e:
            self.logger.error(f"Error getting active connections: {str(e)}")
            return []

    def get_connection_stats(self) -> dict[str, int]:
        """Get statistics about current network connections"""
        try:
            stats = {
                'total_connections': 0,
                'active_connections': 0,
                'unique_ips': set(),
                'connection_types': {},
                'timestamp': datetime.now().isoformat()
            }
            
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                stats['total_connections'] += 1
                if conn.status == 'ESTABLISHED':
                    stats['active_connections'] += 1
                if conn.raddr:
                    stats['unique_ips'].add(conn.raddr.ip)
                stats['connection_types'][conn.status] = stats['connection_types'].get(conn.status, 0) + 1
            
            # Convert set to list for JSON serialization
            stats['unique_ips'] = list(stats['unique_ips'])
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting connection stats: {str(e)}")
            return {
                'total_connections': 0,
                'active_connections': 0,
                'unique_ips': [],
                'connection_types': {},
                'timestamp': datetime.now().isoformat(),
                'error': str(e)
            }

    def perform_initial_analysis(self):
        """Perform initial system analysis using LLM"""
        if not self.initial_analysis_complete:
            try:
                # Get current system state
                performance_metrics = self.performance_monitor.get_system_metrics()
                active_connections = self.get_active_connections()
                threat_data = self.threat_detector.get_current_threats()
                
                # Prepare system state description
                system_state = {
                    "performance": performance_metrics,
                    "connections": len(active_connections),
                    "threats": len(threat_data),
                    "timestamp": datetime.now().isoformat()
                }
                
                # Get LLM analysis of system state
                analysis_prompt = f"""Analyze the current system state:
                Performance Metrics: {json.dumps(performance_metrics, indent=2)}
                Active Connections: {len(active_connections)}
                Detected Threats: {len(threat_data)}
                
                Provide a brief security assessment and recommendations."""
                
                analysis_result = self.analyze_with_llm(analysis_prompt)
                
                # Ensure we return a dictionary
                if isinstance(analysis_result, str):
                    analysis_result = {
                        "system_overview": {
                            "Active Connections": len(active_connections),
                            "CPU Usage": f"{performance_metrics['cpu']['total_usage']}%",
                            "Memory Usage": f"{performance_metrics['memory']['percent']}%",
                            "Disk Usage": f"{performance_metrics['disk']['percent']}%"
                        },
                        "threat_assessment": {
                            "severity": "Unknown",
                            "confidence": 0,
                            "patterns": []
                        },
                        "impact_analysis": ["Initial system analysis completed"],
                        "recommendations": ["System is initializing. Full analysis will be available shortly."]
                    }
                
                self.initial_analysis_result = analysis_result
                self.initial_analysis_complete = True
                
                # Log the analysis
                logging.info("Initial system analysis completed")
                return analysis_result
                
            except Exception as e:
                logging.error(f"Error during initial analysis: {str(e)}")
                # Return a properly formatted error dictionary
                error_result = {
                    "system_overview": {
                        "Status": "Error",
                        "Error": str(e)
                    },
                    "threat_assessment": {
                        "severity": "Unknown",
                        "confidence": 0,
                        "patterns": []
                    },
                    "impact_analysis": ["Error during system analysis"],
                    "recommendations": ["Please check system logs for more information"]
                }
                self.initial_analysis_result = error_result
                self.initial_analysis_complete = True
                return error_result
        
        return self.initial_analysis_result

    def initialize_system(self):
        """Initialize the system with proper sequencing"""
        try:
            # Start with non-Ollama dependent initializations
            self.load_baseline()
            self.update_performance_metrics()
            
            # Initialize components that can work without Ollama
            initial_state = {
                'performance_metrics': self.performance_monitor.get_system_metrics(),
                'connection_stats': self.get_connection_stats(),
                'ollama_available': False  # Will be updated after check
            }
            
            # Check Ollama availability with retries
            initial_state['ollama_available'] = self.check_ollama_health()
            
            self.initial_analysis_complete = True
            self.initial_analysis_result = initial_state
            
            self.logger.info("Initial system analysis completed")
            return initial_state
            
        except Exception as e:
            self.logger.error(f"Error during system initialization: {str(e)}")
            return {
                'performance_metrics': {},
                'connection_stats': {},
                'ollama_available': False,
                'error': str(e)
            }

    def stop(self):
        """Stop the network monitor and cleanup"""
        self.logger.info("Stopping network monitor...")
        
        # Process any remaining batches
        if self.async_db:
            asyncio.run_coroutine_threadsafe(
                self._process_metrics_batch(),
                self.loop
            )
            asyncio.run_coroutine_threadsafe(
                self._process_network_batch(),
                self.loop
            )
        
        # Stop the async event loop
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.async_thread.join(timeout=5)
        
        # Cleanup other components
        if self.backup_manager:
            self.backup_manager.stop()
        
        self.logger.info("Network monitor stopped successfully")

    @cpu_bound
    def analyze_packet(self, packet_data: dict) -> dict:
        """Analyze a network packet (CPU-intensive task)."""
        # Your existing packet analysis code here
        return analyzed_data
    
    async def process_connection(self, connection: dict):
        """Process a single network connection."""
        try:
            # Add to connection history
            self.connection_history.append(connection)
            
            # Submit packet analysis to task manager
            analysis_task_id = await self.task_manager.submit(
                self.analyze_packet,
                connection,
                priority=TaskPriority.HIGH
            )
            
            # Store in database with appropriate priority
            if self.async_db:
                await self.task_manager.submit(
                    self.async_db.add_network_connection,
                    connection['source_ip'],
                    connection['destination_ip'],
                    connection['source_port'],
                    connection['destination_port'],
                    connection['protocol'],
                    connection['bytes_sent'],
                    connection['bytes_received'],
                    connection['status'],
                    priority=TaskPriority.MEDIUM
                )
            
            # Trigger threat analysis if needed
            if connection.get('suspicious', False):
                await self.task_manager.submit(
                    self.analyze_threat,
                    connection,
                    priority=TaskPriority.HIGH
                )
        
        except Exception as e:
            self.logger.error(f"Error processing connection: {str(e)}")
    
    async def analyze_threat(self, ip_address: str) -> Dict[str, Any]:
        """Analyze potential threats from an IP address with caching."""
        # Check cache first
        cached_result = self.cache_manager.get_threat_result(ip_address)
        if cached_result is not None:
            self.logger.debug(f"Using cached threat analysis for IP: {ip_address}")
            return cached_result

        # If not in cache, perform analysis
        try:
            analysis_result = await self.threat_detector.analyze_ip(ip_address)
            
            # Ensure all numeric fields have default values
            analysis_result['risk_score'] = analysis_result.get('risk_score', 0)
            analysis_result['confidence'] = analysis_result.get('confidence', 0)
            analysis_result['severity'] = analysis_result.get('severity', 0)
            
            # Cache the result
            self.cache_manager.set_threat_result(ip_address, analysis_result)
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Error analyzing threat for IP {ip_address}: {str(e)}")
            return {
                'risk_score': 0,
                'confidence': 0,
                'severity': 0,
                'error': str(e)
            }

    @cached_result(cache=CacheManager().api_cache, ttl=300)
    async def get_ollama_analysis(self, data: str) -> Dict[str, Any]:
        """Get Ollama analysis with caching."""
        try:
            async with self.connection_pool.get() as session:
                async with session.post(
                    self.ollama_generate_url,
                    json={"prompt": data, "model": OLLAMA_CONFIG['model']}
                ) as response:
                    return await response.json()
        except Exception as e:
            self.logger.error(f"Error getting Ollama analysis: {str(e)}")
            return {"error": str(e)}

    def show_notification(self, title, message):
        """Show notification with configured timeout"""
        # Use alert manager to handle notification with cooldown
        self.alert_manager.show_notification(
            title=title,
            message=message,
            alert_type='network_monitor',
            identifier=title  # Use the title as the identifier to prevent duplicates
        )

    async def analyze_connection(self, connection_data: Dict[str, Any]):
        """Analyze a network connection with correlation tracking"""
        correlation_id = str(uuid.uuid4())
        self.logger.set_context(
            correlation_id=correlation_id,
            source_ip=connection_data.get('source_ip'),
            destination_ip=connection_data.get('destination_ip')
        )
        
        try:
            self.logger.info("Starting connection analysis")
            
            # Perform threat analysis
            threat_level = await self.threat_detector.analyze_connection(connection_data)
            
            # Log the threat level
            self.logger.info(
                "Threat analysis complete",
                extra={'extra_fields': {'threat_level': threat_level}}
            )
            
            # Record connection in database
            await self.async_db.add_network_connection(
                connection_data['source_ip'],
                connection_data['destination_ip'],
                connection_data['source_port'],
                connection_data['destination_port'],
                connection_data['protocol'],
                connection_data.get('bytes_sent', 0),
                connection_data.get('bytes_received', 0),
                connection_data.get('status', 'unknown'),
                threat_level
            )
            
            # Check if connection requires further analysis
            if threat_level > self.config.get('threat_threshold', 0.7):
                self.logger.warning(
                    "High threat level detected",
                    extra={'extra_fields': {
                        'threat_level': threat_level,
                        'threshold': self.config.get('threat_threshold', 0.7)
                    }}
                )
                await self.handle_threat(connection_data, threat_level)
                
        except Exception as e:
            self.logger.error(
                "Error analyzing connection",
                extra={'extra_fields': {'error': str(e)}}
            )
            raise
        finally:
            self.logger.clear_context()

if __name__ == "__main__":
    monitor = NetworkMonitor()
    monitor.start()
