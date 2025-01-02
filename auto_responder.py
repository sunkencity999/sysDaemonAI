#!/usr/bin/env python3
import logging
import subprocess
import psutil
import json
from datetime import datetime
from typing import Dict, List, Optional
import os
from llm_analyzer import LLMAnalyzer

class AutoResponder:
    def __init__(self, logger=None, confirmation_callback=None):
        self.logger = logger or logging.getLogger(__name__)
        self.last_actions = {}  # Track when actions were last taken
        self.action_cooldown = 300  # 5 minutes between repeated actions
        self.confirmation_callback = confirmation_callback
        self.llm_analyzer = LLMAnalyzer(logger)
        
        # Define response rules
        self.rules = {
            'high_cpu': {
                'condition': lambda metrics: metrics['system_metrics']['cpu']['total_usage'] > 75,
                'actions': [
                    ('identify_cpu_intensive_processes', self.identify_cpu_intensive_processes),
                    ('optimize_process_priority', self.optimize_process_priority, 'Adjust process priorities to optimize CPU usage?')
                ]
            },
            'high_memory': {
                'condition': lambda metrics: metrics['system_metrics']['memory']['percent'] > 75,
                'actions': [
                    ('identify_memory_intensive_processes', self.identify_memory_intensive_processes),
                    ('optimize_memory_usage', self.optimize_memory_usage, 'Optimize memory usage and clear caches?')
                ]
            },
            'bandwidth_spike': {
                'condition': lambda metrics: (
                    metrics['current_bandwidth']['upload'] > metrics.get('bandwidth_stats', {}).get('upload_avg', 0) * 2 or
                    metrics['current_bandwidth']['download'] > metrics.get('bandwidth_stats', {}).get('download_avg', 0) * 2
                ),
                'actions': [
                    ('identify_bandwidth_intensive_processes', self.identify_bandwidth_intensive_processes),
                    ('log_network_activity', self.log_network_activity)
                ]
            },
            'high_latency': {
                'condition': lambda metrics: any(
                    data.get('current', 0) > 200 
                    for data in metrics.get('latency_stats', {}).values()
                ),
                'actions': [
                    ('analyze_network_route', self.analyze_network_route),
                    ('optimize_network_settings', self.optimize_network_settings, 'Optimize network settings (flush DNS and routing tables)?')
                ]
            }
        }
        
    def can_take_action(self, action_type: str) -> bool:
        """Check if enough time has passed since the last action"""
        if action_type not in self.last_actions:
            return True
            
        last_action_time = self.last_actions[action_type]
        return (datetime.now() - last_action_time).total_seconds() >= self.action_cooldown
        
    def record_action(self, action_type: str):
        """Record that an action was taken"""
        self.last_actions[action_type] = datetime.now()
        
    def identify_cpu_intensive_processes(self, metrics: Dict) -> Dict:
        """Identify and log CPU-intensive processes"""
        cpu_intensive = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                if proc.info['cpu_percent'] > 50:  # Processes using more than 50% CPU
                    cpu_intensive.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cpu_percent': proc.info['cpu_percent']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        if cpu_intensive:
            self.logger.warning(f"CPU-intensive processes identified: {json.dumps(cpu_intensive, indent=2)}")
        return {'cpu_intensive_processes': cpu_intensive}
        
    def optimize_process_priority(self, metrics: Dict) -> Dict:
        """Adjust process priorities based on resource usage"""
        adjusted = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                if proc.info['cpu_percent'] > 50:
                    # Lower priority of CPU-intensive processes
                    proc.nice(10)  # Increase nice value (lower priority)
                    adjusted.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'action': 'lowered_priority'
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        if adjusted:
            self.logger.info(f"Adjusted process priorities: {json.dumps(adjusted, indent=2)}")
        return {'adjusted_processes': adjusted}
        
    def identify_memory_intensive_processes(self, metrics: Dict) -> Dict:
        """Identify and log memory-intensive processes"""
        memory_intensive = []
        for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
            try:
                if proc.info['memory_percent'] > 10:  # Processes using more than 10% memory
                    memory_intensive.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'memory_percent': proc.info['memory_percent']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        if memory_intensive:
            self.logger.warning(f"Memory-intensive processes identified: {json.dumps(memory_intensive, indent=2)}")
        return {'memory_intensive_processes': memory_intensive}
        
    def optimize_memory_usage(self, metrics: Dict) -> Dict:
        """Attempt to optimize memory usage"""
        # Request garbage collection in Python
        import gc
        gc.collect()
        
        # Clear disk caches on macOS
        try:
            subprocess.run(['sudo', 'purge'], capture_output=True)
        except subprocess.CalledProcessError:
            self.logger.warning("Failed to clear disk caches")
            
        return {'action': 'memory_optimization_attempted'}
        
    def identify_bandwidth_intensive_processes(self, metrics: Dict) -> Dict:
        """Identify processes using significant bandwidth"""
        bandwidth_intensive = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                # Get process network connections
                connections = proc.connections()
                if connections:
                    # Count active connections
                    active_connections = len([c for c in connections if c.status == 'ESTABLISHED'])
                    if active_connections > 5:  # Processes with many active connections
                        bandwidth_intensive.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'active_connections': active_connections
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        if bandwidth_intensive:
            self.logger.warning(f"Bandwidth-intensive processes identified: {json.dumps(bandwidth_intensive, indent=2)}")
        return {'bandwidth_intensive_processes': bandwidth_intensive}
        
    def log_network_activity(self, metrics: Dict) -> Dict:
        """Log detailed network activity during bandwidth spikes"""
        network_snapshot = {
            'timestamp': datetime.now().isoformat(),
            'bandwidth': metrics['current_bandwidth'],
            'connections': []
        }
        
        # Capture current network connections
        for conn in psutil.net_connections(kind='inet'):
            try:
                if conn.status == 'ESTABLISHED':
                    network_snapshot['connections'].append({
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'status': conn.status,
                        'pid': conn.pid
                    })
            except (AttributeError, psutil.NoSuchProcess):
                continue
                
        # Log the snapshot
        self.logger.warning(f"Network activity snapshot during bandwidth spike: {json.dumps(network_snapshot, indent=2)}")
        return {'network_snapshot': network_snapshot}
        
    def analyze_network_route(self, metrics: Dict) -> Dict:
        """Analyze network route and latency issues with enhanced LLM analysis"""
        analysis_result = {}
        
        # Get LLM analysis for network metrics
        network_analysis = self.llm_analyzer.analyze_system_metrics({
            'system_metrics': metrics.get('system_metrics', {}),
            'current_bandwidth': metrics.get('current_bandwidth', {}),
            'latency_stats': metrics.get('latency_stats', {})
        })
        
        # Add LLM insights to the analysis
        analysis_result['llm_insights'] = network_analysis
        
        # Perform traceroute analysis for high-latency hosts
        high_latency_hosts = [
            host for host, data in metrics.get('latency_stats', {}).items()
            if data.get('current', 0) > 200
        ]
        
        route_analysis = {}
        for host in high_latency_hosts:
            try:
                traceroute = subprocess.run(['traceroute', '-n', host], 
                                         capture_output=True, 
                                         text=True, 
                                         timeout=10)
                route_analysis[host] = {
                    'traceroute': traceroute.stdout,
                    'analysis': self.llm_analyzer.analyze_system_metrics({
                        'traceroute': traceroute.stdout,
                        'host': host,
                        'latency': metrics.get('latency_stats', {}).get(host, {})
                    })
                }
            except subprocess.TimeoutExpired:
                route_analysis[host] = {
                    'error': 'Traceroute timed out',
                    'analysis': self.llm_analyzer.analyze_system_metrics({
                        'error': 'timeout',
                        'host': host,
                        'latency': metrics.get('latency_stats', {}).get(host, {})
                    })
                }
            except subprocess.CalledProcessError as e:
                route_analysis[host] = {
                    'error': f'Traceroute failed: {e}',
                    'analysis': self.llm_analyzer.analyze_system_metrics({
                        'error': str(e),
                        'host': host,
                        'latency': metrics.get('latency_stats', {}).get(host, {})
                    })
                }
                
        analysis_result['route_analysis'] = route_analysis
        
        if high_latency_hosts:
            self.logger.warning(f"High latency detected for hosts: {', '.join(high_latency_hosts)}")
            
            # Get comprehensive analysis of all route data
            comprehensive_analysis = self.llm_analyzer.analyze_system_metrics({
                'high_latency_hosts': high_latency_hosts,
                'route_analysis': route_analysis,
                'network_metrics': metrics
            })
            
            analysis_result['comprehensive_analysis'] = comprehensive_analysis
            
            # Log detailed analysis
            self.logger.info(
                f"Network analysis complete:\n"
                f"{'=' * 50}\n"
                f"Summary: {comprehensive_analysis.get('summary', '')}\n"
                f"Details: {comprehensive_analysis.get('details', '')}\n"
                f"Recommendations: {comprehensive_analysis.get('recommendations', '')}\n"
                f"Confidence Score: {comprehensive_analysis.get('confidence_score', 0.0)}"
            )
            
        return analysis_result
        
    def optimize_network_settings(self, metrics: Dict) -> Dict:
        """Attempt to optimize network settings"""
        optimizations = []
        
        try:
            # Flush DNS cache
            subprocess.run(['sudo', 'killall', '-HUP', 'mDNSResponder'], capture_output=True)
            optimizations.append('flushed_dns_cache')
            
            # Flush routing table
            subprocess.run(['sudo', 'route', '-n', 'flush'], capture_output=True)
            optimizations.append('flushed_routing_table')
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to optimize network settings: {str(e)}")
            
        return {'network_optimizations': optimizations}
        
    def process_metrics(self, metrics: Dict) -> List[Dict]:
        """Process metrics and take appropriate actions based on rules"""
        actions_taken = []
        
        for rule_name, rule in self.rules.items():
            try:
                if rule['condition'](metrics) and self.can_take_action(rule_name):
                    self.logger.info(f"Condition met for {rule_name}, processing actions")
                    
                    # Execute all actions for this rule
                    rule_actions = []
                    for action in rule['actions']:
                        action_name = action[0]
                        action_func = action[1]
                        confirmation_msg = action[2] if len(action) > 2 else None
                        
                        # If action requires confirmation and callback is set
                        if confirmation_msg and self.confirmation_callback:
                            # Create detailed message with current metrics
                            details = self._get_action_details(action_name, metrics)
                            full_msg = f"{confirmation_msg}\n\nDetails:\n{details}"
                            
                            # Ask for confirmation
                            if not self.confirmation_callback(action_name, full_msg):
                                self.logger.info(f"User declined action: {action_name}")
                                continue
                        
                        result = action_func(metrics)
                        rule_actions.append({
                            'action': action_name,
                            'result': result
                        })
                        
                    if rule_actions:  # Only record if actions were actually taken
                        actions_taken.append({
                            'rule': rule_name,
                            'timestamp': datetime.now().isoformat(),
                            'actions': rule_actions
                        })
                        self.record_action(rule_name)
                    
            except Exception as e:
                self.logger.error(f"Error processing rule {rule_name}: {str(e)}")
                
        return actions_taken
        
    def _get_action_details(self, action_name: str, metrics: Dict) -> str:
        """Get detailed information about why an action is being proposed"""
        if action_name == 'optimize_process_priority':
            cpu_intensive = self.identify_cpu_intensive_processes(metrics)
            return f"CPU Usage: {metrics['system_metrics']['cpu']['total_usage']}%\n" + \
                   f"CPU-Intensive Processes:\n" + \
                   "\n".join([f"- {p['name']} (PID: {p['pid']}): {p['cpu_percent']}%" 
                             for p in cpu_intensive.get('cpu_intensive_processes', [])])
                             
        elif action_name == 'optimize_memory_usage':
            memory_intensive = self.identify_memory_intensive_processes(metrics)
            return f"Memory Usage: {metrics['system_metrics']['memory']['percent']}%\n" + \
                   f"Memory-Intensive Processes:\n" + \
                   "\n".join([f"- {p['name']} (PID: {p['pid']}): {p['memory_percent']}%" 
                             for p in memory_intensive.get('memory_intensive_processes', [])])
                             
        elif action_name == 'optimize_network_settings':
            return f"Current Latency Statistics:\n" + \
                   "\n".join([f"- {host}: {data.get('current', 0)}ms" 
                             for host, data in metrics.get('latency_stats', {}).items()])
                             
        return "No additional details available"
