#!/usr/bin/env python3
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any
from database import DatabaseManager
from sqlalchemy import func
import matplotlib.pyplot as plt
import seaborn as sns

class DataAnalyzer:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        
    def analyze_system_performance(self, timespan_hours: int = 24) -> Dict[str, Any]:
        """Analyze system performance metrics over the specified timespan"""
        start_time = datetime.now() - timedelta(hours=timespan_hours)
        metrics = self.db.get_metrics_range(start_time, datetime.now())
        
        if not metrics:
            return {}
            
        df = pd.DataFrame([{
            'timestamp': m.timestamp,
            'cpu_usage': m.cpu_usage,
            'memory_usage': m.memory_usage,
            'disk_usage': m.disk_usage,
            'network_throughput': m.network_throughput,
            'process_count': m.process_count
        } for m in metrics])
        
        return {
            'averages': {
                'cpu': df['cpu_usage'].mean(),
                'memory': df['memory_usage'].mean(),
                'disk': df['disk_usage'].mean(),
                'network': df['network_throughput'].mean(),
                'processes': df['process_count'].mean()
            },
            'peaks': {
                'cpu': df['cpu_usage'].max(),
                'memory': df['memory_usage'].max(),
                'disk': df['disk_usage'].max(),
                'network': df['network_throughput'].max(),
                'processes': df['process_count'].max()
            },
            'trends': {
                'cpu': self._calculate_trend(df['cpu_usage']),
                'memory': self._calculate_trend(df['memory_usage']),
                'disk': self._calculate_trend(df['disk_usage']),
                'network': self._calculate_trend(df['network_throughput'])
            }
        }
    
    def analyze_network_activity(self, timespan_hours: int = 24) -> Dict[str, Any]:
        """Analyze network connections over the specified timespan"""
        start_time = datetime.now() - timedelta(hours=timespan_hours)
        connections = self.db.get_network_connections(start_time, datetime.now())
        
        if not connections:
            return {}
            
        df = pd.DataFrame([{
            'timestamp': c.timestamp,
            'source_ip': c.source_ip,
            'destination_ip': c.destination_ip,
            'source_port': c.source_port,
            'destination_port': c.destination_port,
            'protocol': c.protocol,
            'bytes_sent': c.bytes_sent,
            'bytes_received': c.bytes_received,
            'threat_level': c.threat_level
        } for c in connections])
        
        return {
            'connection_stats': {
                'total_connections': len(df),
                'unique_sources': df['source_ip'].nunique(),
                'unique_destinations': df['destination_ip'].nunique(),
                'total_bytes_sent': df['bytes_sent'].sum(),
                'total_bytes_received': df['bytes_received'].sum()
            },
            'top_talkers': {
                'source_ips': df['source_ip'].value_counts().head(10).to_dict(),
                'destination_ips': df['destination_ip'].value_counts().head(10).to_dict(),
                'ports': df['destination_port'].value_counts().head(10).to_dict()
            },
            'protocols': df['protocol'].value_counts().to_dict(),
            'threat_analysis': {
                'high_threat_count': len(df[df['threat_level'] > 0.7]),
                'medium_threat_count': len(df[(df['threat_level'] > 0.3) & (df['threat_level'] <= 0.7)]),
                'low_threat_count': len(df[df['threat_level'] <= 0.3])
            }
        }
    
    def generate_performance_report(self, timespan_hours: int = 24) -> Dict[str, Any]:
        """Generate a comprehensive performance report"""
        perf_analysis = self.analyze_system_performance(timespan_hours)
        network_analysis = self.analyze_network_activity(timespan_hours)
        
        alerts = self.db.get_alerts(
            datetime.now() - timedelta(hours=timespan_hours),
            datetime.now()
        )
        
        alert_stats = {
            'total_alerts': len(alerts),
            'critical': len([a for a in alerts if a.severity == 'CRITICAL']),
            'warning': len([a for a in alerts if a.severity == 'WARNING']),
            'info': len([a for a in alerts if a.severity == 'INFO'])
        }
        
        return {
            'timestamp': datetime.now().isoformat(),
            'timespan_hours': timespan_hours,
            'performance_metrics': perf_analysis,
            'network_activity': network_analysis,
            'alert_statistics': alert_stats
        }
    
    def plot_system_metrics(self, timespan_hours: int = 24) -> Tuple[plt.Figure, plt.Axes]:
        """Generate plots for system metrics"""
        start_time = datetime.now() - timedelta(hours=timespan_hours)
        metrics = self.db.get_metrics_range(start_time, datetime.now())
        
        # Convert metrics to DataFrame with proper data types
        df = pd.DataFrame([{
            'timestamp': pd.to_datetime(m.timestamp),  # Ensure timestamp is datetime
            'CPU Usage (%)': float(m.cpu_usage),      # Convert to float
            'Memory Usage (%)': float(m.memory_usage),
            'Disk Usage (%)': float(m.disk_usage),
            'Network (MB/s)': float(m.network_throughput) / 1_000_000  # Convert to MB/s
        } for m in metrics])
        
        # Sort by timestamp to ensure proper plotting
        df.sort_values('timestamp', inplace=True)
        df.set_index('timestamp', inplace=True)
        
        # Create the plot
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('System Metrics Over Time')
        
        metrics = ['CPU Usage (%)', 'Memory Usage (%)', 
                  'Disk Usage (%)', 'Network (MB/s)']
        
        for ax, metric in zip(axes.flat, metrics):
            df[metric].plot(ax=ax)
            ax.set_title(metric)
            ax.grid(True)
            ax.set_xlabel('Time')
            ax.set_ylabel(metric)
            
        plt.tight_layout()
        return fig, axes
    
    @staticmethod
    def _calculate_trend(series: pd.Series) -> str:
        """Calculate trend direction and magnitude"""
        if len(series) < 2:
            return "insufficient_data"
            
        z = np.polyfit(range(len(series)), series, 1)
        slope = z[0]
        
        if abs(slope) < 0.01:
            return "stable"
        elif slope > 0:
            return "increasing" if slope > 0.1 else "slightly_increasing"
        else:
            return "decreasing" if slope < -0.1 else "slightly_decreasing"
