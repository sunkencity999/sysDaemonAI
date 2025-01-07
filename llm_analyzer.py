#!/usr/bin/env python3
import json
import logging
import subprocess
import re
import time
from typing import Dict, List, Optional, Tuple, Any, Union
from datetime import datetime
from config import OLLAMA_CONFIG

class LLMAnalyzer:
    """Enhanced LLM analysis for system monitoring and security insights"""
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self._ensure_ollama_model()
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes cache TTL

    def _ensure_ollama_model(self):
        """Ensure the required Ollama model is available"""
        try:
            # Check if the model exists
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                text=True,
                check=True
            )
            
            model = OLLAMA_CONFIG.get('model', 'llama2:latest')
            if model not in result.stdout:
                self.logger.error(f"Model '{model}' not found. Please ensure it is installed.")
                raise RuntimeError(f"Required model '{model}' is not available")
                
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Ollama error: {e.stderr}")
            raise RuntimeError("Ollama is required for LLM analysis")
        except Exception as e:
            self.logger.error(f"Error checking Ollama model: {str(e)}")
            raise

    def _get_cache_key(self, event_data: Dict) -> str:
        """Generate a cache key from event data, excluding timestamp and volatile fields"""
        key_data = {
            k: v for k, v in event_data.items() 
            if k not in ['timestamp', 'system_info']
        }
        return json.dumps(key_data, sort_keys=True)

    def _get_cached_analysis(self, cache_key: str) -> Optional[Dict[str, str]]:
        """Get analysis from cache if it exists and is not expired"""
        if cache_key in self.cache:
            timestamp, analysis = self.cache[cache_key]
            if (datetime.now() - timestamp).total_seconds() < self.cache_ttl:
                return analysis
            del self.cache[cache_key]
        return None

    def _cache_analysis(self, cache_key: str, analysis: Dict[str, str]):
        """Cache analysis result with current timestamp"""
        self.cache[cache_key] = (datetime.now(), analysis)

    def analyze_system_metrics(self, metrics: Dict) -> Dict[str, str]:
        """Perform detailed analysis of system metrics using LLM"""
        prompt = self._create_system_metrics_prompt(metrics)
        return self._get_llm_analysis(prompt)

    def analyze_security_event(self, event_data: Dict) -> Dict[str, str]:
        """Analyze a security event with baseline checks and LLM insights"""
        try:
            # Check cache first
            cache_key = self._get_cache_key(event_data)
            cached_result = self._get_cached_analysis(cache_key)
            if cached_result:
                return cached_result

            # Initialize default response structure
            analysis = {
                'threat_assessment': {
                    'severity': 'Low',
                    'confidence': 100,
                    'patterns': []
                },
                'impact_analysis': [],
                'immediate_actions': [],
                'technical_details': [],
                'long_term_recommendations': []
            }
            
            # Perform baseline analysis first
            self._perform_baseline_analysis(event_data, analysis)
            
            # Try to get LLM insights with retries
            llm_analysis = self._get_llm_analysis_with_retry(event_data)
            if llm_analysis:
                # Merge LLM insights with baseline analysis
                self._merge_llm_analysis(analysis, llm_analysis)
            
            # Cache the final analysis
            self._cache_analysis(cache_key, analysis)
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error in security analysis: {str(e)}")
            return self._get_error_analysis(str(e))

    def _perform_baseline_analysis(self, event_data: Dict, analysis: Dict):
        """Perform baseline analysis without LLM"""
        connections = event_data.get('connections', [])
        system_info = event_data.get('system_info', {})
        
        # Check for high port usage
        high_ports = [conn for conn in connections if conn.get('remote_port', 0) > 49151]
        if high_ports:
            analysis['threat_assessment']['patterns'].append(
                f"Found {len(high_ports)} connections using high ports (>49151)"
            )
        
        # Check resource thresholds
        self._check_resource_thresholds(system_info, analysis)
        
        # Add system state information
        self._add_system_state_info(event_data, analysis)

    def _get_llm_analysis_with_retry(self, event_data: Dict) -> Dict:
        """Get LLM analysis with retry logic"""
        max_retries = OLLAMA_CONFIG.get('retries', 5)
        base_delay = OLLAMA_CONFIG.get('retry_delay', 5)
        backoff_factor = OLLAMA_CONFIG.get('backoff_factor', 2)
        
        for attempt in range(max_retries):
            try:
                prompt = self._create_security_prompt(event_data)
                response = self._get_llm_response(prompt)
                
                if response and isinstance(response, dict):
                    return response
                    
            except Exception as e:
                delay = base_delay * (backoff_factor ** attempt)
                self.logger.warning(f"LLM analysis timeout (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(delay)
                else:
                    self.logger.error(f"All LLM analysis attempts failed: {str(e)}")
                    return self._get_error_analysis("Maximum retry attempts exceeded")
        
        return self._get_error_analysis("Failed to get valid analysis after retries")

    def _get_llm_response(self, prompt: str) -> Dict:
        """Get response from Ollama and parse it into our analysis format"""
        try:
            # Ensure we're working with a string
            if isinstance(prompt, bytes):
                prompt = prompt.decode('utf-8')
            elif not isinstance(prompt, str):
                prompt = str(prompt)
            
            model_info = OLLAMA_CONFIG['model']  # Get the model info string
            model_name = model_info.split()[0]  # Extract just the model name (first part)
            self.logger.info(f"Using model: '{model_name}'")  # Log the model being used
            
            # Log the command being executed
            command = ['ollama', 'run', model_name]  # Use the extracted model name
            self.logger.info(f"Executing command: {command}")  # Log the command
            response = subprocess.run(
                command,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=OLLAMA_CONFIG.get('timeout', 90)
            )
            
            if response.returncode != 0:
                self.logger.error(f"Ollama error with model {model_name}: {response.stderr}")
                raise Exception(f"Ollama error: {response.stderr}")
            
            # Get the raw text response
            text = response.stdout.strip()
            
            # Convert the text analysis into our structured format
            analysis = {
                "threat_assessment": {
                    "severity": "Low",  # Default, can be updated based on text analysis
                    "confidence": 100,
                    "patterns": []
                },
                "impact_analysis": [text],  # Store the full analysis text
                "immediate_actions": [],
                "technical_details": [],
                "long_term_recommendations": []
            }
            
            # Look for severity indicators in the text
            if any(word in text.lower() for word in ['critical', 'severe', 'high risk']):
                analysis['threat_assessment']['severity'] = "Critical"
            elif any(word in text.lower() for word in ['warning', 'moderate', 'medium']):
                analysis['threat_assessment']['severity'] = "Medium"
            
            return analysis
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"LLM request timed out for model {OLLAMA_CONFIG.get('model')}")
            raise
        except Exception as e:
            self.logger.error(f"Error getting LLM response with model {OLLAMA_CONFIG.get('model')}: {str(e)}")
            raise

    def _create_security_prompt(self, event_data: Dict) -> str:
        """Create a detailed prompt for security event analysis"""
        # Extract key metrics for a more focused prompt
        system_info = event_data.get('system_info', {})
        ports = event_data.get('listening_ports', [])
        
        return f"""As a security analyst, evaluate these system metrics and identify any security concerns:

Key Metrics:
- CPU Usage: {system_info.get('cpu_percent')}%
- Memory Usage: {system_info.get('memory_percent')}%
- Active Processes: {system_info.get('total_processes')}
- Active Threads: {system_info.get('total_threads')}
- Number of Listening Ports: {len(ports)}

Analyze these metrics for:
1. Unusual resource usage patterns
2. Suspicious process or thread activity
3. Potential security vulnerabilities
4. System performance concerns
5. Recommended actions if any issues are found

Focus on the actual values and their security implications, not the data structure."""

    def _merge_llm_analysis(self, base_analysis: Dict, llm_analysis: Dict):
        """Merge LLM analysis with baseline analysis"""
        # Update severity only if LLM confidence is high enough
        if llm_analysis.get('threat_assessment', {}).get('confidence', 0) > 70:
            base_analysis['threat_assessment']['severity'] = llm_analysis['threat_assessment']['severity']
            base_analysis['threat_assessment']['confidence'] = llm_analysis['threat_assessment']['confidence']
        
        # Merge other fields
        for field in ['impact_analysis', 'immediate_actions', 'technical_details', 'long_term_recommendations']:
            if field in llm_analysis:
                base_analysis[field].extend(llm_analysis[field])

    def _check_resource_thresholds(self, system_info: Dict, analysis: Dict):
        """Check resource thresholds"""
        cpu_percent = system_info.get('cpu_percent', 0)
        memory_percent = system_info.get('memory_percent', 0)
        
        if cpu_percent > 90:
            analysis['threat_assessment']['severity'] = 'High'
            analysis['impact_analysis'].append(f"Critical CPU usage detected: {cpu_percent}%")
            analysis['immediate_actions'].append("Investigate processes causing high CPU usage")
        
        if memory_percent > 90:
            analysis['threat_assessment']['severity'] = 'High'
            analysis['impact_analysis'].append(f"Critical memory usage detected: {memory_percent}%")
            analysis['immediate_actions'].append("Check for memory leaks and high-memory processes")

    def _add_system_state_info(self, event_data: Dict, analysis: Dict):
        """Add system state information"""
        connections = event_data.get('connections', [])
        listening_ports = event_data.get('listening_ports', [])
        system_info = event_data.get('system_info', {})
        
        analysis['technical_details'].append(
            f"Active Connections: {len(connections)}"
        )
        analysis['technical_details'].append(
            f"Listening Ports: {len(listening_ports)}"
        )
        analysis['technical_details'].append(
            f"CPU Usage: {system_info.get('cpu_percent', 0)}%"
        )
        analysis['technical_details'].append(
            f"Memory Usage: {system_info.get('memory_percent', 0)}%"
        )
        analysis['technical_details'].append(
            f"Total Processes: {system_info.get('total_processes', 0)}"
        )
        analysis['technical_details'].append(
            f"Total Threads: {system_info.get('total_threads', 0)}"
        )

    def _get_error_analysis(self, error_message: str) -> Dict[str, str]:
        """Return a structured error response"""
        return {
            'threat_assessment': {
                'severity': 'Unknown',
                'confidence': 0,
                'patterns': ['Analysis error occurred']
            },
            'impact_analysis': [f'Error during analysis: {error_message}'],
            'immediate_actions': ['Review system logs for more details'],
            'technical_details': ['Analysis failed to complete'],
            'long_term_recommendations': ['Verify system monitoring configuration']
        }

    def analyze_performance_trend(self, metrics_history: List[Dict]) -> Dict[str, str]:
        """Analyze performance trends over time"""
        prompt = self._create_trend_analysis_prompt(metrics_history)
        return self._get_llm_analysis(prompt)

    def _create_system_metrics_prompt(self, metrics: Dict) -> str:
        """Create a detailed prompt for system metrics analysis"""
        return f"""Analyze the following system metrics and provide detailed insights:

System State:
- CPU Usage: {metrics['system_metrics']['cpu']['total_usage']}%
- Memory Usage: {metrics['system_metrics']['memory']['percent']}%
- Disk Usage: {metrics['system_metrics']['disk']['percent']}%
- Network Upload: {metrics['current_bandwidth']['upload_human']}
- Network Download: {metrics['current_bandwidth']['download_human']}

Please provide:
1. A detailed assessment of the system's current state
2. Identification of any potential performance bottlenecks
3. Specific recommendations for optimization
4. Risk assessment for current resource utilization
5. Comparative analysis with typical baseline metrics
"""

    def _get_llm_analysis(self, prompt: str) -> Dict[str, str]:
        """Get analysis from Ollama with enhanced error handling and retries"""
        try:
            # Run Ollama command - pass prompt directly, not as an argument
            model_info = OLLAMA_CONFIG['model']  # Get the model info string
            model_name = model_info.split()[0]  # Extract just the model name (first part)
            self.logger.info(f"Using model: '{model_name}'")  # Log the model being used
            
            # Log the command being executed
            command = ['ollama', 'run', model_name]  # Use the extracted model name
            self.logger.info(f"Executing command: {command}")  # Log the command
            result = subprocess.run(
                command,
                input=prompt,
                capture_output=True,
                text=True,
                check=True,
                timeout=OLLAMA_CONFIG.get('timeout', 90)
            )
            
            # Parse the response and ensure it's properly formatted
            text = result.stdout.strip()
            
            # Convert the text analysis into our structured format
            analysis = {
                "threat_assessment": {
                    "severity": "Low",  # Default, can be updated based on text analysis
                    "confidence": 100,
                    "patterns": []
                },
                "impact_analysis": [text],  # Store the full analysis text
                "immediate_actions": [],
                "technical_details": [],
                "long_term_recommendations": []
            }
            
            # Look for severity indicators in the text
            if any(word in text.lower() for word in ['critical', 'severe', 'high risk']):
                analysis['threat_assessment']['severity'] = "Critical"
            elif any(word in text.lower() for word in ['warning', 'moderate', 'medium']):
                analysis['threat_assessment']['severity'] = "Medium"
            
            # Add metadata
            analysis['timestamp'] = datetime.now().isoformat()
            analysis['analysis_version'] = '2.0'
            
            return analysis
            
        except subprocess.TimeoutExpired:
            self.logger.error("LLM analysis timed out")
            return {
                'error': 'Analysis timed out',
                'timestamp': datetime.now().isoformat(),
                'partial_analysis': True
            }
        except subprocess.CalledProcessError as e:
            self.logger.error(f"LLM analysis failed: {e}")
            return {
                'error': f'Analysis failed: {str(e)}',
                'timestamp': datetime.now().isoformat(),
                'partial_analysis': True
            }

    def _validate_llm_response(self, response: Dict) -> bool:
        """Validate the structure and content of the LLM response"""
        required_keys = ['threat_assessment', 'impact_analysis', 'immediate_actions', 'technical_details', 'long_term_recommendations']
        for key in required_keys:
            if key not in response:
                return False
        return True

    def _calculate_confidence_score(self, analysis: str) -> float:
        """Calculate a confidence score based on the analysis completeness"""
        # Simple scoring based on response completeness
        score = 0.0
        key_indicators = ['analysis', 'recommendation', 'risk', 'pattern', 'suggest']
        
        for indicator in key_indicators:
            if indicator in analysis.lower():
                score += 0.2

        return min(1.0, score)  # Cap at 1.0

    def _detect_scan_pattern(self, event: Dict) -> str:
        """Detect port scanning patterns"""
        # TO DO: Implement port scanning pattern detection
        return "TO DO"

    def _get_common_exploits_for_ports(self, port: int) -> List[str]:
        """Get common exploits for a given port"""
        # TO DO: Implement common exploit retrieval
        return []

    def _generate_firewall_recommendations(self, event: Dict) -> List[str]:
        """Generate firewall recommendations based on the event"""
        # TO DO: Implement firewall recommendation generation
        return []

    def _analyze_file_signatures(self, event: Dict) -> List[str]:
        """Analyze file signatures for malware indicators"""
        # TO DO: Implement file signature analysis
        return []

    def _analyze_process_behavior(self, event: Dict) -> List[str]:
        """Analyze process behavior for malware indicators"""
        # TO DO: Implement process behavior analysis
        return []

    def _generate_containment_steps(self, event: Dict) -> List[str]:
        """Generate containment steps for malware"""
        # TO DO: Implement containment step generation
        return []

    def _analyze_auth_patterns(self, event: Dict) -> List[str]:
        """Analyze authentication patterns for unauthorized access"""
        # TO DO: Implement authentication pattern analysis
        return []

    def _check_privilege_escalation(self, event: Dict) -> List[str]:
        """Check for privilege escalation indicators"""
        # TO DO: Implement privilege escalation indicator checking
        return []

    def _generate_account_recommendations(self, event: Dict) -> List[str]:
        """Generate account security recommendations"""
        # TO DO: Implement account security recommendation generation
        return []

    def _create_trend_analysis_prompt(self, metrics_history: List[Dict]) -> str:
        """Create a detailed prompt for trend analysis"""
        return f"""Analyze the following performance metrics history and provide insights:

Metrics History: {json.dumps(metrics_history, indent=2)}

Please provide:
1. Identification of significant trends
2. Performance pattern analysis
3. Anomaly detection and explanation
4. Resource utilization forecasting
5. Optimization recommendations based on historical patterns
"""
