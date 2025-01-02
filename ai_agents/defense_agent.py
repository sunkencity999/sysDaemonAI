"""Defense agent for implementing security countermeasures."""

from .base_agent import BaseAgent
from typing import Dict, Any, List
import subprocess
import platform
import json

class DefenseAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="Defense",
            role="Security Defense Specialist",
            goal="Implement and manage security countermeasures"
        )
        self.os_type = platform.system().lower()
    
    def implement_firewall_rule(self, rule: Dict[str, Any]) -> bool:
        """Implement a firewall rule based on the operating system."""
        try:
            if self.os_type == 'darwin':  # macOS
                return self._implement_macos_firewall_rule(rule)
            elif self.os_type == 'linux':
                return self._implement_linux_firewall_rule(rule)
            elif self.os_type == 'windows':
                return self._implement_windows_firewall_rule(rule)
            else:
                self.logger.error(f"Unsupported operating system: {self.os_type}")
                return False
        except Exception as e:
            self.logger.error(f"Error implementing firewall rule: {str(e)}")
            return False
    
    def _implement_macos_firewall_rule(self, rule: Dict[str, Any]) -> bool:
        """Implement a firewall rule on macOS using pfctl."""
        try:
            # Example: Block an IP address
            if rule['action'] == 'block' and 'ip' in rule:
                cmd = f"echo 'block in from {rule['ip']} to any' | sudo pfctl -ef -"
                subprocess.run(cmd, shell=True, check=True)
                
                self.store_finding(
                    category="defense",
                    finding=f"Implemented firewall rule to block {rule['ip']}",
                    severity="INFO",
                    metadata=rule
                )
                return True
        except Exception as e:
            self.logger.error(f"Error implementing macOS firewall rule: {str(e)}")
        return False
    
    def _implement_linux_firewall_rule(self, rule: Dict[str, Any]) -> bool:
        """Implement a firewall rule on Linux using iptables."""
        try:
            if rule['action'] == 'block' and 'ip' in rule:
                cmd = f"sudo iptables -A INPUT -s {rule['ip']} -j DROP"
                subprocess.run(cmd, shell=True, check=True)
                
                self.store_finding(
                    category="defense",
                    finding=f"Implemented iptables rule to block {rule['ip']}",
                    severity="INFO",
                    metadata=rule
                )
                return True
        except Exception as e:
            self.logger.error(f"Error implementing Linux firewall rule: {str(e)}")
        return False
    
    def _implement_windows_firewall_rule(self, rule: Dict[str, Any]) -> bool:
        """Implement a firewall rule on Windows using netsh."""
        try:
            if rule['action'] == 'block' and 'ip' in rule:
                rule_name = f"Block_{rule['ip'].replace('.', '_')}"
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={rule["ip"]}'
                subprocess.run(cmd, shell=True, check=True)
                
                self.store_finding(
                    category="defense",
                    finding=f"Implemented Windows firewall rule to block {rule['ip']}",
                    severity="INFO",
                    metadata=rule
                )
                return True
        except Exception as e:
            self.logger.error(f"Error implementing Windows firewall rule: {str(e)}")
        return False
    
    def get_active_defenses(self) -> List[Dict[str, Any]]:
        """Get list of active defense measures."""
        return self.get_recent_findings()
