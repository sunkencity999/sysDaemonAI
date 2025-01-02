"""Base agent class for all AI agents."""

from crewai import Agent
from typing import Optional, Dict, Any
import sqlite3
import json
import logging
from datetime import datetime

class BaseAgent:
    def __init__(self, name: str, role: str, goal: str, db_path: str = "agents.db"):
        self.name = name
        self.role = role
        self.goal = goal
        self.db_path = db_path
        self.logger = logging.getLogger(f"agent.{name}")
        
        # Initialize database
        self._init_db()
        
        # Create CrewAI agent
        self.agent = Agent(
            role=role,
            goal=goal,
            backstory=f"You are {name}, an AI agent responsible for {goal}",
            allow_delegation=False,
            verbose=True
        )
    
    def _init_db(self):
        """Initialize the database for storing agent findings."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create findings table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agent_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_name TEXT,
                timestamp DATETIME,
                category TEXT,
                severity TEXT,
                finding TEXT,
                metadata TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def store_finding(self, category: str, finding: str, severity: str = "INFO", metadata: Optional[Dict[str, Any]] = None):
        """Store a finding in the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO agent_findings (agent_name, timestamp, category, severity, finding, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            self.name,
            datetime.utcnow().isoformat(),
            category,
            severity,
            finding,
            json.dumps(metadata) if metadata else None
        ))
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Stored finding: {finding}")
    
    def get_recent_findings(self, limit: int = 100) -> list:
        """Get recent findings from the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT timestamp, category, severity, finding, metadata
            FROM agent_findings
            WHERE agent_name = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (self.name, limit))
        
        findings = cursor.fetchall()
        conn.close()
        
        return [
            {
                "timestamp": f[0],
                "category": f[1],
                "severity": f[2],
                "finding": f[3],
                "metadata": json.loads(f[4]) if f[4] else None
            }
            for f in findings
        ]
