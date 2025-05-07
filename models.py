"""
MCP-Sec Gateway - Database Models
Defines the database models for storing audit logs and related data
"""
import json
import os
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import JSON, Text

# Initialize SQLAlchemy
db = SQLAlchemy()

class AuditLog(db.Model):
    """
    Model for audit logs
    Stores all MCP traffic audit events
    """
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    model_id = db.Column(db.String(64), index=True)
    session_id = db.Column(db.String(64), index=True)
    tool = db.Column(db.String(128), index=True)
    status = db.Column(db.String(20), index=True)
    reason = db.Column(db.Text, nullable=True)
    latency_ms = db.Column(db.Integer, nullable=True)
    risk_level = db.Column(db.String(10), default="low", index=True)  # low, medium, high
    
    # Use JSON or Text type based on database
    # SQLite doesn't support real JSON columns, but PostgreSQL does
    input_data = db.Column(JSON().with_variant(Text, "sqlite"), nullable=True)
    output_data = db.Column(JSON().with_variant(Text, "sqlite"), nullable=True)
    
    def __repr__(self):
        return f"<AuditLog {self.id}: {self.model_id}/{self.tool}>"
    
    def to_dict(self):
        """Convert model instance to dictionary for API responses"""
        result = {
            "id": self.id,
            "timestamp": self.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "model_id": self.model_id,
            "session_id": self.session_id,
            "tool": self.tool,
            "status": self.status,
            "latency_ms": self.latency_ms,
            "risk_level": self.risk_level
        }
        
        # Add optional fields if present
        if self.reason:
            result["reason"] = self.reason
            
        # Handle JSON data properly depending on database backend
        if self.input_data:
            # For SQLite, the data might be stored as a string
            if isinstance(self.input_data, str):
                try:
                    result["input"] = json.loads(self.input_data)
                except:
                    result["input"] = self.input_data
            else:
                result["input"] = self.input_data
                
        if self.output_data:
            # For SQLite, the data might be stored as a string
            if isinstance(self.output_data, str):
                try:
                    result["output"] = json.loads(self.output_data)
                except:
                    result["output"] = self.output_data
            else:
                result["output"] = self.output_data
            
        return result