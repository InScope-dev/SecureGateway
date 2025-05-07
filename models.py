"""
MCP-Sec Gateway - Database Models
Defines the database models for storing audit logs and related data
"""
import json
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB

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
    
    # Store JSON data in PostgreSQL JSONB format
    input_data = db.Column(JSONB, nullable=True)
    output_data = db.Column(JSONB, nullable=True)
    
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
            "latency_ms": self.latency_ms
        }
        
        # Add optional fields if present
        if self.reason:
            result["reason"] = self.reason
        if self.input_data:
            result["input"] = self.input_data
        if self.output_data:
            result["output"] = self.output_data
            
        return result