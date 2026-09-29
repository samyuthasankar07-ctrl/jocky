"""
agent/artifacts.py - Artifact result container
Defines the ArtifactResult class used by all modules.
"""

from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Any


@dataclass
class ArtifactResult:
    """
    Container for module execution results.
    
    Attributes:
        artifacts: List of (kind, blob, meta) tuples
                  kind: str - artifact type identifier
                  blob: bytes - binary artifact data
                  meta: dict - metadata (out_path, records, etc.)
        anomalies: List of dicts - detected anomalies/findings
    """
    artifacts: List[Tuple[str, bytes, Dict[str, Any]]] = field(default_factory=list)
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_artifact(self, kind: str, blob: bytes, meta: Dict[str, Any] = None):
        """Add an artifact to the result."""
        if meta is None:
            meta = {}
        self.artifacts.append((kind, blob, meta))
    
    def add_anomaly(self, anomaly: Dict[str, Any]):
        """Add an anomaly to the result."""
        self.anomalies.append(anomaly)
