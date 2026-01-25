"""
PhantomCortex - Core Package
Contains main threat collection engine
"""

__version__ = "1.0.0"

from .collector import ThreatCollector, ThreatIntelligence

__all__ = ["ThreatCollector", "ThreatIntelligence"]
