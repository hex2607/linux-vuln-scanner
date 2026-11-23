"""
Abstract Base Class for Vulnerability Advisory Sources.
Defines standard interfaces for querying vendor security advisories,
NVD, CISA KEV, and FIRST EPSS.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from vulnscan.core.models import VulnerabilityAdvisory


class VulnerabilitySource(ABC):
    @abstractmethod
    def get_source_name(self) -> str:
        """Returns the authoritative name of the data source."""
        pass

    @abstractmethod
    def get_last_updated(self) -> Optional[str]:
        """Returns ISO timestamp of when the source was last refreshed."""
        pass

    @abstractmethod
    def fetch_advisories_for_package(
        self, package_name: str, os_family: str, os_version: str
    ) -> List[VulnerabilityAdvisory]:
        """Queries the source for advisories affecting a specific package on target OS."""
        pass

    @abstractmethod
    def fetch_cve(self, cve_id: str) -> Optional[VulnerabilityAdvisory]:
        """Queries detailed information for a single CVE ID."""
        pass
