"""
Core Data Models for Linux Vulnerability Scanner and Security Assessment Tool.
Provides strongly typed dataclasses and enums for all system entities,
vulnerabilities, advisories, applicability conditions, evidence, and report structures.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone


class AssessmentStatus(str, Enum):
    """
    Standard vulnerability applicability classifications.
    Strictly distinguishes between Not Affected, Mitigated, and Fixed.
    """
    AFFECTED = "Affected"
    POTENTIALLY_AFFECTED = "Potentially affected"
    NOT_AFFECTED = "Not affected"
    MITIGATED = "Mitigated"
    FIXED = "Fixed"
    UNABLE_TO_DETERMINE = "Unable to determine"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_cvss(cls, score: Optional[float]) -> "Severity":
        if score is None:
            return cls.UNKNOWN
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0.0:
            return cls.LOW
        return cls.UNKNOWN


class ConfidenceLevel(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class PackageManagerType(str, Enum):
    RPM = "rpm"
    DPKG = "dpkg"
    UNKNOWN = "unknown"


@dataclass
class EvidenceItem:
    """A single piece of cryptographic/auditable evidence supporting an assessment conclusion."""
    command: str
    output_snippet: str
    source_file_or_target: str
    interpretation: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "output_snippet": self.output_snippet,
            "source_file_or_target": self.source_file_or_target,
            "interpretation": self.interpretation,
            "timestamp": self.timestamp,
        }


@dataclass
class CpuCapabilities:
    """CPU hardware specifications and instruction-set extensions."""
    vendor_id: str = "Unknown"
    model_name: str = "Unknown"
    architecture: str = "x86_64"
    cpu_count: int = 1
    flags: List[str] = field(default_factory=list)
    has_avx512: bool = False
    has_avx512_vbmi: bool = False
    has_aes_ni: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vendor_id": self.vendor_id,
            "model_name": self.model_name,
            "architecture": self.architecture,
            "cpu_count": self.cpu_count,
            "flags": self.flags,
            "has_avx512": self.has_avx512,
            "has_avx512_vbmi": self.has_avx512_vbmi,
            "has_aes_ni": self.has_aes_ni,
        }


@dataclass
class SystemInfo:
    """Authoritative host environment and operating system identity."""
    hostname: str
    os_name: str
    os_version: str
    os_family: str  # rhel, debian, etc.
    os_codename: Optional[str]
    platform_id: Optional[str]  # e.g., platform:el9
    kernel_version: str
    architecture: str
    package_manager: PackageManagerType
    uptime_seconds: Optional[float] = None
    virtualization: Optional[str] = None
    cloud_provider: Optional[str] = None  # e.g. AWS EC2, GCP, Azure, On-Premise
    cpu: Optional[CpuCapabilities] = None
    memory_total_mb: Optional[int] = None
    scan_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "os_family": self.os_family,
            "os_codename": self.os_codename,
            "platform_id": self.platform_id,
            "kernel_version": self.kernel_version,
            "architecture": self.architecture,
            "package_manager": self.package_manager.value,
            "uptime_seconds": self.uptime_seconds,
            "virtualization": self.virtualization,
            "cloud_provider": self.cloud_provider,
            "cpu": self.cpu.to_dict() if self.cpu else None,
            "memory_total_mb": self.memory_total_mb,
            "scan_timestamp": self.scan_timestamp,
        }


@dataclass
class Package:
    """An installed system package (RPM, DPKG, etc.)."""
    name: str
    version: str
    release: str = ""
    epoch: str = "0"
    arch: str = "x86_64"
    vendor: str = ""
    source_rpm: Optional[str] = None
    install_time: Optional[str] = None
    status: Optional[str] = None  # for dpkg (e.g. "installed")

    @property
    def full_nevra(self) -> str:
        """Name-Epoch:Version-Release.Arch"""
        epoch_str = f"{self.epoch}:" if self.epoch and self.epoch != "0" else ""
        rel_str = f"-{self.release}" if self.release else ""
        return f"{self.name}-{epoch_str}{self.version}{rel_str}.{self.arch}"

    @property
    def evr(self) -> str:
        epoch_str = f"{self.epoch}:" if self.epoch and self.epoch != "0" else ""
        rel_str = f"-{self.release}" if self.release else ""
        return f"{epoch_str}{self.version}{rel_str}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "release": self.release,
            "epoch": self.epoch,
            "arch": self.arch,
            "vendor": self.vendor,
            "source_rpm": self.source_rpm,
            "status": self.status,
            "full_nevra": self.full_nevra,
        }


@dataclass
class SoftwareRuntime:
    """Manually or package-installed runtime (e.g. OpenJDK, Python, NGINX, Node.js)."""
    name: str
    detected_version: str
    binary_path: str
    install_type: str  # package_manager, standalone_binary, bundled
    associated_package: Optional[str] = None
    runtime_flags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "detected_version": self.detected_version,
            "binary_path": self.binary_path,
            "install_type": self.install_type,
            "associated_package": self.associated_package,
            "runtime_flags": self.runtime_flags,
            "metadata": self.metadata,
        }


@dataclass
class ServiceInfo:
    """System service status and properties."""
    name: str
    load_state: str
    active_state: str
    sub_state: str
    unit_file_state: str = "unknown"  # enabled/disabled
    exec_path: Optional[str] = None
    pid: Optional[int] = None
    listening_ports: List[int] = field(default_factory=list)

    @property
    def is_running(self) -> bool:
        return self.active_state.lower() == "active" or self.sub_state.lower() == "running"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "load_state": self.load_state,
            "active_state": self.active_state,
            "sub_state": self.sub_state,
            "unit_file_state": self.unit_file_state,
            "exec_path": self.exec_path,
            "pid": self.pid,
            "listening_ports": self.listening_ports,
            "is_running": self.is_running,
        }


@dataclass
class ListeningPort:
    protocol: str  # tcp, udp, tcp6, udp6
    local_address: str
    local_port: int
    process_name: Optional[str] = None
    pid: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "local_address": self.local_address,
            "local_port": self.local_port,
            "process_name": self.process_name,
            "pid": self.pid,
        }


@dataclass
class ConfigurationFinding:
    """Configuration assessment finding for a target service."""
    service_name: str
    config_file: str
    directive: str
    value: str
    security_relevance: str
    raw_snippet: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service_name": self.service_name,
            "config_file": self.config_file,
            "directive": self.directive,
            "value": self.value,
            "security_relevance": self.security_relevance,
            "raw_snippet": self.raw_snippet,
        }


@dataclass
class VulnerabilityAdvisory:
    """Security advisory information from an authoritative source (RHSA, RLSA, USN, NVD)."""
    cve_id: str
    advisory_id: str  # e.g., RHSA-2023:5468, RLSA-2023:5468, USN-6428-1
    title: str
    description: str
    severity: Severity
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = None
    cisa_kev: bool = False
    cisa_due_date: Optional[str] = None
    source_name: str = "Vendor"  # Red Hat, Rocky Linux, Ubuntu, NVD, CISA
    affected_packages: Dict[str, Dict[str, str]] = field(default_factory=dict)
    # Format: {"nginx": {"fixed_version": "1.20.1-14.el9_2.1", "affected_range": "< 1.20.1-14.el9_2.1"}}
    references: List[str] = field(default_factory=list)
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None
    remediation_text: Optional[str] = None
    mitigation_text: Optional[str] = None
    prerequisite_rules: List[str] = field(default_factory=list)
    root_cause: Optional[str] = None
    validation_steps: List[Dict[str, str]] = field(default_factory=list)
    safe_verification_procedure: Optional[str] = None
    operational_impact: Optional[str] = None
    compensating_controls: List[str] = field(default_factory=list)
    residual_risk: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "advisory_id": self.advisory_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "epss_score": self.epss_score,
            "cisa_kev": self.cisa_kev,
            "cisa_due_date": self.cisa_due_date,
            "source_name": self.source_name,
            "affected_packages": self.affected_packages,
            "references": self.references,
            "published_date": self.published_date,
            "last_modified_date": self.last_modified_date,
            "remediation_text": self.remediation_text,
            "mitigation_text": self.mitigation_text,
            "prerequisite_rules": self.prerequisite_rules,
            "root_cause": self.root_cause,
            "validation_steps": self.validation_steps,
            "safe_verification_procedure": self.safe_verification_procedure,
            "operational_impact": self.operational_impact,
            "compensating_controls": self.compensating_controls,
            "residual_risk": self.residual_risk,
        }


@dataclass
class AssessmentFinding:
    """Final evaluated assessment for a single CVE against the scanned system."""
    cve_id: str
    title: str
    component: str
    installed_version: str
    fixed_version: Optional[str]
    status: AssessmentStatus
    severity: Severity
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    epss_score: Optional[float]
    cisa_kev: bool
    risk_priority_score: float  # Multi-factor computed score (1 to 100)
    priority_rank: int = 999
    description: str = ""
    advisory_source: str = ""
    advisory_id: str = ""
    evidence: List[EvidenceItem] = field(default_factory=list)
    applicability_reason: str = ""
    prerequisites_met: List[str] = field(default_factory=list)
    prerequisites_not_met: List[str] = field(default_factory=list)
    remediation: str = ""
    remediation_cmd: Optional[str] = None
    mitigation: Optional[str] = None
    verification_cmd: Optional[str] = None
    requires_reboot: bool = False
    requires_service_restart: bool = False
    affected_service_name: Optional[str] = None
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    references: List[str] = field(default_factory=list)
    root_cause: str = ""
    validation_steps: List[Dict[str, str]] = field(default_factory=list)
    safe_verification_procedure: str = ""
    operational_impact: str = ""
    compensating_controls: List[str] = field(default_factory=list)
    residual_risk: str = ""
    contextual_risk_rating: str = "Low / Managed"
    remediation_priority: str = "Normal Maintenance"
    risk_justification: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "title": self.title,
            "component": self.component,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "status": self.status.value,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "epss_score": self.epss_score,
            "cisa_kev": self.cisa_kev,
            "risk_priority_score": self.risk_priority_score,
            "priority_rank": self.priority_rank,
            "description": self.description,
            "advisory_source": self.advisory_source,
            "advisory_id": self.advisory_id,
            "evidence": [e.to_dict() for e in self.evidence],
            "applicability_reason": self.applicability_reason,
            "prerequisites_met": self.prerequisites_met,
            "prerequisites_not_met": self.prerequisites_not_met,
            "remediation": self.remediation,
            "remediation_cmd": self.remediation_cmd,
            "mitigation": self.mitigation,
            "verification_cmd": self.verification_cmd,
            "requires_reboot": self.requires_reboot,
            "requires_service_restart": self.requires_service_restart,
            "affected_service_name": self.affected_service_name,
            "confidence": self.confidence.value,
            "references": self.references,
            "root_cause": self.root_cause,
            "validation_steps": self.validation_steps,
            "safe_verification_procedure": self.safe_verification_procedure,
            "operational_impact": self.operational_impact,
            "compensating_controls": self.compensating_controls,
            "residual_risk": self.residual_risk,
            "contextual_risk_rating": self.contextual_risk_rating,
            "remediation_priority": self.remediation_priority,
            "risk_justification": self.risk_justification,
        }


@dataclass
class ScanSummary:
    """High-level metrics for executive summaries."""
    total_cves_evaluated: int = 0
    affected_count: int = 0
    potentially_affected_count: int = 0
    not_affected_count: int = 0
    mitigated_count: int = 0
    fixed_count: int = 0
    unable_to_determine_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    cisa_kev_count: int = 0
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_cves_evaluated": self.total_cves_evaluated,
            "affected_count": self.affected_count,
            "potentially_affected_count": self.potentially_affected_count,
            "not_affected_count": self.not_affected_count,
            "mitigated_count": self.mitigated_count,
            "fixed_count": self.fixed_count,
            "unable_to_determine_count": self.unable_to_determine_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "cisa_kev_count": self.cisa_kev_count,
            "duration_seconds": self.duration_seconds,
        }


@dataclass
class ReportBranding:
    """Report branding and assessment classification metadata."""
    company_name: Optional[str] = None
    company_logo: Optional[str] = None
    assessor_name: Optional[str] = None
    classification: str = "CONFIDENTIAL"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "company_name": self.company_name,
            "company_logo": self.company_logo,
            "assessor_name": self.assessor_name,
            "classification": self.classification,
        }


@dataclass
class ScanReport:
    """Complete security assessment report data structure."""
    scanner_version: str
    scan_timestamp: str
    system_info: SystemInfo
    summary: ScanSummary
    findings: List[AssessmentFinding] = field(default_factory=list)
    packages: List[Package] = field(default_factory=list)
    runtimes: List[SoftwareRuntime] = field(default_factory=list)
    services: List[ServiceInfo] = field(default_factory=list)
    configurations: List[ConfigurationFinding] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    data_source_timestamps: Dict[str, str] = field(default_factory=dict)
    is_offline_mode: bool = False
    branding: Optional[ReportBranding] = None

    def to_dict(self) -> Dict[str, Any]:
        res = {
            "scanner_version": self.scanner_version,
            "scan_timestamp": self.scan_timestamp,
            "is_offline_mode": self.is_offline_mode,
            "data_source_timestamps": self.data_source_timestamps,
            "system_info": self.system_info.to_dict(),
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "packages_count": len(self.packages),
            "packages": [p.to_dict() for p in self.packages],
            "runtimes": [r.to_dict() for r in self.runtimes],
            "services": [s.to_dict() for s in self.services],
            "configurations": [c.to_dict() for c in self.configurations],
            "limitations": self.limitations,
        }
        if self.branding:
            res["branding"] = self.branding.to_dict()
        return res
