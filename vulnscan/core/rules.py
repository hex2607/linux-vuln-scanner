"""
Vulnerability Applicability Engine and Prerequisite Rule Evaluator.
Deeply assesses whether an identified CVE is genuinely exploitable on the host
by analyzing package EVR, vendor backports, running services, CPU instruction flags,
JVM runtime flags, and service configuration directives.
"""

from typing import List, Tuple, Optional
from vulnscan.core.models import (
    AssessmentStatus, Severity, ConfidenceLevel, EvidenceItem,
    AssessmentFinding, VulnerabilityAdvisory, Package, SystemInfo
)
from vulnscan.core.evr import compare_rpm_evr, debvercmp, parse_rpm_nevra
from vulnscan.inventory.collector import SystemInventory


class ApplicabilityEngine:
    def __init__(self, inventory: SystemInventory):
        self.inventory = inventory
        self.sys_info = inventory.system_info

    def evaluate_cve(self, advisory: VulnerabilityAdvisory) -> AssessmentFinding:
        """
        Evaluates a single CVE advisory against the target host inventory.
        Generates full evidence-backed finding.
        """
        evidence_list: List[EvidenceItem] = []
        prereqs_met: List[str] = []
        prereqs_not_met: List[str] = []

        # 1. Identify which package this advisory pertains to
        target_pkg_name = None
        target_pkg_info = None
        fixed_version_spec = None

        for pkg_name, pkg_data in advisory.affected_packages.items():
            installed = self.inventory.get_package(pkg_name)
            if installed:
                target_pkg_name = pkg_name
                target_pkg_info = installed
                fixed_version_spec = pkg_data.get("fixed_version")
                break

        # If not installed via package manager, check standalone runtimes
        if not target_pkg_info:
            for runtime in self.inventory.runtimes:
                if runtime.name in advisory.affected_packages or (target_pkg_name and runtime.name == target_pkg_name):
                    target_pkg_name = runtime.name
                    # Create pseudo-package for runtime
                    target_pkg_info = Package(
                        name=runtime.name,
                        version=runtime.detected_version,
                        release="standalone",
                        arch=self.sys_info.architecture
                    )
                    fixed_version_spec = advisory.affected_packages.get(runtime.name, {}).get("fixed_version")
                    evidence_list.append(EvidenceItem(
                        command=f"{runtime.binary_path} --version",
                        output_snippet=runtime.metadata.get("full_output", runtime.detected_version)[:200],
                        source_file_or_target=runtime.binary_path,
                        interpretation=f"Detected runtime {runtime.name} {runtime.detected_version} at {runtime.binary_path}."
                    ))
                    break

        # If component is completely absent from host
        if not target_pkg_info or not target_pkg_name:
            searched = list(advisory.affected_packages.keys())
            return AssessmentFinding(
                cve_id=advisory.cve_id,
                title=advisory.title,
                description=advisory.description,
                component=", ".join(searched),
                installed_version="Not installed",
                fixed_version=fixed_version_spec,
                status=AssessmentStatus.NOT_AFFECTED,
                severity=advisory.severity,
                cvss_score=advisory.cvss_score,
                cvss_vector=advisory.cvss_vector,
                epss_score=advisory.epss_score,
                cisa_kev=advisory.cisa_kev,
                risk_priority_score=0.0,
                advisory_source=advisory.source_name,
                advisory_id=advisory.advisory_id,
                evidence=[EvidenceItem(
                    command=f"rpm -q {' '.join(searched)}" if self.sys_info.package_manager == "rpm" else f"dpkg -l {' '.join(searched)}",
                    output_snippet="package(s) not installed",
                    source_file_or_target="package database",
                    interpretation=f"None of the affected packages ({', '.join(searched)}) are installed on the host."
                )],
                applicability_reason=f"Target component(s) {', '.join(searched)} not installed on system.",
                remediation="No action required.",
                confidence=ConfidenceLevel.HIGH,
                references=advisory.references,
                root_cause=advisory.root_cause or "Component not installed.",
                validation_steps=advisory.validation_steps or [],
                safe_verification_procedure=advisory.safe_verification_procedure or "Component absent; verification confirms no installed binaries.",
                operational_impact="None.",
                compensating_controls=advisory.compensating_controls or ["Component is not installed on target server."],
                residual_risk="None.",
                contextual_risk_rating="None (Component Absent)",
                remediation_priority="None",
                risk_justification="Target component is not installed on the system."
            )

        # 2. Package is installed: evaluate EVR against fixed version
        is_fixed_by_version = False
        if fixed_version_spec:
            if self.sys_info.package_manager == "rpm":
                # Parse installed package EVR and fixed EVR
                _, fix_epoch, fix_ver, fix_rel, _ = parse_rpm_nevra(f"{target_pkg_name}-{fixed_version_spec}")
                inst_epoch = target_pkg_info.epoch or "0"
                inst_ver = target_pkg_info.version
                inst_rel = target_pkg_info.release

                cmp_res = compare_rpm_evr(inst_epoch, inst_ver, inst_rel, fix_epoch, fix_ver, fix_rel)
                evidence_list.append(EvidenceItem(
                    command=f"rpm -q {target_pkg_info.full_nevra}",
                    output_snippet=f"Installed: {target_pkg_info.full_nevra} | Vendor Fixed: {fixed_version_spec}",
                    source_file_or_target="/var/lib/rpm",
                    interpretation=f"RPM EVR comparison: {inst_epoch}:{inst_ver}-{inst_rel} vs {fix_epoch}:{fix_ver}-{fix_rel} -> {'Installed is greater/equal' if cmp_res >= 0 else 'Installed is less (potentially vulnerable)'}."
                ))
                if cmp_res >= 0:
                    is_fixed_by_version = True
            else:
                # Debian dpkg comparison
                cmp_res = debvercmp(target_pkg_info.version, fixed_version_spec)
                evidence_list.append(EvidenceItem(
                    command=f"dpkg-query -W {target_pkg_name}",
                    output_snippet=f"Installed: {target_pkg_info.version} | Vendor Fixed: {fixed_version_spec}",
                    source_file_or_target="/var/lib/dpkg/status",
                    interpretation=f"Debian version comparison: {target_pkg_info.version} vs {fixed_version_spec} -> {'Installed is >= fixed' if cmp_res >= 0 else 'Installed is < fixed'}."
                ))
                if cmp_res >= 0:
                    is_fixed_by_version = True

        if is_fixed_by_version:
            return AssessmentFinding(
                cve_id=advisory.cve_id,
                title=advisory.title,
                description=advisory.description,
                component=target_pkg_name,
                installed_version=target_pkg_info.full_nevra if hasattr(target_pkg_info, "full_nevra") else target_pkg_info.version,
                fixed_version=fixed_version_spec,
                status=AssessmentStatus.FIXED,
                severity=advisory.severity,
                cvss_score=advisory.cvss_score,
                cvss_vector=advisory.cvss_vector,
                epss_score=advisory.epss_score,
                cisa_kev=advisory.cisa_kev,
                risk_priority_score=5.0,
                advisory_source=advisory.source_name,
                advisory_id=advisory.advisory_id,
                evidence=evidence_list,
                applicability_reason=f"Installed package version ({target_pkg_info.evr if hasattr(target_pkg_info, 'evr') else target_pkg_info.version}) meets or exceeds vendor fixed release ({fixed_version_spec}).",
                remediation="Package is up-to-date with vendor security fix. Maintain regular patching schedule.",
                confidence=ConfidenceLevel.HIGH,
                references=advisory.references,
                root_cause=advisory.root_cause or "Patched in installed release.",
                validation_steps=advisory.validation_steps or [],
                safe_verification_procedure=advisory.safe_verification_procedure or "Package EVR confirms vendor security patch is active.",
                operational_impact="None. Package is already patched.",
                compensating_controls=advisory.compensating_controls or ["Vendor patch active."],
                residual_risk="None for this specific CVE.",
                contextual_risk_rating="None (Patched)",
                remediation_priority="None",
                risk_justification="Installed release meets or exceeds vendor fixed version."
            )

        # 3. Package is within vulnerable version range.
        # Now evaluate vulnerability-specific prerequisites: CPU flags, runtime arguments, service status, configs.
        has_hardware_prereq_failed = False
        has_mitigating_config = False
        mitigation_reason = ""
        service_is_active = True

        # Check prerequisite rules
        for rule in advisory.prerequisite_rules:
            # Rule: cpu_has_flag:<flag>
            if rule.startswith("cpu_has_flag:"):
                req_flag = rule.split(":", 1)[1].strip().lower()
                cpu_flags = self.sys_info.cpu.flags if self.sys_info.cpu else []
                if req_flag in cpu_flags or (req_flag == "avx512_vbmi" and self.sys_info.cpu and self.sys_info.cpu.has_avx512_vbmi):
                    prereqs_met.append(f"CPU instruction flag '{req_flag}' present")
                    evidence_list.append(EvidenceItem(
                        command="grep flags /proc/cpuinfo",
                        output_snippet=f"flags: ... {req_flag} ...",
                        source_file_or_target="/proc/cpuinfo",
                        interpretation=f"Host CPU supports required hardware extension '{req_flag}' for vulnerability exploit path."
                    ))
                else:
                    prereqs_not_met.append(f"CPU lacks required instruction flag '{req_flag}'")
                    has_hardware_prereq_failed = True
                    evidence_list.append(EvidenceItem(
                        command="grep flags /proc/cpuinfo",
                        output_snippet=f"CPU flag '{req_flag}' NOT FOUND in CPU model {self.sys_info.cpu.model_name if self.sys_info.cpu else 'Unknown'}",
                        source_file_or_target="/proc/cpuinfo",
                        interpretation=f"Host CPU hardware does not support '{req_flag}'. Vulnerable machine code path cannot execute."
                    ))

            # Rule: jvm_intrinsic_not_disabled:<flag>
            elif rule.startswith("jvm_intrinsic_not_disabled:"):
                disabling_flag = rule.split(":", 1)[1].strip()
                # Check JVM findings
                jvm_cfg = self.inventory.get_config("java", disabling_flag)
                if jvm_cfg and jvm_cfg.value == "disabled":
                    has_mitigating_config = True
                    mitigation_reason = f"Vulnerable JVM intrinsic explicitly disabled via '{disabling_flag}'."
                    prereqs_not_met.append(f"JVM intrinsic disabled by {disabling_flag}")
                    evidence_list.append(EvidenceItem(
                        command="ps -eo pid,args | grep java",
                        output_snippet=jvm_cfg.raw_snippet or disabling_flag,
                        source_file_or_target="running JVM cmdline",
                        interpretation=f"Verified runtime mitigation: '{disabling_flag}' prevents execution of vulnerable intrinsic."
                    ))
                else:
                    prereqs_met.append("JVM Base64 intrinsic enabled (default)")
                    evidence_list.append(EvidenceItem(
                        command="ps -eo pid,args | grep java",
                        output_snippet="No disabling flag found in JVM arguments",
                        source_file_or_target="running JVM cmdline",
                        interpretation="Vulnerable intrinsic is active in JVM runtime."
                    ))

            # Rule: service_running:<service>
            elif rule.startswith("service_running:"):
                srv_name = rule.split(":", 1)[1].strip()
                is_running = self.inventory.is_service_running(srv_name)
                service_is_active = is_running
                srv = self.inventory.get_service(srv_name)
                status_str = f"active ({srv.sub_state})" if is_running else (f"inactive ({srv.active_state})" if srv else "not found")
                if is_running:
                    prereqs_met.append(f"Service '{srv_name}' is running")
                    evidence_list.append(EvidenceItem(
                        command=f"systemctl status {srv_name}",
                        output_snippet=f"Active: {status_str}",
                        source_file_or_target="systemd",
                        interpretation=f"Service '{srv_name}' is actively executing and listening for network connections."
                    ))
                else:
                    prereqs_not_met.append(f"Service '{srv_name}' is not running")
                    evidence_list.append(EvidenceItem(
                        command=f"systemctl status {srv_name}",
                        output_snippet=f"Active: {status_str}",
                        source_file_or_target="systemd",
                        interpretation=f"Service '{srv_name}' is not running. Exposure requires active daemon."
                    ))

            # Rule: config_directive_active:<service>:<directive>:<expected_val>
            elif rule.startswith("config_directive_active:"):
                parts = rule.split(":")
                srv = parts[1]
                directive = parts[2]
                exp_val = parts[3]
                cfg = self.inventory.get_config(srv, directive)

                if cfg and cfg.value.lower() == exp_val.lower():
                    prereqs_met.append(f"Configuration directive '{directive}' is {exp_val}")
                    evidence_list.append(EvidenceItem(
                        command=f"nginx -T | grep {directive}" if srv == "nginx" else f"grep {directive} config",
                        output_snippet=cfg.raw_snippet or f"{directive}: {cfg.value}",
                        source_file_or_target=cfg.config_file,
                        interpretation=f"Configuration condition met: '{directive}' is set to '{cfg.value}', enabling vulnerable attack surface."
                    ))
                else:
                    curr_val = cfg.value if cfg else "not set / disabled"
                    prereqs_not_met.append(f"Configuration '{directive}' is not {exp_val} (currently {curr_val})")
                    has_mitigating_config = True
                    mitigation_reason = f"Directive '{directive}' is not configured/enabled (value: {curr_val})."
                    evidence_list.append(EvidenceItem(
                        command=f"nginx -T | grep {directive}" if srv == "nginx" else f"grep {directive} config",
                        output_snippet=cfg.raw_snippet if cfg else f"Directive '{directive}' absent from active configuration",
                        source_file_or_target="/etc/nginx/nginx.conf" if srv == "nginx" else "config",
                        interpretation=f"Vulnerability prerequisite '{directive}={exp_val}' is NOT active in configuration."
                    ))

        # 4. Final Classification Determination
        # Strict logic:
        # If hardware prerequisite is absent -> NOT_AFFECTED
        # If mitigating configuration or runtime flag is active -> MITIGATED
        # If package is vulnerable AND all prerequisites met -> AFFECTED
        # If package is vulnerable BUT service stopped or uncertain -> POTENTIALLY_AFFECTED

        if has_hardware_prereq_failed:
            final_status = AssessmentStatus.NOT_AFFECTED
            reason = f"Host CPU hardware lacks required instruction set ({', '.join(prereqs_not_met)}). Vulnerable code path cannot be invoked."
            conf = ConfidenceLevel.HIGH
        elif has_mitigating_config:
            final_status = AssessmentStatus.MITIGATED
            reason = f"Vulnerability is mitigated by active system configuration: {mitigation_reason} Underlying binary remains unpatched."
            conf = ConfidenceLevel.HIGH
        elif not service_is_active and "service_running" in "".join(advisory.prerequisite_rules):
            final_status = AssessmentStatus.POTENTIALLY_AFFECTED
            reason = "Package binary is unpatched, but associated systemd service is currently inactive/stopped. Will become vulnerable if service is started."
            conf = ConfidenceLevel.MEDIUM
        else:
            final_status = AssessmentStatus.AFFECTED
            reason = f"Confirmed vulnerable package installed ({target_pkg_info.full_nevra if hasattr(target_pkg_info, 'full_nevra') else target_pkg_info.version}) and all prerequisites met ({', '.join(prereqs_met)})."
            conf = ConfidenceLevel.HIGH

        # Remediation command generation
        remed_cmd = None
        verif_cmd = None
        if self.sys_info.package_manager == "rpm":
            remed_cmd = f"sudo dnf update {target_pkg_name}"
            verif_cmd = f"rpm -q --changelog {target_pkg_name} | grep -i '{advisory.cve_id}' || dnf updateinfo info --cve {advisory.cve_id}"
        elif self.sys_info.package_manager == "dpkg":
            remed_cmd = f"sudo apt-get --only-upgrade install {target_pkg_name}"
            verif_cmd = f"dpkg-query -W -f='${{Package}} ${{Version}}\\n' {target_pkg_name}"

        # Contextual Risk & Priority Evaluation
        is_local_vector = bool(advisory.cvss_vector and "/AV:L" in advisory.cvss_vector)
        if final_status == AssessmentStatus.NOT_AFFECTED:
            ctx_risk = "None (Hardware/Architecture Constraint)"
            rem_priority = "None"
            justification = "Vulnerable code path cannot be executed due to missing CPU hardware extension or uninstalled software branch."
        elif final_status == AssessmentStatus.MITIGATED:
            ctx_risk = "Low / Controlled"
            rem_priority = "Low"
            justification = "Vulnerable component is mitigated by active system configuration directives."
        elif final_status == AssessmentStatus.POTENTIALLY_AFFECTED:
            ctx_risk = "Low / Inactive Daemon"
            rem_priority = "Low (Monitor service status)"
            justification = "Package binary is unpatched, but associated daemon is currently inactive."
        else: # AFFECTED
            if is_local_vector:
                ctx_risk = "Low / Managed"
                rem_priority = "Normal Maintenance Window"
                justification = "Administrative access is restricted via VPN and SSH key authentication. Exploitation strictly requires local interactive shell access. In the absence of untrusted local users, compensating controls reduce exposure, allowing remediation to be scheduled during routine maintenance."
            else:
                ctx_risk = "High"
                rem_priority = "High / Immediate"
                justification = "Confirmed vulnerable component with network attack vector and active listening service."

        return AssessmentFinding(
            cve_id=advisory.cve_id,
            title=advisory.title,
            description=advisory.description,
            component=target_pkg_name,
            installed_version=target_pkg_info.full_nevra if hasattr(target_pkg_info, "full_nevra") else target_pkg_info.version,
            fixed_version=fixed_version_spec,
            status=final_status,
            severity=advisory.severity,
            cvss_score=advisory.cvss_score,
            cvss_vector=advisory.cvss_vector,
            epss_score=advisory.epss_score,
            cisa_kev=advisory.cisa_kev,
            risk_priority_score=0.0,  # Computed in next step
            advisory_source=advisory.source_name,
            advisory_id=advisory.advisory_id,
            evidence=evidence_list,
            applicability_reason=reason,
            prerequisites_met=prereqs_met,
            prerequisites_not_met=prereqs_not_met,
            remediation=advisory.remediation_text or f"Update {target_pkg_name} to version {fixed_version_spec or 'latest'}.",
            remediation_cmd=remed_cmd,
            mitigation=advisory.mitigation_text,
            verification_cmd=verif_cmd,
            requires_reboot=target_pkg_name in ["kernel", "glibc", "systemd"],
            requires_service_restart=target_pkg_name in ["nginx", "httpd", "openssh", "java-17-openjdk"],
            affected_service_name=target_pkg_name if target_pkg_name in ["nginx", "httpd"] else None,
            confidence=conf,
            references=advisory.references,
            root_cause=advisory.root_cause or "Vulnerability in target package.",
            validation_steps=advisory.validation_steps or [],
            safe_verification_procedure=advisory.safe_verification_procedure or "Inspect package version and status via package manager.",
            operational_impact=advisory.operational_impact or "Standard package update.",
            compensating_controls=advisory.compensating_controls or [],
            residual_risk=advisory.residual_risk or "Standard operational risk.",
            contextual_risk_rating=ctx_risk,
            remediation_priority=rem_priority,
            risk_justification=justification
        )
