#!/usr/bin/env python3
"""
Clean Vulnerability Correlation Agent

A simplified implementation that correlates vulnerabilities from Vanir 
with unused functions from Joern to provide prioritized vulnerability reports.

Key Features:
- Parses Vanir vulnerability reports
- Parses Joern unused function reports  
- Correlates vulnerabilities with code reachability
- Generates prioritized security recommendations
- Clean, maintainable codebase
"""

import json
import os
import re
import sys
import logging
import subprocess
import argparse
import traceback
import tempfile
import glob
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Callable, Union
from dataclasses import dataclass, field


@dataclass
class Vulnerability:
    """Represents a security vulnerability"""
    id: str
    cve_ids: List[str] = field(default_factory=list)
    severity: str = "UNKNOWN"
    file_path: str = ""
    function_name: str = ""
    description: str = ""
    patch_url: str = ""
    osv_url: str = ""


@dataclass
class UnusedFunction:
    """Represents an unused/dead function"""
    function_name: str
    file_path: str
    line_number: int = 0
    confidence: float = 1.0


@dataclass
class VulnerabilityCorrelation:
    """Represents correlation between a vulnerability and code usage"""
    vulnerability: Vulnerability
    risk_level: str  # HIGH, MEDIUM, LOW
    risk_explanation: str
    is_function_unused: bool
    is_reachable: bool


class VanirParser:
    """Parser for Vanir vulnerability reports"""
    
    @staticmethod
    def parse(vanir_data: Dict[str, Any]) -> List[Vulnerability]:
        """Parse Vanir JSON output into Vulnerability objects
        
        Args:
            vanir_data: JSON data from Vanir tool output
            
        Returns:
            List of Vulnerability objects
        """
        vulnerabilities = []
        
        # Handle standard Vanir output format
        vanir_vulnerabilities = vanir_data.get("vulnerabilities", [])
        
        for vuln_data in vanir_vulnerabilities:
            vuln_id = vuln_data.get("id", "")
            severity = vuln_data.get("severity", "UNKNOWN").upper()
            package = vuln_data.get("package", "")
            version = vuln_data.get("version", "")
            description = vuln_data.get("description", "")
            
            # Extract CVE IDs if available
            cve_ids = []
            if vuln_id.startswith("CVE-"):
                cve_ids = [vuln_id]
            
            # For correlation purposes, we'll use package name as the "function" 
            # since Vanir vulnerabilities are at package level, not function level
            vuln = Vulnerability(
                id=vuln_id,
                cve_ids=cve_ids,
                severity=severity,
                file_path=package,  # Use package name as file path for correlation
                function_name=package,  # Use package name as function name
                description=description,
                patch_url="",
                osv_url=""
            )
            
            vulnerabilities.append(vuln)
        
        # Also handle legacy format for backward compatibility
        missing_patches = vanir_data.get("missing_patches", [])
        
        for patch_data in missing_patches:
            osv_id = patch_data.get("ID", "")
            cve_ids = patch_data.get("CVE", [])
            osv_url = patch_data.get("OSV", "")
            
            details = patch_data.get("details", [])
            
            for detail in details:
                unpatched_code = detail.get("unpatched_code", "")
                patch_url = detail.get("patch", "")
                
                # Extract file path and function name
                if "::" in unpatched_code:
                    file_path, function_name = unpatched_code.rsplit("::", 1)
                else:
                    file_path = unpatched_code
                    function_name = ""  # Function not specified
                
                # Determine severity
                severity = "HIGH"
                if cve_ids:
                    severity = "CRITICAL" if len(cve_ids) > 1 else "HIGH"
                elif "CRITICAL" in osv_id.upper():
                    severity = "CRITICAL"
                
                vuln = Vulnerability(
                    id=cve_ids[0] if cve_ids else osv_id,
                    cve_ids=cve_ids,
                    severity=severity,
                    file_path=file_path,
                    function_name=function_name,
                    description=f"Missing security patch for {unpatched_code}",
                    patch_url=patch_url,
                    osv_url=osv_url
                )
                
                vulnerabilities.append(vuln)
        
        return vulnerabilities


class JoernParser:
    """Parser for Joern unused function reports"""
    
    @staticmethod
    def parse(joern_data: Union[List[Dict[str, Any]], Dict[str, Any], str, None]) -> List[UnusedFunction]:
        """Parse Joern JSON output into UnusedFunction objects
        
        Args:
            joern_data: JSON data from Joern tool output - can be a list, dict, JSON string, or None
            
        Returns:
            List of UnusedFunction objects
        """
        unused_functions = []
        
        # Handle None input
        if joern_data is None:
            logging.warning("None data provided to JoernParser")
            return []
        
        # Handle JSON string input - parse it first
        if isinstance(joern_data, str):
            try:
                if joern_data.strip():
                    joern_data = json.loads(joern_data)
                else:
                    logging.warning("Empty JSON string provided to JoernParser")
                    return []
            except json.JSONDecodeError as e:
                logging.error(f"Failed to parse JSON string in JoernParser: {e}")
                logging.error(f"Invalid JSON content: {joern_data[:200]}...")
                return []
        
        # Handle fallback results format (single dict with status)
        if isinstance(joern_data, dict):
            if "status" in joern_data:
                status = joern_data.get("status", "")
                if status in ["completed_with_fallback", "error"]:
                    logging.warning(f"Joern analysis fallback: {joern_data.get('error', 'Unknown error')}")
                    # Return the unused_functions from fallback (usually empty)
                    fallback_functions = joern_data.get("unused_functions", [])
                    if isinstance(fallback_functions, list):
                        for func_data in fallback_functions:
                            if isinstance(func_data, dict):
                                unused_func = UnusedFunction(
                                    function_name=func_data.get("name", ""),
                                    file_path=func_data.get("file", ""),
                                    line_number=func_data.get("line", 0),
                                    confidence=1.0
                                )
                                unused_functions.append(unused_func)
                    return unused_functions
            # If it's a single dict but not a fallback, treat it as a single item
            joern_data = [joern_data]
        
        # Handle normal list format
        if not isinstance(joern_data, list):
            logging.error(f"Unexpected joern_data format after processing: {type(joern_data)}")
            return []
        
        for func_data in joern_data:
            # Ensure func_data is a dictionary
            if not isinstance(func_data, dict):
                logging.warning(f"Skipping non-dict item in joern_data: {type(func_data)}")
                continue
                
            # Skip metadata entries (added in Joern script v1.1.0+)
            if "version" in func_data or "statistics" in func_data:
                logging.info(f"Detected Joern script version: {func_data.get('version', 'unknown')}")
                continue
                
            # Skip entries that aren't unused methods
            if func_data.get("type") != "unused_method" and "type" in func_data:
                continue
                
            unused_func = UnusedFunction(
                function_name=func_data.get("name", ""),
                file_path=func_data.get("file", ""),
                line_number=func_data.get("line", 0),
                confidence=1.0  # Joern provides high-confidence results
            )
            unused_functions.append(unused_func)
        
        return unused_functions


class CorrelationEngine:
    """Core engine for correlating vulnerabilities with code usage"""
    
    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def correlate(self, vulnerabilities: List[Vulnerability], 
                  unused_functions: List[UnusedFunction]) -> List[VulnerabilityCorrelation]:
        """Correlate vulnerabilities with unused functions
        
        Args:
            vulnerabilities: List of vulnerabilities from Vanir
            unused_functions: List of unused functions from Joern
            
        Returns:
            List of correlation results with risk assessments
        """
        
        self.logger.info(f"Correlating {len(vulnerabilities)} vulnerabilities with {len(unused_functions)} unused functions")
        
        # Build lookup set for fast unused function checking
        unused_lookup = self._build_unused_lookup(unused_functions)
        
        correlations = []
        
        for vuln in vulnerabilities:
            # Check if vulnerable function is unused
            is_unused = self._is_function_unused(vuln, unused_lookup)
            
            # Log correlation details for debugging
            func_desc = f"{vuln.file_path}::{vuln.function_name}" if vuln.function_name else f"{vuln.file_path} (no function specified)"
            self.logger.debug(f"Correlation: {func_desc} - Is unused: {is_unused}")
            
            # Determine risk level based on usage
            if is_unused:
                risk_level = "LOW"
                if not vuln.function_name or vuln.function_name == "unknown":
                    risk_explanation = "Vulnerable file contains unused code - lower priority"
                else:
                    risk_explanation = "Vulnerable function is unused/dead code - low priority"
            else:
                risk_level = "HIGH" if vuln.severity in ["CRITICAL", "HIGH"] else "MEDIUM"
                if not vuln.function_name or vuln.function_name == "unknown":
                    risk_explanation = f"Vulnerable file is actively used - {vuln.severity.lower()} priority"
                else:
                    risk_explanation = f"Vulnerable function is actively used - {vuln.severity.lower()} priority"
            
            correlation = VulnerabilityCorrelation(
                vulnerability=vuln,
                risk_level=risk_level,
                risk_explanation=risk_explanation,
                is_function_unused=is_unused,
                is_reachable=not is_unused
            )
            
            correlations.append(correlation)
        
        return correlations
    
    def _build_unused_lookup(self, unused_functions: List[UnusedFunction]) -> Set[str]:
        """Build lookup set for unused functions
        
        Args:
            unused_functions: List of unused functions
            
        Returns:
            Set of lookup keys for fast matching
        """
        unused_lookup = set()
        
        for func in unused_functions:
            # Add full path::function key
            func_key = f"{func.file_path}::{func.function_name}"
            unused_lookup.add(func_key)
            
            # Also add function name only for broader matching
            unused_lookup.add(func.function_name)
            
            # Also store file path alone for file-based matching
            if func.file_path:
                # Add special entry for file-based matching
                file_key = f"{func.file_path}::*"
                unused_lookup.add(file_key)
                
                # Also add filename only (without path) for flexible matching
                filename = os.path.basename(func.file_path)
                if filename:
                    filename_key = f"{filename}::*"
                    unused_lookup.add(filename_key)
        
        return unused_lookup
    
    def _is_function_unused(self, vuln: Vulnerability, unused_lookup: Set[str]) -> bool:
        """Check if a vulnerable function is unused
        
        Args:
            vuln: Vulnerability to check
            unused_lookup: Set of unused function keys
            
        Returns:
            True if function is unused, False otherwise
        """
        # Check full path::function match
        func_key = f"{vuln.file_path}::{vuln.function_name}"
        if func_key in unused_lookup:
            return True
        
        # Check function name only (if not "unknown" or empty)
        if vuln.function_name and vuln.function_name != "unknown" and vuln.function_name in unused_lookup:
            return True
        
        # If function name is "unknown" or empty, try to find a match by file path
        if (not vuln.function_name or vuln.function_name == "unknown") and vuln.file_path:
            # 1. First look for exact match with wildcard
            file_wildcard = f"{vuln.file_path}::*"
            if file_wildcard in unused_lookup:
                self.logger.info(f"Found direct wildcard match for file: {vuln.file_path}")
                return True
            
            # 2. Check functions with this file path
            for key in unused_lookup:
                # Check if vulnerability path is in the search key
                if "::" in key:
                    file_path = key.split("::")[0]
                    # Exact match or sub-path match
                    if file_path == vuln.file_path or file_path.endswith("/" + vuln.file_path):
                        self.logger.info(f"Found file path match: {key}")
                        return True
                    
                    # Check if filename (without path) matches
                    vuln_filename = os.path.basename(vuln.file_path)
                    if vuln_filename and os.path.basename(file_path) == vuln_filename:
                        self.logger.info(f"Found filename match: {key} for {vuln_filename}")
                        return True
        
        return False


class ReportGenerator:
    """Generates correlation analysis reports"""
    
    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def generate_analysis_report(self, correlations: List[VulnerabilityCorrelation]) -> Dict[str, Any]:
        """Generate comprehensive analysis report
        
        Args:
            correlations: List of vulnerability correlations
            
        Returns:
            Dictionary containing analysis report
        """
        
        # Calculate summary statistics
        total_vulns = len(correlations)
        high_risk = [c for c in correlations if c.risk_level == "HIGH"]
        medium_risk = [c for c in correlations if c.risk_level == "MEDIUM"]
        low_risk = [c for c in correlations if c.risk_level == "LOW"]
        
        # Calculate workload reduction potential
        prioritization_effectiveness = (len(low_risk) / total_vulns * 100) if total_vulns > 0 else 0
        
        # Generate recommendations
        recommendations = self._generate_recommendations(correlations)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "analysis_summary": {
                "total_vulnerabilities": total_vulns,
                "high_risk_count": len(high_risk),
                "medium_risk_count": len(medium_risk),
                "low_risk_count": len(low_risk),
                "prioritization_effectiveness": prioritization_effectiveness,
                "security_debt_score": len(high_risk) * 3 + len(medium_risk) * 2 + len(low_risk) * 1
            },
            "correlations": [self._correlation_to_dict(c) for c in correlations],
            "recommendations": recommendations
        }
    
    def _correlation_to_dict(self, correlation: VulnerabilityCorrelation) -> Dict[str, Any]:
        """Convert correlation to dictionary for JSON serialization
        
        Args:
            correlation: Vulnerability correlation object
            
        Returns:
            Dictionary representation
        """
        return {
            "vulnerability": {
                "id": correlation.vulnerability.id,
                "cve_ids": correlation.vulnerability.cve_ids,
                "severity": correlation.vulnerability.severity,
                "file_path": correlation.vulnerability.file_path,
                "function_name": correlation.vulnerability.function_name,
                "description": correlation.vulnerability.description,
                "patch_url": correlation.vulnerability.patch_url,
                "osv_url": correlation.vulnerability.osv_url
            },
            "risk_level": correlation.risk_level,
            "risk_explanation": correlation.risk_explanation,
            "is_function_unused": correlation.is_function_unused,
            "is_reachable": correlation.is_reachable
        }
    
    def _generate_recommendations(self, correlations: List[VulnerabilityCorrelation]) -> List[Dict[str, Any]]:
        """Generate actionable security recommendations"""
        recommendations = []
        
        high_risk = [c for c in correlations if c.risk_level == "HIGH"]
        low_risk = [c for c in correlations if c.risk_level == "LOW"]
        
        # High priority vulnerabilities
        if high_risk:
            recommendations.append({
                "priority": "CRITICAL",
                "category": "Immediate Action Required",
                "title": f"Address {len(high_risk)} high-risk vulnerabilities in active code",
                "description": "These vulnerabilities affect actively used functions and require immediate patching.",
                "action_items": [
                    f"Apply patch for {c.vulnerability.id} in {c.vulnerability.file_path}" 
                    for c in high_risk[:3]  # Top 3
                ],
                "estimated_effort": "High",
                "security_impact": "Critical"
            })
        
        # Low priority optimization
        if low_risk:
            recommendations.append({
                "priority": "LOW",
                "category": "Code Cleanup Opportunity",
                "title": f"Consider removing {len(low_risk)} unused vulnerable functions",
                "description": "These vulnerable functions are unused and can be safely removed to reduce attack surface.",
                "action_items": [
                    "Review and remove unused vulnerable code",
                    "Update build system to exclude dead code",
                    "Set up automated dead code detection"
                ],
                "estimated_effort": "Medium",
                "security_impact": "Low"
            })
        
        # Process improvement
        total_vulns = len(correlations)
        if total_vulns > 0:
            workload_reduction = (len(low_risk) / total_vulns) * 100
            if workload_reduction > 20:
                recommendations.append({
                    "priority": "MEDIUM",
                    "category": "Process Optimization",
                    "title": f"Achieve {workload_reduction:.1f}% reduction in security workload",
                    "description": "Implement vulnerability prioritization based on code reachability analysis.",
                    "action_items": [
                        "Integrate correlation analysis into security workflow",
                        "Train team on vulnerability prioritization",
                        "Automate correlation analysis in CI/CD"
                    ],
                    "estimated_effort": "Medium",
                    "security_impact": "Process Improvement"
                })
        
        return recommendations
    
    def save_report(self, report: Dict[str, Any], output_file: str) -> None:
        """Save report to JSON file
        
        Args:
            report: Analysis report dictionary
            output_file: Output file path
        """
        self.logger.info(f"Saving analysis report to {output_file}")
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Also save a human-readable summary
        summary_file = output_file.replace('.json', '_summary.txt')
        self._save_summary(report, summary_file)
    
    def _save_summary(self, report: Dict[str, Any], summary_file: str) -> None:
        """Save human-readable summary
        
        Args:
            report: Analysis report dictionary
            summary_file: Summary file path
        """
        with open(summary_file, 'w') as f:
            f.write("VULNERABILITY CORRELATION ANALYSIS SUMMARY\n")
            f.write("=" * 50 + "\n\n")
            
            summary = report["analysis_summary"]
            f.write(f"Analysis Date: {report['timestamp']}\n\n")
            
            f.write("RISK ASSESSMENT:\n")
            f.write(f"  Total vulnerabilities: {summary['total_vulnerabilities']}\n")
            f.write(f"  High risk (active code): {summary['high_risk_count']}\n")
            f.write(f"  Medium risk: {summary['medium_risk_count']}\n")
            f.write(f"  Low risk: {summary['low_risk_count']}\n")
            f.write(f"  Workload reduction potential: {summary['prioritization_effectiveness']:.1f}%\n\n")
            
            f.write("RECOMMENDATIONS:\n")
            for i, rec in enumerate(report.get("recommendations", []), 1):
                f.write(f"{i}. [{rec['priority']}] {rec['title']}\n")
                f.write(f"   {rec['description']}\n\n")


class VanirToolRunner:
    """Runs Vanir tool and returns results"""
    
    def __init__(self, vanir_path: str) -> None:
        self.vanir_path = vanir_path
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def check_vanir_built(self) -> Dict[str, Any]:
        """Check if Vanir is correctly built and available
        
        Returns:
            Dictionary with build status and details
        """
        result = {
            "built": False,
            "binary_path": "",
            "error": "",
            "details": {}
        }
        
        # Check if Vanir path exists
        if not self.vanir_path or not os.path.exists(self.vanir_path):
            result["error"] = f"Vanir path does not exist: {self.vanir_path}"
            return result
            
        # Check for the detector_runner binary
        primary_bin = os.path.join(self.vanir_path, "vanir", "bazel-bin", "detector_runner")
        alt_bin = os.path.join(self.vanir_path, "bazel-bin", "detector_runner")
        
        if os.path.exists(primary_bin):
            result["built"] = True
            result["binary_path"] = primary_bin
        elif os.path.exists(alt_bin):
            result["built"] = True
            result["binary_path"] = alt_bin
        else:
            result["error"] = "Vanir binary (detector_runner) not found"
            result["details"]["searched_paths"] = [primary_bin, alt_bin]
            
        return result
    
    def run_scan(self, repo_path: str, scanner_type: str, 
                package_name: str = None, ecosystem: str = None) -> Dict[str, Any]:
        """Run Vanir scan on repository"""
        self.logger.info(f"Running Vanir {scanner_type} scan on {repo_path} with ecosystem={ecosystem}, package_name={package_name}")
        
        # Validate repository path
        if not os.path.exists(repo_path):
            self.logger.error(f"Repository path does not exist: {repo_path}")
            return {"vulnerabilities": [], "error": f"Repository path does not exist: {repo_path}"}
        
        # Validate Vanir path
        if not self.vanir_path or not os.path.exists(self.vanir_path):
            self.logger.error(f"Invalid Vanir path: {self.vanir_path}")
            return {"vulnerabilities": [], "error": f"Invalid Vanir path: {self.vanir_path}"}
            
        vanir_bin = os.path.join(self.vanir_path, "vanir", "bazel-bin", "detector_runner")
        self.logger.info(f"Looking for Vanir binary at: {vanir_bin}")
        
        if not os.path.exists(vanir_bin):
            # Try alternative paths as fallback
            alt_bin = os.path.join(self.vanir_path, "bazel-bin", "detector_runner")
            if os.path.exists(alt_bin):
                vanir_bin = alt_bin
                self.logger.info(f"Found Vanir binary at alternate location: {vanir_bin}")
            else:
                self.logger.error(f"Vanir binary not found at {vanir_bin} or {alt_bin}")
                return {"vulnerabilities": [], "error": "Vanir binary not found"}
        
        with tempfile.TemporaryDirectory() as temp_dir:
            cmd = [
                vanir_bin,
                "--target_selection_strategy=truncated_path_match",
                f"--report_file_name_prefix={temp_dir}/report",
            ]
            
            # Add scanner-specific parameters
            if scanner_type == "package_scanner":
                if package_name and ecosystem:
                    cmd.extend([scanner_type, ecosystem, package_name, repo_path])
                    self.logger.info(f"Using package_scanner with ecosystem={ecosystem}, package={package_name}")
                else:
                    missing = []
                    if not package_name:
                        missing.append("package_name")
                    if not ecosystem:
                        missing.append("ecosystem")
                    error_msg = f"Missing required parameters for package_scanner: {', '.join(missing)}"
                    self.logger.error(error_msg)
                    return {"vulnerabilities": [], "error": error_msg}
            elif scanner_type == "repo_scanner":
                if ecosystem:
                    cmd.extend([scanner_type, ecosystem, repo_path])
                    self.logger.info(f"Using repo_scanner with ecosystem={ecosystem}")
                else:
                    self.logger.error("Missing required parameter 'ecosystem' for repo_scanner")
                    return {"vulnerabilities": [], "error": "Missing required parameter 'ecosystem' for repo_scanner"}
            elif scanner_type in ["android_kernel_scanner", "offline_directory_scanner"]:
                cmd.extend([scanner_type, repo_path])
                self.logger.info(f"Using {scanner_type}")
            else:
                if ecosystem:
                    self.logger.info(f"Using {scanner_type} with ecosystem={ecosystem}")
                    cmd.extend([scanner_type, ecosystem, repo_path])
                else:
                    self.logger.warning(f"Using default parameters for scanner_type={scanner_type}, ecosystem not specified")
                    cmd.extend([scanner_type, repo_path])
            
            try:
                self.logger.info(f"Executing: {' '.join(cmd)}")
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    cwd=self.vanir_path
                )
                
                # Log all output for debugging
                self.logger.info(f"Vanir stdout: {result.stdout}")
                if result.stderr:
                    self.logger.warning(f"Vanir stderr: {result.stderr}")
                
                if result.returncode != 0:
                    error_msg = f"Vanir scan failed (return code {result.returncode}): {result.stderr}"
                    self.logger.error(error_msg)
                    return {
                        "vulnerabilities": [], 
                        "error": error_msg,
                        "command": " ".join(cmd),
                        "stdout": result.stdout,
                        "stderr": result.stderr
                    }
                
                # Find and load the JSON report
                json_files = glob.glob(f"{temp_dir}/report*.json")
                if json_files:
                    latest_report = max(json_files, key=os.path.getctime)
                    self.logger.info(f"Found report file: {latest_report}")
                    try:
                        with open(latest_report, 'r') as f:
                            result_data = json.load(f)
                            # Add a default vulnerabilities key if it doesn't exist
                            if "vulnerabilities" not in result_data and "missing_patches" in result_data:
                                result_data["vulnerabilities"] = []
                            return result_data
                    except json.JSONDecodeError as e:
                        self.logger.error(f"Failed to parse Vanir JSON output: {e}")
                        with open(latest_report, 'r') as f:
                            raw_content = f.read()
                        return {
                            "vulnerabilities": [],
                            "error": f"Failed to parse Vanir output: {e}",
                            "raw_content": raw_content[:1000]  # Include first 1000 chars of content
                        }
                else:
                    self.logger.warning("No JSON report generated")
                    return {"vulnerabilities": [], "error": "No Vanir report generated"}
            except Exception as e:
                self.logger.error(f"Vanir scan failed: {e}")
                return {"missing_patches": [], "error": str(e)}


class JoernToolRunner:
    """Runs Joern tool and returns results"""
    
    def __init__(self, joern_script_path: str, max_heap: Optional[str] = None, 
                 initial_heap: Optional[str] = None) -> None:
        self.joern_script_path = joern_script_path
        self.max_heap = max_heap
        self.initial_heap = initial_heap
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def check_joern_setup(self) -> Dict[str, Any]:
        """Check if Joern is correctly installed and configured
        
        Returns:
            Dictionary containing status information:
            {
                "installed": bool,  # Whether Joern is installed
                "script_path_valid": bool,  # Whether the script path is valid
                "script_found": bool,  # Whether the specific script is found
                "joern_path": str,  # Path to the joern-scan executable (if found)
                "error": str,  # Error message (if any)
                "details": Dict  # Additional details
            }
        """
        result = {
            "installed": False,
            "script_path_valid": False,
            "script_found": False,
            "joern_path": "",
            "error": "",
            "details": {}
        }
        
        # Check if joern-scan is in PATH
        try:
            joern_check = subprocess.run(
                ["which", "joern-scan"], 
                capture_output=True, 
                text=True,
                check=False
            )
            
            if joern_check.returncode == 0:
                result["installed"] = True
                result["joern_path"] = joern_check.stdout.strip()
            else:
                result["error"] = "joern-scan not found in PATH"
                result["details"]["help"] = "Run 'verify_joern_installation.sh' in the detection_script directory"
                
                # Try to find the verification script
                if self.joern_script_path:
                    verify_script = os.path.join(self.joern_script_path, "verify_joern_installation.sh")
                    if os.path.exists(verify_script):
                        result["details"]["verify_script_path"] = verify_script
        except Exception as e:
            result["error"] = f"Error checking joern-scan: {str(e)}"
        
        # Check if script path exists
        if self.joern_script_path and os.path.exists(self.joern_script_path):
            result["script_path_valid"] = True
            result["details"]["script_path"] = self.joern_script_path
            
            # Check if specific script exists
            script_path = os.path.join(self.joern_script_path, "find_non_called_methods.sh")
            if os.path.exists(script_path):
                result["script_found"] = True
            else:
                if not result["error"]:
                    result["error"] = f"Script not found: {script_path}"
                result["details"]["missing_script"] = "find_non_called_methods.sh"
        else:
            if not result["error"]:
                result["error"] = f"Invalid script path: {self.joern_script_path}"
            
        return result
    
    def check_joern_compatibility(self) -> Dict[str, Any]:
        """Check Joern version compatibility and diagnose common issues
        
        Returns:
            Dict containing compatibility information and troubleshooting tips
        """
        compatibility_info = {
            "version": "unknown",
            "compatible": False,
            "issues": [],
            "recommendations": []
        }
        
        try:
            # Check Joern version from joern-scan --help
            version_check = subprocess.run(
                ["joern-scan", "--help"], 
                capture_output=True, 
                text=True,
                check=False
            )
            
            if version_check.returncode == 0:
                help_output = version_check.stdout
                if "Version:" in help_output:
                    version_line = [line for line in help_output.split('\n') if "Version:" in line][0]
                    version = version_line.split("Version:")[1].strip().strip('`')
                    compatibility_info["version"] = version
                    self.logger.info(f"Detected Joern version: {version}")
                    
                    # Check if version is compatible
                    if version.startswith("4.0."):
                        compatibility_info["compatible"] = True
                        compatibility_info["recommendations"].append("Version 4.0.x is supported")
                    else:
                        compatibility_info["issues"].append(f"Untested version: {version}")
                        compatibility_info["recommendations"].append("Consider upgrading to Joern 4.0.x")
                else:
                    compatibility_info["issues"].append("Could not parse version from help output")
            else:
                compatibility_info["issues"].append("joern-scan command failed")
                compatibility_info["recommendations"].append("Ensure Joern is properly installed and in PATH")
                
        except FileNotFoundError:
            compatibility_info["issues"].append("joern-scan command not found")
            compatibility_info["recommendations"].append("Install Joern and add to PATH")
        except Exception as e:
            compatibility_info["issues"].append(f"Error checking version: {str(e)}")
            compatibility_info["recommendations"].append("Check Joern installation")
            
        return compatibility_info
    
    def run_analysis(self, repo_path: str) -> List[Dict[str, Any]]:
        """Run Joern unused function analysis"""
        self.logger.info(f"Running Joern analysis on {repo_path}")
        
        # Prefer the specialized analysis script for unused function analysis
        joern_script = os.path.join(self.joern_script_path, "find_non_called_methods.sh")
        
        if not os.path.exists(joern_script):
            self.logger.warning(f"Joern analysis script not found at {joern_script}, falling back to direct joern-scan")
        
        try:
            if os.path.exists(joern_script):
                # Use the specialized script for unused function analysis
                project_name = os.path.basename(os.path.abspath(repo_path))
                output_file = "joern_results.json"  # Use a consistent output filename
                cmd = ["bash", joern_script, os.path.abspath(repo_path), project_name, output_file]
                
                # Add memory arguments if configured
                if self.max_heap and self.initial_heap:
                    cmd.extend(["--max-heap", self.max_heap, "--initial-heap", self.initial_heap])
                    self.logger.info(f"Using Joern-specific memory settings: max={self.max_heap}, initial={self.initial_heap}")
                
                self.logger.info(f"Executing specialized analysis script: {' '.join(cmd)}")
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    cwd=self.joern_script_path
                )
            else:
                # Fall back to using joern-scan directly with memory configuration
                self.logger.info("Using direct joern-scan command as fallback for analysis")
                
                # Create workspace directory to avoid CPG generation issues
                workspace_dir = os.path.join(self.joern_script_path, "workspace")
                if not os.path.exists(workspace_dir):
                    os.makedirs(workspace_dir, exist_ok=True)
                
                # Create a project directory inside workspace
                project_name = os.path.basename(os.path.abspath(repo_path))
                project_dir = os.path.join(workspace_dir, project_name)
                if not os.path.exists(project_dir):
                    os.makedirs(project_dir, exist_ok=True)
                    
                # Create project.json file
                project_json_path = os.path.join(project_dir, "project.json")
                if not os.path.exists(project_json_path):
                    with open(project_json_path, 'w') as f:
                        json.dump({
                            "name": project_name,
                            "inputPath": os.path.abspath(repo_path)
                        }, f, indent=2)
                    self.logger.info(f"Created project.json at {project_json_path}")
                
                # Create the tmp directory inside workspace_dir and ensure it exists
                tmp_dir = os.path.join(workspace_dir, "tmp")
                if not os.path.exists(tmp_dir):
                    os.makedirs(tmp_dir, exist_ok=True)
                    
                # Set proper permissions for the tmp directory
                os.chmod(tmp_dir, 0o755)  # rwxr-xr-x
                
                # Also create a project.json in the tmp directory as a fallback
                tmp_project_json = os.path.join(tmp_dir, "project.json")
                if not os.path.exists(tmp_project_json):
                    with open(tmp_project_json, 'w') as f:
                        json.dump({
                            "name": "temp_project",
                            "inputPath": os.path.abspath(repo_path)
                        }, f, indent=2)
                
                # Use joern-scan with Joern-specific JVM flags
                cmd = ["joern-scan"]
                
                # Apply memory settings using Joern's -J format
                if self.max_heap and self.initial_heap:
                    # Use Joern-specific -J format for JVM options
                    cmd.extend([f"-J-Xmx{self.max_heap}", f"-J-Xms{self.initial_heap}"])
                    
                    # Add GC optimization
                    cmd.append("-J-XX:+UseG1GC")
                    
                    # Add optional GC tuning for large codebases
                    if "g" in self.max_heap and int(self.max_heap.replace("g", "")) > 8:
                        cmd.extend(["-J-XX:ParallelGCThreads=4", "-J-XX:ConcGCThreads=2"])
                    
                    # Set Java temporary directory
                    cmd.append(f"-J-Djava.io.tmpdir={tmp_dir}")
                    
                    self.logger.info(f"Using Joern-specific JVM options: max={self.max_heap}, initial={self.initial_heap}")
                
                # Add joern-scan specific flags
                cmd.extend(["--overwrite", os.path.abspath(repo_path)])
                output_file = "joern_results.json"
                
                # Set up environment 
                env = os.environ.copy()
                
                # Create a temporary file to store the output
                with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as temp:
                    temp_file_path = temp.name
                
                # Run joern-scan and capture output
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    env=env
                )
                
                # Write output to file for processing
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
                
                # For direct joern-scan, we need to parse the output format differently
                # This is a stub - actual implementation would depend on output format
                self.logger.warning("Using direct joern-scan output - parsing may need adjustment")
                result.stdout = "{}"  # Default empty JSON
            
            if result.returncode != 0:
                self.logger.error(f"Joern analysis failed: {result.stderr}")
                return []
            
            # Parse JSON output from Joern
            try:
                # For the bash script, read the JSON file directly instead of stdout
                if os.path.exists(joern_script):
                    output_file_path = os.path.join(self.joern_script_path, output_file)
                    if os.path.exists(output_file_path):
                        self.logger.info(f"Reading Joern results from: {output_file_path}")
                        with open(output_file_path, 'r') as f:
                            json_data = json.load(f)
                            return json_data
                    else:
                        self.logger.warning(f"Joern output file not found at: {output_file_path}")
                        return []
                else:
                    # For direct joern-scan, try to parse stdout
                    if result.stdout.strip():
                        return json.loads(result.stdout)
                    else:
                        self.logger.warning("No output from Joern analysis")
                        return []
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to parse Joern JSON output: {e}")
                return []
        except Exception as e:
            self.logger.error(f"Joern analysis failed: {e}")
            return []
    
    def run_joern_with_fallback(self, project_path: str, result_file: str) -> Dict[str, Any]:
        """Run Joern analysis with fallback strategies for compatibility issues
        
        Args:
            project_path: Path to the project to analyze
            result_file: File to store raw Joern scan output
            
        Returns:
            Dict with analysis results or error information
        """
        self.logger.info(f"Running Joern analysis with fallback strategies on {project_path}")
        
        # Check compatibility first
        compatibility = self.check_joern_compatibility()
        if not compatibility["compatible"]:
            self.logger.warning(f"Joern compatibility issues detected: {compatibility['issues']}")
            for recommendation in compatibility["recommendations"]:
                self.logger.info(f"Recommendation: {recommendation}")
        
        # Strategy 1: Try with reduced memory if NoSuchMethodError occurs
        strategies = [
            {"name": "Standard", "max_heap": self.max_heap, "initial_heap": self.initial_heap},
            {"name": "Reduced Memory", "max_heap": "4g", "initial_heap": "2g"},
            {"name": "Minimal Memory", "max_heap": "2g", "initial_heap": "1g"}
        ]
        
        for strategy in strategies:
            self.logger.info(f"Attempting Joern analysis with {strategy['name']} strategy")
            
            try:
                # Create command with current strategy
                cmd = ["joern-scan"]
                
                if strategy["max_heap"] and strategy["initial_heap"]:
                    cmd.extend([f"-J-Xmx{strategy['max_heap']}", f"-J-Xms{strategy['initial_heap']}"])
                    cmd.append("-J-XX:+UseG1GC")
                
                cmd.extend(["--overwrite", project_path])
                
                # Run the command
                self.logger.info(f"Executing: {' '.join(cmd)}")
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True
                )
                
                # Write output to result file
                with open(result_file, 'w') as f:
                    f.write(result.stdout)
                    if result.stderr:
                        f.write(f"\n\n===== STDERR =====\n{result.stderr}")
                
                if result.returncode == 0:
                    self.logger.info(f"Joern analysis succeeded with {strategy['name']} strategy")
                    return {"success": True, "strategy": strategy["name"]}
                else:
                    # Check for specific error patterns
                    if "NoSuchMethodError" in result.stderr:
                        self.logger.warning(f"NoSuchMethodError detected with {strategy['name']} strategy")
                        if strategy == strategies[-1]:  # Last strategy
                            return {
                                "error": "NoSuchMethodError: Joern library compatibility issue",
                                "error_detail": "This is typically caused by version mismatches in Joern's dependencies. Try updating Joern or using a different version.",
                                "stderr": result.stderr,
                                "compatibility_info": compatibility
                            }
                        continue  # Try next strategy
                    elif "OutOfMemoryError" in result.stderr:
                        self.logger.warning(f"OutOfMemoryError with {strategy['name']} strategy")
                        continue  # Try next strategy with less memory
                    else:
                        # Other error
                        return {
                            "error": f"Joern scan failed with {strategy['name']} strategy",
                            "error_detail": result.stderr,
                            "returncode": result.returncode,
                            "compatibility_info": compatibility
                        }
                        
            except Exception as e:
                self.logger.error(f"Unexpected error with {strategy['name']} strategy: {e}")
                continue
        
        # If all strategies failed
        return {
            "error": "All Joern analysis strategies failed",
            "error_detail": "Tried multiple memory configurations and fallback strategies",
            "compatibility_info": compatibility
        }
    


class CorrelationAgent:
    """Main correlation agent - simplified and clean implementation"""
    
    def __init__(self, vanir_path: Optional[str] = None, joern_script_path: Optional[str] = None, 
                 progress_callback: Optional[Callable] = None, 
                 joern_max_heap: Optional[str] = None, joern_initial_heap: Optional[str] = None) -> None:
        # Set up logging
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Initialize progress callback
        self.progress_callback = progress_callback
        
        # Initialize configuration
        self.config: Dict[str, Any] = {}
        
        # Store memory configuration with conservative defaults for stability
        self.joern_max_heap = joern_max_heap or "16g"  # More conservative default (was 32g)
        self.joern_initial_heap = joern_initial_heap or "4g"  # More conservative default (was 8g)
        
        # Initialize paths
        analysis_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.vanir_path = vanir_path or os.path.join(analysis_root, "vanir")
        self.joern_script_path = joern_script_path or os.path.join(analysis_root, "detection_script")

        self.logger.info(f"Initializing CorrelationAgent with vanir_path={self.vanir_path}, joern_script_path={self.joern_script_path}")
        
        # Initialize components
        self.vanir_parser = VanirParser()
        self.joern_parser = JoernParser()
        self.correlation_engine = CorrelationEngine()
        self.report_generator = ReportGenerator()
        
        # Initialize tool runners
        try:
            self.logger.info(f"Initializing VanirToolRunner with path: {self.vanir_path}")
            self.vanir_runner = VanirToolRunner(self.vanir_path)
        except Exception as e:
            self.logger.error(f"Failed to initialize VanirToolRunner: {e}")
            # Create a placeholder that will be initialized later
            self.vanir_runner = None
            
        try:
            self.logger.info(f"Initializing JoernToolRunner with path: {self.joern_script_path}")
            self.joern_runner = JoernToolRunner(self.joern_script_path, self.joern_max_heap, self.joern_initial_heap)
        except Exception as e:
            self.logger.error(f"Failed to initialize JoernToolRunner: {e}")
            # Create a placeholder that will be initialized later
            self.joern_runner = None
    
    def analyze_repository(self, repo_path: str, scanner_type: str,
                          output_file: str = None, format_type: str = "auto",
                          package_name: str = None, ecosystem: str = None,
                          vulnerability_files: List[str] = None) -> Dict[str, Any]:
        """Complete repository analysis workflow"""
        self.logger.info(f"Starting repository analysis: {repo_path}")
        
        # Log additional parameters for debugging
        self.logger.info(f"Analysis parameters: format_type={format_type}, scanner_type={scanner_type}, "
                        f"package_name={package_name}, ecosystem={ecosystem}")
        
        # Handle vulnerability files if provided
        if vulnerability_files:
            self.logger.info(f"Using provided vulnerability files: {vulnerability_files}")
            # Load vulnerability data from provided files
            vanir_data = {"vulnerabilities": []}
            for vuln_file in vulnerability_files:
                if os.path.exists(vuln_file):
                    with open(vuln_file, 'r') as f:
                        file_data = json.load(f)
                        if "vulnerabilities" in file_data:
                            vanir_data["vulnerabilities"].extend(file_data["vulnerabilities"])
        else:
            # Run Vanir scan
            self._update_progress("vanir", "Running Vanir vulnerability scan...", 0.2)
            self.logger.info(f"Running Vanir vulnerability scan with scanner_type={scanner_type}, package_name={package_name}, ecosystem={ecosystem}")
            vanir_data = self.vanir_runner.run_scan(
                repo_path=repo_path,
                scanner_type=scanner_type,
                package_name=package_name,
                ecosystem=ecosystem
            )
            
            if "error" in vanir_data:
                self.logger.error(f"Vanir scan failed: {vanir_data['error']}")
                return {"error": f"Vanir scan failed: {vanir_data['error']}"}
        
        # Run Joern analysis
        self._update_progress("joern", "Running Joern unused function analysis...", 0.5)
        self.logger.info("Running Joern unused function analysis...")
        joern_data = self.joern_runner.run_analysis(repo_path)
        
        # Parse results
        self._update_progress("parsing", "Parsing analysis results...", 0.7)
        vulnerabilities = self.vanir_parser.parse(vanir_data)
        unused_functions = self.joern_parser.parse(joern_data)
        
        self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities and {len(unused_functions)} unused functions")
        
        # Correlate vulnerabilities with code usage
        self._update_progress("correlation", "Correlating vulnerabilities with code usage...", 0.8)
        self.logger.info("Correlating vulnerabilities with code usage...")
        correlations = self.correlation_engine.correlate(vulnerabilities, unused_functions)
        
        # Generate report
        self._update_progress("report", "Generating correlation report...", 0.9)
        report = self.report_generator.generate_analysis_report(correlations)
        
        # Add analysis metadata
        report.update({
            "analysis_metadata": {
                "format_type": format_type,
                "scanner_type": scanner_type,
                "package_name": package_name,
                "ecosystem": ecosystem,
                "repository_path": repo_path
            }
        })
        
        # Save report if output file specified
        if output_file:
            self.report_generator.save_report(report, output_file)
        
        self._update_progress("complete", "Analysis completed successfully", 1.0)
        self.logger.info("Analysis completed successfully")
        return report
        
    def correlate_from_files(self, vanir_file: str, joern_file: str, output_file: str = None) -> Dict[str, Any]:
        """Correlate from existing Vanir and Joern output files"""
        self.logger.info(f"Correlating from files: {vanir_file}, {joern_file}")
        
        try:
            # Load data from files
            self._update_progress("loading", "Loading analysis files...", 0.1)
            with open(vanir_file, 'r') as f:
                vanir_data = json.load(f)
            
            with open(joern_file, 'r') as f:
                joern_data = json.load(f)
            
            # Parse results
            self._update_progress("parsing", "Parsing results...", 0.3)
            vulnerabilities = self.vanir_parser.parse(vanir_data)
            unused_functions = self.joern_parser.parse(joern_data)
            
            # Correlate
            self._update_progress("correlation", "Correlating vulnerabilities...", 0.6)
            correlations = self.correlation_engine.correlate(vulnerabilities, unused_functions)
            
            # Generate report
            self._update_progress("report", "Generating report...", 0.8)
            report = self.report_generator.generate_analysis_report(correlations)
            
            # Save if requested
            if output_file:
                self._update_progress("saving", "Saving report...", 0.9)
                self.report_generator.save_report(report, output_file)
            
            self._update_progress("complete", "Correlation completed", 1.0)
            return report
        
        except Exception as e:
            self.logger.error(f"Correlation failed: {e}")
            return {"error": str(e)}
    
    def _update_progress(self, stage: str, message: str, progress: float):
        """Send progress update if callback is available"""
        if self.progress_callback:
            try:
                self.progress_callback(stage, message, progress)
            except Exception as e:
                self.logger.warning(f"Progress callback failed: {e}")
    
    def update_joern_memory_config(self, max_heap: str = None, initial_heap: str = None):
        """Update Joern memory configuration after initialization"""
        if max_heap:
            self.joern_max_heap = max_heap
            self.joern_runner.max_heap = max_heap
            self.logger.info(f"Updated Joern max heap to: {max_heap}")
        
        if initial_heap:
            self.joern_initial_heap = initial_heap  
            self.joern_runner.initial_heap = initial_heap
            self.logger.info(f"Updated Joern initial heap to: {initial_heap}")
    
    def run_vanir_only_analysis(self, repo_path: str, scanner_type: str,
                              package_name: str = None, ecosystem: str = None,
                              vulnerability_files: List[str] = None) -> Dict[str, Any]:
        """Vanir-only analysis workflow without correlating with Joern"""
        self.logger.info(f"Starting Vanir-only analysis: {repo_path}")
        
        # Log additional parameters for debugging
        self.logger.info(f"Analysis parameters: scanner_type={scanner_type}, "
                        f"package_name={package_name}, ecosystem={ecosystem}")
        
        # Ensure Vanir runner is initialized
        if not hasattr(self, 'vanir_runner') or self.vanir_runner is None:
            self.logger.warning("Vanir runner not initialized. Creating a new instance.")
            analysis_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.vanir_path = self.vanir_path or os.path.join(analysis_root, "vanir")
            self.vanir_runner = VanirToolRunner(self.vanir_path)
        
        # Check if Vanir is properly built
        build_status = self.vanir_runner.check_vanir_built()
        if not build_status["built"]:
            error_msg = f"Vanir is not properly built: {build_status['error']}"
            self.logger.error(error_msg)
            return {"error": error_msg, "error_detail": "Vanir not built", "build_status": build_status}
        
        # Handle vulnerability files if provided
        if vulnerability_files:
            self.logger.info(f"Using provided vulnerability files: {vulnerability_files}")
            # Load vulnerability data from provided files
            vanir_data = {"vulnerabilities": []}
            for vuln_file in vulnerability_files:
                if os.path.exists(vuln_file):
                    with open(vuln_file, 'r') as f:
                        file_data = json.load(f)
                        if "vulnerabilities" in file_data:
                            vanir_data["vulnerabilities"].extend(file_data["vulnerabilities"])
        else:
            # Run Vanir scan
            self._update_progress("vanir", "Running Vanir vulnerability scan...", 0.3)
            self.logger.info(f"Running Vanir scan with scanner_type: {scanner_type}")
            
            try:
                # Pass all relevant parameters to run_scan
                vanir_data = self.vanir_runner.run_scan(
                    repo_path=repo_path,
                    scanner_type=scanner_type,
                    package_name=package_name,
                    ecosystem=ecosystem
                )
                
                if "error" in vanir_data:
                    self.logger.error(f"Vanir scan failed: {vanir_data['error']}")
                    return {"error": f"Vanir scan failed: {vanir_data['error']}"}
            except Exception as e:
                error_msg = f"Vanir scan failed: {str(e)}"
                self.logger.error(error_msg)
                return {"error": error_msg, "error_detail": "Vanir interface initialization error"}
        
        # Parse results
        self._update_progress("parsing", "Parsing Vanir results...", 0.7)
        vulnerabilities = self.vanir_parser.parse(vanir_data)
        
        self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities")
        
        # Since this is Vanir-only mode, we'll create simple correlations without Joern data
        self._update_progress("processing", "Processing vulnerabilities...", 0.8)
        vanir_only_correlations = []
        
        for vuln in vulnerabilities:
            # In Vanir-only mode, all vulnerabilities are considered "reachable" (not unused)
            correlation = VulnerabilityCorrelation(
                vulnerability=vuln,
                risk_level="HIGH" if vuln.severity in ["CRITICAL", "HIGH"] else "MEDIUM",
                risk_explanation=f"Vulnerability severity: {vuln.severity}",
                is_function_unused=False,  # We don't have Joern data, so assume all functions are used
                is_reachable=True
            )
            vanir_only_correlations.append(correlation)
        
        # Generate report
        self._update_progress("report", "Generating vulnerability report...", 0.9)
        report = self.report_generator.generate_analysis_report(vanir_only_correlations)
        
        # Add analysis metadata
        report.update({
            "analysis_metadata": {
                "analysis_type": "vanir_only",
                "scanner_type": scanner_type,
                "package_name": package_name,
                "ecosystem": ecosystem,
                "repository_path": repo_path
            },
            "raw_vanir_data": vanir_data  # Include raw data for downstream processing
        })
        
        self._update_progress("complete", "Analysis completed successfully", 1.0)
        self.logger.info("Vanir-only analysis completed successfully")
        return report
    
    def run_joern_only_analysis(self, project_path: str, result_file: str = "joern_results.txt", output_file: str = "vulns_parsed.json") -> Dict[str, Any]:
        """Joern-only analysis workflow for vulnerability detection without correlating with Vanir
        
        Args:
            project_path: Path to the project to analyze
            result_file: File to store raw Joern scan output
            output_file: File to store parsed vulnerabilities in JSON format
            
        Returns:
            Dict with analysis results and metadata
        """
        self.logger.info(f"Starting Joern-only analysis: {project_path}")
        
        # Validate project path
        if not os.path.exists(project_path):
            error_msg = f"Project path does not exist: {project_path}"
            self.logger.error(error_msg)
            return {"error": error_msg}
            
        # Run joern-scan directly with memory configuration through -J-Xmx format
        self._update_progress("joern-scan", "Running Joern vulnerability scan...", 0.1)
        
        try:
            # Make paths absolute
            if not os.path.isabs(result_file):
                result_file = os.path.abspath(result_file)
                
            if not os.path.isabs(output_file):
                output_file = os.path.abspath(output_file)
            
            # Create a workspace directory to avoid CPG generation issues
            workspace_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "workspace")
            if not os.path.exists(workspace_dir):
                os.makedirs(workspace_dir, exist_ok=True)
            
            # Create a project directory inside workspace
            project_name = os.path.basename(os.path.abspath(project_path))
            project_dir = os.path.join(workspace_dir, project_name)
            if not os.path.exists(project_dir):
                os.makedirs(project_dir, exist_ok=True)
                self.logger.info(f"Created project directory at {project_dir}")
            else:
                self.logger.info(f"Using existing project directory: {project_dir}")
                
            # Create project.json file
            project_json_path = os.path.join(project_dir, "project.json")
            if not os.path.exists(project_json_path):
                project_config = {
                    "name": project_name,
                    "inputPath": os.path.abspath(project_path)
                }
                with open(project_json_path, 'w') as f:
                    json.dump(project_config, f, indent=2)
                self.logger.info(f"Created project.json at {project_json_path}")
                self.logger.info(f"Project config: {project_config}")
            else:
                self.logger.info(f"Using existing project.json at {project_json_path}")
                
            # Create the tmp directory inside workspace_dir and ensure it exists
            tmp_dir = os.path.join(workspace_dir, "tmp")
            if not os.path.exists(tmp_dir):
                os.makedirs(tmp_dir, exist_ok=True)
                self.logger.info(f"Created tmp directory at {tmp_dir}")
            else:
                self.logger.info(f"Using existing tmp directory: {tmp_dir}")
                
            # Set proper permissions for the tmp directory
            os.chmod(tmp_dir, 0o755)  # rwxr-xr-x
            
            # Create a project.json in the tmp directory as a fallback
            tmp_project_json = os.path.join(tmp_dir, "project.json")
            if not os.path.exists(tmp_project_json):
                with open(tmp_project_json, 'w') as f:
                    json.dump({
                        "name": "temp_project",
                        "inputPath": os.path.abspath(project_path)
                    }, f, indent=2)
                self.logger.info(f"Created tmp project.json at {tmp_project_json}")
            else:
                self.logger.info(f"Using existing tmp project.json at {tmp_project_json}")
            
            # Use direct joern-scan command with Joern-specific JVM options
            self.logger.info(f"Running joern-scan: joern-scan --overwrite {project_path}")
            self._update_progress("joern-scan", "Running Joern vulnerability scan...", 0.3)
            
            # Use the enhanced fallback strategy for running Joern
            scan_result = self.joern_runner.run_joern_with_fallback(project_path, result_file)
            
            # Check if scan failed
            if "error" in scan_result:
                self.logger.error(f"Joern scan failed: {scan_result['error']}")
                return scan_result  # Return the detailed error information
            
            # Process the results using the parsing code
            self._update_progress("parsing", "Parsing Joern scan results...", 0.7)
            num_vulns, skipped = self._extract_vulnerabilities(result_file, output_file)
            
            self.logger.info(f"Extracted {num_vulns} vulnerabilities, skipped {skipped} lines")
            
            # Load and prepare the parsed results
            vulnerabilities = []
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    try:
                        parsed_results = json.load(f)
                        
                        # Convert the parsed results to our vulnerability format for the report
                        for vuln in parsed_results:
                            severity = "HIGH" if float(vuln.get("score", 0)) > 8.0 else "MEDIUM" if float(vuln.get("score", 0)) > 5.0 else "LOW"
                            
                            vulnerability = Vulnerability(
                                id=f"JOERN-{len(vulnerabilities) + 1}",
                                cve_ids=[],  # Joern doesn't provide CVE IDs
                                severity=severity,
                                file_path=vuln.get("file", ""),
                                function_name=vuln.get("function", ""),
                                description=vuln.get("description", "")
                            )
                            vulnerabilities.append(vulnerability)
                            
                    except json.JSONDecodeError as e:
                        self.logger.error(f"Failed to parse Joern results: {e}")
                        return {"error": f"Failed to parse Joern results: {e}"}
            
            # Generate report
            self._update_progress("report", "Generating vulnerability report...", 0.9)
            
            # Create simple correlations (without usage data since this is Joern-only mode)
            joern_correlations = []
            for vuln in vulnerabilities:
                correlation = VulnerabilityCorrelation(
                    vulnerability=vuln,
                    risk_level=vuln.severity,
                    risk_explanation=f"Vulnerability detected by Joern with severity: {vuln.severity}",
                    is_function_unused=False,  # We don't have unused function data in this mode
                    is_reachable=True  # Assume all functions are reachable in this mode
                )
                joern_correlations.append(correlation)
            
            # Generate full report
            report = self.report_generator.generate_analysis_report(joern_correlations)
            
            # Add metadata
            report.update({
                "analysis_metadata": {
                    "analysis_type": "joern_only",
                    "project_path": project_path,
                    "result_file": result_file,
                    "output_file": output_file,
                    "timestamp": datetime.now().isoformat()
                },
                "raw_results": {
                    "result_file": result_file,
                    "parsed_file": output_file,
                    "vulnerability_count": num_vulns
                }
            })
            
            self._update_progress("complete", "Analysis completed successfully", 1.0)
            self.logger.info(f"Joern-only analysis completed successfully: {num_vulns} vulnerabilities found")
            
            return report
            
        except Exception as e:
            error_msg = f"Joern analysis failed: {str(e)}"
            self.logger.error(error_msg)
            return {"error": error_msg}
    
    def _extract_vulnerabilities(self, input_file: str, output_file: str) -> tuple:
        """Extract vulnerabilities from Joern scan output
        
        Args:
            input_file: Path to the raw Joern scan output
            output_file: Path to save parsed vulnerabilities as JSON
            
        Returns:
            Tuple of (number of vulnerabilities extracted, number of lines skipped)
        """
        # Pattern to extract vulnerability info from Joern output
        
        # This regex tolerates special characters and optional <duplicate> tags
        pattern = re.compile(
            r'^Result:\s+([\d.]+)\s*:\s*(.*?)\s*:\s*([^\s:]+(?:/[^\s:]+)+):(\d+):([^\s<]+)'
        )
        
        results = []
        skipped = 0
        error_messages = []
        found_results = False
        
        try:
            with open(input_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Check for error messages that might be helpful
                    if "Error" in line or "Exception" in line or "Failed" in line:
                        error_messages.append(line)
                    
                    match = pattern.match(line)
                    if match:
                        found_results = True
                        score, description, filepath, lineno, func = match.groups()
                        func = func.split('<')[0]  # remove <duplicate> if present
                        
                        # Better error handling for malformed lines
                        try:
                            result_item = {
                                "score": float(score),
                                "description": description.strip(),
                                "file": filepath.strip(),
                                "line": int(lineno),
                                "function": func.strip()
                            }
                            results.append(result_item)
                        except (ValueError, TypeError) as e:
                            self.logger.warning(f"Error parsing vulnerability line: {line}, error: {e}")
                            skipped += 1
                    else:
                        skipped += 1
        except Exception as e:
            self.logger.error(f"Error reading joern output file: {e}")
            # Try to continue even with errors
        
        # Save to JSON
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error writing parsed vulnerabilities to {output_file}: {e}")
            
        # Log key error messages if no results found
        if not found_results and error_messages:
            self.logger.warning("No vulnerabilities found, but errors were detected:")
            for msg in error_messages[:5]:  # Log first 5 error messages
                self.logger.warning(f"- {msg}")
                
        return len(results), skipped


def main() -> int:
    """Command-line interface
    
    Returns:
        Exit code (0 for success, 1 for error)
    """
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Clean Vulnerability Correlation Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze repository with integrated tools
  python correlation_agent.py analyze /path/to/repo --output results.json
  
  # Correlate from existing output files
  python correlation_agent.py correlate vanir_output.json joern_output.json --output correlation.json
  
  # Run Joern-only analysis
  python correlation_agent.py joern-only /path/to/repo --output vulns.json --result-file joern_results.txt
  
  # Run Joern-only analysis with memory configuration
  python correlation_agent.py joern-only /path/to/repo --max-heap 16g --initial-heap 4g
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a repository')
    analyze_parser.add_argument('repository', help='Path to repository to analyze')
    analyze_parser.add_argument('--output', '-o', help='Output file path')
    analyze_parser.add_argument('--vanir-path', help='Path to Vanir installation')
    analyze_parser.add_argument('--joern-path', help='Path to Joern script directory')
    
    # Correlate command
    correlate_parser = subparsers.add_parser('correlate', help='Correlate existing outputs')
    correlate_parser.add_argument('vanir_file', help='Vanir output JSON file')
    correlate_parser.add_argument('joern_file', help='Joern output JSON file')
    correlate_parser.add_argument('--output', '-o', help='Output file path')
    
    # Joern-only command
    joern_parser = subparsers.add_parser('joern-only', help='Run Joern-only analysis')
    joern_parser.add_argument('repository', help='Path to repository to analyze')
    joern_parser.add_argument('--output', '-o', help='Output file path')
    joern_parser.add_argument('--result-file', help='File to store raw Joern scan output', default="joern_results.txt")
    joern_parser.add_argument('--joern-path', help='Path to Joern script directory')
    joern_parser.add_argument('--max-heap', help='Maximum heap size for JVM (e.g., 16g)')
    joern_parser.add_argument('--initial-heap', help='Initial heap size for JVM (e.g., 4g)')
    
    # Global options
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set up logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        # Initialize agent with appropriate options based on command
        joern_max_heap = getattr(args, 'max_heap', None) if hasattr(args, 'max_heap') else None
        joern_initial_heap = getattr(args, 'initial_heap', None) if hasattr(args, 'initial_heap') else None
        
        agent = CorrelationAgent(
            vanir_path=getattr(args, 'vanir_path', None),
            joern_script_path=getattr(args, 'joern_path', None),
            joern_max_heap=joern_max_heap,
            joern_initial_heap=joern_initial_heap
        )
        
        if args.command == 'analyze':
            # Generate default output filename if not provided
            output_file = args.output or f"analysis_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            results = agent.analyze_repository(args.repository, output_file)
            
            if "error" in results:
                print(f"❌ Analysis failed: {results['error']}")
                return 1
            
            # Print summary
            summary = results["analysis_summary"]
            print(f"\n✅ Analysis completed!")
            print(f"   Results saved to: {output_file}")
            print(f"   Total vulnerabilities: {summary['total_vulnerabilities']}")
            print(f"   High risk: {summary['high_risk_count']}")
            print(f"   Medium risk: {summary['medium_risk_count']}")
            print(f"   Low risk: {summary['low_risk_count']}")
            print(f"   Workload reduction potential: {summary['prioritization_effectiveness']:.1f}%")
            
        elif args.command == 'joern-only':
            # Generate default output filename if not provided
            output_file = args.output or f"joern_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            result_file = args.result_file
            
            print(f"Running Joern-only analysis on {args.repository}...")
            print(f"Raw results will be saved to: {result_file}")
            print(f"Parsed vulnerabilities will be saved to: {output_file}")
            
            # Run Joern-only analysis
            results = agent.run_joern_only_analysis(
                project_path=args.repository,
                result_file=result_file,
                output_file=output_file
            )
            
            if "error" in results:
                print(f"❌ Joern analysis failed: {results['error']}")
                if "error_detail" in results:
                    print(f"   Details: {results['error_detail']}")
                return 1
                
            # Print summary
            if "analysis_summary" in results:
                summary = results["analysis_summary"]
                print(f"\n✅ Joern analysis completed!")
                print(f"   Results saved to: {output_file}")
                print(f"   Total vulnerabilities: {summary['total_vulnerabilities']}")
                print(f"   High risk: {summary.get('high_risk_count', 0)}")
                print(f"   Medium risk: {summary.get('medium_risk_count', 0)}")
                print(f"   Low risk: {summary.get('low_risk_count', 0)}")
            else:
                print(f"\n✅ Joern analysis completed, but no vulnerabilities were found.")
            
            # Show vulnerability count
            vuln_count = results.get("raw_results", {}).get("vulnerability_count", 0)
            print(f"   Detected {vuln_count} potential vulnerabilities")
            
        elif args.command == 'correlate':
            # Generate default output filename if not provided
            output_file = args.output or f"correlation_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            results = agent.correlate_from_files(args.vanir_file, args.joern_file, output_file)
            
            if "error" in results:
                print(f"❌ Correlation failed: {results['error']}")
                return 1
            
            # Print summary
            summary = results["analysis_summary"]
            print(f"\n✅ Correlation completed!")
            print(f"   Results saved to: {output_file}")
            print(f"   Total vulnerabilities: {summary['total_vulnerabilities']}")
            print(f"   High risk: {summary['high_risk_count']}")
            print(f"   Low risk: {summary['low_risk_count']}")
            print(f"   Workload reduction: {summary['prioritization_effectiveness']:.1f}%")
        
        return 0
        
    except Exception as e:
        print(f"❌ Operation failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
