import json
import subprocess
from datetime import datetime
import os
import logging
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path
import signal
import time

# Handle imports for both package and direct execution
try:
    from . import converter
except ImportError:
    # When imported from outside the package, try absolute import
    import sys
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
    import converter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()  # Only output to console/terminal
    ]
)
logger = logging.getLogger(__name__)

class SBOMAnalyzer:
    def __init__(self, sbom_file, progress_callback=None):
        self.sbom_file = sbom_file
        self.packages = []
        self.vulnerabilities = []
        self.total_packages = 0
        self.progress_callback = progress_callback
        self._severity_values = {
            'Critical': 4,
            'High': 3,
            'Medium': 2,
            'Low': 1,
            'Unknown': 0
        }
        
    def update_progress(self, progress_value, status_message):
        """Update progress with percentage and status message"""
        if self.progress_callback:
            self.progress_callback(progress_value, status_message)

    @lru_cache(maxsize=128)
    def _severity_value(self, severity):
        return self._severity_values.get(severity, 0)

    def load_sbom(self):
        """Load and parse the SBOM file (JSON or SPDX)"""
        try:
            logger.info(f"Attempting to load SBOM file: {self.sbom_file}")
            self.update_progress(0.15, "15% - Validating SBOM file format...")
            
            if not os.path.exists(self.sbom_file):
                logger.error(f"File not found: {self.sbom_file}")
                return False

            # If file is SPDX format, convert it to JSON first
            if self.sbom_file.lower().endswith('.spdx'):
                try:
                    self.update_progress(0.18, "18% - Converting SPDX to JSON format...")
                    logger.info("Converting SPDX file to JSON format...")
                    json_path = converter.convert_spdx_to_json(self.sbom_file)
                    self.sbom_file = json_path  # Update file path to converted JSON
                except Exception as e:
                    logger.error(f"Error converting SPDX to JSON: {str(e)}")
                    return False
            
            # Check for different SBOM formats and normalize them if needed
            if self.sbom_file.lower().endswith('.json'):
                try:
                    with open(self.sbom_file, 'r') as f:
                        test_data = json.load(f)
                        # Check for alternative SBOM formats
                        if 'packages' not in test_data:
                            logger.info("Standard 'packages' not found, checking for alternative formats")
                            
                            # Check for CycloneDX format
                            if 'components' in test_data:
                                logger.info("CycloneDX format detected, adapting...")
                                test_data['packages'] = test_data['components']
                                
                                # Write modified data back to the file
                                with open(self.sbom_file, 'w') as f_out:
                                    json.dump(test_data, f_out)
                            
                            # Check for other formats and map them as needed
                            elif 'bomFormat' in test_data and 'dependencies' in test_data:
                                logger.info("Alternative BOM format detected")
                                # Try to extract package-like information
                                packages = []
                                for dep in test_data.get('dependencies', []):
                                    if isinstance(dep, dict):
                                        packages.append({
                                            'name': dep.get('name', 'Unknown'),
                                            'versionInfo': dep.get('version', 'Unknown'),
                                            'SPDXID': f"SPDXRef-{len(packages)}",
                                            'downloadLocation': 'NONE'
                                        })
                                
                                if packages:
                                    logger.info(f"Extracted {len(packages)} packages from alternative format")
                                    test_data['packages'] = packages
                                    
                                    # Write modified data back to the file
                                    with open(self.sbom_file, 'w') as f_out:
                                        json.dump(test_data, f_out)
                except Exception as e:
                    logger.warning(f"Pre-processing of SBOM file format failed: {str(e)}")
                    # Continue with original file

            # Load and parse the JSON file
            self.update_progress(0.22, "22% - Parsing SBOM JSON data...")
            with open(self.sbom_file, 'r') as f:
                data = json.load(f)
                logger.info(f"JSON structure keys: {list(data.keys())}")
                
                if 'packages' in data:
                    self.packages = data['packages']
                    self.total_packages = len(self.packages)
                    logger.info(f"Loaded {self.total_packages} packages from SBOM")
                    logger.info(f"Sample package: {self.packages[0] if self.packages else 'No packages'}")
                    self.update_progress(0.25, f"25% - Successfully loaded {self.total_packages} packages from SBOM")
                    return True
                else:
                    logger.warning(f"No 'packages' key found in SBOM file. Available keys: {list(data.keys())}")
                    return False
        except Exception as e:
            logger.error(f"Error loading SBOM file: {str(e)}")
            logger.exception("Detailed exception information:")
            return False

    def run_grype_analysis(self):
        """Run Grype vulnerability scanner on the SBOM file using Docker"""
        try:
            logger.info(f"Running Grype analysis on: {self.sbom_file}")
            self.update_progress(0.45, "45% - Preparing Grype vulnerability scanner...")
            
            # Get absolute path and directory of the SBOM file
            sbom_path = os.path.abspath(self.sbom_file)
            sbom_dir = os.path.dirname(sbom_path)
            sbom_filename = os.path.basename(sbom_path)
            
            # Run Grype using Docker with proper volume mounting
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{sbom_dir}:/scan",
                "anchore/grype:latest",
                f"sbom:/scan/{sbom_filename}",
                "-o", "json"
            ]
            
            logger.info(f"🐍 Running Grype vulnerability scan: {' '.join(cmd)}")
            self.update_progress(0.5, "50% - Starting Grype vulnerability scanner with Docker...")
            
            # Run Docker with real-time output and proper logging
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                     text=True, universal_newlines=True)
            
            # Capture output for processing while showing progress
            stdout_lines = []
            stderr_lines = []
            start_time = time.time()
            scan_progress = 0.5
            last_progress_update = start_time
            
            # Read stdout and stderr in real-time
            while True:
                # Check elapsed time for progress updates
                elapsed_time = time.time() - start_time
                
                # Update progress periodically during long-running scan
                if time.time() - last_progress_update > 5:  # Update every 5 seconds
                    # Calculate progress based on elapsed time (max 70% during scanning phase)
                    # This provides visual feedback even if Grype doesn't report progress
                    scan_progress = min(0.5 + (elapsed_time / 1800) * 0.2, 0.7)  # Use 30 minutes as reference for progress
                    self.update_progress(scan_progress, f"{int(scan_progress*100)}% - Running vulnerability scan...")
                    last_progress_update = time.time()
                
                stdout_line = process.stdout.readline()
                stderr_line = process.stderr.readline()
                
                if stdout_line:
                    stdout_lines.append(stdout_line.strip())
                if stderr_line:
                    stderr_lines.append(stderr_line.strip())
                    logger.warning(f"Grype: {stderr_line.strip()}")
                
                if process.poll() is not None:
                    break
                
                # Small delay to prevent excessive CPU usage
                time.sleep(0.1)
            
            # Get any remaining output
            remaining_stdout, remaining_stderr = process.communicate()
            if remaining_stdout:
                stdout_lines.extend(remaining_stdout.strip().split('\n'))
            if remaining_stderr:
                stderr_lines.extend(remaining_stderr.strip().split('\n'))
                for line in remaining_stderr.strip().split('\n'):
                    if line:
                        logger.warning(f"Grype: {line}")
            
            logger.info("✅ Grype vulnerability scan completed")
            self.update_progress(0.75, "75% - Grype vulnerability scan completed, processing results...")
            
            if process.returncode != 0:
                logger.error(f"Grype Docker error (exit code {process.returncode})")
                for line in stderr_lines:
                    if line:
                        logger.error(f"Grype stderr: {line}")
                return False
            
            # Process Grype output directly without storing full results
            full_stdout = '\n'.join(stdout_lines)
            if full_stdout.strip():
                self.update_progress(0.78, "78% - Parsing Grype vulnerability data...")
                grype_results = json.loads(full_stdout)
                self.vulnerabilities = grype_results.get('matches', [])
                vuln_count = len(self.vulnerabilities)
                logger.info(f"Found {vuln_count} vulnerabilities")
                self.update_progress(0.8, f"80% - Found {vuln_count} vulnerabilities in {self.total_packages} packages")
            else:
                logger.warning("No output received from Grype")
                self.vulnerabilities = []
                self.update_progress(0.8, "80% - No vulnerabilities found (empty Grype output)")
            return True
            
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing Grype JSON output: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Error running Grype analysis: {str(e)}")
            return False

    def _process_vulnerability(self, vuln):
        """Process a single vulnerability (for parallel processing)"""
        vulnerability = vuln.get('vulnerability', {})
        artifact = vuln.get('artifact', {})
        vuln_id = vulnerability.get('id', 'Unknown')
        
        # Process CVSS scores if available
        cvss_list = vulnerability.get('cvss', [])
        primary_cvss = None
        max_cvss = 0
        
        if cvss_list:
            # Find highest CVSS score and its data in one pass
            primary_cvss = max(cvss_list, key=lambda x: float(x.get('metrics', {}).get('baseScore', 0)), default=None)
            max_cvss = float(primary_cvss.get('metrics', {}).get('baseScore', 0)) if primary_cvss else 0

        return {
            'id': vuln_id,
            'severity': vulnerability.get('severity', 'Unknown'),
            'package': artifact.get('name', 'Unknown'),
            'version': artifact.get('version', 'Unknown'),
            'description': vulnerability.get('description', ''),
            'fix_versions': vulnerability.get('fix', {}).get('versions', []),
            'cvss': [{
                'version': primary_cvss.get('version', 'Unknown') if primary_cvss else 'Unknown',
                'vector': primary_cvss.get('vector', '') if primary_cvss else '',
                'metrics': {
                    'baseScore': max_cvss,
                    'exploitabilityScore': primary_cvss.get('metrics', {}).get('exploitabilityScore', 0) if primary_cvss else 0,
                    'impactScore': primary_cvss.get('metrics', {}).get('impactScore', 0) if primary_cvss else 0
                } if primary_cvss and primary_cvss.get('metrics') else {}
            }] if primary_cvss else [],
            'cvss_score': max_cvss
        }

    def analyze_vulnerabilities(self):
        """Analyze vulnerabilities found by Grype using parallel processing"""
        if not self.run_grype_analysis():
            return False

        self.update_progress(0.82, "82% - Processing and analyzing vulnerability data...")
        
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Unknown': 0
        }

        # Process vulnerabilities in parallel
        processed_vulns = []
        seen_vulns = set()

        # Track progress for vulnerability processing
        total_vulns = len(self.vulnerabilities)
        progress_step = 0.15 / (total_vulns if total_vulns > 0 else 1)
        current_progress = 0.82
        vulns_processed = 0
        
        with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            # Process vulnerabilities in parallel batches
            future_to_vuln = {executor.submit(self._process_vulnerability, vuln): vuln 
                            for vuln in self.vulnerabilities}
            
            for future in future_to_vuln:
                try:
                    result = future.result()
                    if result and result['id'] not in seen_vulns:
                        seen_vulns.add(result['id'])
                        processed_vulns.append(result)
                        severity_counts[result['severity']] = severity_counts.get(result['severity'], 0) + 1
                        
                        # Update progress periodically (every ~5% of vulnerabilities or at least once)
                        vulns_processed += 1
                        if vulns_processed % max(1, total_vulns // 20) == 0:
                            current_progress = min(0.82 + (vulns_processed / total_vulns) * 0.15, 0.97)
                            progress_pct = int(current_progress * 100)
                            self.update_progress(current_progress, f"{progress_pct}% - Analyzing vulnerability {vulns_processed}/{total_vulns}...")
                            
                except Exception as e:
                    logger.error(f"Error processing vulnerability: {str(e)}")

        # Sort vulnerabilities (sorting is fast since we're only sorting processed results)
        self.update_progress(0.97, "97% - Sorting and prioritizing vulnerabilities...")
        processed_vulns.sort(key=lambda x: (-x.get('cvss_score', 0), -self._severity_value(x.get('severity', 'Unknown'))))

        return {
            'severity_summary': severity_counts,
            'vulnerabilities': processed_vulns
        }

    def generate_report(self):
        """Generate vulnerability analysis report"""
        self.update_progress(0.1, "10% - Starting SBOM analysis...")
        
        if not self.load_sbom():
            return False

        self.update_progress(0.4, "40% - SBOM loaded successfully, preparing for vulnerability analysis...")
        
        analysis_results = self.analyze_vulnerabilities()
        if not analysis_results:
            return False

        self.update_progress(0.98, "98% - Generating final vulnerability report...")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'sbom_file': self.sbom_file,
            'total_packages': self.total_packages,
            'summary': analysis_results['severity_summary'],
            'vulnerabilities': analysis_results['vulnerabilities']
        }
        
        # Write report to file with logging
        try:
            with open('vulnerability_report.json', 'w') as f:
                json.dump(report, f, indent=4)
            logger.info("📄 Vulnerability report saved to vulnerability_report.json")
            self.update_progress(1.0, "100% - Vulnerability analysis completed successfully!")
        except Exception as e:
            logger.error(f"Error writing report to file: {str(e)}")
        
        return report

def main():
    """Main function to run SBOM analysis"""
    sbom_file = 'sbom.json'
    logger.info(f"🚀 Starting SBOM analysis for: {sbom_file}")
    
    analyzer = SBOMAnalyzer(sbom_file)
    report = analyzer.generate_report()
    
    if report:
        logger.info("✅ SBOM analysis completed successfully")
        logger.info(f"📊 Found {sum(report['summary'].values())} total vulnerabilities")
        for severity, count in report['summary'].items():
            if count > 0:
                logger.info(f"   - {severity}: {count}")
    else:
        logger.error("❌ SBOM analysis failed")
        return False
    
    return True

if __name__ == "__main__":
    main()