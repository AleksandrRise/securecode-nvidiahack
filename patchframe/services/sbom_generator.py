"""
SBOM generator service for PatchFrame - generates Software Bill of Materials.
"""

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
import uuid

from ..api.models import SBOMResult
from ..core.scanner import PatchFrameScanner

logger = logging.getLogger(__name__)

class SBOMGenerator:
    """Service for generating Software Bill of Materials."""
    
    def __init__(self):
        self.scanner = PatchFrameScanner()
        self.supported_formats = ['spdx', 'cyclonedx', 'swid']
    
    async def generate_sbom(
        self,
        project_path: str,
        format: str = "spdx"
    ) -> SBOMResult:
        """Generate SBOM for a project."""
        try:
            # Validate format
            if format not in self.supported_formats:
                raise ValueError(f"Unsupported SBOM format: {format}")
            
            # Scan project for dependencies
            scan_result = await self.scanner.scan_project(project_path)
            
            # Generate SBOM content based on format
            if format == "spdx":
                content = self._generate_spdx_sbom(scan_result)
            elif format == "cyclonedx":
                content = self._generate_cyclonedx_sbom(scan_result)
            elif format == "swid":
                content = self._generate_swid_sbom(scan_result)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            # Count vulnerabilities
            vulnerabilities_found = len(scan_result.get('vulnerabilities', []))
            
            return SBOMResult(
                project_path=project_path,
                format=format,
                content=content,
                generated_at=datetime.now(),
                total_components=len(scan_result.get('dependencies', [])),
                vulnerabilities_found=vulnerabilities_found
            )
            
        except Exception as e:
            logger.error(f"Failed to generate SBOM: {e}")
            raise
    
    def _generate_spdx_sbom(self, scan_result: Dict[str, Any]) -> str:
        """Generate SPDX format SBOM."""
        spdx_doc = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": f"SPDXRef-DOCUMENT-{uuid.uuid4().hex[:8]}",
            "documentName": f"PatchFrame SBOM for {scan_result.get('project_path', 'Unknown Project')}",
            "documentNamespace": f"https://patchframe.io/sbom/{uuid.uuid4()}",
            "creator": "Tool: PatchFrame-1.0.0",
            "created": datetime.now().isoformat(),
            "packages": [],
            "relationships": [],
            "snippets": []
        }
        
        # Add packages
        for dep in scan_result.get('dependencies', []):
            package = {
                "SPDXID": f"SPDXRef-Package-{dep['name']}-{dep['version']}",
                "name": dep['name'],
                "versionInfo": dep['version'],
                "packageFileName": f"{dep['name']}-{dep['version']}",
                "packageVerificationCode": {
                    "packageVerificationCodeValue": "NONE"
                },
                "downloadLocation": dep.get('registry_url', 'NOASSERTION'),
                "homepage": dep.get('git_url', 'NOASSERTION'),
                "packageManager": dep.get('package_type', 'unknown'),
                "supplier": "NOASSERTION",
                "originator": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "summary": f"Package {dep['name']} version {dep['version']}",
                "description": f"Automatically detected dependency {dep['name']}@{dep['version']}",
                "externalRefs": []
            }
            
            # Add external references
            if dep.get('git_url'):
                package["externalRefs"].append({
                    "referenceCategory": "VCS",
                    "referenceType": "git",
                    "referenceLocator": dep['git_url']
                })
            
            if dep.get('registry_url'):
                package["externalRefs"].append({
                    "referenceCategory": "PACKAGE_MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:npm/{dep['name']}@{dep['version']}"
                })
            
            spdx_doc["packages"].append(package)
        
        # Add vulnerability information
        for vuln in scan_result.get('vulnerabilities', []):
            # Create snippet for vulnerability
            snippet = {
                "SPDXID": f"SPDXRef-Snippet-{vuln['patch_sha']}",
                "snippetFromFile": f"package://{vuln['dependency_name']}@{vuln['dependency_version']}",
                "ranges": [{
                    "startPointer": {"lineNumber": 1},
                    "endPointer": {"lineNumber": 1}
                }],
                "snippetText": f"Vulnerability: {vuln['description']}",
                "licenseConcluded": "NOASSERTION",
                "licenseInfoInSnippets": ["NOASSERTION"],
                "copyrightText": "NOASSERTION",
                "comment": f"Security vulnerability detected in {vuln['dependency_name']}@{vuln['dependency_version']}"
            }
            spdx_doc["snippets"].append(snippet)
        
        return json.dumps(spdx_doc, indent=2)
    
    def _generate_cyclonedx_sbom(self, scan_result: Dict[str, Any]) -> str:
        """Generate CycloneDX format SBOM."""
        cyclonedx_doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [{
                    "vendor": "PatchFrame",
                    "name": "PatchFrame Scanner",
                    "version": "1.0.0"
                }],
                "component": {
                    "type": "application",
                    "name": Path(scan_result.get('project_path', 'Unknown')).name,
                    "version": "1.0.0"
                }
            },
            "components": [],
            "vulnerabilities": []
        }
        
        # Add components
        for dep in scan_result.get('dependencies', []):
            component = {
                "type": "library",
                "name": dep['name'],
                "version": dep['version'],
                "purl": f"pkg:npm/{dep['name']}@{dep['version']}",
                "externalReferences": []
            }
            
            if dep.get('git_url'):
                component["externalReferences"].append({
                    "type": "vcs",
                    "url": dep['git_url']
                })
            
            if dep.get('registry_url'):
                component["externalReferences"].append({
                    "type": "distribution",
                    "url": dep['registry_url']
                })
            
            cyclonedx_doc["components"].append(component)
        
        # Add vulnerabilities
        for vuln in scan_result.get('vulnerabilities', []):
            vulnerability = {
                "id": f"PATCHFRAME-{vuln['patch_sha']}",
                "ratings": [{
                    "severity": vuln['severity'],
                    "score": vuln['confidence'],
                    "method": "other",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
                }],
                "description": vuln['description'],
                "advisories": [],
                "affects": [{
                    "ref": f"pkg:npm/{vuln['dependency_name']}@{vuln['dependency_version']}"
                }]
            }
            
            if vuln.get('cve_id'):
                vulnerability["advisories"].append({
                    "id": vuln['cve_id'],
                    "url": f"https://nvd.nist.gov/vuln/detail/{vuln['cve_id']}"
                })
            
            cyclonedx_doc["vulnerabilities"].append(vulnerability)
        
        return json.dumps(cyclonedx_doc, indent=2)
    
    def _generate_swid_sbom(self, scan_result: Dict[str, Any]) -> str:
        """Generate SWID format SBOM."""
        swid_doc = {
            "swid": {
                "tagId": f"patchframe-{uuid.uuid4()}",
                "name": f"PatchFrame SBOM for {Path(scan_result.get('project_path', 'Unknown')).name}",
                "version": "1.0.0",
                "versionScheme": "semver",
                "tagVersion": "1",
                "xmlns": "http://standards.iso.org/iso/19770/-2/2015/schema.xsd",
                "xmlns:swid": "http://standards.iso.org/iso/19770/-2/2015/schema.xsd",
                "entity": [{
                    "name": "PatchFrame",
                    "regid": "patchframe.io",
                    "role": "softwareCreator"
                }],
                "link": [],
                "softwareId": f"patchframe-sbom-{uuid.uuid4().hex[:8]}",
                "evidence": {
                    "deviceId": "unknown",
                    "date": datetime.now().isoformat()
                },
                "payload": {
                    "files": [],
                    "directories": [],
                    "resources": []
                }
            }
        }
        
        # Add software resources
        for dep in scan_result.get('dependencies', []):
            resource = {
                "type": "software",
                "name": dep['name'],
                "version": dep['version'],
                "size": 0,
                "fileVersion": dep['version'],
                "description": f"Dependency {dep['name']}@{dep['version']}"
            }
            
            if dep.get('git_url'):
                resource["link"] = [{
                    "href": dep['git_url'],
                    "rel": "repository"
                }]
            
            swid_doc["swid"]["payload"]["resources"].append(resource)
        
        return json.dumps(swid_doc, indent=2)
    
    async def generate_comparison_sbom(
        self,
        project_path: str,
        baseline_path: Optional[str] = None,
        format: str = "spdx"
    ) -> Dict[str, Any]:
        """Generate comparison SBOM between current and baseline."""
        try:
            # Generate current SBOM
            current_sbom = await self.generate_sbom(project_path, format)
            
            # Generate baseline SBOM if provided
            baseline_sbom = None
            if baseline_path:
                baseline_sbom = await self.generate_sbom(baseline_path, format)
            
            # Compare SBOMs
            comparison = {
                'current_sbom': current_sbom,
                'baseline_sbom': baseline_sbom,
                'differences': self._compare_sboms(current_sbom, baseline_sbom) if baseline_sbom else None,
                'generated_at': datetime.now().isoformat()
            }
            
            return comparison
            
        except Exception as e:
            logger.error(f"Failed to generate comparison SBOM: {e}")
            raise
    
    def _compare_sboms(
        self,
        current_sbom: SBOMResult,
        baseline_sbom: SBOMResult
    ) -> Dict[str, Any]:
        """Compare two SBOMs and identify differences."""
        differences = {
            'added_components': [],
            'removed_components': [],
            'updated_components': [],
            'added_vulnerabilities': [],
            'removed_vulnerabilities': []
        }
        
        # Parse SBOM content
        current_components = self._extract_components(current_sbom.content, current_sbom.format)
        baseline_components = self._extract_components(baseline_sbom.content, baseline_sbom.format)
        
        # Find added and removed components
        current_names = {comp['name']: comp for comp in current_components}
        baseline_names = {comp['name']: comp for comp in baseline_components}
        
        for name, component in current_names.items():
            if name not in baseline_names:
                differences['added_components'].append(component)
            elif component['version'] != baseline_names[name]['version']:
                differences['updated_components'].append({
                    'name': name,
                    'old_version': baseline_names[name]['version'],
                    'new_version': component['version']
                })
        
        for name, component in baseline_names.items():
            if name not in current_names:
                differences['removed_components'].append(component)
        
        return differences
    
    def _extract_components(self, sbom_content: str, format: str) -> List[Dict[str, Any]]:
        """Extract components from SBOM content."""
        try:
            data = json.loads(sbom_content)
            
            if format == "spdx":
                return [
                    {
                        'name': pkg.get('name', ''),
                        'version': pkg.get('versionInfo', ''),
                        'type': 'spdx'
                    }
                    for pkg in data.get('packages', [])
                ]
            elif format == "cyclonedx":
                return [
                    {
                        'name': comp.get('name', ''),
                        'version': comp.get('version', ''),
                        'type': 'cyclonedx'
                    }
                    for comp in data.get('components', [])
                ]
            elif format == "swid":
                return [
                    {
                        'name': res.get('name', ''),
                        'version': res.get('version', ''),
                        'type': 'swid'
                    }
                    for res in data.get('swid', {}).get('payload', {}).get('resources', [])
                ]
            
        except Exception as e:
            logger.warning(f"Failed to extract components from {format} SBOM: {e}")
        
        return []
    
    async def validate_sbom(self, sbom_content: str, format: str) -> Dict[str, Any]:
        """Validate SBOM content."""
        validation_result = {
            'valid': False,
            'errors': [],
            'warnings': [],
            'format': format
        }
        
        try:
            # Parse JSON
            data = json.loads(sbom_content)
            
            # Basic format validation
            if format == "spdx":
                if 'spdxVersion' not in data:
                    validation_result['errors'].append("Missing spdxVersion")
                if 'packages' not in data:
                    validation_result['errors'].append("Missing packages section")
                    
            elif format == "cyclonedx":
                if 'bomFormat' not in data:
                    validation_result['errors'].append("Missing bomFormat")
                if 'components' not in data:
                    validation_result['errors'].append("Missing components section")
                    
            elif format == "swid":
                if 'swid' not in data:
                    validation_result['errors'].append("Missing swid root element")
            
            # Check for required fields in components
            components = self._extract_components(sbom_content, format)
            for i, comp in enumerate(components):
                if not comp.get('name'):
                    validation_result['warnings'].append(f"Component {i} missing name")
                if not comp.get('version'):
                    validation_result['warnings'].append(f"Component {i} missing version")
            
            validation_result['valid'] = len(validation_result['errors']) == 0
            
        except json.JSONDecodeError as e:
            validation_result['errors'].append(f"Invalid JSON: {str(e)}")
        except Exception as e:
            validation_result['errors'].append(f"Validation error: {str(e)}")
        
        return validation_result 