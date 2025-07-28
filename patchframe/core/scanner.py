"""
Core scanner module for PatchFrame - handles dependency parsing, git analysis, and vulnerability detection.
"""

import json
import os
import re
import subprocess
import tempfile
import pathlib
import shutil
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import asyncio
import aiohttp
import aiofiles
from git import Repo, Commit
from tree_sitter import Language, Parser, Node
import logging

logger = logging.getLogger(__name__)

@dataclass
class Dependency:
    """Represents a dependency with its metadata."""
    name: str
    version: str
    git_url: Optional[str] = None
    registry_url: Optional[str] = None
    package_type: str = "npm"  # npm, pip, cargo, etc.
    file_path: Optional[str] = None

@dataclass
class Patch:
    """Represents a git patch/commit."""
    sha: str
    message: str
    author: str
    date: datetime
    files_changed: List[str]
    risk_score: float
    risk_factors: List[str]
    diff_content: Optional[str] = None
    ast_changes: Optional[Dict] = None

@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""
    dependency: Dependency
    patch: Patch
    severity: str  # low, medium, high, critical
    description: str
    confidence: float
    detection_method: str
    cve_id: Optional[str] = None

class DependencyParser:
    """Parses different package manager files to extract dependencies."""
    
    SUPPORTED_FILES = {
        "package.json": "npm",
        "requirements.txt": "pip",
        "Cargo.toml": "cargo",
        "composer.json": "composer",
        "Gemfile": "ruby",
        "go.mod": "go"
    }
    
    def __init__(self):
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def parse_dependencies(self, file_path: str) -> List[Dependency]:
        """Parse dependencies from a package manager file."""
        file_type = self.SUPPORTED_FILES.get(pathlib.Path(file_path).name)
        if not file_type:
            raise ValueError(f"Unsupported file type: {file_path}")
        
        if file_type == "npm":
            return await self._parse_npm_dependencies(file_path)
        elif file_type == "pip":
            return await self._parse_pip_dependencies(file_path)
        # Add other parsers as needed
        
        return []
    
    async def _parse_npm_dependencies(self, file_path: str) -> List[Dependency]:
        """Parse npm package.json dependencies."""
        async with aiofiles.open(file_path, 'r') as f:
            content = await f.read()
        
        data = json.loads(content)
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        
        dependencies = []
        for name, version in deps.items():
            # Get package metadata from npm registry
            metadata = await self._get_npm_metadata(name)
            git_url = metadata.get("repository", {}).get("url", "")
            if git_url.startswith("git+"):
                git_url = git_url[4:]
            
            dependencies.append(Dependency(
                name=name,
                version=version.strip("^~"),
                git_url=git_url,
                registry_url=f"https://registry.npmjs.org/{name}",
                package_type="npm",
                file_path=file_path
            ))
        
        return dependencies
    
    async def _parse_pip_dependencies(self, file_path: str) -> List[Dependency]:
        """Parse pip requirements.txt dependencies."""
        async with aiofiles.open(file_path, 'r') as f:
            content = await f.read()
        
        dependencies = []
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                # Simple parsing - could be enhanced
                parts = line.split('==')
                if len(parts) == 2:
                    name, version = parts
                    dependencies.append(Dependency(
                        name=name.strip(),
                        version=version.strip(),
                        package_type="pip",
                        file_path=file_path
                    ))
        
        return dependencies
    
    async def _get_npm_metadata(self, package_name: str) -> Dict[str, Any]:
        """Get package metadata from npm registry."""
        if not self.session:
            return {}
        
        try:
            async with self.session.get(f"https://registry.npmjs.org/{package_name}") as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            logger.warning(f"Failed to get metadata for {package_name}: {e}")
        
        return {}

class GitAnalyzer:
    """Analyzes git repositories for security-relevant patches."""
    
    def __init__(self):
        self.risk_patterns = {
            'security_keywords': re.compile(
                r'\b(CVE-\d{4}-\d+|prototype\s+pollution|command\s+injection|XSS|CSRF|SQL\s+injection|RCE|ReDoS|security\s+fix.*vuln|fix.*prototype\s+pollution|fix.*command\s+injection)\b',
                re.I
            ),
            'dangerous_functions': re.compile(
                r'\b(eval\s*\(|Function\s*\(|exec\s*\(|setTimeout\s*\(.*\)|setInterval\s*\(.*\))\b',
                re.I
            ),
            'suspicious_patterns': re.compile(
                r'\b(base64_decode|hex2bin|obfuscated|minified|encoded\s+string)\b',
                re.I
            )
        }
        
        # Initialize Tree-sitter for AST analysis
        self._init_tree_sitter()
    
    def _init_tree_sitter(self):
        """Initialize Tree-sitter parsers for different languages."""
        self.parsers = {}
        self.languages = {}
        
        # For now, we'll skip Tree-sitter initialization
        # This can be enhanced later with proper grammar installation
        print("Warning: Tree-sitter AST analysis disabled for now")
        try:
            # Placeholder for future Tree-sitter implementation
            pass
        except Exception as e:
            print(f"Warning: Tree-sitter initialization failed: {e}")
    
    async def analyze_repository(self, dependency: Dependency, max_commits: int = 100) -> List[Patch]:
        """Analyze a git repository for security-relevant patches."""
        if not dependency.git_url:
            return []
        
        temp_dir = tempfile.mkdtemp()
        try:
            # Clone repository
            repo = Repo.clone_from(dependency.git_url, temp_dir, depth=max_commits)
            
            # Get commits
            commits = list(repo.iter_commits(max_count=max_commits))
            
            patches = []
            for commit in commits:
                patch = await self._analyze_commit(commit, repo)
                if patch and patch.risk_score > 0.1:  # Only include relevant patches
                    patches.append(patch)
            
            return patches
            
        except Exception as e:
            logger.error(f"Failed to analyze repository {dependency.git_url}: {e}")
            return []
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    async def _analyze_commit(self, commit: Commit, repo: Repo) -> Optional[Patch]:
        """Analyze a single commit for security risks."""
        risk_score = 0.0
        risk_factors = []
        
        # Check commit message
        if self.risk_patterns['security_keywords'].search(commit.message):
            risk_score += 0.3
            risk_factors.append("security_keywords_in_message")
        
        # Get diff and analyze
        try:
            # Use a safer diff approach
            if commit.parents:
                diff = repo.git.diff(commit.parents[0].hexsha, commit.hexsha, "--unified=0", "--no-color")
            else:
                # For initial commits, get the full content
                diff = repo.git.show(commit.hexsha, "--unified=0", "--no-color")
            
            # Only analyze if we have meaningful content
            if diff and len(diff.strip()) > 0:
                # Check for dangerous functions in diff
                if self.risk_patterns['dangerous_functions'].search(diff):
                    risk_score += 0.4
                    risk_factors.append("dangerous_functions_in_diff")
                
                # Check for suspicious patterns
                if self.risk_patterns['suspicious_patterns'].search(diff):
                    risk_score += 0.2
                    risk_factors.append("suspicious_patterns")
            
            # Get files changed safely
            try:
                if commit.parents:
                    files_changed = [item.a_path or item.b_path for item in commit.diff(commit.parents[0])]
                else:
                    files_changed = [item.a_path or item.b_path for item in commit.diff()]
            except Exception:
                files_changed = []
            
            return Patch(
                sha=commit.hexsha[:8],
                message=commit.message.split('\n')[0],
                author=commit.author.name,
                date=datetime.fromtimestamp(commit.committed_date),
                files_changed=files_changed,
                risk_score=min(risk_score, 1.0),
                risk_factors=risk_factors,
                diff_content=diff,
                ast_changes=None  # AST analysis disabled for now
            )
            
        except Exception as e:
            logger.warning(f"Failed to analyze commit {commit.hexsha}: {e}")
            return None
    
    async def _analyze_ast_changes(self, diff: str, commit: Commit, repo: Repo) -> Optional[Dict]:
        """Analyze AST changes in the diff."""
        if 'javascript' not in self.parsers:
            return None
        
        risk_score = 0.0
        risk_factors = []
        
        # Extract JavaScript files from diff
        js_files = []
        for line in diff.split('\n'):
            if line.startswith('+++') and line.endswith('.js'):
                filename = line[4:]  # Remove '+++ '
                js_files.append(filename)
        
        # Analyze each JavaScript file
        for filename in js_files:
            try:
                file_content = repo.git.show(f"{commit.hexsha}:{filename}")
                tree = self.parsers['javascript'].parse(file_content.encode())
                
                # Look for dangerous patterns in AST
                if self._has_dangerous_ast_patterns(tree.root_node):
                    risk_score += 0.3
                    risk_factors.append("dangerous_ast_patterns")
                    
            except Exception as e:
                logger.debug(f"Failed to analyze AST for {filename}: {e}")
        
        return {
            'risk_score': risk_score,
            'risk_factors': risk_factors
        } if risk_score > 0 else None
    
    def _has_dangerous_ast_patterns(self, node: Node) -> bool:
        """Check if AST contains dangerous patterns."""
        if node.type == "call_expression":
            # Check for eval, Function, etc.
            if hasattr(node, 'children') and node.children:
                first_child = node.children[0]
                if first_child.type == "identifier":
                    identifier = first_child.text.decode() if hasattr(first_child, 'text') else ""
                    if identifier.lower() in ['eval', 'function', 'exec']:
                        return True
        
        # Recursively check children
        for child in node.children:
            if self._has_dangerous_ast_patterns(child):
                return True
        
        return False

class VulnerabilityDetector:
    """Detects vulnerabilities based on patch analysis."""
    
    def __init__(self):
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d+', re.I)
    
    def detect_vulnerabilities(self, dependency: Dependency, patches: List[Patch]) -> List[Vulnerability]:
        """Detect vulnerabilities from patches."""
        vulnerabilities = []
        
        for patch in patches:
            # Only create vulnerabilities for patches with very specific security indicators
            # This prevents false positives by being extremely selective
            if (patch.risk_score > 0.8 and 
                "security_keywords_in_message" in patch.risk_factors and
                any(keyword in patch.message.lower() for keyword in [
                    "cve-", "prototype pollution", "command injection", "security fix", 
                    "vulnerability fix", "security patch", "fix.*vuln", "fix.*security"
                ])):
                vuln = self._create_vulnerability(dependency, patch)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _create_vulnerability(self, dependency: Dependency, patch: Patch) -> Optional[Vulnerability]:
        """Create a vulnerability object from a patch."""
        # Extract CVE ID if present
        cve_id = None
        cve_match = self.cve_pattern.search(patch.message)
        if cve_match:
            cve_id = cve_match.group(0)
        
        # Determine severity based on risk score and factors
        if patch.risk_score >= 0.8 and "dangerous_functions_in_diff" in patch.risk_factors:
            severity = "critical"
        elif patch.risk_score >= 0.7 and "security_keywords_in_message" in patch.risk_factors:
            severity = "high"
        elif patch.risk_score >= 0.6:
            severity = "medium"
        else:
            severity = "low"
        
        # Generate description
        description = self._generate_vulnerability_description(patch)
        
        return Vulnerability(
            dependency=dependency,
            patch=patch,
            severity=severity,
            description=description,
            cve_id=cve_id,
            confidence=patch.risk_score,
            detection_method="patch_analysis"
        )
    
    def _generate_vulnerability_description(self, patch: Patch) -> str:
        """Generate a human-readable vulnerability description."""
        factors = []
        
        if "security_keywords_in_message" in patch.risk_factors:
            factors.append("Security-related commit message")
        
        if "dangerous_functions_in_diff" in patch.risk_factors:
            factors.append("Dangerous functions detected in code changes")
        
        if "suspicious_patterns" in patch.risk_factors:
            factors.append("Suspicious patterns (obfuscation/minification)")
        
        if "dangerous_ast_patterns" in patch.risk_factors:
            factors.append("Dangerous AST patterns detected")
        
        if factors:
            return f"Potential security issue detected: {'; '.join(factors)}"
        else:
            return "Security-relevant patch detected"

class PatchFrameScanner:
    """Main scanner class that orchestrates the entire scanning process."""
    
    def __init__(self):
        self.parser = DependencyParser()
        self.git_analyzer = GitAnalyzer()
        self.vuln_detector = VulnerabilityDetector()
    
    async def scan_project(self, project_path: str) -> Dict[str, Any]:
        """Scan a project for vulnerabilities."""
        logger.info(f"Starting scan of project: {project_path}")
        
        # Find package files
        package_files = self._find_package_files(project_path)
        
        all_dependencies = []
        all_vulnerabilities = []
        
        async with self.parser:
            for package_file in package_files:
                try:
                    # Parse dependencies
                    dependencies = await self.parser.parse_dependencies(package_file)
                    all_dependencies.extend(dependencies)
                    
                    # Analyze each dependency
                    for dependency in dependencies:
                        logger.info(f"Analyzing dependency: {dependency.name}@{dependency.version}")
                        
                        # Analyze git repository
                        patches = await self.git_analyzer.analyze_repository(dependency)
                        
                        # Detect vulnerabilities
                        vulnerabilities = self.vuln_detector.detect_vulnerabilities(dependency, patches)
                        all_vulnerabilities.extend(vulnerabilities)
                        
                except Exception as e:
                    logger.error(f"Failed to process {package_file}: {e}")
        
        return {
            'project_path': project_path,
            'scan_timestamp': datetime.now().isoformat(),
            'dependencies': [self._dependency_to_dict(d) for d in all_dependencies],
            'vulnerabilities': [self._vulnerability_to_dict(v) for v in all_vulnerabilities],
            'summary': {
                'total_dependencies': len(all_dependencies),
                'total_vulnerabilities': len(all_vulnerabilities),
                'critical_vulns': len([v for v in all_vulnerabilities if v.severity == 'critical']),
                'high_vulns': len([v for v in all_vulnerabilities if v.severity == 'high']),
                'medium_vulns': len([v for v in all_vulnerabilities if v.severity == 'medium']),
                'low_vulns': len([v for v in all_vulnerabilities if v.severity == 'low'])
            }
        }
    
    def _find_package_files(self, project_path: str) -> List[str]:
        """Find package manager files in the project."""
        package_files = []
        
        for filename, package_type in DependencyParser.SUPPORTED_FILES.items():
            file_path = pathlib.Path(project_path) / filename
            if file_path.exists():
                package_files.append(str(file_path))
        
        return package_files
    
    def _dependency_to_dict(self, dep: Dependency) -> Dict[str, Any]:
        """Convert Dependency to dictionary."""
        return {
            'name': dep.name,
            'version': dep.version,
            'git_url': dep.git_url,
            'registry_url': dep.registry_url,
            'package_type': dep.package_type,
            'file_path': dep.file_path
        }
    
    def _vulnerability_to_dict(self, vuln: Vulnerability) -> Dict[str, Any]:
        """Convert Vulnerability to dictionary."""
        return {
            'dependency_name': vuln.dependency.name,
            'dependency_version': vuln.dependency.version,
            'patch_sha': vuln.patch.sha,
            'patch_message': vuln.patch.message,
            'patch_author': vuln.patch.author,
            'patch_date': vuln.patch.date.isoformat(),
            'severity': vuln.severity,
            'description': vuln.description,
            'cve_id': vuln.cve_id,
            'confidence': vuln.confidence,
            'detection_method': vuln.detection_method,
            'risk_factors': vuln.patch.risk_factors
        } 