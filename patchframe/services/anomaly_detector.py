"""
Anomaly detection service for PatchFrame - identifies suspicious patterns in patches.
"""

import re
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import hashlib
import base64
from collections import Counter

from ..api.models import AnomalyResult

logger = logging.getLogger(__name__)

@dataclass
class AnomalyPattern:
    """Represents an anomaly pattern with its characteristics."""
    name: str
    pattern: re.Pattern
    weight: float
    description: str
    risk_level: str  # low, medium, high, critical

class AnomalyDetector:
    """Service for detecting anomalies in patches and code changes."""
    
    def __init__(self):
        self.anomaly_patterns = self._initialize_patterns()
        self.suspicious_keywords = {
            'obfuscation': ['obfuscated', 'minified', 'packed', 'encoded', 'compressed'],
            'suspicious_functions': ['eval', 'Function', 'exec', 'setTimeout', 'setInterval'],
            'dangerous_apis': ['innerHTML', 'outerHTML', 'document.write', 'document.writeln'],
            'data_exfiltration': ['fetch', 'XMLHttpRequest', 'navigator.sendBeacon'],
            'crypto_suspicious': ['crypto', 'encrypt', 'decrypt', 'hash', 'md5', 'sha1']
        }
        
        # Thresholds for anomaly detection
        self.thresholds = {
            'low': 0.3,
            'medium': 0.5,
            'high': 0.7,
            'critical': 0.9
        }
    
    def _initialize_patterns(self) -> List[AnomalyPattern]:
        """Initialize anomaly detection patterns."""
        patterns = [
            # Obfuscated code patterns
            AnomalyPattern(
                name="base64_encoded",
                pattern=re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
                weight=0.4,
                description="Base64 encoded content detected",
                risk_level="medium"
            ),
            AnomalyPattern(
                name="hex_encoded",
                pattern=re.compile(r'\\x[0-9a-fA-F]{2}'),
                weight=0.3,
                description="Hex encoded content detected",
                risk_level="medium"
            ),
            AnomalyPattern(
                name="unicode_escaped",
                pattern=re.compile(r'\\u[0-9a-fA-F]{4}'),
                weight=0.2,
                description="Unicode escaped content detected",
                risk_level="low"
            ),
            
            # Suspicious code patterns
            AnomalyPattern(
                name="eval_usage",
                pattern=re.compile(r'\beval\s*\('),
                weight=0.8,
                description="eval() function usage detected",
                risk_level="high"
            ),
            AnomalyPattern(
                name="function_constructor",
                pattern=re.compile(r'\bFunction\s*\('),
                weight=0.7,
                description="Function constructor usage detected",
                risk_level="high"
            ),
            AnomalyPattern(
                name="inner_html",
                pattern=re.compile(r'\.innerHTML\s*='),
                weight=0.6,
                description="innerHTML assignment detected",
                risk_level="medium"
            ),
            
            # Network activity patterns
            AnomalyPattern(
                name="external_fetch",
                pattern=re.compile(r'fetch\s*\(\s*["\']https?://'),
                weight=0.5,
                description="External network request detected",
                risk_level="medium"
            ),
            AnomalyPattern(
                name="beacon_send",
                pattern=re.compile(r'navigator\.sendBeacon'),
                weight=0.6,
                description="Data beacon detected",
                risk_level="medium"
            ),
            
            # File system patterns
            AnomalyPattern(
                name="file_read",
                pattern=re.compile(r'FileReader|readAsText|readAsDataURL'),
                weight=0.4,
                description="File reading operation detected",
                risk_level="medium"
            ),
            
            # Crypto patterns
            AnomalyPattern(
                name="crypto_operations",
                pattern=re.compile(r'crypto\.|CryptoJS|md5|sha1'),
                weight=0.3,
                description="Cryptographic operations detected",
                risk_level="low"
            ),
            
            # Large content patterns
            AnomalyPattern(
                name="large_string",
                pattern=re.compile(r'["\'][^"\']{1000,}["\']'),
                weight=0.4,
                description="Very large string content detected",
                risk_level="medium"
            ),
            
            # Comment patterns
            AnomalyPattern(
                name="suspicious_comments",
                pattern=re.compile(r'//\s*(hack|fixme|todo|bug|vuln|exploit)', re.I),
                weight=0.2,
                description="Suspicious comments detected",
                risk_level="low"
            ),
        ]
        
        return patterns
    
    async def detect_anomaly(
        self,
        dependency_name: str,
        patch_sha: str,
        diff_content: str
    ) -> AnomalyResult:
        """Detect anomalies in a patch."""
        try:
            # Analyze the diff content
            anomaly_score = 0.0
            detected_patterns = []
            anomaly_type = None
            
            # Check for pattern matches
            for pattern in self.anomaly_patterns:
                matches = pattern.pattern.findall(diff_content)
                if matches:
                    pattern_score = len(matches) * pattern.weight
                    anomaly_score += pattern_score
                    detected_patterns.append({
                        'name': pattern.name,
                        'description': pattern.description,
                        'risk_level': pattern.risk_level,
                        'matches': len(matches)
                    })
            
            # Check for suspicious keywords
            keyword_score = self._check_suspicious_keywords(diff_content)
            anomaly_score += keyword_score
            
            # Check for entropy (randomness) in the content
            entropy_score = self._calculate_entropy_score(diff_content)
            anomaly_score += entropy_score
            
            # Check for unusual file size changes
            size_score = self._check_size_anomalies(diff_content)
            anomaly_score += size_score
            
            # Normalize score to 0-1 range
            anomaly_score = min(anomaly_score, 1.0)
            
            # Determine if it's an anomaly
            is_anomaly = anomaly_score > self.thresholds['medium']
            
            # Determine anomaly type
            if anomaly_score > self.thresholds['critical']:
                anomaly_type = "critical"
            elif anomaly_score > self.thresholds['high']:
                anomaly_type = "high"
            elif anomaly_score > self.thresholds['medium']:
                anomaly_type = "medium"
            elif anomaly_score > self.thresholds['low']:
                anomaly_type = "low"
            else:
                anomaly_type = "none"
            
            # Generate description
            description = self._generate_anomaly_description(
                detected_patterns, anomaly_score, anomaly_type
            )
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                detected_patterns, anomaly_score, anomaly_type
            )
            
            return AnomalyResult(
                dependency_name=dependency_name,
                patch_sha=patch_sha,
                is_anomaly=is_anomaly,
                anomaly_score=anomaly_score,
                anomaly_type=anomaly_type,
                description=description,
                recommendations=recommendations
            )
            
        except Exception as e:
            logger.error(f"Failed to detect anomaly: {e}")
            return AnomalyResult(
                dependency_name=dependency_name,
                patch_sha=patch_sha,
                is_anomaly=False,
                anomaly_score=0.0,
                anomaly_type="error",
                description=f"Error during anomaly detection: {str(e)}",
                recommendations=["Review the patch manually due to detection error"]
            )
    
    def _check_suspicious_keywords(self, content: str) -> float:
        """Check for suspicious keywords in the content."""
        score = 0.0
        content_lower = content.lower()
        
        for category, keywords in self.suspicious_keywords.items():
            for keyword in keywords:
                count = content_lower.count(keyword.lower())
                if count > 0:
                    # Weight based on category
                    if category == 'obfuscation':
                        score += count * 0.3
                    elif category == 'suspicious_functions':
                        score += count * 0.5
                    elif category == 'dangerous_apis':
                        score += count * 0.4
                    elif category == 'data_exfiltration':
                        score += count * 0.4
                    elif category == 'crypto_suspicious':
                        score += count * 0.2
        
        return min(score, 0.5)  # Cap at 0.5
    
    def _calculate_entropy_score(self, content: str) -> float:
        """Calculate entropy score to detect obfuscated/random content."""
        try:
            # Remove common programming constructs
            cleaned_content = re.sub(r'[a-zA-Z_][a-zA-Z0-9_]*\s*[=\(\)\[\]\{\}]', '', content)
            cleaned_content = re.sub(r'["\'][^"\']*["\']', '', cleaned_content)  # Remove strings
            cleaned_content = re.sub(r'//.*?\n|/\*.*?\*/', '', cleaned_content, flags=re.DOTALL)  # Remove comments
            
            if len(cleaned_content) < 50:
                return 0.0
            
            # Calculate character frequency
            char_counts = Counter(cleaned_content)
            total_chars = len(cleaned_content)
            
            # Calculate entropy
            entropy = 0.0
            for count in char_counts.values():
                probability = count / total_chars
                if probability > 0:
                    entropy -= probability * (probability.bit_length() - 1)
            
            # Normalize entropy (0-1 scale)
            max_entropy = 8.0  # Maximum entropy for 256 possible characters
            normalized_entropy = entropy / max_entropy
            
            # High entropy suggests obfuscated/random content
            if normalized_entropy > 0.8:
                return 0.4
            elif normalized_entropy > 0.6:
                return 0.2
            else:
                return 0.0
                
        except Exception as e:
            logger.debug(f"Failed to calculate entropy: {e}")
            return 0.0
    
    def _check_size_anomalies(self, diff_content: str) -> float:
        """Check for unusual file size changes."""
        score = 0.0
        
        # Count lines added/removed
        lines_added = len([line for line in diff_content.split('\n') if line.startswith('+') and not line.startswith('+++')])
        lines_removed = len([line for line in diff_content.split('\n') if line.startswith('-') and not line.startswith('---')])
        
        # Large additions might be suspicious
        if lines_added > 100:
            score += 0.3
        elif lines_added > 50:
            score += 0.2
        elif lines_added > 20:
            score += 0.1
        
        # Very large additions are highly suspicious
        if lines_added > 500:
            score += 0.4
        
        # Check for large binary-like content
        binary_patterns = re.findall(r'[A-Za-z0-9+/]{50,}={0,2}', diff_content)
        if len(binary_patterns) > 5:
            score += 0.3
        
        return min(score, 0.5)
    
    def _generate_anomaly_description(
        self,
        detected_patterns: List[Dict],
        anomaly_score: float,
        anomaly_type: str
    ) -> str:
        """Generate human-readable anomaly description."""
        if anomaly_type == "none":
            return "No significant anomalies detected in this patch."
        
        descriptions = []
        
        if anomaly_type == "critical":
            descriptions.append("Critical anomaly detected")
        elif anomaly_type == "high":
            descriptions.append("High-risk anomaly detected")
        elif anomaly_type == "medium":
            descriptions.append("Medium-risk anomaly detected")
        elif anomaly_type == "low":
            descriptions.append("Low-risk anomaly detected")
        
        # Add specific pattern descriptions
        pattern_descriptions = []
        for pattern in detected_patterns[:3]:  # Limit to top 3
            if pattern['matches'] == 1:
                pattern_descriptions.append(f"{pattern['description']}")
            else:
                pattern_descriptions.append(f"{pattern['matches']} instances of {pattern['description'].lower()}")
        
        if pattern_descriptions:
            descriptions.append(f"Detected: {', '.join(pattern_descriptions)}")
        
        descriptions.append(f"Anomaly score: {anomaly_score:.2f}")
        
        return ". ".join(descriptions) + "."
    
    def _generate_recommendations(
        self,
        detected_patterns: List[Dict],
        anomaly_score: float,
        anomaly_type: str
    ) -> List[str]:
        """Generate recommendations based on detected anomalies."""
        recommendations = []
        
        if anomaly_type == "critical":
            recommendations.extend([
                "Immediately review this patch before deployment",
                "Consider reverting to previous version",
                "Contact maintainers for clarification",
                "Run additional security tests"
            ])
        elif anomaly_type == "high":
            recommendations.extend([
                "Thoroughly review this patch",
                "Test in isolated environment first",
                "Verify patch source and authenticity"
            ])
        elif anomaly_type == "medium":
            recommendations.extend([
                "Review patch contents carefully",
                "Check maintainer reputation",
                "Monitor for any unexpected behavior"
            ])
        elif anomaly_type == "low":
            recommendations.extend([
                "Standard review recommended",
                "Monitor for any issues"
            ])
        
        # Add specific recommendations based on patterns
        for pattern in detected_patterns:
            if pattern['name'] == 'eval_usage':
                recommendations.append("Avoid eval() usage - consider safer alternatives")
            elif pattern['name'] == 'inner_html':
                recommendations.append("Be cautious with innerHTML - validate content")
            elif pattern['name'] == 'base64_encoded':
                recommendations.append("Review base64 encoded content for malicious code")
            elif pattern['name'] == 'external_fetch':
                recommendations.append("Verify external network requests are legitimate")
        
        return list(set(recommendations))  # Remove duplicates
    
    async def analyze_patch_history(
        self,
        dependency_name: str,
        patches: List[Dict]
    ) -> Dict[str, Any]:
        """Analyze patch history for patterns and trends."""
        try:
            analysis = {
                'total_patches': len(patches),
                'anomaly_count': 0,
                'high_risk_patches': 0,
                'suspicious_authors': [],
                'common_patterns': [],
                'trends': {}
            }
            
            # Analyze each patch
            for patch in patches:
                if 'diff_content' in patch:
                    anomaly_result = await self.detect_anomaly(
                        dependency_name,
                        patch.get('sha', 'unknown'),
                        patch['diff_content']
                    )
                    
                    if anomaly_result.is_anomaly:
                        analysis['anomaly_count'] += 1
                    
                    if anomaly_result.anomaly_score > self.thresholds['high']:
                        analysis['high_risk_patches'] += 1
            
            # Calculate anomaly rate
            if analysis['total_patches'] > 0:
                analysis['anomaly_rate'] = analysis['anomaly_count'] / analysis['total_patches']
            else:
                analysis['anomaly_rate'] = 0.0
            
            return analysis
            
        except Exception as e:
            logger.error(f"Failed to analyze patch history: {e}")
            return {
                'error': str(e),
                'total_patches': 0,
                'anomaly_count': 0,
                'anomaly_rate': 0.0
            } 