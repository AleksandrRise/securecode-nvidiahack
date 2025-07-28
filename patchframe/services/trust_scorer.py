"""
Trust scoring service for PatchFrame - evaluates maintainer reputation and patch trustworthiness.
"""

import asyncio
import aiohttp
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import re
from dataclasses import dataclass

from ..api.models import TrustScore

logger = logging.getLogger(__name__)

@dataclass
class MaintainerProfile:
    """Represents a maintainer's profile and reputation."""
    email: str
    name: str
    github_username: Optional[str] = None
    total_commits: int = 0
    security_commits: int = 0
    reputation_score: float = 0.0
    account_age_days: int = 0
    verified_email: bool = False
    organization_member: bool = False
    recent_activity: bool = True

class TrustScorer:
    """Service for calculating trust scores for patches and maintainers."""
    
    def __init__(self):
        self.session = None
        self.github_token = None  # Set from environment in production
        self.maintainer_cache: Dict[str, MaintainerProfile] = {}
        
        # Trust factors and weights
        self.trust_factors = {
            'author_reputation': 0.4,
            'commit_pattern': 0.2,
            'security_history': 0.2,
            'account_age': 0.1,
            'verification': 0.1
        }
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def calculate_trust_score(
        self,
        dependency_name: str,
        patch_sha: str,
        author_email: Optional[str] = None
    ) -> TrustScore:
        """Calculate overall trust score for a patch."""
        try:
            # Get maintainer profile
            maintainer_profile = await self._get_maintainer_profile(author_email)
            
            # Calculate author trust score
            author_trust_score = self._calculate_author_trust_score(maintainer_profile)
            
            # Calculate commit trust score
            commit_trust_score = await self._calculate_commit_trust_score(
                dependency_name, patch_sha
            )
            
            # Calculate overall trust score
            overall_trust_score = (
                author_trust_score * self.trust_factors['author_reputation'] +
                commit_trust_score * self.trust_factors['commit_pattern']
            )
            
            # Generate factors and explanation
            factors = self._generate_trust_factors(maintainer_profile, commit_trust_score)
            explanation = self._generate_trust_explanation(
                maintainer_profile, commit_trust_score, overall_trust_score
            )
            
            return TrustScore(
                dependency_name=dependency_name,
                patch_sha=patch_sha,
                author_trust_score=author_trust_score,
                commit_trust_score=commit_trust_score,
                overall_trust_score=overall_trust_score,
                factors=factors,
                explanation=explanation
            )
            
        except Exception as e:
            logger.error(f"Failed to calculate trust score: {e}")
            # Return default low trust score
            return TrustScore(
                dependency_name=dependency_name,
                patch_sha=patch_sha,
                author_trust_score=0.1,
                commit_trust_score=0.1,
                overall_trust_score=0.1,
                factors=["error_calculating_trust"],
                explanation=f"Failed to calculate trust score: {str(e)}"
            )
    
    async def _get_maintainer_profile(self, email: Optional[str]) -> MaintainerProfile:
        """Get or create maintainer profile."""
        if not email:
            return self._create_default_profile()
        
        # Check cache first
        if email in self.maintainer_cache:
            return self.maintainer_cache[email]
        
        # Create new profile
        profile = MaintainerProfile(email=email, name="Unknown")
        
        try:
            # Try to get GitHub profile
            github_username = await self._get_github_username(email)
            if github_username:
                profile.github_username = github_username
                await self._enrich_github_profile(profile)
            
            # Cache the profile
            self.maintainer_cache[email] = profile
            
        except Exception as e:
            logger.warning(f"Failed to enrich profile for {email}: {e}")
        
        return profile
    
    def _create_default_profile(self) -> MaintainerProfile:
        """Create a default low-trust profile."""
        return MaintainerProfile(
            email="unknown@example.com",
            name="Unknown Maintainer",
            reputation_score=0.1,
            verified_email=False,
            recent_activity=False
        )
    
    async def _get_github_username(self, email: str) -> Optional[str]:
        """Get GitHub username from email using GitHub API."""
        if not self.session:
            return None
        
        try:
            # Search for user by email
            headers = {}
            if self.github_token:
                headers['Authorization'] = f'token {self.github_token}'
            
            async with self.session.get(
                f"https://api.github.com/search/users?q={email}",
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('items'):
                        return data['items'][0]['login']
                        
        except Exception as e:
            logger.debug(f"Failed to get GitHub username for {email}: {e}")
        
        return None
    
    async def _enrich_github_profile(self, profile: MaintainerProfile):
        """Enrich profile with GitHub data."""
        if not profile.github_username or not self.session:
            return
        
        try:
            headers = {}
            if self.github_token:
                headers['Authorization'] = f'token {self.github_token}'
            
            # Get user profile
            async with self.session.get(
                f"https://api.github.com/users/{profile.github_username}",
                headers=headers
            ) as response:
                if response.status == 200:
                    user_data = await response.json()
                    
                    profile.name = user_data.get('name', profile.name)
                    profile.verified_email = user_data.get('email_verified', False)
                    profile.organization_member = user_data.get('type') == 'Organization'
                    
                    # Calculate account age
                    created_at = datetime.fromisoformat(user_data['created_at'].replace('Z', '+00:00'))
                    profile.account_age_days = (datetime.now(created_at.tzinfo) - created_at).days
                    
                    # Get recent activity
                    await self._get_recent_activity(profile, headers)
                    
        except Exception as e:
            logger.warning(f"Failed to enrich GitHub profile: {e}")
    
    async def _get_recent_activity(self, profile: MaintainerProfile, headers: Dict[str, str]):
        """Get recent activity for the maintainer."""
        if not profile.github_username or not self.session:
            return
        
        try:
            # Get recent events
            async with self.session.get(
                f"https://api.github.com/users/{profile.github_username}/events",
                headers=headers,
                params={'per_page': 10}
            ) as response:
                if response.status == 200:
                    events = await response.json()
                    
                    # Check if there's recent activity (last 30 days)
                    recent_events = [
                        event for event in events
                        if datetime.fromisoformat(event['created_at'].replace('Z', '+00:00')) >
                           datetime.now() - timedelta(days=30)
                    ]
                    
                    profile.recent_activity = len(recent_events) > 0
                    
        except Exception as e:
            logger.debug(f"Failed to get recent activity: {e}")
    
    def _calculate_author_trust_score(self, profile: MaintainerProfile) -> float:
        """Calculate author trust score based on profile."""
        score = 0.0
        
        # Base score from reputation
        score += profile.reputation_score * 0.3
        
        # Account age factor
        if profile.account_age_days > 365:  # More than 1 year
            score += 0.2
        elif profile.account_age_days > 180:  # More than 6 months
            score += 0.1
        
        # Verification factor
        if profile.verified_email:
            score += 0.2
        
        # Organization membership factor
        if profile.organization_member:
            score += 0.1
        
        # Recent activity factor
        if profile.recent_activity:
            score += 0.1
        
        # Security history factor
        if profile.security_commits > 0:
            security_ratio = min(profile.security_commits / max(profile.total_commits, 1), 0.5)
            score += security_ratio * 0.1
        
        return min(score, 1.0)
    
    async def _calculate_commit_trust_score(
        self,
        dependency_name: str,
        patch_sha: str
    ) -> float:
        """Calculate commit trust score based on commit characteristics."""
        score = 0.5  # Base score
        
        try:
            # Get commit details from GitHub API
            commit_data = await self._get_commit_data(dependency_name, patch_sha)
            if not commit_data:
                return score
            
            # Check commit message quality
            message = commit_data.get('commit', {}).get('message', '')
            if self._is_well_formatted_commit(message):
                score += 0.2
            
            # Check if it's a signed commit
            if commit_data.get('verification', {}).get('verified', False):
                score += 0.2
            
            # Check if it's a merge commit
            if len(commit_data.get('parents', [])) > 1:
                score += 0.1
            
            # Check file changes (reasonable number of files)
            files_changed = len(commit_data.get('files', []))
            if 1 <= files_changed <= 10:
                score += 0.1
            elif files_changed > 50:  # Suspicious
                score -= 0.2
            
        except Exception as e:
            logger.warning(f"Failed to calculate commit trust score: {e}")
        
        return max(score, 0.0)
    
    async def _get_commit_data(self, dependency_name: str, patch_sha: str) -> Optional[Dict[str, Any]]:
        """Get commit data from GitHub API."""
        if not self.session:
            return None
        
        try:
            # Try to get repository from dependency name
            repo_url = await self._get_repo_url(dependency_name)
            if not repo_url:
                return None
            
            # Extract owner/repo from URL
            match = re.search(r'github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$', repo_url)
            if not match:
                return None
            
            owner_repo = match.group(1)
            
            headers = {}
            if self.github_token:
                headers['Authorization'] = f'token {self.github_token}'
            
            async with self.session.get(
                f"https://api.github.com/repos/{owner_repo}/commits/{patch_sha}",
                headers=headers
            ) as response:
                if response.status == 200:
                    return await response.json()
                    
        except Exception as e:
            logger.debug(f"Failed to get commit data: {e}")
        
        return None
    
    async def _get_repo_url(self, dependency_name: str) -> Optional[str]:
        """Get repository URL for a dependency."""
        if not self.session:
            return None
        
        try:
            # Try npm registry first
            async with self.session.get(f"https://registry.npmjs.org/{dependency_name}") as response:
                if response.status == 200:
                    data = await response.json()
                    repo_url = data.get("repository", {}).get("url", "")
                    if repo_url.startswith("git+"):
                        repo_url = repo_url[4:]
                    return repo_url
                    
        except Exception as e:
            logger.debug(f"Failed to get repo URL for {dependency_name}: {e}")
        
        return None
    
    def _is_well_formatted_commit(self, message: str) -> bool:
        """Check if commit message is well formatted."""
        lines = message.split('\n')
        
        # Check conventional commit format
        conventional_pattern = re.compile(
            r'^(feat|fix|docs|style|refactor|test|chore)(\(.+\))?: .+'
        )
        
        if conventional_pattern.match(lines[0]):
            return True
        
        # Check for good practices
        if len(lines[0]) <= 72:  # Good length
            return True
        
        return False
    
    def _generate_trust_factors(
        self,
        profile: MaintainerProfile,
        commit_trust_score: float
    ) -> List[str]:
        """Generate list of trust factors."""
        factors = []
        
        if profile.verified_email:
            factors.append("verified_email")
        
        if profile.organization_member:
            factors.append("organization_member")
        
        if profile.account_age_days > 365:
            factors.append("established_account")
        
        if profile.recent_activity:
            factors.append("recent_activity")
        
        if profile.security_commits > 0:
            factors.append("security_experience")
        
        if commit_trust_score > 0.7:
            factors.append("well_formatted_commit")
        
        if not factors:
            factors.append("limited_trust_indicators")
        
        return factors
    
    def _generate_trust_explanation(
        self,
        profile: MaintainerProfile,
        commit_trust_score: float,
        overall_trust_score: float
    ) -> str:
        """Generate human-readable trust explanation."""
        explanations = []
        
        if overall_trust_score >= 0.8:
            explanations.append("High trust score")
        elif overall_trust_score >= 0.6:
            explanations.append("Moderate trust score")
        elif overall_trust_score >= 0.4:
            explanations.append("Low trust score")
        else:
            explanations.append("Very low trust score")
        
        if profile.verified_email:
            explanations.append("Email is verified")
        
        if profile.organization_member:
            explanations.append("Organization member")
        
        if profile.account_age_days > 365:
            explanations.append("Established account")
        
        if profile.security_commits > 0:
            explanations.append("Has security experience")
        
        if commit_trust_score > 0.7:
            explanations.append("Well-formatted commit")
        
        return ". ".join(explanations) + "." 