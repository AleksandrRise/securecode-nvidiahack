"""
Notification service for PatchFrame - sends alerts about vulnerabilities and scan results.
"""

import asyncio
import logging
import smtplib
import aiohttp
from typing import Dict, Any, List, Optional
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json

logger = logging.getLogger(__name__)

class NotificationService:
    """Service for sending notifications about vulnerabilities and scan results."""
    
    def __init__(self):
        self.smtp_config = {
            'host': 'localhost',
            'port': 587,
            'username': None,
            'password': None,
            'use_tls': True
        }
        self.slack_webhook_url = None
        self.teams_webhook_url = None
        self.notification_threshold = 'medium'  # low, medium, high, critical
        
        # Load configuration from environment
        self._load_config()
    
    def _load_config(self):
        """Load notification configuration from environment variables."""
        import os
        
        # SMTP configuration
        if os.getenv('SMTP_HOST'):
            self.smtp_config['host'] = os.getenv('SMTP_HOST')
        if os.getenv('SMTP_PORT'):
            self.smtp_config['port'] = int(os.getenv('SMTP_PORT'))
        if os.getenv('SMTP_USERNAME'):
            self.smtp_config['username'] = os.getenv('SMTP_USERNAME')
        if os.getenv('SMTP_PASSWORD'):
            self.smtp_config['password'] = os.getenv('SMTP_PASSWORD')
        
        # Webhook URLs
        self.slack_webhook_url = os.getenv('SLACK_WEBHOOK_URL')
        self.teams_webhook_url = os.getenv('TEAMS_WEBHOOK_URL')
        
        # Notification threshold
        threshold = os.getenv('NOTIFICATION_THRESHOLD', 'medium')
        if threshold in ['low', 'medium', 'high', 'critical']:
            self.notification_threshold = threshold
    
    async def send_vulnerability_notification(self, scan_result: Dict[str, Any]):
        """Send notification about detected vulnerabilities."""
        try:
            # Check if we should send notifications
            if not self._should_send_notification(scan_result):
                return
            
            # Prepare notification content
            notification_data = self._prepare_vulnerability_notification(scan_result)
            
            # Send notifications through different channels
            tasks = []
            
            if self.smtp_config['username']:
                tasks.append(self._send_email_notification(notification_data))
            
            if self.slack_webhook_url:
                tasks.append(self._send_slack_notification(notification_data))
            
            if self.teams_webhook_url:
                tasks.append(self._send_teams_notification(notification_data))
            
            # Execute all notification tasks
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
                logger.info(f"Sent vulnerability notifications for scan: {scan_result.get('project_path', 'Unknown')}")
            
        except Exception as e:
            logger.error(f"Failed to send vulnerability notification: {e}")
    
    def _should_send_notification(self, scan_result: Dict[str, Any]) -> bool:
        """Determine if notification should be sent based on threshold."""
        summary = scan_result.get('summary', {})
        
        # Check if any vulnerabilities meet the threshold
        threshold_levels = {
            'low': 0,
            'medium': 1,
            'high': 2,
            'critical': 3
        }
        
        current_threshold = threshold_levels.get(self.notification_threshold, 1)
        
        # Count high-severity vulnerabilities
        high_severity_count = (
            summary.get('critical_vulns', 0) +
            summary.get('high_vulns', 0)
        )
        
        return high_severity_count >= current_threshold
    
    def _prepare_vulnerability_notification(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare notification data from scan result."""
        summary = scan_result.get('summary', {})
        vulnerabilities = scan_result.get('vulnerabilities', [])
        
        # Group vulnerabilities by severity
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'high']
        medium_vulns = [v for v in vulnerabilities if v.get('severity') == 'medium']
        low_vulns = [v for v in vulnerabilities if v.get('severity') == 'low']
        
        return {
            'project_path': scan_result.get('project_path', 'Unknown'),
            'scan_timestamp': scan_result.get('scan_timestamp', datetime.now().isoformat()),
            'total_dependencies': summary.get('total_dependencies', 0),
            'total_vulnerabilities': summary.get('total_vulnerabilities', 0),
            'critical_vulns': len(critical_vulns),
            'high_vulns': len(high_vulns),
            'medium_vulns': len(medium_vulns),
            'low_vulns': len(low_vulns),
            'critical_vulnerabilities': critical_vulns[:5],  # Limit to top 5
            'high_vulnerabilities': high_vulns[:5],
            'scan_id': scan_result.get('scan_id', 'unknown')
        }
    
    async def _send_email_notification(self, notification_data: Dict[str, Any]):
        """Send email notification."""
        try:
            # Create email content
            subject = f"🚨 PatchFrame Security Alert: {notification_data['total_vulnerabilities']} vulnerabilities detected"
            
            html_content = self._generate_email_html(notification_data)
            text_content = self._generate_email_text(notification_data)
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.smtp_config['username']
            msg['To'] = self.smtp_config['username']  # Send to self for now
            
            # Attach content
            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_config['host'], self.smtp_config['port']) as server:
                if self.smtp_config['use_tls']:
                    server.starttls()
                
                if self.smtp_config['username'] and self.smtp_config['password']:
                    server.login(self.smtp_config['username'], self.smtp_config['password'])
                
                server.send_message(msg)
            
            logger.info("Email notification sent successfully")
            
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
    
    def _generate_email_html(self, data: Dict[str, Any]) -> str:
        """Generate HTML email content."""
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #dc3545; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ background-color: #f8f9fa; padding: 15px; margin: 20px 0; border-radius: 5px; }}
                .vulnerability {{ background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 3px; }}
                .critical {{ background-color: #f8d7da; border-color: #f5c6cb; }}
                .high {{ background-color: #fff3cd; border-color: #ffeaa7; }}
                .medium {{ background-color: #d1ecf1; border-color: #bee5eb; }}
                .low {{ background-color: #d4edda; border-color: #c3e6cb; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚨 PatchFrame Security Alert</h1>
                <p>Vulnerabilities detected in {data['project_path']}</p>
            </div>
            
            <div class="summary">
                <h2>Scan Summary</h2>
                <p><strong>Total Dependencies:</strong> {data['total_dependencies']}</p>
                <p><strong>Total Vulnerabilities:</strong> {data['total_vulnerabilities']}</p>
                <p><strong>Critical:</strong> {data['critical_vulns']}</p>
                <p><strong>High:</strong> {data['high_vulns']}</p>
                <p><strong>Medium:</strong> {data['medium_vulns']}</p>
                <p><strong>Low:</strong> {data['low_vulns']}</p>
                <p><strong>Scan Time:</strong> {data['scan_timestamp']}</p>
            </div>
        """
        
        # Add critical vulnerabilities
        if data['critical_vulnerabilities']:
            html += "<h2>Critical Vulnerabilities</h2>"
            for vuln in data['critical_vulnerabilities']:
                html += f"""
                <div class="vulnerability critical">
                    <h3>{vuln['dependency_name']}@{vuln['dependency_version']}</h3>
                    <p><strong>Description:</strong> {vuln['description']}</p>
                    <p><strong>Patch SHA:</strong> {vuln['patch_sha']}</p>
                    <p><strong>Author:</strong> {vuln['patch_author']}</p>
                    <p><strong>Confidence:</strong> {vuln['confidence']:.2f}</p>
                </div>
                """
        
        # Add high vulnerabilities
        if data['high_vulnerabilities']:
            html += "<h2>High Vulnerabilities</h2>"
            for vuln in data['high_vulnerabilities']:
                html += f"""
                <div class="vulnerability high">
                    <h3>{vuln['dependency_name']}@{vuln['dependency_version']}</h3>
                    <p><strong>Description:</strong> {vuln['description']}</p>
                    <p><strong>Patch SHA:</strong> {vuln['patch_sha']}</p>
                    <p><strong>Author:</strong> {vuln['patch_author']}</p>
                    <p><strong>Confidence:</strong> {vuln['confidence']:.2f}</p>
                </div>
                """
        
        html += """
            <p><em>This is an automated security alert from PatchFrame. Please review these vulnerabilities and take appropriate action.</em></p>
        </body>
        </html>
        """
        
        return html
    
    def _generate_email_text(self, data: Dict[str, Any]) -> str:
        """Generate plain text email content."""
        text = f"""
PatchFrame Security Alert
========================

Project: {data['project_path']}
Scan Time: {data['scan_timestamp']}

Summary:
- Total Dependencies: {data['total_dependencies']}
- Total Vulnerabilities: {data['total_vulnerabilities']}
- Critical: {data['critical_vulns']}
- High: {data['high_vulns']}
- Medium: {data['medium_vulns']}
- Low: {data['low_vulns']}

"""
        
        if data['critical_vulnerabilities']:
            text += "Critical Vulnerabilities:\n"
            text += "=" * 30 + "\n"
            for vuln in data['critical_vulnerabilities']:
                text += f"""
Dependency: {vuln['dependency_name']}@{vuln['dependency_version']}
Description: {vuln['description']}
Patch SHA: {vuln['patch_sha']}
Author: {vuln['patch_author']}
Confidence: {vuln['confidence']:.2f}

"""
        
        if data['high_vulnerabilities']:
            text += "High Vulnerabilities:\n"
            text += "=" * 25 + "\n"
            for vuln in data['high_vulnerabilities']:
                text += f"""
Dependency: {vuln['dependency_name']}@{vuln['dependency_version']}
Description: {vuln['description']}
Patch SHA: {vuln['patch_sha']}
Author: {vuln['patch_author']}
Confidence: {vuln['confidence']:.2f}

"""
        
        text += "\nThis is an automated security alert from PatchFrame. Please review these vulnerabilities and take appropriate action."
        
        return text
    
    async def _send_slack_notification(self, notification_data: Dict[str, Any]):
        """Send Slack notification."""
        try:
            if not self.slack_webhook_url:
                return
            
            # Create Slack message
            slack_message = {
                "text": "🚨 PatchFrame Security Alert",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🚨 PatchFrame Security Alert"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Project:*\n{notification_data['project_path']}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Total Vulnerabilities:*\n{notification_data['total_vulnerabilities']}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Critical:*\n{notification_data['critical_vulns']}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*High:*\n{notification_data['high_vulns']}"
                            }
                        ]
                    }
                ]
            }
            
            # Add vulnerability details
            if notification_data['critical_vulnerabilities']:
                slack_message["blocks"].append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Critical Vulnerabilities:*"
                    }
                })
                
                for vuln in notification_data['critical_vulnerabilities'][:3]:  # Limit to 3
                    slack_message["blocks"].append({
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"• {vuln['dependency_name']}@{vuln['dependency_version']}: {vuln['description']}"
                        }
                    })
            
            # Send to Slack
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.slack_webhook_url,
                    json=slack_message
                ) as response:
                    if response.status == 200:
                        logger.info("Slack notification sent successfully")
                    else:
                        logger.error(f"Failed to send Slack notification: {response.status}")
            
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
    
    async def _send_teams_notification(self, notification_data: Dict[str, Any]):
        """Send Microsoft Teams notification."""
        try:
            if not self.teams_webhook_url:
                return
            
            # Create Teams message
            teams_message = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "FF0000",
                "summary": "PatchFrame Security Alert",
                "sections": [
                    {
                        "activityTitle": "🚨 PatchFrame Security Alert",
                        "activitySubtitle": f"Project: {notification_data['project_path']}",
                        "facts": [
                            {
                                "name": "Total Dependencies",
                                "value": str(notification_data['total_dependencies'])
                            },
                            {
                                "name": "Total Vulnerabilities",
                                "value": str(notification_data['total_vulnerabilities'])
                            },
                            {
                                "name": "Critical",
                                "value": str(notification_data['critical_vulns'])
                            },
                            {
                                "name": "High",
                                "value": str(notification_data['high_vulns'])
                            }
                        ]
                    }
                ]
            }
            
            # Add vulnerability details
            if notification_data['critical_vulnerabilities']:
                vuln_text = "**Critical Vulnerabilities:**\n"
                for vuln in notification_data['critical_vulnerabilities'][:3]:
                    vuln_text += f"• {vuln['dependency_name']}@{vuln['dependency_version']}: {vuln['description']}\n"
                
                teams_message["sections"].append({
                    "text": vuln_text
                })
            
            # Send to Teams
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.teams_webhook_url,
                    json=teams_message
                ) as response:
                    if response.status == 200:
                        logger.info("Teams notification sent successfully")
                    else:
                        logger.error(f"Failed to send Teams notification: {response.status}")
            
        except Exception as e:
            logger.error(f"Failed to send Teams notification: {e}")
    
    async def send_scan_completion_notification(self, scan_result: Dict[str, Any]):
        """Send notification about scan completion."""
        try:
            notification_data = self._prepare_scan_completion_notification(scan_result)
            
            # Send notifications
            tasks = []
            
            if self.smtp_config['username']:
                tasks.append(self._send_scan_completion_email(notification_data))
            
            if self.slack_webhook_url:
                tasks.append(self._send_scan_completion_slack(notification_data))
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
                logger.info(f"Sent scan completion notification for: {scan_result.get('project_path', 'Unknown')}")
            
        except Exception as e:
            logger.error(f"Failed to send scan completion notification: {e}")
    
    def _prepare_scan_completion_notification(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare scan completion notification data."""
        summary = scan_result.get('summary', {})
        
        return {
            'project_path': scan_result.get('project_path', 'Unknown'),
            'scan_timestamp': scan_result.get('scan_timestamp', datetime.now().isoformat()),
            'status': 'completed',
            'total_dependencies': summary.get('total_dependencies', 0),
            'total_vulnerabilities': summary.get('total_vulnerabilities', 0),
            'scan_duration': scan_result.get('scan_duration', 'unknown')
        }
    
    async def _send_scan_completion_email(self, notification_data: Dict[str, Any]):
        """Send scan completion email."""
        try:
            subject = f"✅ PatchFrame Scan Complete: {notification_data['project_path']}"
            
            text_content = f"""
PatchFrame Scan Complete
========================

Project: {notification_data['project_path']}
Status: {notification_data['status']}
Scan Time: {notification_data['scan_timestamp']}
Duration: {notification_data['scan_duration']}

Results:
- Total Dependencies: {notification_data['total_dependencies']}
- Total Vulnerabilities: {notification_data['total_vulnerabilities']}

Scan completed successfully.
            """
            
            msg = MIMEMultipart()
            msg['Subject'] = subject
            msg['From'] = self.smtp_config['username']
            msg['To'] = self.smtp_config['username']
            msg.attach(MIMEText(text_content, 'plain'))
            
            with smtplib.SMTP(self.smtp_config['host'], self.smtp_config['port']) as server:
                if self.smtp_config['use_tls']:
                    server.starttls()
                
                if self.smtp_config['username'] and self.smtp_config['password']:
                    server.login(self.smtp_config['username'], self.smtp_config['password'])
                
                server.send_message(msg)
            
            logger.info("Scan completion email sent successfully")
            
        except Exception as e:
            logger.error(f"Failed to send scan completion email: {e}")
    
    async def _send_scan_completion_slack(self, notification_data: Dict[str, Any]):
        """Send scan completion Slack notification."""
        try:
            if not self.slack_webhook_url:
                return
            
            slack_message = {
                "text": "✅ PatchFrame Scan Complete",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "✅ PatchFrame Scan Complete"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Project:*\n{notification_data['project_path']}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Status:*\n{notification_data['status']}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Dependencies:*\n{notification_data['total_dependencies']}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Vulnerabilities:*\n{notification_data['total_vulnerabilities']}"
                            }
                        ]
                    }
                ]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.slack_webhook_url,
                    json=slack_message
                ) as response:
                    if response.status == 200:
                        logger.info("Scan completion Slack notification sent successfully")
                    else:
                        logger.error(f"Failed to send scan completion Slack notification: {response.status}")
            
        except Exception as e:
            logger.error(f"Failed to send scan completion Slack notification: {e}") 