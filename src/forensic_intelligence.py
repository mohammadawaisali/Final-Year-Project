"""
Forensic Intelligence Module
Provides contextual analysis, risk scoring, and anomaly correlation
Reduces false positives through intelligent reasoning
"""

from datetime import datetime, timedelta
from typing import Dict, List, Tuple

class ForensicIntelligence:
    """
    Intelligent forensic analysis engine
    Provides contextual interpretation and confidence scoring
    """
    
    # Risk weights for different anomaly types
    ANOMALY_WEIGHTS = {
        'timestamp_future': 0.9,              # Very suspicious
        'timestamp_impossible': 1.0,          # Extremely suspicious
        'timestamp_metadata_mismatch_high': 0.7,  # Suspicious
        'timestamp_metadata_mismatch_medium': 0.3,  # Weak signal
        'metadata_stripped': 0.6,             # Moderately suspicious
        'author_mismatch': 0.2,               # Very weak signal (often normal)
        'unusual_application': 0.4,           # Weak to moderate
        'missing_camera_info': 0.3,           # Weak (images only)
        'missing_author': 0.5,                # Moderate
        'entropy_very_high': 0.8,             # Suspicious
        'signature_mismatch': 0.9,            # Very suspicious
    }
    
    # Known benign software variants
    KNOWN_APPLICATIONS = {
        'Microsoft Office Word',
        'Microsoft Macintosh Word',
        'Microsoft Word',
        'Word',
        'Microsoft Excel',
        'Microsoft PowerPoint',
        'LibreOffice Writer',
        'LibreOffice Calc',
        'LibreOffice Impress',
        'LibreOffice',
        'Pages',
        'Numbers',
        'Keynote',
        'Google Docs',
        'WPS Office',
        'OpenOffice'
    }
    
    def __init__(self):
        """Initialize forensic intelligence engine"""
        self.risk_thresholds = {
            'normal': 0.0,
            'low_risk': 0.3,
            'suspicious': 0.6,
            'highly_suspicious': 0.8
        }
    
    def analyze_anomalies(self, raw_indicators: List[str], metadata: Dict, 
                         file_type: str) -> Dict:
        """
        Analyze raw anomaly indicators and provide intelligent assessment
        
        Args:
            raw_indicators: List of raw anomaly strings
            metadata: File metadata dictionary
            file_type: Type of file being analyzed
            
        Returns:
            dict: Intelligent analysis with scoring and explanations
        """
        
        # Parse and classify anomalies
        classified_anomalies = self._classify_anomalies(
            raw_indicators, metadata, file_type
        )
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(classified_anomalies)
        
        # Determine risk level
        risk_level = self._determine_risk_level(risk_score)
        
        # Generate contextual explanations
        explanations = self._generate_explanations(
            classified_anomalies, metadata, file_type
        )
        
        # Correlate anomalies for stronger conclusions
        correlated_findings = self._correlate_anomalies(
            classified_anomalies, metadata
        )
        
        return {
            'risk_score': round(risk_score, 2),
            'risk_level': risk_level,
            'classified_anomalies': classified_anomalies,
            'explanations': explanations,
            'correlated_findings': correlated_findings,
            'requires_investigation': risk_level in ['suspicious', 'highly_suspicious']
        }
    
    def _classify_anomalies(self, raw_indicators: List[str], metadata: Dict, 
                           file_type: str) -> List[Dict]:
        """
        Classify raw anomaly indicators into structured categories
        """
        classified = []
        
        for indicator in raw_indicators:
            indicator_lower = indicator.lower()
            
            # Timestamp anomalies
            if 'future' in indicator_lower:
                if 'modified' in indicator_lower or 'created' in indicator_lower:
                    classified.append({
                        'type': 'timestamp_future',
                        'severity': 'high',
                        'raw': indicator,
                        'benign_explanation': 'System clock misconfiguration',
                        'malicious_explanation': 'Timestamp manipulation to hide activity'
                    })
            
            elif 'impossible' in indicator_lower or 'newer than modified' in indicator_lower:
                classified.append({
                    'type': 'timestamp_impossible',
                    'severity': 'critical',
                    'raw': indicator,
                    'benign_explanation': 'File copy/transfer artifact',
                    'malicious_explanation': 'Manual timestamp manipulation'
                })
            
            elif 'differs from file system' in indicator_lower:
                # Extract day difference if possible
                try:
                    days_diff = int(''.join(filter(str.isdigit, indicator)))
                except:
                    days_diff = 0
                
                # Contextual assessment of timestamp difference
                if days_diff > 3650:  # > 10 years
                    # Likely template or generated file
                    classified.append({
                        'type': 'timestamp_metadata_mismatch_medium',
                        'severity': 'low',
                        'raw': indicator,
                        'benign_explanation': f'Template-based or generated file (difference: {days_diff} days suggests creation from old template)',
                        'malicious_explanation': 'Metadata backdating (less likely with such large differences)'
                    })
                elif days_diff > 365:  # > 1 year but < 10 years
                    classified.append({
                        'type': 'timestamp_metadata_mismatch_medium',
                        'severity': 'medium',
                        'raw': indicator,
                        'benign_explanation': f'File from old template or restored from backup ({days_diff} days)',
                        'malicious_explanation': 'Possible metadata manipulation'
                    })
                elif days_diff > 30:  # > 1 month
                    classified.append({
                        'type': 'timestamp_metadata_mismatch_high',
                        'severity': 'medium-high',
                        'raw': indicator,
                        'benign_explanation': f'Modified after extended period ({days_diff} days)',
                        'malicious_explanation': 'Possible timestamp alteration'
                    })
                else:
                    # Small difference - likely normal
                    continue
            
            # Author/editor anomalies
            elif 'modified by different user' in indicator_lower:
                # This is OFTEN normal in collaborative environments
                last_modifier = metadata.get('LastModifiedBy', '')
                author = metadata.get('Author', '')
                
                # Check if it's a suspicious pattern
                is_suspicious_pattern = self._is_suspicious_author_pattern(
                    author, last_modifier
                )
                
                if is_suspicious_pattern:
                    classified.append({
                        'type': 'author_mismatch',
                        'severity': 'medium',
                        'raw': indicator,
                        'benign_explanation': 'Collaborative editing (normal in shared documents)',
                        'malicious_explanation': f'Document modified by unauthorized user: {last_modifier}'
                    })
                else:
                    # Normal collaboration - downgrade severity
                    classified.append({
                        'type': 'author_mismatch',
                        'severity': 'info',
                        'raw': indicator,
                        'benign_explanation': 'Normal collaborative editing',
                        'malicious_explanation': 'Unlikely to be malicious'
                    })
            
            # Application anomalies
            elif 'unusual application' in indicator_lower:
                app_name = metadata.get('Application', '')
                
                # Check against known applications
                if self._is_known_application(app_name):
                    # False positive - ignore
                    continue
                else:
                    classified.append({
                        'type': 'unusual_application',
                        'severity': 'low',
                        'raw': indicator,
                        'benign_explanation': f'Uncommon software used: {app_name}',
                        'malicious_explanation': 'Potentially malicious document creation tool'
                    })
            
            # Metadata stripping
            elif 'no exif' in indicator_lower or 'stripped' in indicator_lower:
                if file_type == 'image':
                    classified.append({
                        'type': 'metadata_stripped',
                        'severity': 'medium',
                        'raw': indicator,
                        'benign_explanation': 'Privacy protection (common for social media images)',
                        'malicious_explanation': 'Evidence concealment'
                    })
            
            elif 'no author' in indicator_lower or 'no camera' in indicator_lower:
                classified.append({
                    'type': 'missing_author',
                    'severity': 'low',
                    'raw': indicator,
                    'benign_explanation': 'File created programmatically or metadata not captured',
                    'malicious_explanation': 'Metadata deliberately removed'
                })
            
            # Generic catch-all for other indicators
            else:
                classified.append({
                    'type': 'other',
                    'severity': 'low',
                    'raw': indicator,
                    'benign_explanation': 'Minor anomaly',
                    'malicious_explanation': 'Requires further investigation'
                })
        
        return classified
    
    def _is_known_application(self, app_name: str) -> bool:
        """Check if application is in known benign list"""
        if not app_name or app_name == 'N/A':
            return False
        
        # Normalize and check
        app_normalized = app_name.strip()
        
        # Exact match
        if app_normalized in self.KNOWN_APPLICATIONS:
            return True
        
        # Partial match for variants
        for known_app in self.KNOWN_APPLICATIONS:
            if known_app.lower() in app_normalized.lower():
                return True
            if app_normalized.lower() in known_app.lower():
                return True
        
        return False
    
    def _is_suspicious_author_pattern(self, author: str, last_modifier: str) -> bool:
        """
        Determine if author mismatch represents a suspicious pattern
        """
        if not author or not last_modifier or author == 'N/A' or last_modifier == 'N/A':
            return False
        
        # Check for obviously suspicious patterns
        suspicious_keywords = ['hacker', 'anonymous', 'unknown', 'temp', 'admin', 
                              'root', 'system', 'malicious', 'attacker']
        
        for keyword in suspicious_keywords:
            if keyword in last_modifier.lower():
                return True
        
        # Normal collaboration indicators
        # Same organization (e.g., john.smith@company.com, jane.doe@company.com)
        if '@' in author and '@' in last_modifier:
            author_domain = author.split('@')[-1]
            modifier_domain = last_modifier.split('@')[-1]
            if author_domain == modifier_domain:
                return False  # Same organization - likely benign
        
        # Different people, no red flags - likely normal collaboration
        return False
    
    def _calculate_risk_score(self, classified_anomalies: List[Dict]) -> float:
        """
        Calculate overall risk score based on weighted anomalies
        """
        if not classified_anomalies:
            return 0.0
        
        total_weight = 0.0
        
        for anomaly in classified_anomalies:
            anomaly_type = anomaly.get('type', 'other')
            severity = anomaly.get('severity', 'low')
            
            # Get base weight
            base_weight = self.ANOMALY_WEIGHTS.get(anomaly_type, 0.2)
            
            # Adjust based on severity
            severity_multiplier = {
                'info': 0.1,
                'low': 0.5,
                'medium': 1.0,
                'medium-high': 1.3,
                'high': 1.5,
                'critical': 2.0
            }.get(severity, 1.0)
            
            total_weight += base_weight * severity_multiplier
        
        # Normalize to 0-1 range (cap at 1.0)
        # Use logarithmic scaling to prevent single anomalies from dominating
        import math
        risk_score = min(1.0, 1 - math.exp(-total_weight))
        
        return risk_score
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level category from score"""
        if risk_score >= self.risk_thresholds['highly_suspicious']:
            return 'highly_suspicious'
        elif risk_score >= self.risk_thresholds['suspicious']:
            return 'suspicious'
        elif risk_score >= self.risk_thresholds['low_risk']:
            return 'low_risk'
        else:
            return 'normal'
    
    def _generate_explanations(self, classified_anomalies: List[Dict], 
                               metadata: Dict, file_type: str) -> List[Dict]:
        """
        Generate human-readable explanations for each finding
        """
        explanations = []
        
        for anomaly in classified_anomalies:
            # Skip info-level items
            if anomaly.get('severity') == 'info':
                continue
            
            explanation = {
                'finding': anomaly['raw'],
                'severity': anomaly['severity'],
                'likely_benign_reason': anomaly.get('benign_explanation', 'Unknown'),
                'possible_malicious_reason': anomaly.get('malicious_explanation', 'Unknown'),
                'recommendation': self._get_recommendation(anomaly)
            }
            
            explanations.append(explanation)
        
        return explanations
    
    def _get_recommendation(self, anomaly: Dict) -> str:
        """Get investigation recommendation based on anomaly"""
        severity = anomaly.get('severity', 'low')
        anomaly_type = anomaly.get('type', 'other')
        
        if severity in ['critical', 'high']:
            return "PRIORITY: Manual verification required"
        elif severity == 'medium-high':
            return "Recommended: Verify with file owner/creator"
        elif severity == 'medium':
            return "Suggested: Review in context of other findings"
        else:
            return "Optional: Note for reference"
    
    def _correlate_anomalies(self, classified_anomalies: List[Dict], 
                            metadata: Dict) -> List[str]:
        """
        Correlate multiple weak signals into stronger conclusions
        """
        findings = []
        
        # Get anomaly types present
        anomaly_types = [a['type'] for a in classified_anomalies]
        
        # Pattern 1: Timestamp manipulation + Author mismatch
        if ('timestamp_metadata_mismatch_high' in anomaly_types or 
            'timestamp_impossible' in anomaly_types) and \
           'author_mismatch' in anomaly_types:
            findings.append(
                "⚠️ CORRELATION: Timestamp anomaly combined with author mismatch "
                "suggests possible document backdating or metadata manipulation"
            )
        
        # Pattern 2: Multiple timestamp anomalies
        timestamp_anomalies = [a for a in classified_anomalies 
                              if 'timestamp' in a['type']]
        if len(timestamp_anomalies) >= 2:
            findings.append(
                f"⚠️ CORRELATION: Multiple timestamp anomalies ({len(timestamp_anomalies)}) "
                "increase likelihood of deliberate manipulation"
            )
        
        # Pattern 3: Metadata stripping + Unusual application
        if 'metadata_stripped' in anomaly_types and 'unusual_application' in anomaly_types:
            findings.append(
                "⚠️ CORRELATION: Metadata removal combined with unusual creation tool "
                "may indicate anti-forensic activity"
            )
        
        # Pattern 4: No concerning correlations
        if not findings and classified_anomalies:
            findings.append(
                "✓ No significant correlation between anomalies detected. "
                "Findings appear independent and may be benign."
            )
        
        return findings


class ForensicReporter:
    """Enhanced reporting with forensic intelligence"""
    
    @staticmethod
    def format_intelligent_findings(analysis: Dict, filename: str) -> str:
        """
        Format analysis results into readable forensic report
        """
        risk_level = analysis['risk_level']
        risk_score = analysis['risk_score']
        
        # Risk level emoji and description
        risk_display = {
            'normal': ('✓', 'NORMAL', 'No significant anomalies detected'),
            'low_risk': ('ℹ️', 'LOW RISK', 'Minor anomalies - likely benign'),
            'suspicious': ('⚠️', 'SUSPICIOUS', 'Multiple anomalies - review recommended'),
            'highly_suspicious': ('🚨', 'HIGHLY SUSPICIOUS', 'Significant anomalies - investigation required')
        }
        
        symbol, level_text, description = risk_display.get(
            risk_level, ('?', 'UNKNOWN', 'Unable to assess')
        )
        
        report = [
            f"\n{symbol} {filename}",
            f"   Risk Level: {level_text} (Score: {risk_score:.2f}/1.00)",
            f"   Assessment: {description}"
        ]
        
        # Add explanations
        if analysis['explanations']:
            report.append(f"\n   Findings:")
            for i, exp in enumerate(analysis['explanations'], 1):
                report.append(f"\n   [{i}] {exp['finding']}")
                report.append(f"       Severity: {exp['severity'].upper()}")
                report.append(f"       Likely Benign: {exp['likely_benign_reason']}")
                if exp['severity'] in ['high', 'critical', 'medium-high']:
                    report.append(f"       Possible Threat: {exp['possible_malicious_reason']}")
                report.append(f"       → {exp['recommendation']}")
        
        # Add correlations
        if analysis['correlated_findings']:
            report.append(f"\n   Correlation Analysis:")
            for finding in analysis['correlated_findings']:
                report.append(f"   {finding}")
        
        return '\n'.join(report)