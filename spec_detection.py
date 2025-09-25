import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict, deque

@dataclass
class BehaviorViolation:
    rule_id: str
    severity: str
    description: str
    timestamp: float
    evidence: Dict
    confidence: float

class NormalBehaviorValidator:
    def __init__(self):
        self.violations = []
        self.message_history = deque(maxlen=1000)
        self.session_state = {}
        
    def load_data(self, nas_csv_path: str, rrc_csv_path: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Load NAS and RRC data from CSV files"""
        # NAS CSV columns (updated with new headers)
        nas_cols = [
            'e212_gummei_mcc_show', 'e212_gummei_mcc_value', 'e212_gummei_mcc_showname',
            'e212_gummei_mnc_show', 'e212_gummei_mnc_value', 'e212_gummei_mnc_showname',
            'frame_time_epoch_show', 'frame_time_epoch_value', 'frame_time_epoch_showname',
            'nas-eps_emm_cause_show', 'nas-eps_emm_cause_value', 'nas-eps_emm_cause_showname',
            'nas-eps_emm_eps_att_type_show', 'nas-eps_emm_eps_att_type_value', 
            'nas-eps_emm_eps_att_type_showname', 'nas-eps_emm_m_tmsi_show',
            'nas-eps_emm_m_tmsi_value', 'nas-eps_emm_m_tmsi_showname',
            'nas-eps_nas_msg_emm_type_show', 'nas-eps_nas_msg_emm_type_value',
            'nas-eps_nas_msg_emm_type_showname', 'nas-eps_nas_msg_esm_type_show',
            'nas-eps_nas_msg_esm_type_value', 'nas-eps_nas_msg_esm_type_showname',
            'nas-eps_security_header_type_show', 'nas-eps_security_header_type_value',
            'nas-eps_security_header_type_showname', 'nas-eps_seq_no_show',
            'nas-eps_seq_no_value', 'nas-eps_seq_no_showname', 'label'
        ]
        
        # RRC CSV columns (updated with new headers)
        rrc_cols = [
            'frame_time_epoch_show', 'frame_time_epoch_value', 'frame_time_epoch_showname',
            'lte-rrc_c1_show', 'lte-rrc_c1_value', 'lte-rrc_c1_showname',
            'lte-rrc_c_rnti_show', 'lte-rrc_c_rnti_value', 'lte-rrc_c_rnti_showname',
            'lte-rrc_establishmentcause_show', 'lte-rrc_establishmentcause_value',
            'lte-rrc_establishmentcause_showname', 'lte-rrc_ue_identity_show',
            'lte-rrc_ue_identity_value', 'lte-rrc_ue_identity_showname', 'label'
        ]
        
        nas_df = pd.read_csv(nas_csv_path)
        rrc_df = pd.read_csv(rrc_csv_path)
        
        # Use frame_time_epoch_value as timestamp
        if 'frame_time_epoch_value' in nas_df.columns:
            nas_df['timestamp'] = pd.to_numeric(nas_df['frame_time_epoch_value'], errors='coerce')
        else:
            nas_df['timestamp'] = range(len(nas_df))
            
        if 'frame_time_epoch_value' in rrc_df.columns:
            rrc_df['timestamp'] = pd.to_numeric(rrc_df['frame_time_epoch_value'], errors='coerce')
        else:
            rrc_df['timestamp'] = range(len(rrc_df))
            
        return nas_df, rrc_df
    
    def validate_normal_behavior(self, nas_df: pd.DataFrame, rrc_df: pd.DataFrame):
        """Run all normal behavior validation rules"""
        self._rule_nb1_proper_attach_sequence(nas_df)
        self._rule_nb2_security_progression(nas_df)
        self._rule_nb3_cause_code_legitimacy(nas_df)
        self._rule_nb4_establishment_cause_consistency(nas_df, rrc_df)
        self._rule_nb5_sequence_number_progression(nas_df)
        self._rule_nb6_tmsi_stability(nas_df)
        self._rule_nb7_message_type_flow(nas_df)
        self._rule_nb8_network_identity_consistency(nas_df)
        
        return self.violations
    
    def _rule_nb1_proper_attach_sequence(self, nas_df: pd.DataFrame):
        """NB1: Validate proper attach procedure sequence"""
        attach_requests = nas_df[nas_df['nas-eps_nas_msg_emm_type_value'] == 65]
        
        for idx, attach_req in attach_requests.iterrows():
            # Look for proper sequence after attach request
            subsequent_msgs = nas_df[
                (nas_df['timestamp'] > attach_req['timestamp']) & 
                (nas_df['timestamp'] <= attach_req['timestamp'] + 30)
            ]
            
            expected_sequence = [67, 69, 73, 66]  # Auth Req, Sec Mode, TAU Accept, Attach Accept
            has_valid_response = any(
                subsequent_msgs['nas-eps_nas_msg_emm_type_value'].isin(expected_sequence)
            )
            
            # Check for immediate reject without proper procedure
            immediate_reject = subsequent_msgs[
                (subsequent_msgs['nas-eps_nas_msg_emm_type_value'] == 68) &  # Attach Reject
                (subsequent_msgs['timestamp'] <= attach_req['timestamp'] + 5)
            ]
            
            if not has_valid_response and len(immediate_reject) > 0:
                self.violations.append(BehaviorViolation(
                    rule_id='NB1',
                    severity='HIGH',
                    description='Attach request followed by immediate reject without proper procedure',
                    timestamp=attach_req['timestamp'],
                    evidence={
                        'attach_timestamp': attach_req['timestamp'],
                        'reject_timestamp': immediate_reject.iloc[0]['timestamp'],
                        'time_diff': immediate_reject.iloc[0]['timestamp'] - attach_req['timestamp']
                    },
                    confidence=0.9
                ))
    
    def _rule_nb2_security_progression(self, nas_df: pd.DataFrame):
        """NB2: Validate security header progression follows protocol"""
        security_progression = nas_df.groupby('nas-eps_emm_m_tmsi_value')['nas-eps_security_header_type_value'].apply(list)
        
        for tmsi, sec_headers in security_progression.items():
            if pd.isna(tmsi) or len(sec_headers) < 2:
                continue
                
            # Security should not downgrade without explicit procedure
            for i in range(1, len(sec_headers)):
                if pd.notna(sec_headers[i-1]) and pd.notna(sec_headers[i]):
                    # Handle hexadecimal values safely
                    try:
                        prev_sec = int(str(sec_headers[i-1]), 16) if str(sec_headers[i-1]) != '' else 0
                    except (ValueError, TypeError):
                        prev_sec = 0
                    
                    try:
                        curr_sec = int(str(sec_headers[i]), 16) if str(sec_headers[i]) != '' else 0
                    except (ValueError, TypeError):
                        curr_sec = 0
                    
                    # Downgrade from protected to unprotected
                    if prev_sec > 0 and curr_sec == 0:
                        corresponding_row = nas_df[
                            (nas_df['nas-eps_emm_m_tmsi_value'] == tmsi) &
                            (nas_df['nas-eps_security_header_type_value'] == sec_headers[i])
                        ].iloc[0] if len(nas_df[
                            (nas_df['nas-eps_emm_m_tmsi_value'] == tmsi) &
                            (nas_df['nas-eps_security_header_type_value'] == sec_headers[i])
                        ]) > 0 else None
                        
                        if corresponding_row is not None:
                            self.violations.append(BehaviorViolation(
                                rule_id='NB2',
                                severity='HIGH',
                                description='Security header downgrade detected',
                                timestamp=corresponding_row['timestamp'],
                                evidence={
                                    'tmsi': tmsi,
                                    'previous_security': prev_sec,
                                    'current_security': curr_sec
                                },
                                confidence=0.85
                            ))
    
    def _rule_nb3_cause_code_legitimacy(self, nas_df: pd.DataFrame):
        """NB3: Validate cause codes appear in legitimate contexts"""
        # Persistent cause codes that should be rare
        persistent_causes = [8, 15, 3]  
        
        # Filter messages safely
        reject_msgs = nas_df[
            nas_df['nas-eps_nas_msg_emm_type_value'].isin([68, 78])  # Attach/Service Reject
        ]
        
        for idx, reject_msg in reject_msgs.iterrows():
            # Safely convert cause code
            try:
                cause_code = int(str(reject_msg['nas-eps_emm_cause_value']), 16) if pd.notna(reject_msg['nas-eps_emm_cause_value']) else None
            except (ValueError, TypeError):
                cause_code = None
                
            if cause_code not in persistent_causes:
                continue
                
            # Check if reject has integrity protection
            try:
                sec_header = int(str(reject_msg['nas-eps_security_header_type_value']), 16) if pd.notna(reject_msg['nas-eps_security_header_type_value']) else 0
                is_protected = sec_header > 0
            except (ValueError, TypeError):
                is_protected = False
            
            # Look for preceding authentication failure or other legitimate reason
            preceding_msgs = nas_df[
                (nas_df['timestamp'] < reject_msg['timestamp']) &
                (nas_df['timestamp'] >= reject_msg['timestamp'] - 60)
            ]
            
            has_auth_failure = any(
                preceding_msgs['nas-eps_nas_msg_emm_type_value'].isin([71, 84])  # Auth Failure, Auth Reject
            )
            
            if not is_protected and not has_auth_failure:
                self.violations.append(BehaviorViolation(
                    rule_id='NB3',
                    severity='HIGH',
                    description=f'Persistent cause code {cause_code} without legitimate context',
                    timestamp=reject_msg['timestamp'],
                    evidence={
                        'cause_code': cause_code,
                        'message_type': reject_msg['nas-eps_nas_msg_emm_type_value'],
                        'integrity_protected': is_protected,
                        'has_auth_context': has_auth_failure
                    },
                    confidence=0.92
                ))
    
    def _rule_nb4_establishment_cause_consistency(self, nas_df: pd.DataFrame, rrc_df: pd.DataFrame):
        """NB4: Validate RRC establishment cause matches NAS procedure"""
        # Merge RRC and NAS data by timestamp proximity
        for idx, rrc_msg in rrc_df.iterrows():
            if pd.isna(rrc_msg['lte-rrc_establishmentcause_value']):
                continue
                
            # Find NAS messages within 5 seconds
            time_window = 5
            nearby_nas = nas_df[
                (nas_df['timestamp'] >= rrc_msg['timestamp'] - time_window) &
                (nas_df['timestamp'] <= rrc_msg['timestamp'] + time_window)
            ]
            
            rrc_cause = rrc_msg['lte-rrc_establishmentcause_value']
            
            for _, nas_msg in nearby_nas.iterrows():
                nas_type = nas_msg['nas-eps_nas_msg_emm_type_value']
                
                # Define expected mappings
                inconsistent = False
                if rrc_cause == 'mo-Signalling' and nas_type not in [65, 76]:  # Should be Attach/Service Req
                    inconsistent = True
                elif rrc_cause == 'mo-Data' and nas_type != 76:  # Should be Service Request
                    inconsistent = True
                elif rrc_cause == 'emergency' and nas_type != 65:  # Should be Attach Request
                    inconsistent = True
                    
                if inconsistent:
                    self.violations.append(BehaviorViolation(
                        rule_id='NB4',
                        severity='MEDIUM',
                        description='RRC establishment cause inconsistent with NAS procedure',
                        timestamp=nas_msg['timestamp'],
                        evidence={
                            'rrc_cause': rrc_cause,
                            'nas_message_type': nas_type,
                            'time_diff': abs(nas_msg['timestamp'] - rrc_msg['timestamp'])
                        },
                        confidence=0.75
                    ))
    
    def _rule_nb5_sequence_number_progression(self, nas_df: pd.DataFrame):
        """NB5: Validate sequence number progression is logical"""
        tmsi_sequences = nas_df.groupby('nas-eps_emm_m_tmsi_value')['nas-eps_seq_no_value'].apply(list)
        
        for tmsi, seq_nums in tmsi_sequences.items():
            if pd.isna(tmsi) or len(seq_nums) < 2:
                continue
                
            # Remove NaN values and convert to integers safely
            valid_seqs = []
            for s in seq_nums:
                if pd.notna(s) and str(s) != '':
                    try:
                        # Try hex first, then decimal
                        if isinstance(s, str) and any(c in s.lower() for c in 'abcdef'):
                            valid_seqs.append(int(s, 16))
                        else:
                            valid_seqs.append(int(s))
                    except (ValueError, TypeError):
                        continue
            
            if len(valid_seqs) < 2:
                continue
                
            # Check for large gaps or duplicates
            for i in range(1, len(valid_seqs)):
                gap = valid_seqs[i] - valid_seqs[i-1]
                
                if gap > 10:  # Unusually large sequence gap
                    corresponding_rows = nas_df[
                        (nas_df['nas-eps_emm_m_tmsi_value'] == tmsi) &
                        (nas_df['nas-eps_seq_no_value'].notna())
                    ]
                    
                    if len(corresponding_rows) > i:
                        corresponding_row = corresponding_rows.iloc[i]
                        self.violations.append(BehaviorViolation(
                            rule_id='NB5',
                            severity='MEDIUM',
                            description='Abnormal sequence number progression',
                            timestamp=corresponding_row['timestamp'],
                            evidence={
                                'tmsi': tmsi,
                                'sequence_gap': gap,
                                'prev_seq': valid_seqs[i-1],
                                'curr_seq': valid_seqs[i]
                            },
                            confidence=0.7
                        ))
    
    def _rule_nb6_tmsi_stability(self, nas_df: pd.DataFrame):
        """NB6: Validate TMSI changes follow proper procedures"""
        tmsi_changes = []
        current_tmsi = None
        
        for idx, row in nas_df.iterrows():
            if pd.notna(row['nas-eps_emm_m_tmsi_value']):
                if current_tmsi and current_tmsi != row['nas-eps_emm_m_tmsi_value']:
                    tmsi_changes.append({
                        'timestamp': row['timestamp'],
                        'old_tmsi': current_tmsi,
                        'new_tmsi': row['nas-eps_emm_m_tmsi_value'],
                        'message_type': row['nas-eps_nas_msg_emm_type_value']
                    })
                current_tmsi = row['nas-eps_emm_m_tmsi_value']
        
        # Check for rapid TMSI changes without proper procedure
        for i in range(len(tmsi_changes) - 1):
            time_diff = tmsi_changes[i+1]['timestamp'] - tmsi_changes[i]['timestamp']
            
            if time_diff < 30:  # Rapid TMSI change within 30 seconds
                # Check if preceded by TAU Accept or Attach Accept
                msg_type = tmsi_changes[i+1]['message_type']
                if msg_type not in [66, 73]:  # Not Attach Accept or TAU Accept
                    self.violations.append(BehaviorViolation(
                        rule_id='NB6',
                        severity='MEDIUM',
                        description='Rapid TMSI change without proper procedure',
                        timestamp=tmsi_changes[i+1]['timestamp'],
                        evidence={
                            'time_between_changes': time_diff,
                            'message_type': msg_type,
                            'old_tmsi': tmsi_changes[i]['old_tmsi'],
                            'new_tmsi': tmsi_changes[i+1]['new_tmsi']
                        },
                        confidence=0.8
                    ))
    
    def _rule_nb7_message_type_flow(self, nas_df: pd.DataFrame):
        """NB7: Validate message type flows follow protocol state machine"""
        # Define valid message sequences
        valid_transitions = {
            65: [67, 68, 69],    # Attach Request -> Auth Req, Attach Reject, Security Mode
            67: [68, 70, 84],    # Auth Request -> Attach Reject, Auth Response, Auth Reject  
            69: [66, 68, 70],    # Security Mode -> Attach Accept, Attach Reject, Security Mode Response
            76: [77, 78, 69],    # Service Request -> Service Accept, Service Reject, Security Mode
        }
        
        for i in range(len(nas_df) - 1):
            current_msg = nas_df.iloc[i]
            next_msg = nas_df.iloc[i + 1]
            
            if pd.isna(current_msg['nas-eps_nas_msg_emm_type_value']):
                continue
                
            # Safely convert message types
            try:
                curr_type = int(str(current_msg['nas-eps_nas_msg_emm_type_value']), 16) if pd.notna(current_msg['nas-eps_nas_msg_emm_type_value']) else None
            except (ValueError, TypeError):
                continue
                
            try:
                next_type = int(str(next_msg['nas-eps_nas_msg_emm_type_value']), 16) if pd.notna(next_msg['nas-eps_nas_msg_emm_type_value']) else None
            except (ValueError, TypeError):
                next_type = None
            
            # Check if within reasonable time window (30 seconds)
            time_diff = next_msg['timestamp'] - current_msg['timestamp']
            if time_diff > 30:
                continue
                
            if curr_type in valid_transitions and next_type:
                if next_type not in valid_transitions[curr_type]:
                    self.violations.append(BehaviorViolation(
                        rule_id='NB7',
                        severity='MEDIUM',
                        description='Invalid message type transition',
                        timestamp=next_msg['timestamp'],
                        evidence={
                            'from_message_type': curr_type,
                            'to_message_type': next_type,
                            'time_diff': time_diff
                        },
                        confidence=0.65
                    ))
    
    def _rule_nb8_network_identity_consistency(self, nas_df: pd.DataFrame):
        """NB8: Validate network identity (MCC/MNC) remains consistent"""
        unique_networks = nas_df[['e212_gummei_mcc_value', 'e212_gummei_mnc_value']].drop_duplicates()
        
        if len(unique_networks) > 1:
            # Check for network changes within single session
            for tmsi in nas_df['nas-eps_emm_m_tmsi_value'].unique():
                if pd.isna(tmsi):
                    continue
                    
                tmsi_msgs = nas_df[nas_df['nas-eps_emm_m_tmsi_value'] == tmsi]
                tmsi_networks = tmsi_msgs[['e212_gummei_mcc_value', 'e212_gummei_mnc_value']].drop_duplicates()
                
                if len(tmsi_networks) > 1:
                    self.violations.append(BehaviorViolation(
                        rule_id='NB8',
                        severity='HIGH',
                        description='Network identity change within single TMSI session',
                        timestamp=tmsi_msgs.iloc[-1]['timestamp'],
                        evidence={
                            'tmsi': tmsi,
                            'network_changes': len(tmsi_networks),
                            'networks': tmsi_networks.to_dict('records')
                        },
                        confidence=0.9
                    ))
    
    def generate_behavior_report(self):
        """Generate comprehensive behavior analysis report"""
        total_violations = len(self.violations)
        high_severity = len([v for v in self.violations if v.severity == 'HIGH'])
        medium_severity = len([v for v in self.violations if v.severity == 'MEDIUM'])
        
        rule_counts = {}
        for violation in self.violations:
            rule_counts[violation.rule_id] = rule_counts.get(violation.rule_id, 0) + 1
        
        return {
            'summary': {
                'total_violations': total_violations,
                'high_severity_violations': high_severity,
                'medium_severity_violations': medium_severity,
                'rule_trigger_counts': rule_counts
            },
            'violations': [
                {
                    'rule_id': v.rule_id,
                    'severity': v.severity,
                    'description': v.description,
                    'timestamp': v.timestamp,
                    'confidence': v.confidence,
                    'evidence': v.evidence
                }
                for v in sorted(self.violations, key=lambda x: x.timestamp)
            ],
            'behavior_assessment': self._assess_overall_behavior()
        }
    
    def _assess_overall_behavior(self):
        """Assess overall behavior normalcy"""
        if len(self.violations) == 0:
            return "NORMAL - No behavioral violations detected"
        elif len([v for v in self.violations if v.severity == 'HIGH']) > 3:
            return "HIGHLY SUSPICIOUS - Multiple high-severity violations"
        elif len([v for v in self.violations if v.severity == 'HIGH']) > 0:
            return "SUSPICIOUS - High-severity violations detected"
        else:
            return "MINOR_ANOMALIES - Only minor violations detected"

def main():
    """Main execution function"""
    validator = NormalBehaviorValidator()
    
    try:
        # Load CSV data
        nas_df, rrc_df = validator.load_data('emm_information_20250921_232148_nas.csv', 'emm_information_20250921_232148_rrc.csv')
        print(f"Loaded {len(nas_df)} NAS messages and {len(rrc_df)} RRC messages")
        
        # Run behavior validation
        violations = validator.validate_normal_behavior(nas_df, rrc_df)
        
        # Generate report
        report = validator.generate_behavior_report()
        
        print(f"\nBehavior Analysis Complete:")
        print(f"Total Violations: {report['summary']['total_violations']}")
        print(f"High Severity: {report['summary']['high_severity_violations']}")
        print(f"Assessment: {report['behavior_assessment']}")
        
        # Display violations
        for violation in report['violations']:
            print(f"\n[{violation['severity']}] {violation['rule_id']}: {violation['description']}")
            print(f"Confidence: {violation['confidence']:.2f}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()