#!/usr/bin/env python3
# coding: utf8

import tempfile
import os
import struct
import datetime
import logging
import re
import csv
from io import StringIO
from pathlib import Path

# Conditional import of pyshark
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    pyshark = None

class DataWriter:
    """Enhanced PCAP writing with Wireshark dissector integration"""

    def __init__(self):
        self.port_cp = 4729
        self.port_up = 47290
        self.ip_id = 0
        self.base_address = 0x7f000001
        self.eth_hdr = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00'
        self.logger = logging.getLogger(__name__)

        # Dissector directory path (kept for potential future use)
        self.dissector_path = Path(__file__).parent / "dissector"
        
        # CSV export data
        self._rrc_packets_data = []
        self._all_rrc_fields = set()
        self._packet_count = 0

        # Layer usage statistics for optimization
        self._layer_stats = {
            'processed': {},
            'skipped': {},
            'total_packets': 0
        }

        # Optimized layer filtering sets for faster lookup
        self._transport_layers = frozenset(['ip', 'eth', 'udp', 'tcp', 'frame', 'geninfo'])
        self._protocol_keywords = frozenset(['rrc', 'nas', 'mac', 'rlc', 'pdcp', 'gsm', 'umts', 'lte', 'nr'])

    def get_layer_filtering_info(self):
        """Get information about current layer filtering configuration"""
        return {
            'transport_layers': list(self._transport_layers),
            'protocol_keywords': list(self._protocol_keywords),
            'layer_stats': self._layer_stats.copy()
        }





    def _identify_packet_protocol(self, packet):
        """Identify the actual protocol from packet layers"""
        try:
            protocol_info = {
                'primary_protocol': 'unknown',
                'secondary_protocol': 'unknown',
                'nested_protocol': 'unknown',
                'channel_type': 'unknown',
                'message_type': 'unknown'
            }
            
            # First try to identify from GSMTAP layer if present
            for layer in packet.layers:
                try:
                    layer_name = layer.layer_name.lower()
                    
                    if layer_name == 'gsmtap':
                        # Try to get GSMTAP protocol info
                        if hasattr(layer, 'field_names'):
                            for field_name in layer.field_names:
                                field_value = getattr(layer, field_name, None)
                                if field_value:
                                    if 'type' in field_name.lower():
                                        # Map GSMTAP type to protocol
                                        try:
                                            gsmtap_type = int(field_value)
                                            if gsmtap_type == 0x0d:  # LTE RRC
                                                protocol_info['primary_protocol'] = 'lte_rrc'
                                            elif gsmtap_type == 0x12:  # LTE NAS
                                                protocol_info['primary_protocol'] = 'nas_eps'
                                            elif gsmtap_type == 0x0e:  # LTE MAC
                                                protocol_info['primary_protocol'] = 'mac_lte'
                                            elif gsmtap_type == 0x0c:  # UMTS RRC
                                                protocol_info['primary_protocol'] = 'umts_rrc'
                                            elif gsmtap_type == 0x01:  # GSM UM
                                                protocol_info['primary_protocol'] = 'gsm_um'
                                            elif gsmtap_type == 0x02:  # GSM ABIS
                                                protocol_info['primary_protocol'] = 'gsm_abis'
                                            elif gsmtap_type == 0x10:  # Osmocom
                                                protocol_info['primary_protocol'] = 'osmocore'
                                            elif gsmtap_type == 0x11:  # Qualcomm
                                                protocol_info['primary_protocol'] = 'qc_diag'
                                        except (ValueError, TypeError):
                                            pass
                                    
                                    if 'subtype' in field_name.lower():
                                        protocol_info['channel_type'] = str(field_value)

                                    # Detect nested protocol from GSMTAP type
                                    if 'type' in field_name.lower():
                                        gsmtap_type = int(field_value) if field_value.isdigit() else 0
                                        if gsmtap_type == 0x0d and protocol_info['primary_protocol'] == 'unknown':
                                            protocol_info['primary_protocol'] = 'lte_rrc'
                                        elif gsmtap_type == 0x12 and protocol_info['primary_protocol'] == 'unknown':
                                            protocol_info['primary_protocol'] = 'nas_eps'
                                        elif gsmtap_type == 0x0e and protocol_info['primary_protocol'] == 'unknown':
                                            protocol_info['primary_protocol'] = 'mac_lte'
                                        elif gsmtap_type == 0x0c and protocol_info['primary_protocol'] == 'unknown':
                                            protocol_info['primary_protocol'] = 'umts_rrc'

                        break
                        
                except Exception as e:
                    continue
            
            # If no GSMTAP info, try to identify from other layers
            if protocol_info['primary_protocol'] == 'unknown':
                for layer in packet.layers:
                    try:
                        layer_name = layer.layer_name.lower()
            
                        # Skip transport layers
                        if layer_name in ['ip', 'eth', 'udp', 'tcp', 'frame', 'geninfo']:
                            continue

                        # Identify primary protocol from layer names
                        if 'rrc' in layer_name:
                            if 'lte' in layer_name:
                                protocol_info['primary_protocol'] = 'lte_rrc'
                                # Check for nested NAS-EPS in LTE RRC
                                if any('nas' in l.layer_name.lower() for l in packet.layers):
                                    protocol_info['nested_protocol'] = 'nas_eps'
                            elif 'nr' in layer_name:
                                protocol_info['primary_protocol'] = 'nr_rrc'
                                # Check for nested NAS-5GS in NR RRC
                                if any('nas' in l.layer_name.lower() for l in packet.layers):
                                    protocol_info['nested_protocol'] = 'nas_5gs'
                            elif 'umts' in layer_name:
                                protocol_info['primary_protocol'] = 'umts_rrc'
                                # Check for nested NAS-EPS in UMTS RRC
                                if any('nas' in l.layer_name.lower() for l in packet.layers):
                                    protocol_info['nested_protocol'] = 'nas_eps'
                            else:
                                protocol_info['primary_protocol'] = 'rrc'

                            # Check for dedicatedInfoNAS field within RRC layers
                            if hasattr(layer, 'field_names'):
                                for field_name in layer.field_names:
                                    field_name_lower = field_name.lower()
                                    # Check for various NAS-related fields in RRC
                                    nas_indicators = [
                                        'dedicatedinfonas', 'dedicated_info_nas',
                                        'dedicatedinfonaslist', 'dedicated_info_nas_list',
                                        'nas_message', 'nas_msg', 'emm_msg', 'esm_msg'
                                    ]

                                    if any(indicator in field_name_lower for indicator in nas_indicators):
                                        field_value = getattr(layer, field_name, None)
                                        if field_value and str(field_value).strip() and str(field_value) != '0':
                                            # This RRC packet contains NAS data

                                            if 'lte' in layer_name:
                                                protocol_info['nested_protocol'] = 'nas_eps'
                                            elif 'nr' in layer_name:
                                                protocol_info['nested_protocol'] = 'nas_5gs'
                                            elif 'umts' in layer_name:
                                                protocol_info['nested_protocol'] = 'nas_eps'
                        elif 'nas' in layer_name:
                            if 'eps' in layer_name:
                                protocol_info['primary_protocol'] = 'nas_eps'
                            elif '5gs' in layer_name:
                                protocol_info['primary_protocol'] = 'nas_5gs'
                            else:
                                protocol_info['primary_protocol'] = 'nas'
                        elif 'mac' in layer_name:
                            if 'lte' in layer_name:
                                protocol_info['primary_protocol'] = 'mac_lte'
                            elif 'nr' in layer_name:
                                protocol_info['primary_protocol'] = 'mac_nr'
                            else:
                                protocol_info['primary_protocol'] = 'mac'
                        elif 'gsm' in layer_name:
                            protocol_info['primary_protocol'] = 'gsm'
                        elif 'umts' in layer_name:
                            protocol_info['primary_protocol'] = 'umts'
                        elif 'lte' in layer_name:
                            protocol_info['primary_protocol'] = 'lte'
                        elif 'nr' in layer_name:
                            protocol_info['primary_protocol'] = 'nr'
                        
                        # Try to identify message type and channel
                        if hasattr(layer, 'field_names'):
                            for field_name in layer.field_names:
                                field_value = getattr(layer, field_name, None)
                                if field_value:
                                    # Look for message type indicators - be more comprehensive
                                    field_name_lower = field_name.lower()
                                    field_value_str = str(field_value).lower()

                                    # Message type detection - try to get display value first
                                    display_value = self._get_display_value_from_field(layer, field_name, field_value)

                                    # Enhanced message type detection with comprehensive field name patterns
                                    if protocol_info['message_type'] == 'unknown':
                                        # Primary message type fields
                                        if any(pattern in field_name_lower for pattern in [
                                            'message', 'msg', 'procedure', 'command', 'response',
                                            'request', 'complete', 'reject', 'failure', 'cause'
                                        ]) and field_value != '0' and field_value != '':
                                            protocol_info['message_type'] = display_value

                                        # Protocol-specific message type fields
                                        elif any(pattern in field_name_lower for pattern in [
                                            'rrc_message', 'nas_message', 'lte_rrc_message',
                                            'emm_message', 'esm_message', 'message_type',
                                            'rrc_msg', 'nas_msg', 'emm_msg', 'esm_msg'
                                        ]) and field_value != '0' and field_value != '':
                                            protocol_info['message_type'] = display_value

                                        # Specific message type indicators
                                        elif any(pattern in field_name_lower for pattern in [
                                            'paging_type', 'connection_type', 'handover_type',
                                            'measurement_type', 'security_type', 'capability_type',
                                            'system_type', 'information_type', 'setup_type'
                                        ]) and field_value != '0' and field_value != '':
                                            protocol_info['message_type'] = display_value

                                        # Type fields (excluding channel types)
                                        elif ('type' in field_name_lower and
                                              'channel' not in field_name_lower and
                                              field_value != '0' and field_value != ''):
                                            protocol_info['message_type'] = display_value

                                    # Channel type detection
                                    if ('channel' in field_name_lower and
                                        field_value != '0' and field_value != ''):
                                        protocol_info['channel_type'] = str(field_value)
                                    elif ('subtype' in field_name_lower and
                                          field_value != '0' and field_value != ''):
                                        protocol_info['channel_type'] = str(field_value)
                                    elif ('direction' in field_name_lower and
                                          field_value != '0' and field_value != ''):
                                        protocol_info['channel_type'] = str(field_value)

                                    # Special handling for NAS message type fields
                                    if (protocol_info['primary_protocol'] in ['nas_eps', 'nas_5gs'] and
                                        protocol_info['message_type'] == 'unknown'):
                                        # Look for specific NAS message type fields
                                        if any(nas_field in field_name_lower for nas_field in [
                                            'nas_msg_type', 'emm_type', 'esm_type', 'message_type',
                                            'protocol_discriminator', 'security_header_type'
                                        ]):
                                            if field_value != '0' and field_value != '':
                                                protocol_info['message_type'] = display_value

                                        # Special cases for system information
                                        elif 'bcch_bch_message' in field_name_lower:
                                            protocol_info['message_type'] = 'MasterInformationBlock'
                                        elif 'systeminformationblock' in field_name_lower or 'sib' in field_name_lower:
                                            if 'type' in field_name_lower:
                                                protocol_info['message_type'] = f'SIB{field_value}'

                    except Exception as e:
                        continue
            
            # Final attempt: analyze field values for message types and channels
            if protocol_info['message_type'] == 'unknown' or protocol_info['channel_type'] == 'unknown':
                for layer in packet.layers:
                    try:
                        layer_name = layer.layer_name.lower()
                        if layer_name in ['ip', 'eth', 'udp', 'tcp', 'frame', 'geninfo']:
                            continue
                            
                        if hasattr(layer, 'field_names'):
                            for field_name in layer.field_names:
                                field_value = getattr(layer, field_name, None)
                                if field_value:
                                    field_str = str(field_value).lower()
                                    
                                    # Message type detection from field values
                                    if protocol_info['message_type'] == 'unknown':
                                        # Common RRC message types
                                        if any(msg in field_str for msg in [
                                            'connection', 'setup', 'release', 'reconfig', 'reestablishment',
                                            'attach', 'detach', 'update', 'request', 'response', 'complete',
                                            'reject', 'failure', 'handover', 'measurement', 'security',
                                            'capability', 'information', 'system', 'paging', 'broadcast'
                                        ]):
                                            display_value = self._get_display_value_from_field(layer, field_name, field_value)
                                            protocol_info['message_type'] = display_value
                                        # Common NAS message types
                                        elif any(msg in field_str for msg in [
                                            'attach', 'detach', 'update', 'request', 'response', 'complete',
                                            'reject', 'failure', 'security', 'authentication', 'identity',
                                            'location', 'routing', 'service', 'pdn', 'bearer', 'session',
                                            'registration', 'deregistration', 'configuration', 'notification'
                                        ]):
                                            display_value = self._get_display_value_from_field(layer, field_name, field_value)
                                            protocol_info['message_type'] = display_value
                                        # Additional common protocol message patterns
                                        elif any(msg in field_str for msg in [
                                            'paging', 'rrcconnection', 'connectionrequest', 'connectionsetup',
                                            'connectioncomplete', 'connectionreject', 'connectionrelease',
                                            'handovercommand', 'handovercomplete', 'measurementreport',
                                            'securitymode', 'uecapability', 'systeminformation',
                                            'masterinformation', 'sib', 'systeminfo'
                                        ]):
                                            display_value = self._get_display_value_from_field(layer, field_name, field_value)
                                            protocol_info['message_type'] = display_value

                                    # Channel type detection from field values
                                    if protocol_info['channel_type'] == 'unknown':
                                        # Common channel types
                                        if any(channel in field_str for channel in [
                                            'ccch', 'dcch', 'bcch', 'pcch', 'mcch', 'scch',
                                            'uplink', 'downlink', 'ul', 'dl', 'broadcast', 'control',
                                            'traffic', 'signaling', 'data', 'control'
                                        ]):
                                            protocol_info['channel_type'] = str(field_value)


                                
                    except Exception as e:
                        continue
            
            # Final check: ensure nested protocol is detected
            if protocol_info['nested_protocol'] == 'unknown':
                all_layer_names = [l.layer_name.lower() for l in packet.layers]

                # Check for common nested protocol patterns
                if protocol_info['primary_protocol'] == 'lte_rrc' and any('nas' in name for name in all_layer_names):
                    protocol_info['nested_protocol'] = 'nas_eps'
                elif protocol_info['primary_protocol'] == 'nr_rrc' and any('nas' in name for name in all_layer_names):
                    protocol_info['nested_protocol'] = 'nas_5gs'
                elif protocol_info['primary_protocol'] == 'umts_rrc' and any('nas' in name for name in all_layer_names):
                    protocol_info['nested_protocol'] = 'nas_eps'

                # Check for NAS-related fields in any RRC layer and enhance info field
                for layer in packet.layers:
                    if 'rrc' in layer.layer_name.lower() and hasattr(layer, 'field_names'):
                        for field_name in layer.field_names:
                            field_name_lower = field_name.lower()
                            # Check for various NAS-related fields in RRC
                            nas_indicators = [
                                'dedicatedinfonas', 'dedicated_info_nas',
                                'dedicatedinfonaslist', 'dedicated_info_nas_list',
                                'nas_message', 'nas_msg', 'emm_msg', 'esm_msg'
                            ]

                            if any(indicator in field_name_lower for indicator in nas_indicators):
                                field_value = getattr(layer, field_name, None)
                                if field_value and str(field_value).strip() and str(field_value) != '0':
                                    # Found NAS data in RRC packet

                                    if 'lte' in layer.layer_name.lower():
                                        protocol_info['nested_protocol'] = 'nas_eps'
                                    elif 'nr' in layer.layer_name.lower():
                                        protocol_info['nested_protocol'] = 'nas_5gs'
                                    elif 'umts' in layer.layer_name.lower():
                                        protocol_info['nested_protocol'] = 'nas_eps'
                                    break

                            # Enhanced message type extraction for system messages
                            if protocol_info['message_type'] == 'unknown':
                                # Check for BCCH-BCH message (MasterInformationBlock)
                                if 'bcch_bch_message' in field_name_lower:
                                    protocol_info['message_type'] = 'MasterInformationBlock'
                                # Check for system information blocks
                                elif 'systeminformationblock' in field_name_lower and 'type' in field_name_lower:
                                    field_value = getattr(layer, field_name, None)
                                    if field_value and str(field_value) != '0':
                                        protocol_info['message_type'] = f'SIB{field_value}'

            return protocol_info
                
        except Exception as e:
            self.logger.debug(f"Error identifying packet protocol: {e}")
            return {
                'primary_protocol': 'unknown',
                'secondary_protocol': 'unknown',
                'nested_protocol': 'unknown',
                'channel_type': 'unknown',
                'message_type': 'unknown'
            }

    def _extract_rrc_data_for_csv(self, packet, packet_num):
        """Extract all protocol data from packet for CSV export"""
        try:
            packet_data = {'packet_number': packet_num}
            has_protocol_data = False
            processed_layers = []
            skipped_layers = []

            # First, identify protocol from packet layers
            protocol_info = self._identify_packet_protocol(packet)
            packet_data['primary_protocol'] = protocol_info['primary_protocol']
            packet_data['nested_protocol'] = protocol_info['nested_protocol']
            packet_data['message_type'] = protocol_info['message_type']
            packet_data['channel_type'] = protocol_info['channel_type']

            # Process all relevant layers in the packet
            for layer in packet.layers:
                try:
                    layer_name = layer.layer_name.lower()

                    # Skip transport layers (optimized with frozenset)
                    if layer_name in self._transport_layers:
                        skipped_layers.append(layer_name)
                        continue

                    # Process all protocol layers (not just RRC) - optimized with frozenset
                    # Use set intersection for potentially better performance with many keywords
                    if self._protocol_keywords & set(layer_name.split('_')) or any(protocol in layer_name for protocol in self._protocol_keywords):
                        has_protocol_data = True
                        processed_layers.append(layer_name)
                        # Extract fields from this protocol layer (e.g., nas_eps, lte_rrc)
                        self._extract_layer_fields_for_csv(layer, layer_name, packet_data)
                    # Also process GSMTAP layer for metadata and transport info
                    elif layer_name == 'gsmtap':
                        has_protocol_data = True
                        processed_layers.append(layer_name)
                        # Extract GSMTAP metadata (protocol type, subtype, etc.)
                        self._extract_layer_fields_for_csv(layer, layer_name, packet_data)
                    else:
                        skipped_layers.append(layer_name)

                except Exception as e:
                    self.logger.debug(f"Error processing layer in packet {packet_num}: {e}")
                    continue

            # Collect layer statistics for optimization analysis
            self._layer_stats['total_packets'] += 1
            for layer in processed_layers:
                self._layer_stats['processed'][layer] = self._layer_stats['processed'].get(layer, 0) + 1
            for layer in skipped_layers:
                self._layer_stats['skipped'][layer] = self._layer_stats['skipped'].get(layer, 0) + 1

            # Add packet if it contains any protocol data
            if has_protocol_data:
                self._rrc_packets_data.append(packet_data)
                self._packet_count += 1
                
        except Exception as e:
            self.logger.debug(f"Error extracting protocol data for CSV: {e}")

    def _get_display_value_from_field(self, layer, field_name, raw_value):
        """Get the display value from dissector field if available"""
        try:
            # Try to get the field object which may have display information
            if hasattr(layer, field_name):
                field_obj = getattr(layer, field_name)

                # PyShark field objects have display information from the dissector
                # Priority order: showname (most complete) > show > display
                if hasattr(field_obj, 'showname') and field_obj.showname:
                    return str(field_obj.showname)
                elif hasattr(field_obj, 'show') and field_obj.show:
                    return str(field_obj.show)
                elif hasattr(field_obj, 'display') and field_obj.display:
                    return str(field_obj.display)

                # Some PyShark fields have additional display attributes
                if hasattr(field_obj, 'display_name') and field_obj.display_name:
                    return str(field_obj.display_name)

                # Check if the field has a decoded value that differs from raw
                if hasattr(field_obj, 'value'):
                    field_value = field_obj.value
                    # Only return the value if it's different from raw (meaning it was decoded)
                    if str(field_value) != str(raw_value):
                        return str(field_value)

            # Fallback to raw value if no display information available
            return str(raw_value)
        except Exception as e:
            self.logger.debug(f"Error getting display value for {field_name}: {e}")
            return str(raw_value)

    def _extract_layer_fields_for_csv(self, layer, layer_name, packet_data):
        """Extract fields from a layer for CSV export"""
        try:
            if hasattr(layer, 'field_names'):
                # Process all available fields for comprehensive extraction
                field_names = list(layer.field_names)

                
                for field_name in field_names:
                    try:
                        raw_field_value = getattr(layer, field_name, None)
                        if raw_field_value is not None and raw_field_value != '':
                            # Create CSV field name using layer name and field name
                            csv_field_name = f"{layer_name}.{field_name}"

                            # Try to get the display value (readable text) instead of raw value
                            field_value = self._get_display_value_from_field(layer, field_name, raw_field_value)

                            # Convert field value to string and handle special cases
                            if isinstance(field_value, (list, tuple)):
                                field_value = ','.join(str(v) for v in field_value)
                            elif isinstance(field_value, dict):
                                field_value = str(field_value)
                            else:
                                field_value = str(field_value)

                            # Only add meaningful values (not empty, None, 0, or -1)
                            # Also filter out Wireshark expert info messages and other noise
                            if (field_value and
                                field_value != 'None' and
                                field_value != '' and
                                field_value != '0' and
                                field_value != '-1' and
                                len(field_value.strip()) > 0 and
                                not field_value.startswith('Expert Info') and
                                not field_value.startswith('All ') and
                                not field_value.startswith('dissector bug') and
                                not field_value.startswith('report to wireshark.org') and
                                not 'extraneous data' in field_value.lower() and
                                not 'later version spec' in field_value.lower()):

                                packet_data[csv_field_name] = field_value
                            self._all_rrc_fields.add(csv_field_name)
                            
                    except Exception as e:
                        self.logger.debug(f"Error processing field {field_name}: {e}")
                        continue
                        
        except Exception as e:
            self.logger.debug(f"Error extracting layer fields for CSV: {e}")

    def _export_rrc_to_csv(self, csv_output_path):
        """Export all protocol data to CSV file"""
        try:
            if not self._rrc_packets_data:
                self.logger.warning("No protocol data to export to CSV")
                return
            
            # Add protocol identification columns at the beginning
            protocol_columns = ['packet_number', 'primary_protocol', 'nested_protocol', 'message_type', 'channel_type']
            
            # Sort field names for consistent column ordering, excluding protocol columns
            other_fields = [f for f in self._all_rrc_fields if f not in protocol_columns]
            sorted_fields = protocol_columns + sorted(other_fields)
            
            self.logger.info(f"Exporting {len(self._rrc_packets_data)} packets to CSV")
            
            with open(csv_output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=sorted_fields, restval='-1')
                
                # Write header
                writer.writeheader()
                
                # Write packet data
                for packet_data in self._rrc_packets_data:
                    # Create row with -1 for missing fields
                    row = {}
                    for field in sorted_fields:
                        if field in protocol_columns:
                            # Use actual values for protocol columns, or 'unknown' if missing
                            row[field] = packet_data.get(field, 'unknown')
                        else:
                            # Use -1 for missing data fields
                            row[field] = packet_data.get(field, '-1')
                    writer.writerow(row)
            
            self.logger.info(f"Successfully exported protocol data to {csv_output_path}")

            # Log layer usage statistics for optimization analysis
            self.log_layer_usage_statistics()

        except Exception as e:
            self.logger.error(f"Error exporting protocol data to CSV: {e}")

    def _reset_csv_data(self):
        """Reset CSV data for new processing session"""
        self._rrc_packets_data = []
        self._all_rrc_fields = set()
        self._packet_count = 0
        self._layer_stats = {
            'processed': {},
            'skipped': {},
            'total_packets': 0
        }

    def log_layer_usage_statistics(self):
        """Log basic statistics about layer usage"""
        if self._layer_stats['total_packets'] == 0:
            return

        total_processed = sum(self._layer_stats['processed'].values())
        self.logger.info(f"Processed {self._layer_stats['total_packets']} packets with {total_processed} layers extracted")



    def _init_pcap_file(self, filename):
        """Initialize PCAP file with global header"""
        self.pcap_file = open(filename, 'wb')
        pcap_global_hdr = struct.pack('<LHHLLLL',
                0xa1b2c3d4,  # magic number
                2,           # version major
                4,           # version minor
                0,           # timezone
                0,           # sigfigs
                0xffff,      # snaplen
                1,           # network
                )
        self.pcap_file.write(pcap_global_hdr)

    def _close_pcap_file(self):
        """Close PCAP file"""
        if hasattr(self, 'pcap_file') and self.pcap_file:
            self.pcap_file.close()

    def write_pkt(self, sock_content, port, radio_id=0, ts=datetime.datetime.now()):
        """Write packet to PCAP file"""
        pcap_hdr = struct.pack('<LLLL',
                int(ts.timestamp()) % 4294967296,
                ts.microsecond,
                len(sock_content) + 8 + 20 + 14,
                len(sock_content) + 8 + 20 + 14,
                )

        dest_address = self.base_address + radio_id if radio_id > 0 else self.base_address

        ip_hdr = struct.pack('!BBHHBBBBHLL',
                0x45,                        # version, IHL, dsf
                0x00,
                len(sock_content) + 8 + 20,  # length
                self.ip_id,                  # id
                0x40,                        # flags/fragment offset
                0x00,
                0x40,                        # TTL
                0x11,                        # proto = udp
                0xffff,                      # header checksum
                0x7f000001,                  # src address
                dest_address,                # dest address
                )

        udp_hdr = struct.pack('!HHHH',
                13337,                 # source port
                port,                  # destination port
                len(sock_content) + 8, # length
                0xffff,                # checksum
                )

        self.pcap_file.write(pcap_hdr + self.eth_hdr + ip_hdr + udp_hdr + sock_content)
        self.ip_id += 1
        if self.ip_id > 65535:
            self.ip_id = 0

    def write_cp(self, sock_content, radio_id=0, ts=datetime.datetime.now()):
        """Write control plane packet"""
        self.write_pkt(sock_content, self.port_cp, radio_id, ts)

    def write_up(self, sock_content, radio_id=0, ts=datetime.datetime.now()):
        """Write user plane packet"""
        self.write_pkt(sock_content, self.port_up, radio_id, ts)



    def is_pyshark_available(self):
        """Check if PyShark is available"""
        return PYSHARK_AVAILABLE

    def get_tshark_version_info(self):
        """Get version information (PyShark equivalent)"""
        try:
            import pyshark
            return f"PyShark {pyshark.__version__} with Wireshark backend"
        except:
            return "PyShark not available"

# Backward compatibility
class PySharkDataWriter(DataWriter):
    """Alias for backward compatibility"""
    pass


