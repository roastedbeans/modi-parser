#!/usr/bin/env python3.8
# coding: utf8

import re
import struct
import datetime
import logging
import csv
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

        # CSV export data
        self._rrc_packets_data = []
        self._all_rrc_fields = set()

        # Separate data structures for RRC and NAS packets
        self._rrc_packets_only = []
        self._nas_packets_only = []
        self._rrc_fields_only = set()
        self._nas_fields_only = set()

        self._packet_count = 0

        # Optimized layer filtering sets for faster lookup
        self._transport_layers = frozenset(['ip', 'eth', 'udp', 'tcp', 'frame', 'geninfo'])

        # Core mobile network protocols - removed peripheral/specialized protocols
        self._protocol_keywords = frozenset([
            'rrc',     # Radio Resource Control (all generations)
            'nas',     # Non-Access Stratum (all generations)
            'mac',     # Medium Access Control
            'rlc',     # Radio Link Control
            'pdcp',    # Packet Data Convergence Protocol
            'gsm',     # GSM core protocols
            'umts',    # UMTS core protocols
            'lte',     # LTE core protocols
            'nr'       # NR/5G core protocols
        ])

        # Removed protocols (peripheral/specialized):
        # fp, llc, gprs, gprscdr, map, sms, dtap, cbch, gsup, bssgp,
        # ranap, s1ap, ngap, x2ap, xnap, gtp, sgsap, rsl, sabp, cell_broadcast

        # UMTS RRC fields to include in CSV output
        self._umts_rrc_fields = frozenset([
            'rrc_firstsegment_element',
            'rrc_lastsegmentshort_element',
            'rrc_subsequentsegment_element',
            'rrc_schedulinginfo_element',
            'rrc_schedulinginformationsibsb_element',
            'rrc_sib_data_fixed',
            'rrc_sib_data_variable',
            'rrc_sib_type',
            'rrc_sibsb_type'
        ])

    def _identify_packet_protocol(self, packet):
        """Identify the actual protocol from packet layers"""
        try:
            protocol_info = {
                'primary_protocol': 'unknown',
                'nested_protocol': 'unknown',
                'channel_type': 'unknown',
                'message_type': 'unknown',
                'direction': 'unknown'
            }
            
            # First try to identify from GSMTAP layer if present
            for layer in packet.layers:
                try:
                    layer_name = layer.layer_name.lower()
                    
                    if layer_name == 'gsmtap':
                        # Try to get GSMTAP protocol info
                        if hasattr(layer, 'field_names'):
                            for field_name in layer.field_names:
                                field_name_lower = field_name.lower()
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
                                            elif gsmtap_type == 0x0f:  # LTE MAC Framed
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
                                    
                                    # Channel type detection from GSMTAP fields
                                    if 'subtype' in field_name_lower or 'sub_type' in field_name_lower or 'channel' in field_name_lower:
                                        if field_value and str(field_value) != '0':
                                            protocol_info['channel_type'] = str(field_value)

                                    # Direction detection from GSMTAP fields
                                    if 'direction' in field_name_lower or 'dir' in field_name_lower:
                                        if str(field_value).lower() in ['0', 'uplink', 'ul', 'up']:
                                            protocol_info['direction'] = 'uplink'
                                        elif str(field_value).lower() in ['1', 'downlink', 'dl', 'down']:
                                            protocol_info['direction'] = 'downlink'
                                        elif field_value and str(field_value) != '0':
                                            # Handle other direction values that might be display strings
                                            direction_str = str(field_value).lower()
                                            if 'uplink' in direction_str or 'ul' in direction_str:
                                                protocol_info['direction'] = 'uplink'
                                            elif 'downlink' in direction_str or 'dl' in direction_str:
                                                protocol_info['direction'] = 'downlink'

                        break
                        
                except Exception as e:
                    continue
            
            # If no GSMTAP info, try to identify from other layers
            if protocol_info['primary_protocol'] == 'unknown':
                for layer in packet.layers:
                    try:
                        layer_name = layer.layer_name.lower()

                        # Skip transport layers
                        if layer_name in self._transport_layers:
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
                                        'nas_message', 'nas_msg', 'emm_msg', 'esm_msg', 'nas_msg_type', 'emm_type', 'esm_type', 'message_type',
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
                            elif 'umts' in layer_name:
                                protocol_info['primary_protocol'] = 'mac_umts'
                            else:
                                protocol_info['primary_protocol'] = 'mac'
                        elif 'rlc' in layer_name:
                            if 'lte' in layer_name:
                                protocol_info['primary_protocol'] = 'rlc_lte'
                            elif 'nr' in layer_name:
                                protocol_info['primary_protocol'] = 'rlc_nr'
                            elif 'umts' in layer_name:
                                protocol_info['primary_protocol'] = 'rlc_umts'
                            else:
                                protocol_info['primary_protocol'] = 'rlc'
                        elif 'pdcp' in layer_name:
                            if 'lte' in layer_name:
                                protocol_info['primary_protocol'] = 'pdcp_lte'
                            elif 'nr' in layer_name:
                                protocol_info['primary_protocol'] = 'pdcp_nr'
                            else:
                                protocol_info['primary_protocol'] = 'pdcp'
                        elif 'rlcmac' in layer_name:
                            protocol_info['primary_protocol'] = 'gsm_rlcmac'
                        elif 'gsm' in layer_name:
                            protocol_info['primary_protocol'] = 'gsm'
                        elif 'umts' in layer_name:
                            protocol_info['primary_protocol'] = 'umts'
                        elif 'lte' in layer_name:
                            protocol_info['primary_protocol'] = 'lte'
                        elif 'nr' in layer_name:
                            protocol_info['primary_protocol'] = 'nr'
                        
                    except Exception as e:
                        continue
            
            # Final attempt: analyze field values for message types and channels
            if protocol_info['message_type'] == 'unknown' or protocol_info['channel_type'] == 'unknown':
                for layer in packet.layers:
                    try:
                        layer_name = layer.layer_name.lower()
                        if layer_name in self._transport_layers:
                            continue
                            
                        if hasattr(layer, 'field_names'):
                            for field_name in layer.field_names:
                                field_value = getattr(layer, field_name, None)
                                if field_value:
                                    # Only check fields with message, type, or element in the name for efficiency
                                    field_name_lower = str(field_name).lower()
                                    if not any(keyword in field_name_lower for keyword in ['message', 'type', 'element', 'ul', 'invalid', 'short', 'discriminator']):
                                        continue

                                    field_str = str(field_value).lower()

                                    # Message type detection from field values
                                    if protocol_info['message_type'] == 'unknown':
                                        # Consolidated message type patterns
                                        message_patterns = [
                                            'connection', 'setup', 'release', 'reconfig', 'reestablishment',
                                            'attach', 'detach', 'update', 'request', 'response', 'complete',
                                            'reject', 'failure', 'handover', 'measurement', 'security', 'active',
                                            'capability', 'information', 'system', 'paging', 'broadcast',
                                            'authentication', 'location', 'routing', 'service',
                                            'pdn', 'bearer', 'session', 'registration', 'deregistration',
                                            'configuration', 'notification', 'rrcconnection', 'connectionrequest',
                                            'connectionsetup', 'connectioncomplete', 'connectionreject',
                                            'connectionrelease', 'handovercommand', 'handovercomplete',
                                            'measurementreport', 'securitymode', 'uecapability', 'systeminformation',
                                            'masterinformation', 'sib', 'systeminfo', 'segment', 'sibsb', 'procedure', 'protocol'
                                        ]
                                        
                                        if re.match(r'^0x[0-9a-fA-F]+$', field_str):
                                            # Check for priority prefixes including continuation for 0x4XXX, 0x5XXX, 0x6XXX
                                            if (re.match(r'^0x[4567acd][0-9a-fA-F]+$', field_str) and len(field_str) <= 6):
                                                field_str = str(self._get_display_value_from_field(layer, field_name, field_str)).lower()
                                      
                                        if any(msg in field_str for msg in message_patterns):
                                            display_value = self._get_display_value_from_field(layer, field_name, field_value)
                                            protocol_info['message_type'] = display_value

                                    # Channel type detection from field values
                                    if protocol_info['channel_type'] == 'unknown':
                                        # Common channel types
                                        if any(channel in field_str for channel in [
                                            'ccch', 'dcch', 'bcch', 'pcch', 'mcch', 'scch',
                                            'uplink', 'downlink', 'ul', 'dl', 'broadcast', 'control',
                                            'traffic', 'signaling', 'data'
                                        ]):
                                            protocol_info['channel_type'] = str(field_value)
                                        # Don't set to '-1' here - let it remain 'unknown' if not detected

                                    # Direction detection from field values
                                    if protocol_info['direction'] == 'unknown':
                                        if any(dir_pattern in field_str for dir_pattern in ['uplink', 'ul', 'up']):
                                            protocol_info['direction'] = 'uplink'
                                        elif any(dir_pattern in field_str for dir_pattern in ['downlink', 'dl', 'down']):
                                            protocol_info['direction'] = 'downlink'
                                        # Don't set to '-1' here - let it remain 'unknown' if not detected

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
                else:
                    protocol_info['nested_protocol'] = '-1'


                # Check for UMTS RRC payload in DATA layer
                if protocol_info['primary_protocol'] == 'umts_rrc':
                    for layer in packet.layers:
                        if layer.layer_name.lower() == 'data' and hasattr(layer, 'field_names'):
                            # Check if DATA layer has UMTS RRC fields
                            if any('rrc_' in field_name.lower() for field_name in layer.field_names):
                                protocol_info['primary_protocol'] = 'umts_rrc'  # Ensure it's set
                                break

                # Check for NAS-related fields in any RRC layer and enhance info field
                for layer in packet.layers:
                    if 'rrc' in layer.layer_name.lower() and hasattr(layer, 'field_names'):
                        for field_name in layer.field_names:
                            field_name_lower = field_name.lower()
                            # Check for various NAS-related fields in RRC
                            nas_indicators = [
                                'dedicatedinfonas', 'dedicated_info_nas',
                                'dedicatedinfonaslist', 'dedicated_info_nas_list',
                                'nas_message', 'nas_msg', 'emm_msg', 'esm_msg', 'nas_msg_type', 'nas_msg_emm_type', 'nas_msg_esm_type', 'emm_type', 'esm_type', 'message_type',
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

            # Final fallback: set unknown values to '-1'
            if protocol_info['channel_type'] == 'unknown':
                protocol_info['channel_type'] = '-1'
            if protocol_info['direction'] == 'unknown':
                protocol_info['direction'] = '-1'
            if protocol_info['message_type'] == 'unknown':
                protocol_info['message_type'] = '-1'

            return protocol_info
                
        except Exception as e:
            self.logger.debug(f"Error identifying packet protocol: {e}")
            return {
                'primary_protocol': 'unknown',
                'nested_protocol': 'unknown',
                'channel_type': 'unknown',
                'message_type': 'unknown',
                'direction': 'unknown'
            }

    def _extract_rrc_data_for_csv(self, packet, packet_num):
        """Extract all protocol data from packet for CSV export"""
        try:
            packet_data = {'packet_number': packet_num}
            has_protocol_data = False

            # First, identify protocol from packet layers
            protocol_info = self._identify_packet_protocol(packet)
            packet_data['nested_protocol'] = protocol_info['nested_protocol']
            packet_data['message_type'] = protocol_info['message_type']
            packet_data['channel_type'] = protocol_info['channel_type']
            packet_data['direction'] = protocol_info['direction']

            # Process all relevant layers in the packet
            for layer in packet.layers:
                try:
                    layer_name = layer.layer_name.lower()

                    # Skip transport layers (optimized with frozenset)
                    if layer_name in self._transport_layers:
                        continue

                    # Process all protocol layers (not just RRC) - optimized with frozenset
                    if any(protocol in layer_name for protocol in self._protocol_keywords):
                        has_protocol_data = True
                        # Extract fields from this protocol layer (e.g., nas_eps, lte_rrc)
                        self._extract_layer_fields_for_csv(layer, layer_name, packet_data)
                    # Special handling for UMTS RRC packets - their payload is in DATA layer
                    elif layer_name == 'data' and hasattr(packet, 'gsmtap'):
                        gsmtap_type = getattr(packet.gsmtap, 'type', None)
                        if gsmtap_type and str(gsmtap_type) == '12':  # UMTS RRC
                            has_protocol_data = True
                            # Extract UMTS RRC fields from DATA layer
                            self._extract_layer_fields_for_csv(layer, 'umts_rrc', packet_data)
                    # Also process GSMTAP layer for metadata and transport info
                    elif layer_name == 'gsmtap':
                        has_protocol_data = True
                        # Extract GSMTAP metadata (protocol type, subtype, etc.)
                        self._extract_layer_fields_for_csv(layer, layer_name, packet_data)

                except Exception as e:
                    self.logger.debug(f"Error processing layer in packet {packet_num}: {e}")
                    continue

            # Add packet if it contains any protocol data
            if has_protocol_data:
                self._rrc_packets_data.append(packet_data)
                self._packet_count += 1

                # Categorize packet for separate RRC/NAS CSV exports
                packet_type = self._determine_packet_type(packet_data, packet)

                # Collect fields for RRC/NAS specific exports
                for key, value in packet_data.items():
                    # Normalize key to use underscores for consistent processing
                    normalized_key = key.replace('-', '_').replace('.', '_')
                    field_protocol = self._determine_field_protocol(normalized_key)

                    # Add field to appropriate protocol field sets based on field type and packet type
                    if field_protocol == 'both':
                        # GSMTAP and protocol identification fields go to both
                        if packet_type in ['rrc', 'nas']:
                            self._rrc_fields_only.add(key)
                            self._nas_fields_only.add(key)
                    elif field_protocol == 'rrc':
                        # RRC-specific fields only go to RRC (only if packet is RRC type)
                        if packet_type == 'rrc':
                            self._rrc_fields_only.add(key)
                    elif field_protocol == 'nas':
                        # NAS-specific fields only go to NAS (only if packet is NAS type)
                        if packet_type == 'nas':
                            self._nas_fields_only.add(key)
                    # For unknown fields, include them in both if they're not transport-related
                    elif field_protocol == 'unknown' and not any(transport in key.lower() for transport in ['ip.', 'eth.', 'udp.', 'tcp.', 'frame.', 'geninfo.']):
                        # Include unknown protocol fields in both RRC and NAS for comprehensive coverage
                        if packet_type in ['rrc', 'nas']:
                            self._rrc_fields_only.add(key)
                            self._nas_fields_only.add(key)

                # Add packet to appropriate separate data structure
                if packet_type == 'rrc':
                    self._rrc_packets_only.append(packet_data)
                elif packet_type == 'nas':
                    self._nas_packets_only.append(packet_data)
                
        except Exception as e:
            self.logger.debug(f"Error extracting protocol data for CSV: {e}")

    def _determine_field_protocol(self, field_name):
        """Determine which protocol a field belongs to based on field name"""
        field_lower = field_name.lower()
        field_normalized = field_name.lower().replace('-', '_').replace('.', '_')

        # GSMTAP fields belong to both (metadata)
        if field_lower.startswith('gsmtap'):
            return 'both'

        # Protocol identification fields belong to both
        if field_name in ['packet_number', 'nested_protocol', 'message_type', 'channel_type', 'direction']:
            return 'both'

        # RRC-specific fields (exclude from NAS)
        if any(keyword in field_normalized for keyword in ['rrc', 'lte_rrc', 'umts_rrc', 'nr_rrc']):
            return 'rrc'

        # NAS-specific fields (only include nas_eps and gsm_a as requested)
        # Be very specific to only include these exact protocol prefixes
        if (field_normalized.startswith('nas_eps') or
            field_normalized.startswith('gsm_a')):
            return 'nas'

        # Default to unknown (will be skipped)
        return 'unknown'

    def _determine_packet_type(self, packet_data, packet):
        """Determine if packet is RRC or NAS based on nested_protocol and gsmtap.type"""
        nested_protocol = packet_data.get('nested_protocol', 'unknown')

        # Check nested_protocol first
        if 'nas' in nested_protocol.lower():
            return 'nas'
        elif 'rrc' in nested_protocol.lower():
            return 'rrc'

        # Fallback: check gsmtap.type for additional hints
        if hasattr(packet, 'gsmtap'):
            gsmtap_type = getattr(packet.gsmtap, 'type', None)
            if gsmtap_type is not None:
                gsmtap_type_str = str(gsmtap_type)
                # Handle both raw numbers and display strings
                if '12' in gsmtap_type_str and 'UMTS RRC' in gsmtap_type_str:
                    return 'rrc'  # UMTS RRC type 12 (0x0c)
                elif '13' in gsmtap_type_str and 'LTE RRC' in gsmtap_type_str:
                    return 'rrc'  # LTE RRC type 13 (0x0d)
                elif '12' in gsmtap_type_str and 'LTE NAS' in gsmtap_type_str:
                    return 'nas'  # LTE NAS type 18 (0x12)
                elif '0' in gsmtap_type_str and 'NR' in gsmtap_type_str:
                    return 'nas'  # NR NAS
                # Also handle raw numeric values
                elif gsmtap_type_str == '12':
                    return 'rrc'  # UMTS RRC
                elif gsmtap_type_str == '13':
                    return 'rrc'  # LTE RRC
                elif gsmtap_type_str == '18':
                    return 'nas'  # LTE NAS

        return 'unknown'

    def _get_display_value_from_field(self, layer, field_name, raw_value):
        """Get the display value from dissector field if available"""
        try:
            # Try to get the field object which may have display information
            if hasattr(layer, field_name):
                field_obj = getattr(layer, field_name)

                # PyShark field objects have display information from the dissector
                # Priority order: showname (most complete) > show > display
                if raw_value.lower().startswith('0x'):
                    if hasattr(field_obj, 'showname') and field_obj.showname:
                        return str(field_obj.showname)
              
            # Fallback to raw value if no display information available
            return str(raw_value)
        except Exception as e:
            self.logger.debug(f"Error getting display value for {field_name}: {e}")
            return str(raw_value) if raw_value is not None else ''

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
                            # Normalize both layer name and field name to use underscores for consistent syntax
                            normalized_layer_name = layer_name.replace('-', '_').replace('.', '_')
                            normalized_field_name = field_name.replace('-', '_').replace('.', '_')
                            csv_field_name = "_".join(filter(None, [normalized_layer_name, normalized_field_name]))

                            # Filter UMTS RRC fields to only include specified ones
                            if layer_name == 'umts_rrc' and normalized_field_name not in self._umts_rrc_fields:
                                continue

                            # Try to get the display value (readable text) instead of raw value
                            field_value = self._get_display_value_from_field(layer, field_name, raw_field_value)

                            # Convert raw field value to string for storage
                            raw_field_value_str = str(raw_field_value) if raw_field_value is not None else ''

                            # Only add meaningful raw values (not empty, None, or -1)
                            # Also filter out Wireshark expert info messages and other noise
                            # Special handling for GSMTAP fields where '0' is a valid value
                            is_valid_value = True
                            if raw_field_value_str in ['None', '']:
                                is_valid_value = False
                            elif raw_field_value_str == '-1' and layer_name != 'gsmtap':
                                # -1 might be valid for GSMTAP but not for other protocols
                                is_valid_value = False
                            elif raw_field_value_str == '0':
                                # '0' is invalid for most protocols but valid for GSMTAP
                                if layer_name != 'gsmtap':
                                    is_valid_value = False

                            if (is_valid_value and
                                len(raw_field_value_str.strip()) > 0 and
                                not raw_field_value_str.startswith('Expert Info') and
                                not raw_field_value_str.startswith('All ') and
                                not raw_field_value_str.startswith('dissector bug') and
                                not raw_field_value_str.startswith('report to wireshark.org') and
                                not 'extraneous data' in raw_field_value_str.lower() and
                                not 'later version spec' in raw_field_value_str.lower()):

                                # Store raw value
                                packet_data[csv_field_name] = raw_field_value_str

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
            protocol_columns = ['packet_number', 'nested_protocol', 'message_type', 'channel_type', 'direction']
            
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
                            # Use raw value
                            row[field] = packet_data.get(field, '-1')
                    writer.writerow(row)
            
            self.logger.info(f"Successfully exported protocol data to {csv_output_path}")

            # Log layer usage statistics for optimization analysis
            self.log_layer_usage_statistics()

        except Exception as e:
            self.logger.error(f"Error exporting protocol data to CSV: {e}")

    def _should_normalize_field_value(self, field_value):
        """Determine if a field value should be normalized based on its content"""
        if field_value == '-1' or field_value == '':
            return False  # Don't normalize missing values

        value_str = str(field_value).strip()

        # Check for usable data patterns (hexadecimal, decimal, etc.)
        import re

        # Hexadecimal patterns (0x..., 0X..., or just hex digits)
        if re.match(r'^0[xX][0-9a-fA-F]+$', value_str):
            return False  # Keep hex values as-is

        # Decimal numbers (integers)
        if re.match(r'^-?\d+$', value_str):
            return False  # Keep decimal values as-is

        # Hex codes without 0x prefix (pure hex digits)
        if re.match(r'^[0-9a-fA-F]+$', value_str):
            return False  # Keep hex codes as-is

        # Boolean values - convert to 1/0 but don't consider as message
        if value_str.lower() in ['true', 'false']:
            return False  # Handle separately for boolean conversion

        # Floating point numbers
        if re.match(r'^-?\d+\.\d+$', value_str):
            return False  # Keep float values as-is

        # IP addresses
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', value_str):
            return False  # Keep IP addresses as-is

        # MAC addresses
        if re.match(r'^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$', value_str):
            return False  # Keep MAC addresses as-is

        # Any other value is considered a message and should be normalized to '1'
        return True

    def _export_rrc_only_to_csv(self, csv_output_path):
        """Export only RRC packets to CSV file"""
        try:
            if not self._rrc_packets_only:
                self.logger.warning("No RRC packets to export to CSV")
                return

            # For separated RRC export, only include packet_number (exclude other protocol columns)
            protocol_columns = ['packet_number']

            # Sort field names for consistent column ordering, excluding protocol columns
            other_fields = [f for f in self._rrc_fields_only if f not in ['packet_number', 'nested_protocol', 'message_type', 'channel_type', 'direction']]
            sorted_fields = protocol_columns + sorted(other_fields)

            self.logger.info(f"Exporting {len(self._rrc_packets_only)} RRC packets to CSV")

            with open(csv_output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=sorted_fields, restval='-1')

                # Write header
                writer.writeheader()

                # Write packet data
                for packet_data in self._rrc_packets_only:
                    # Create row with -1 for missing fields
                    row = {}
                    for field in sorted_fields:
                        if field == 'packet_number':
                            # Use actual values for packet_number, or 'unknown' if missing
                            row[field] = packet_data.get(field, 'unknown')
                        else:
                            # For separated RRC export, normalize based on value content
                            raw_value = packet_data.get(field, '-1')

                            # Handle boolean values
                            if str(raw_value).lower() == 'true':
                                row[field] = '1'
                            elif str(raw_value).lower() == 'false':
                                row[field] = '0'
                            # Check if value should be normalized (is a message)
                            elif self._should_normalize_field_value(raw_value):
                                row[field] = '1'  # Message content -> '1'
                            else:
                                row[field] = raw_value  # Keep usable data as-is
                    writer.writerow(row)

            self.logger.info(f"Successfully exported RRC packets to {csv_output_path}")

        except Exception as e:
            self.logger.error(f"Error exporting RRC packets to CSV: {e}")

    def _export_nas_only_to_csv(self, csv_output_path):
        """Export only NAS packets to CSV file"""
        try:
            if not self._nas_packets_only:
                self.logger.warning("No NAS packets to export to CSV")
                return

            # For separated NAS export, only include packet_number (exclude other protocol columns)
            protocol_columns = ['packet_number']

            # Sort field names for consistent column ordering, excluding protocol columns
            other_fields = [f for f in self._nas_fields_only if f not in ['packet_number', 'nested_protocol', 'message_type', 'channel_type', 'direction']]
            sorted_fields = protocol_columns + sorted(other_fields)

            self.logger.info(f"Exporting {len(self._nas_packets_only)} NAS packets to CSV")

            with open(csv_output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=sorted_fields, restval='-1')

                # Write header
                writer.writeheader()

                # Write packet data
                for packet_data in self._nas_packets_only:
                    # Create row with -1 for missing fields
                    row = {}
                    for field in sorted_fields:
                        if field == 'packet_number':
                            # Use actual values for packet_number, or 'unknown' if missing
                            row[field] = packet_data.get(field, 'unknown')
                        else:
                            # For separated NAS export, normalize based on value content
                            raw_value = packet_data.get(field, '-1')

                            # Handle boolean values
                            if str(raw_value).lower() == 'true':
                                row[field] = '1'
                            elif str(raw_value).lower() == 'false':
                                row[field] = '0'
                            # Check if value should be normalized (is a message)
                            elif self._should_normalize_field_value(raw_value):
                                row[field] = '1'  # Message content -> '1'
                            else:
                                row[field] = raw_value  # Keep usable data as-is
                    writer.writerow(row)

            self.logger.info(f"Successfully exported NAS packets to {csv_output_path}")

        except Exception as e:
            self.logger.error(f"Error exporting NAS packets to CSV: {e}")

    def _reset_csv_data(self):
        """Reset CSV data for new processing session"""
        self._rrc_packets_data = []
        self._all_rrc_fields = set()

        # Reset separate RRC/NAS data structures
        self._rrc_packets_only = []
        self._nas_packets_only = []
        self._rrc_fields_only = set()
        self._nas_fields_only = set()

        self._packet_count = 0

    def log_layer_usage_statistics(self):
        """Log basic statistics about processing"""
        self.logger.info(f"Processed {self._packet_count} packets")

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

# Backward compatibility
class PySharkDataWriter(DataWriter):
    """Alias for backward compatibility"""
    pass


