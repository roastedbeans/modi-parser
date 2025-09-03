#!/usr/bin/env python3
# coding: utf8

import tempfile
import os
import struct
import datetime
import logging
import re
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
    """PCAP writing and CSV export for RRC and NAS data using PyShark"""

    def __init__(self):
        self.port_cp = 4729
        self.port_up = 47290
        self.ip_id = 0
        self.base_address = 0x7f000001
        self.eth_hdr = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00'
        self.logger = logging.getLogger(__name__)
        
        # CSV export data - separate for RRC and NAS
        self._rrc_packets_data = []
        self._nas_packets_data = []
        self._all_rrc_fields = set()
        self._all_nas_fields = set()
        self._packet_count = 0

    def _extract_protocol_and_info(self, packet):
        """Extract protocol and info fields similar to how Wireshark displays them"""
        protocol = 'Unknown'
        info = ''
        
        try:
            if not hasattr(packet, 'layers') or not packet.layers:
                return protocol, info
            
            # Wireshark's protocol column shows the most relevant protocol
            # Priority order: NAS > RRC > Other protocols > Transport layers
            skip_layers = {'FRAME', 'ETH', 'IP', 'IPV6', 'UDP', 'TCP'}
            
            # Collect all meaningful layers
            meaningful_layers = []
            for layer in packet.layers:
                try:
                    layer_name = layer.layer_name.upper()
                    if layer_name not in skip_layers:
                        meaningful_layers.append(layer_name)
                except:
                    continue
            
            if meaningful_layers:
                # Priority-based protocol selection (like Wireshark)
                if any('NAS_EPS' in layer for layer in meaningful_layers):
                    protocol = 'NAS-EPS'
                elif any('NAS_5GS' in layer for layer in meaningful_layers):
                    protocol = 'NAS-5GS'
                elif any('LTE_RRC' in layer for layer in meaningful_layers):
                    # Check if RRC contains NAS data
                    if any('NAS' in layer for layer in meaningful_layers):
                        # If RRC contains NAS, show NAS as primary
                        nas_layers = [l for l in meaningful_layers if 'NAS' in l]
                        protocol = nas_layers[0] if nas_layers else 'LTE_RRC'
                    else:
                        protocol = 'LTE_RRC'
                elif any('NR_RRC' in layer for layer in meaningful_layers):
                    protocol = 'NR_RRC'
                elif any('GSM_A' in layer for layer in meaningful_layers):
                    protocol = 'GSM_A'
                else:
                    # Use the highest meaningful layer
                    protocol = meaningful_layers[-1]
            
            # Extract info based on the determined protocol
            info = self._extract_info_for_protocol(packet, protocol, meaningful_layers)
            
        except Exception as e:
            self.logger.debug(f"Error extracting protocol and info: {e}")
            
        return protocol, info
    
    
    def _extract_info_for_protocol(self, packet, protocol, layer_names):
        """Extract info field content based on the protocol - focusing on ASN.1 PDU names"""
        info = ''
        
        try:
            protocol_lower = protocol.lower()
            
            # Method 1: Handle NAS EPS/5GS protocols specifically
            if 'nas_eps' in protocol_lower or 'nas_5gs' in protocol_lower:
                info = self._extract_nas_info(packet, protocol)
            
            # Method 2: Handle GSM A-interface protocols
            elif 'gsm_a' in protocol_lower:
                info = self._extract_gsm_a_info(packet, protocol)
            
            # Method 3: Handle RRC protocols (LTE, NR, UMTS)
            elif 'rrc' in protocol_lower:
                info = self._extract_rrc_info(packet, protocol)
            
            # Method 4: For GSMTAP, show the encapsulated protocol type
            elif protocol_lower == 'gsmtap':
                info = self._extract_gsmtap_info(packet)
            
            # Method 5: Generic protocol info extraction
            else:
                info = self._extract_generic_protocol_info(packet, protocol)
            
            # Fallback: if no info found, provide basic protocol info
            if not info:
                info = protocol
                
        except Exception as e:
            self.logger.debug(f"Error in _extract_info_for_protocol: {e}")
            info = protocol
            
        return info
    
    def _extract_nas_info(self, packet, protocol):
        """Extract NAS EPS/5GS specific information"""
        info = ''
        
        try:
            protocol_lower = protocol.lower()
            for layer in packet.layers:
                layer_name = layer.layer_name.lower()
                
                # Look for the specific NAS layer
                if protocol_lower.replace('_', '-') in layer_name.replace('_', '-'):
                    if hasattr(layer, 'field_names'):
                        # NAS message type priority fields
                        nas_msg_fields = ['nas_eps_msg_type', 'nas_5gs_msg_type', 'msg_type', 'message_type']
                        
                        for field_name in nas_msg_fields:
                            if hasattr(layer, field_name):
                                field_value = getattr(layer, field_name)
                                if field_value and str(field_value).strip():
                                    info = str(field_value).strip()
                                    break
                        
                        # If no message type found, look for other meaningful fields
                        if not info:
                            info = self._extract_generic_layer_info(layer)
                    break
                    
        except Exception as e:
            self.logger.debug(f"Error extracting NAS info: {e}")
            
        return info
    
    def _extract_gsm_a_info(self, packet, protocol):
        """Extract GSM A-interface specific information"""
        info = ''
        
        try:
            for layer in packet.layers:
                layer_name = layer.layer_name.lower()
                
                # Look for GSM A-interface layers
                if 'gsm_a' in layer_name:
                    if hasattr(layer, 'field_names'):
                        # GSM A-interface message type fields
                        gsm_fields = ['msg_type', 'message_type', 'dtap_msg_type', 'pd', 'protocol_discriminator']
                        
                        for field_name in gsm_fields:
                            if hasattr(layer, field_name):
                                field_value = getattr(layer, field_name)
                                if field_value and str(field_value).strip():
                                    info = str(field_value).strip()
                                    break
                        
                        # If no specific field found, look for other meaningful fields
                        if not info:
                            info = self._extract_generic_layer_info(layer)
                    break
                    
        except Exception as e:
            self.logger.debug(f"Error extracting GSM A info: {e}")
            
        return info
    
    def _extract_rrc_info(self, packet, protocol):
        """Extract RRC specific information (LTE, NR, UMTS)"""
        return self._extract_asn1_pdu_info(packet, protocol.lower())
    
    def _extract_generic_layer_info(self, layer):
        """Extract generic information from a layer"""
        try:
            if hasattr(layer, 'field_names'):
                priority_fields = ['message_type', 'msg_type', 'command', 'type', 'request', 'response']
                
                for field_name in priority_fields:
                    if hasattr(layer, field_name):
                        field_value = getattr(layer, field_name)
                        if field_value and str(field_value).strip():
                            return str(field_value).strip()
                            
                # If no priority field found, try first few meaningful fields
                for field_name in list(layer.field_names)[:5]:
                    if not field_name.startswith('_') and 'length' not in field_name.lower():
                        try:
                            field_value = getattr(layer, field_name)
                            if field_value and str(field_value).strip() and str(field_value) != '0':
                                return str(field_value).strip()
                        except:
                            continue
        except:
            pass
            
        return ''
    
    def _extract_asn1_pdu_info(self, packet, protocol_lower):
        """Extract ASN.1 PDU names from RRC/NAS layers"""
        info = ''
        
        try:
            for layer in packet.layers:
                layer_name = layer.layer_name.lower()
                
                # Focus on RRC and NAS layers
                if not any(proto in layer_name for proto in ['rrc', 'nas']):
                    continue
                
                # Method 1: Look for PDU-related fields that contain message names
                if hasattr(layer, 'field_names'):
                    field_names = list(layer.field_names)
                    
                    # Look for fields that might contain the PDU/message name
                    pdu_fields = []
                    message_name_fields = []
                    
                    for field_name in field_names:
                        field_lower = field_name.lower()
                        
                        # Look for PDU fields (these often contain the actual message name)
                        if '_pdu' in field_lower or field_lower.endswith('_pdu'):
                            pdu_fields.append(field_name)
                        
                        # Look for message-related fields
                        elif any(msg_pattern in field_lower for msg_pattern in [
                            'message', 'msg_type', 'messagetype', 'pdu_type', 'choice',
                            'masterinformationblock', 'systeminformationblock', 
                            'rrcconnection', 'ueeutra', 'dl_dcch', 'ul_dcch', 'dl_ccch', 'ul_ccch'
                        ]):
                            message_name_fields.append(field_name)
                    
                    # Try PDU fields first (most likely to have the exact message name)
                    for field_name in pdu_fields:
                        try:
                            field_value = getattr(layer, field_name)
                            if field_value and str(field_value).strip() and str(field_value) != '0':
                                # Clean up the PDU name
                                pdu_name = str(field_value).strip()
                                # Remove common suffixes/prefixes
                                pdu_name = pdu_name.replace('_PDU', '').replace('PDU_', '')
                                if pdu_name:
                                    info = pdu_name
                                    break
                        except:
                            continue
                    
                    # If no PDU field found, try message name fields
                    if not info:
                        for field_name in message_name_fields:
                            try:
                                field_value = getattr(layer, field_name)
                                if field_value and str(field_value).strip() and str(field_value) != '0':
                                    field_str = str(field_value).strip()
                                    # If it looks like a message name, use it
                                    if any(pattern in field_str.lower() for pattern in [
                                        'information', 'block', 'connection', 'reconfiguration',
                                        'request', 'response', 'complete', 'setup', 'release'
                                    ]):
                                        info = field_str
                                        break
                            except:
                                continue
                
                # Method 2: Look for specific known RRC/NAS message patterns in field values
                if not info and hasattr(layer, 'field_names'):
                    # Check all fields for RRC message patterns
                    for field_name in list(layer.field_names)[:20]:  # Limit to avoid performance issues
                        try:
                            field_value = str(getattr(layer, field_name, '')).strip()
                            
                            # Look for common RRC message names
                            if any(msg_name in field_value for msg_name in [
                                'MasterInformationBlock', 'SystemInformationBlockType', 
                                'RRCConnectionRequest', 'RRCConnectionSetup', 'RRCConnectionSetupComplete',
                                'RRCConnectionReconfiguration', 'RRCConnectionReconfigurationComplete',
                                'RRCConnectionReestablishment', 'RRCConnectionReestablishmentComplete',
                                'RRCConnectionRelease', 'SecurityModeCommand', 'SecurityModeComplete',
                                'UECapabilityEnquiry', 'UECapabilityInformation', 'Paging'
                            ]):
                                info = field_value
                                break
                            
                            # Look for NAS message types
                            elif any(nas_msg in field_value.lower() for nas_msg in [
                                'attach', 'detach', 'tau', 'service', 'identity', 'authentication',
                                'security', 'emm', 'esm', 'activate', 'deactivate', 'bearer'
                            ]):
                                info = field_value
                                break
                                
                        except:
                            continue
                
                if info:
                    # Add SFN information if available (like "MasterInformationBlock (SFN=141)")
                    sfn_info = self._extract_sfn_info(layer)
                    if sfn_info:
                        info = f"{info} {sfn_info}"
                    break
                    
        except Exception as e:
            self.logger.debug(f"Error extracting ASN.1 PDU info: {e}")
            
        return info
    
    def _extract_sfn_info(self, layer):
        """Extract SFN (System Frame Number) information if available"""
        try:
            if hasattr(layer, 'field_names'):
                for field_name in layer.field_names:
                    if 'sfn' in field_name.lower():
                        sfn_value = getattr(layer, field_name)
                        if sfn_value and str(sfn_value).isdigit():
                            return f"(SFN={sfn_value})"
        except:
            pass
        return ''
    
    def _extract_gsmtap_info(self, packet):
        """Extract GSMTAP specific information"""
        try:
            for layer in packet.layers:
                if layer.layer_name.lower() == 'gsmtap':
                    if hasattr(layer, 'type'):
                        gsmtap_type = getattr(layer, 'type')
                        type_map = {
                            '1': 'GSM UM', '2': 'GSM Abis', '3': 'GSM UM Burst',
                            '4': 'SIM', '10': 'UMTS RRC', '11': 'LTE RRC',
                            '12': 'LTE MAC', '13': 'LTE MAC Framed', '21': 'NR RRC'
                        }
                        return type_map.get(str(gsmtap_type), f"GSMTAP Type {gsmtap_type}")
        except:
            pass
        return 'GSMTAP'
    
    def _extract_generic_protocol_info(self, packet, protocol):
        """Extract generic protocol information"""
        try:
            for layer in packet.layers:
                if layer.layer_name.lower() == protocol.lower():
                    if hasattr(layer, 'field_names'):
                        priority_fields = ['message_type', 'msg_type', 'command', 'type', 'request', 'response']
                        for field_name in priority_fields:
                            if hasattr(layer, field_name):
                                field_value = getattr(layer, field_name)
                                if field_value and str(field_value).strip():
                                    return str(field_value).strip()
        except:
            pass
        return ''











    def _extract_rrc_data_for_csv(self, packet, packet_num):
        """Extract RRC and NAS data from packet for CSV export"""
        try:
            # Extract protocol and info using enhanced methods
            protocol, info = self._extract_protocol_and_info(packet)
            
            rrc_packet_data = {'packet_number': packet_num, 'protocol': protocol, 'info': info}
            nas_packet_data = {'packet_number': packet_num, 'protocol': protocol, 'info': info}
            has_rrc_data = False
            has_nas_data = False
            
            # Look for RRC and NAS layers in the packet
            for layer in packet.layers:
                try:
                    layer_name = layer.layer_name.lower()
                    
                    # Skip non-RRC/NAS layers (IP, ETH, UDP, GSMTAP)
                    if layer_name in ['ip', 'eth', 'udp', 'gsmtap', 'frame', 'geninfo']:
                        continue
                    
                    # Process RRC and NAS related layers
                    if any(protocol_type in layer_name for protocol_type in ['rrc', 'nas_eps', 'nas_5gs', 'gsm_a']):
                        self._extract_layer_fields_for_separate_csv(layer, layer_name, rrc_packet_data, nas_packet_data)
                        
                        # Check if we have data in either category
                        if any(key != 'packet_number' for key in rrc_packet_data.keys()):
                            has_rrc_data = True
                        if any(key != 'packet_number' for key in nas_packet_data.keys()):
                            has_nas_data = True
                            
                except Exception as e:
                    self.logger.debug(f"Error processing layer in packet {packet_num}: {e}")
                    continue
            
            # Add packets to appropriate data lists
            if has_rrc_data:
                self._rrc_packets_data.append(rrc_packet_data)
                # Ensure protocol and info are in the field sets
                self._all_rrc_fields.add('protocol')
                self._all_rrc_fields.add('info')
            if has_nas_data:
                self._nas_packets_data.append(nas_packet_data)
                # Ensure protocol and info are in the field sets
                self._all_nas_fields.add('protocol')
                self._all_nas_fields.add('info')
                
            if has_rrc_data or has_nas_data:
                self._packet_count += 1
                
        except Exception as e:
            self.logger.debug(f"Error extracting RRC/NAS data for CSV: {e}")

    def _extract_layer_fields_for_separate_csv(self, layer, layer_name, rrc_packet_data, nas_packet_data):
        """Extract fields from a layer and categorize them for separate RRC/NAS CSV export"""
        try:
            if hasattr(layer, 'field_names'):
                # Limit the number of fields to process to prevent infinite loops
                field_names = list(layer.field_names)[:50]  # Process max 50 fields per layer
                
                for field_name in field_names:
                    try:
                        field_value = getattr(layer, field_name, None)
                        if field_value is not None:
                            # Create field name
                            csv_field_name = f"{layer_name}.{field_name}"
                            
                            # Categorize the field
                            field_category = self._categorize_field(csv_field_name, layer_name)
                            
                            # Add field to appropriate packet data and global field sets
                            if field_category == 'rrc':
                                rrc_packet_data[csv_field_name] = str(field_value)
                                self._all_rrc_fields.add(csv_field_name)
                            elif field_category == 'nas':
                                norm_name = self._normalize_nas_csv_field_name(csv_field_name)
                                nas_packet_data[norm_name] = str(field_value)
                                self._all_nas_fields.add(norm_name)
                            # Note: 'other' category fields are not included in CSV export
                            
                    except Exception as e:
                        self.logger.debug(f"Error processing field {field_name}: {e}")
                        continue
                        
        except Exception as e:
            self.logger.debug(f"Error extracting layer fields for separate CSV: {e}")

    def _categorize_field(self, field_name, layer_name):
        """
        Categorize a field as RRC, NAS, or other based on layer name and field patterns
        
        Args:
            field_name (str): The field name to categorize
            layer_name (str): The protocol layer name
            
        Returns:
            str: 'rrc', 'nas', or 'other'
        """
        try:
            normalized_field_name = field_name.lower().replace('_', '-').replace('.', '-')
            normalized_layer_name = layer_name.lower()
            
            # First priority: Field name pattern analysis (most reliable for embedded fields)
            # Look for NAS-related patterns in field names - this catches embedded NAS fields in RRC layers
            nas_patterns = ['nas-eps', 'nas-5gs', 'nas_eps', 'nas_5gs', 'emm', 'esm', 'gmm', 'sm-', 'mm-', 'gprs', 'gsm-a', 'attach', 'detach', 'tau', 'rai', 'tmsi', 'imsi', 'imei']
            if any(pattern in normalized_field_name for pattern in nas_patterns):
                return 'nas'
            
            # Second priority: Layer-based categorization
            # NAS layers should always be categorized as NAS
            if any(nas_type in normalized_layer_name for nas_type in ['nas', 'nas_eps', 'nas_5gs']):
                return 'nas'
            
            # GSM A-interface layers should be categorized as NAS (they're part of NAS)
            if any(gsm_type in normalized_layer_name for gsm_type in ['gsm_a', 'gsm_a_common', 'gsm_a_rr', 'gsm_a_gm', 'gsm_a_rp']):
                return 'nas'
            
            # Look for RRC-related patterns in field names
            rrc_patterns = ['lte-rrc', 'nr-rrc', 'rrc-', 'radio', 'resource', 'connection', 'setup', 'release', 'reconfiguration', 'measurement', 'handover', 'cell', 'paging', 'broadcast']
            if any(pattern in normalized_field_name for pattern in rrc_patterns):
                return 'rrc'
            
            # RRC layers should be categorized as RRC (after field pattern check)
            if any(rrc_type in normalized_layer_name for rrc_type in ['rrc', 'lte_rrc', 'nr_rrc']):
                return 'rrc'
            
            # Default to other for unknown fields
            return 'other'
            
        except Exception as e:
            self.logger.debug(f"Error categorizing field {field_name}: {e}")
            return 'other'

    def _normalize_nas_csv_field_name(self, field_name):
        """Normalize NAS CSV header names by collapsing RAT RRC prefixes.
        Examples: lte_rrc.foo -> lte.foo, lte-rrc.foo -> lte.foo, nr_rrc.foo -> nr.foo, nr-rrc.foo -> nr.foo"""
        try:
            return re.sub(r'^([a-z0-9]+)[-_]rrc\.', r'\1.', str(field_name).lower())
        except Exception:
            return field_name

    def _export_rrc_to_csv(self, csv_output_path):
        """Export RRC data to CSV file"""
        try:
            if not self._rrc_packets_data:
                self.logger.warning("No RRC data to export to CSV")
                return
            
            # Sort field names for consistent column ordering, with protocol and info first
            other_fields = sorted([f for f in self._all_rrc_fields if f not in ['protocol', 'info']])
            sorted_fields = ['packet_number', 'protocol', 'info'] + other_fields
            
            self.logger.info(f"Exporting {len(self._rrc_packets_data)} RRC packets with {len(sorted_fields)} fields to CSV")
            
            with open(csv_output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=sorted_fields, restval='-1')
                
                # Write header
                writer.writeheader()
                
                # Write packet data
                for packet_data in self._rrc_packets_data:
                    # Create row with -1 for missing fields
                    row = {}
                    for field in sorted_fields:
                        row[field] = packet_data.get(field, '-1')
                    writer.writerow(row)
            
            self.logger.info(f"Successfully exported RRC data to {csv_output_path}")
            
        except Exception as e:
            self.logger.error(f"Error exporting RRC data to CSV: {e}")

    def _export_nas_to_csv(self, csv_output_path):
        """Export NAS data to CSV file"""
        try:
            if not self._nas_packets_data:
                self.logger.warning("No NAS data to export to CSV")
                return
            
            # Sort field names for consistent column ordering, with protocol and info first
            other_fields = sorted([self._normalize_nas_csv_field_name(f) for f in self._all_nas_fields if f not in ['protocol', 'info']])
            sorted_fields = ['packet_number', 'protocol', 'info'] + other_fields
            
            self.logger.info(f"Exporting {len(self._nas_packets_data)} NAS packets with {len(sorted_fields)} fields to CSV")
            
            with open(csv_output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=sorted_fields, restval='-1')
                
                # Write header
                writer.writeheader()
                
                # Write packet data
                for packet_data in self._nas_packets_data:
                    # Create row with -1 for missing fields
                    row = {}
                    for field in sorted_fields:
                        row[field] = packet_data.get(field, '-1')
                    writer.writerow(row)
            
            self.logger.info(f"Successfully exported NAS data to {csv_output_path}")
            
        except Exception as e:
            self.logger.error(f"Error exporting NAS data to CSV: {e}")

    def _export_separate_rrc_nas_csv(self, base_csv_path):
        """
        Export RRC and NAS data to separate CSV files
        
        Args:
            base_csv_path (str): Base path for CSV files (without extension)
        """
        try:
            # Generate separate file paths
            rrc_csv_path = f"{base_csv_path}_rrc.csv"
            nas_csv_path = f"{base_csv_path}_nas.csv"
            
            # Export RRC data
            if self._rrc_packets_data:
                self._export_rrc_to_csv(rrc_csv_path)
                print(f"RRC CSV exported to: {rrc_csv_path}")
            else:
                print("No RRC data found for CSV export")
            
            # Export NAS data
            if self._nas_packets_data:
                self._export_nas_to_csv(nas_csv_path)
                print(f"NAS CSV exported to: {nas_csv_path}")
            else:
                print("No NAS data found for CSV export")
                
        except Exception as e:
            self.logger.error(f"Error exporting separate RRC/NAS CSV files: {e}")

    def _reset_csv_data(self):
        """Reset CSV data for new processing session"""
        self._rrc_packets_data = []
        self._nas_packets_data = []
        self._all_rrc_fields = set()
        self._all_nas_fields = set()
        self._packet_count = 0



    def process_qmdl_to_csv(self, packet_processor_func, pcap_output_path=None, csv_output_path=None):
        """
        Process QMDL packets and export to PCAP and CSV files

        Args:
            packet_processor_func: Function that writes packets using this DataWriter
            pcap_output_path (str): Optional permanent PCAP output file path
            csv_output_path (str): Optional CSV output file path for RRC/NAS data

        Returns:
            bool: Success status
        """
        pcap_file_path = None
        try:
            # Reset CSV data for new processing session
            self._reset_csv_data()
            
            # Create PCAP file path
            if pcap_output_path:
                # Use provided permanent path
                pcap_file_path = pcap_output_path
                # Ensure directory exists
                pcap_dir = os.path.dirname(pcap_file_path)
                if pcap_dir and not os.path.exists(pcap_dir):
                    os.makedirs(pcap_dir)
            else:
                # Create temporary PCAP file as fallback
                temp_dir = tempfile.gettempdir()
                temp_pcap = tempfile.NamedTemporaryFile(
                    delete=False,
                    suffix='.pcap',
                    prefix='qmdl_temp_',
                    dir=temp_dir
                )
                pcap_file_path = temp_pcap.name
                temp_pcap.close()

            # Initialize PCAP file
            self._init_pcap_file(pcap_file_path)

            # Call packet processor function
            if packet_processor_func:
                packet_processor_func(self)

            # Close PCAP file
            self._close_pcap_file()

            # Extract CSV data from PCAP using PyShark
            if csv_output_path:
                self._extract_csv_from_pcap(pcap_file_path)
                
                # Export RRC and NAS data to separate CSV files
                if self._rrc_packets_data or self._nas_packets_data:
                    self._export_separate_rrc_nas_csv(csv_output_path)

            return True

        except Exception as e:
            error_msg = f"Error processing QMDL to CSV: {e}"
            self.logger.error(error_msg)
            return False

        finally:
            # Only clean up if it's a temporary file (no pcap_output_path provided)
            if not pcap_output_path and pcap_file_path and os.path.exists(pcap_file_path):
                try:
                    os.unlink(pcap_file_path)
                    self.logger.debug(f"Cleaned up temporary PCAP file: {pcap_file_path}")
                except Exception as e:
                    self.logger.warning(f"Failed to clean up temporary file {pcap_file_path}: {e}")
            elif pcap_output_path and pcap_file_path:
                self.logger.info(f"Permanent PCAP file saved: {pcap_file_path}")

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

    def _extract_csv_from_pcap(self, pcap_file_path):
        """Extract RRC and NAS data from PCAP file for CSV export"""
        try:
            if not PYSHARK_AVAILABLE:
                self.logger.warning("PyShark not available for CSV extraction")
                return
                
            # Use single pass with detailed packet analysis
            cap = pyshark.FileCapture(pcap_file_path, include_raw=False, use_json=False)
            
            packet_count = 0
            max_packets = 5000  # Limit to prevent infinite processing
            
            # Process each packet
            for packet in cap:
                packet_count += 1
                
                # Limit packet processing to prevent hanging
                if packet_count > max_packets:
                    self.logger.warning(f"Reached packet limit ({max_packets}), stopping processing")
                    break
                
                # Extract RRC and NAS data for CSV export with enhanced protocol/info extraction
                self._extract_rrc_data_for_csv(packet, packet_count)
            
            cap.close()
            
            self.logger.info(f"Processed {packet_count} packets for CSV extraction")
            
        except Exception as e:
            error_msg = f"PyShark CSV extraction error: {e}"
            self.logger.error(error_msg)

















    def is_pyshark_available(self):
        """Check if PyShark is available"""
        return PYSHARK_AVAILABLE

# Backward compatibility
class PySharkDataWriter(DataWriter):
    """Alias for backward compatibility"""
    pass