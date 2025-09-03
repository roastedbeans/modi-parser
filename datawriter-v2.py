#!/usr/bin/env python3
# coding: utf8

import tempfile
import xml.etree.ElementTree as ET
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

        # Dissector directory path
        self.dissector_path = Path(__file__).parent / "dissector"
        
        # Cache for parsed dissector field definitions
        self._dissector_fields_cache = {}
        
        # Enhanced dissector field mappings using actual Wireshark dissector files
        self.protocol_dissectors = {
            'lte_rrc': self._extract_fields_from_dissector,
            'nr_rrc': self._extract_fields_from_dissector,
            'nas_eps': self._extract_fields_from_dissector,
            'nas_5gs': self._extract_fields_from_dissector,
            'rrc': self._extract_fields_from_dissector,
            'gsm_a': self._extract_fields_from_dissector,
            'gsm_a_common': self._extract_fields_from_dissector,
            'gsm_a_rr': self._extract_fields_from_dissector,
            'gsm_a_gm': self._extract_fields_from_dissector,
            'gsm_a_rp': self._extract_fields_from_dissector,
            'gsmtap': self._extract_fields_from_dissector,
            'mac_lte': self._extract_fields_from_dissector,
            'rlc_lte': self._extract_fields_from_dissector,
            'pdcp_lte': self._extract_fields_from_dissector
        }
        
        # Initialize dissector field definitions
        self._load_dissector_fields()
        
        # CSV export data - separate for RRC and NAS
        self._rrc_packets_data = []
        self._nas_packets_data = []
        self._all_rrc_fields = set()
        self._all_nas_fields = set()
        self._packet_count = 0

    def _load_dissector_fields(self):
        """Load field definitions from Wireshark dissector files"""
        try:
            # Map protocol names to dissector files
            dissector_files = {
                'lte_rrc': 'packet-lte-rrc.c',
                'nr_rrc': 'packet-nr-rrc.c',
                'nas_eps': 'packet-nas_eps.c',
                'nas_5gs': 'packet-nas_5gs.c',
                'rrc': 'packet-rrc.c',
                'gsm_a': 'packet-gsm_a_common.c',
                'gsm_a_common': 'packet-gsm_a_common.c',
                'gsm_a_rr': 'packet-gsm_a_rr.c',
                'gsm_a_gm': 'packet-gsm_a_gm.c',
                'gsm_a_rp': 'packet-gsm_a_rp.c',
                'gsmtap': 'packet-gsmtap.c',
                'mac_lte': 'packet-mac-lte.c',    # May not exist, will handle gracefully
                'rlc_lte': 'packet-rlc-lte.c',    # May not exist, will handle gracefully
                'pdcp_lte': 'packet-pdcp-lte.c'   # May not exist, will handle gracefully
            }
            
            for protocol, filename in dissector_files.items():
                dissector_file = self.dissector_path / filename
                if dissector_file.exists():
                    self._dissector_fields_cache[protocol] = self._parse_dissector_fields(dissector_file, protocol)
                    self.logger.debug(f"Loaded {len(self._dissector_fields_cache[protocol])} fields for {protocol}")
                else:
                    self.logger.debug(f"Dissector file not found: {dissector_file}")
                    self._dissector_fields_cache[protocol] = {}
                    
        except Exception as e:
            self.logger.warning(f"Error loading dissector fields: {e}")
            # Initialize empty cache for all protocols to prevent errors
            for protocol in ['lte_rrc', 'nr_rrc', 'nas_eps', 'nas_5gs', 'rrc', 'gsm_a', 'gsm_a_common', 'gsm_a_rr', 'gsm_a_gm', 'gsm_a_rp', 'gsmtap', 'mac_lte', 'rlc_lte', 'pdcp_lte']:
                self._dissector_fields_cache[protocol] = {}

    def _parse_dissector_fields(self, dissector_file, protocol):
        """Parse field definitions from a Wireshark dissector C file"""
        fields = {}
        try:
            with open(dissector_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Pattern to match Wireshark field definitions like:
            # { &hf_lte_rrc_measId,
            #   { "measId", "lte-rrc.measId",
            #     FT_UINT32, BASE_DEC, NULL, 0,
            #     NULL, HFILL }},
            
            field_pattern = re.compile(
                r'{\s*&(hf_[^,]+),\s*'  # Field variable name
                r'{\s*"([^"]+)",\s*'     # Field display name
                r'"([^"]+)",\s*'         # Field filter name
                r'([^,]+),\s*'           # Field type
                r'([^,]+),\s*'           # Base
                r'([^,]+),\s*'           # Value string/NULL
                r'([^,]+),\s*'           # Mask
                r'"?([^"]*)"?,\s*'       # Description (optional)
                r'HFILL\s*}',            # HFILL ending
                re.MULTILINE | re.DOTALL
            )
            
            matches = field_pattern.findall(content)
            
            for match in matches:
                hf_name, display_name, filter_name, field_type, base, value_string, mask, description = match
                
                # Clean up the field information
                fields[hf_name] = {
                    'display_name': display_name.strip(),
                    'filter_name': filter_name.strip(),
                    'field_type': field_type.strip(),
                    'base': base.strip(),
                    'value_string': value_string.strip(),
                    'mask': mask.strip(),
                    'description': description.strip() if description else display_name.strip()
                }
            
            self.logger.info(f"Parsed {len(fields)} field definitions from {dissector_file.name}")
            return fields
            
        except Exception as e:
            self.logger.error(f"Error parsing dissector file {dissector_file}: {e}")
            return {}

    def _extract_fields_from_dissector(self, proto_elem, layer):
        """Extract fields using actual Wireshark dissector definitions"""
        try:
            layer_name = layer.layer_name.lower()
            
            # Get protocol-specific field definitions
            protocol_fields = self._dissector_fields_cache.get(layer_name, {})
            
            # Add fake-field-wrapper for compatibility
            fake_wrapper = ET.SubElement(proto_elem, "proto")
            fake_wrapper.set("name", "fake-field-wrapper")
            fake_wrapper.set("showname", f"{layer_name.upper()} Protocol Fields (from dissector)")
            
            # Extract fields available in the layer
            if hasattr(layer, 'field_names'):
                available_fields = layer.field_names
                
                for field_name in available_fields:
                    try:
                        field_value = getattr(layer, field_name, None)
                        if field_value is not None:
                            # Look for matching dissector field definition
                            matching_hf = self._find_matching_field_definition(field_name, protocol_fields, layer_name)
                            
                            if matching_hf:
                                field_info = protocol_fields[matching_hf]
                                field_elem = ET.SubElement(fake_wrapper, "field")
                                field_elem.set("name", field_info['filter_name'])
                                field_elem.set("showname", f"{field_info['display_name']}: {field_value}")
                                field_elem.set("show", str(field_value))
                                field_elem.set("value", self._format_field_value(field_value))
                                field_elem.set("size", "0")
                                field_elem.set("pos", "0")
                                
                                # Add field type information as comment
                                if field_info['description']:
                                    field_elem.set("description", field_info['description'])
                                
                                # Add specialized information for certain protocols
                                if layer_name == 'gsmtap':
                                    self._add_gsmtap_specialized_info(field_elem, field_name, field_value, field_info)
                                elif layer_name.startswith('gsm_a_'):
                                    self._add_gsm_a_specialized_info(field_elem, field_name, field_value, field_info, layer_name)
                            else:
                                # Fallback: create field with basic information
                                field_elem = ET.SubElement(fake_wrapper, "field")
                                field_elem.set("name", f"{layer_name}.{field_name}")
                                field_elem.set("showname", f"{field_name}: {field_value}")
                                field_elem.set("show", str(field_value))
                                field_elem.set("value", self._format_field_value(field_value))
                                field_elem.set("size", "0")
                                field_elem.set("pos", "0")
                                
                    except Exception as e:
                        continue  # Skip problematic fields
            
            # If no fields were extracted, add a note
            if len(fake_wrapper) == 0:
                note_field = ET.SubElement(fake_wrapper, "field")
                note_field.set("name", f"{layer_name}.info")
                note_field.set("show", f"No extractable fields found for {layer_name}")
                note_field.set("showname", f"Protocol Info: {layer_name} layer detected")
                
        except Exception as e:
            self._add_error_field(proto_elem, f'{layer_name}_dissector_extraction_error', 
                                f'Dissector extraction error for {layer_name}: {e}')

    def _add_gsmtap_specialized_info(self, field_elem, field_name, field_value, field_info):
        """Add specialized information for GSMTAP protocol fields"""
        try:
            # Add GSMTAP-specific field information
            if 'type' in field_name:
                field_elem.set("gsmtap_type", "payload_type")
            elif 'burst_type' in field_name:
                field_elem.set("gsmtap_burst", "burst_type")
            elif 'channel_type' in field_name:
                field_elem.set("gsmtap_channel", "channel_type")
            elif 'arfcn' in field_name:
                field_elem.set("gsmtap_radio", "frequency")
            elif 'signal_dbm' in field_name:
                field_elem.set("gsmtap_radio", "signal_strength")
            elif 'snr_db' in field_name:
                field_elem.set("gsmtap_radio", "signal_quality")
        except Exception:
            pass

    def _add_gsm_a_specialized_info(self, field_elem, field_name, field_value, field_info, layer_name):
        """Add specialized information for GSM A-interface protocol fields"""
        try:
            # Add GSM A-interface specific field information
            if layer_name == 'gsm_a_rr':
                if 'cause' in field_name:
                    field_elem.set("gsm_a_rr", "radio_resource_cause")
                elif 'channel' in field_name:
                    field_elem.set("gsm_a_rr", "channel_information")
                elif 'measurement' in field_name:
                    field_elem.set("gsm_a_rr", "measurement_data")
            elif layer_name == 'gsm_a_gm':
                if 'cause' in field_name:
                    field_elem.set("gsm_a_gm", "mobility_cause")
                elif 'identity' in field_name:
                    field_elem.set("gsm_a_gm", "identity_information")
                elif 'timer' in field_name:
                    field_elem.set("gsm_a_gm", "timer_information")
            elif layer_name == 'gsm_a_rp':
                if 'cause' in field_name:
                    field_elem.set("gsm_a_rp", "radio_paging_cause")
        except Exception:
            pass

    def _extract_rrc_data_for_csv(self, packet, packet_num):
        """Extract RRC and NAS data from packet for CSV export"""
        try:
            rrc_packet_data = {'packet_number': packet_num}
            nas_packet_data = {'packet_number': packet_num}
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
            if has_nas_data:
                self._nas_packets_data.append(nas_packet_data)
                
            if has_rrc_data or has_nas_data:
                self._packet_count += 1
                
        except Exception as e:
            self.logger.debug(f"Error extracting RRC/NAS data for CSV: {e}")

    def _extract_layer_fields_for_separate_csv(self, layer, layer_name, rrc_packet_data, nas_packet_data):
        """Extract fields from a layer and categorize them for separate RRC/NAS CSV export"""
        try:
            # Get protocol-specific field definitions
            protocol_fields = self._dissector_fields_cache.get(layer_name, {})
            
            if hasattr(layer, 'field_names'):
                # Limit the number of fields to process to prevent infinite loops
                field_names = list(layer.field_names)[:50]  # Process max 50 fields per layer
                
                for field_name in field_names:
                    try:
                        field_value = getattr(layer, field_name, None)
                        if field_value is not None:
                            # Create proper field name using dissector definitions
                            matching_hf = self._find_matching_field_definition(field_name, protocol_fields, layer_name)
                            
                            if matching_hf and matching_hf in protocol_fields:
                                field_info = protocol_fields[matching_hf]
                                csv_field_name = field_info.get('filter_name', f"{layer_name}.{field_name}")
                            else:
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
            
            # Sort field names for consistent column ordering
            sorted_fields = ['packet_number'] + sorted([f for f in self._all_rrc_fields])
            
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
            
            # Sort field names for consistent column ordering
            sorted_fields = ['packet_number'] + sorted([self._normalize_nas_csv_field_name(f) for f in self._all_nas_fields])
            
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

    def _find_matching_field_definition(self, field_name, protocol_fields, protocol_name):
        """Find matching field definition in dissector fields"""
        try:
            # Early return if no protocol fields available
            if not protocol_fields:
                return None
                
            # Direct match with hf_ prefix
            hf_name = f"hf_{protocol_name}_{field_name}"
            if hf_name in protocol_fields:
                return hf_name
            
            # Try variations for different naming conventions
            variations = [
                f"hf_{protocol_name.replace('_', '-')}_{field_name}",
                f"hf_{protocol_name}_{field_name.replace('-', '_')}",
                f"hf_{protocol_name.replace('_', '')}_{field_name}",
                # Handle gsm_a variations
                f"hf_gsm_a_{field_name}" if protocol_name.startswith('gsm_a_') else None,
                f"hf_gsm_a_{protocol_name.split('_')[-1]}_{field_name}" if protocol_name.startswith('gsm_a_') else None,
                # Handle gsmtap variations
                f"hf_gsmtap_{field_name}" if protocol_name == 'gsmtap' else None,
            ]
            
            for variation in variations:
                if variation and variation in protocol_fields:
                    return variation
            
            # Limit the search to prevent infinite loops - only check first 100 fields
            field_count = 0
            max_fields_to_check = 100
            
            # Search by filter name match with enhanced patterns
            field_name_normalized = field_name.replace('_', '-').replace('-', '.')
            
            for hf_name, field_info in protocol_fields.items():
                field_count += 1
                if field_count > max_fields_to_check:
                    break
                    
                try:
                    # Direct filter name match
                    if field_name_normalized in field_info.get('filter_name', ''):
                        return hf_name
                    if field_name in field_info.get('filter_name', ''):
                        return hf_name
                    # Display name match
                    if field_info.get('display_name', '').lower() == field_name.lower():
                        return hf_name
                    # Partial matches for complex field names
                    if field_name.lower() in field_info.get('display_name', '').lower():
                        return hf_name
                    # Handle gsm_a specific patterns
                    if protocol_name.startswith('gsm_a_') and field_name in hf_name:
                        return hf_name
                except (KeyError, AttributeError, TypeError):
                    continue  # Skip problematic field info
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error in field matching for {field_name}: {e}")
            return None

    def process_qmdl_to_pdml(self, packet_processor_func, pcap_output_path=None, csv_output_path=None):
        """
        Process QMDL packets and convert to PDML XML using permanent PCAP with PyShark

        Args:
            packet_processor_func: Function that writes packets using this DataWriter
            pcap_output_path (str): Optional permanent PCAP output file path
            csv_output_path (str): Optional CSV output file path for RRC data

        Returns:
            str: PDML XML data from PyShark dissection
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

            # Export RRC and NAS data to separate CSV files if requested
            if csv_output_path and (self._rrc_packets_data or self._nas_packets_data):
                self._export_separate_rrc_nas_csv(csv_output_path)

            return f'<pdml><error>PDML export is no longer supported.</error></pdml>'

        except Exception as e:
            error_msg = f"Error processing QMDL to PDML: {e}"
            self.logger.error(error_msg)
            return f'<pdml><error>{error_msg}</error></pdml>'

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

    def _pcap_to_pdml_with_pyshark(self, pcap_file_path):
        """Convert PCAP file to PDML XML using PyShark"""
        try:
            # Open PCAP with PyShark
            cap = pyshark.FileCapture(pcap_file_path, include_raw=False, use_json=False)
            
            # Create PDML root element
            pdml = ET.Element("pdml")
            pdml.set("version", "0")
            pdml.set("creator", "pyshark-datawriter/1.0")
            pdml.set("time", datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y"))
            pdml.set("capture_file", os.path.basename(pcap_file_path))
            
            packet_count = 0
            max_packets = 5000  # Limit to prevent infinite processing
            
            # Process each packet
            for packet in cap:
                packet_count += 1
                
                # Limit packet processing to prevent hanging
                if packet_count > max_packets:
                    self.logger.warning(f"Reached packet limit ({max_packets}), stopping processing")
                    break
                
                packet_elem = ET.SubElement(pdml, "packet")
                
                # Add packet timestamp and frame info
                self._add_packet_metadata(packet_elem, packet, packet_count)
                
                # Process all protocol layers in the packet
                self._process_packet_layers(packet_elem, packet)
                
                # Extract RRC data for CSV export
                self._extract_rrc_data_for_csv(packet, packet_count)
            
            cap.close()
            
            if packet_count == 0:
                return '<pdml><error>No packets found in PCAP</error></pdml>'
            
            # Convert XML tree to string
            xml_str = self._xml_to_string_with_header(pdml)
            
            self.logger.info(f"Processed {packet_count} packets with PyShark")
            return xml_str

        except Exception as e:
            error_msg = f"PyShark processing error: {e}"
            self.logger.error(error_msg)
            return f'<pdml><error>{error_msg}</error></pdml>'

    def _add_packet_metadata(self, packet_elem, packet, packet_num):
        """Add packet metadata and frame information"""
        # Get packet size
        packet_size = int(packet.length) if hasattr(packet, 'length') else len(packet.get_raw_packet())
        
        # Add geninfo protocol
        geninfo = ET.SubElement(packet_elem, "proto")
        geninfo.set("name", "geninfo")
        geninfo.set("pos", "0")
        geninfo.set("showname", "General information")
        geninfo.set("size", str(packet_size))
        
        # Packet number
        num_field = ET.SubElement(geninfo, "field")
        num_field.set("name", "num")
        num_field.set("pos", "0")
        num_field.set("show", str(packet_num))
        num_field.set("showname", "Number")
        num_field.set("value", str(packet_num))
        num_field.set("size", str(packet_size))
        
        # Frame length
        len_field = ET.SubElement(geninfo, "field")
        len_field.set("name", "len")
        len_field.set("pos", "0")
        len_field.set("show", str(packet_size))
        len_field.set("showname", "Frame Length")
        len_field.set("value", hex(packet_size)[2:])
        len_field.set("size", str(packet_size))
        
        # Timestamp
        if hasattr(packet, 'sniff_time'):
            timestamp = packet.sniff_time
            timestamp_str = timestamp.strftime("%b %d, %Y %H:%M:%S.%f000")
            ts_field = ET.SubElement(geninfo, "field")
            ts_field.set("name", "timestamp")
            ts_field.set("pos", "0")
            ts_field.set("show", timestamp_str)
            ts_field.set("showname", "Captured Time")
            ts_field.set("value", f"{timestamp.timestamp():.9f}")
            ts_field.set("size", str(packet_size))

    def _process_packet_layers(self, packet_elem, packet):
        """Process all protocol layers in the packet"""
        try:
            # Get all layers
            for layer in packet.layers:
                layer_name = layer.layer_name.lower()
                
                # Create protocol element
                proto_elem = ET.SubElement(packet_elem, "proto")
                proto_elem.set("name", layer_name)
                proto_elem.set("showname", f"{layer_name.upper()} Layer")
                proto_elem.set("size", "0")  # PyShark doesn't always provide size
                proto_elem.set("pos", "0")   # PyShark doesn't provide position info
                
                # Add fields from this layer
                self._add_layer_fields(proto_elem, layer, layer_name)
                
                # Special handling for specific protocols using dissector definitions
                if layer_name in self.protocol_dissectors:
                    self.protocol_dissectors[layer_name](proto_elem, layer)
                    
        except Exception as e:
            # Add error information if layer processing fails
            error_proto = ET.SubElement(packet_elem, "proto")
            error_proto.set("name", "processing_error")
            error_field = ET.SubElement(error_proto, "field")
            error_field.set("name", "error")
            error_field.set("show", f"Layer processing error: {e}")

    def _add_layer_fields(self, proto_elem, layer, layer_name):
        """Add fields from a protocol layer"""
        try:
            field_names = layer.field_names if hasattr(layer, 'field_names') else []
            
            for field_name in field_names:
                try:
                    field_value = getattr(layer, field_name, None)
                    
                    # Skip None values that cause serialization errors
                    if field_value is not None:
                        field_elem = ET.SubElement(proto_elem, "field")
                        field_elem.set("name", f"{layer_name}.{field_name}")
                        field_elem.set("showname", f"{field_name}: {field_value}")
                        field_elem.set("show", str(field_value))
                        field_elem.set("value", str(field_value))
                        field_elem.set("size", "0")
                        field_elem.set("pos", "0")
                            
                except Exception as e:
                    continue
                        
        except Exception as e:
            error_field = ET.SubElement(proto_elem, "field")
            error_field.set("name", "field_error")
            error_field.set("show", f"Field processing error: {e}")

    def _add_specialized_protocol_fields(self, proto_elem, layer, layer_name):
        """Add comprehensive specialized fields for all supported cellular protocols"""
        try:
            # Use the enhanced dissector mappings
            if layer_name in self.protocol_dissectors:
                self.protocol_dissectors[layer_name](proto_elem, layer)
            else:
                # Fallback for unknown protocols - extract all available fields
                self._extract_all_available_fields(proto_elem, layer, layer_name)
                
        except Exception as e:
            # Add detailed error information for debugging
            error_field = ET.SubElement(proto_elem, "field")
            error_field.set("name", f"{layer_name}_specialized_error")
            error_field.set("show", f"Specialized processing error: {e}")
            error_field.set("showname", f"Error in {layer_name} processing: {str(e)}")
            error_field.set("size", "0")
            error_field.set("pos", "0")

    def _format_field_value(self, value):
        """Format field value for XML output"""
        try:
            if isinstance(value, bytes):
                return value.hex()
            elif isinstance(value, (int, float)):
                return str(value)
            elif isinstance(value, bool):
                return "1" if value else "0"
            else:
                return str(value)
        except Exception:
            return str(value)

    def _add_error_field(self, parent_elem, error_name, error_message):
        """Add an error field to the parent element"""
        try:
            error_field = ET.SubElement(parent_elem, "field")
            error_field.set("name", error_name)
            error_field.set("show", error_message)
            error_field.set("showname", f"Error: {error_message}")
            error_field.set("size", "0")
            error_field.set("pos", "0")
        except Exception:
            pass  # Silently handle error field creation errors

    def _xml_to_string_with_header(self, root_element):
        """Convert XML element to string with proper PDML header"""
        # Create XML string with header
        xml_str = '<?xml version="1.0" encoding="utf-8"?>\n'
        xml_str += '<?xml-stylesheet type="text/xsl" href="pdml2html.xsl"?>\n'
        
        # Convert element to string
        rough_string = ET.tostring(root_element, encoding='unicode')
        xml_str += rough_string
        
        return xml_str

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