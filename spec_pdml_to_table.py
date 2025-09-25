#!/usr/bin/env python3.8
# coding: utf8

import xml.etree.ElementTree as ET
import csv
import re
from pathlib import Path
from spec_nas_header import nas_headers
from spec_rrc_header import rrc_headers


class PdmlToTableConverter:
    def __init__(self, excluded_fields=None):
        self.all_fields = set()
        self.packet_data = []
        self.nas_packets = []
        self.rrc_packets = []
        self.nas_fields = set()
        self.rrc_fields = set()
        self.excluded_fields = set(excluded_fields) if excluded_fields else set()
        
        # Set target fields
        self.nas_target_fields = set(self._slugify(field) for field in nas_headers)
        self.rrc_target_fields = set(self._slugify(field) for field in rrc_headers)

    def _slugify(self, text):
        """Convert text to slug format with underscores"""
        if not text:
            return ""
        text = re.sub(r'[^\w\s-]', '_', text)
        text = re.sub(r'[\s_]+', '_', text)
        text = text.strip('_')
        return text.lower()

    def _classify_packet_type(self, packet):
        """Classify packet as NAS, RRC, or other"""
        fields = packet.findall('.//field')
        nas_patterns = {'lte_nas', 'nas', 'emm', 'esm', 'nas-5gs', '5g_nas'}
        rrc_patterns = {'lte_rrc', 'rrc', 'bcch', 'dcch', 'ccch', 'pcch', 'nr-rrc', 'nr_rrc'}
        
        nas_count = 0
        rrc_count = 0
        
        for field in fields:
            field_name = field.get('name', '').lower().replace('-', '_')
            if any(pattern in field_name for pattern in nas_patterns):
                nas_count += 1
            elif any(pattern in field_name for pattern in rrc_patterns):
                rrc_count += 1
        
        if nas_count > rrc_count:
            return 'nas'
        elif rrc_count > nas_count:
            return 'rrc'
        else:
            return 'other'

    def _normalize_field_value(self, value, field_type=None):
        """Simplified normalization for show, value, and showname"""
        if value is None or value == '':
            return '-1'
        
        value_str = str(value).strip()
        if value_str.lower() in {'n/a', 'null', 'none'}:
            return '-1'
        
        # Special handling for showname with common patterns
        if field_type == 'showname':
            # Handle c1: patterns
            if 'c1:' in value_str.lower():
                parts = value_str.split('c1:')
                if len(parts) > 1:
                    word = parts[1].strip().split()[0]  # Get first word after c1:
                    # Remove parentheses, numbers, colons, commas first
                    cleaned = re.sub(r'[()0-9:,]', '', word).strip()
                    # Remove -r followed by any characters
                    cleaned = re.sub(r'-r.*', '', cleaned)
                    return cleaned
            
            # Handle establishmentCause: patterns
            if 'establishmentcause:' in value_str.lower():
                parts = value_str.split(':')
                if len(parts) > 1:
                    word = parts[1].strip().split()[0]  # Get first word after colon
                    # Remove parentheses and numbers
                    cleaned = re.sub(r'[()0-9]', '', word).strip()
                    return cleaned
                
            if 'ue-Identity:' in value_str.lower():
                parts = value_str.split(':')
                if len(parts) > 1:
                    word = parts[1].strip().split()[0]  # Get first word after colon
                    # Remove parentheses and numbers
                    cleaned = re.sub(r'[()0-9]', '', word).strip()
                    return cleaned
        
        return value_str

    def _should_skip_field(self, field_name):
        """Check if field should be skipped"""
        if not field_name:
            return True
        
        skip_prefixes = ('geninfo.', 'user_dlt.', 'aww.')
        if field_name.startswith(skip_prefixes):
            return True
        
        geninfo_fields = {'num', 'len', 'caplen', 'timestamp'}
        if field_name in geninfo_fields:
            return True
        
        return any(excluded in field_name for excluded in self.excluded_fields)

    def _process_field_values(self, field_element):
        """Process show, value, and showname attributes"""
        show_value = self._normalize_field_value(field_element.get('show', ''), 'show')
        value_value = self._normalize_field_value(field_element.get('value', ''), 'value')
        showname_value = self._normalize_field_value(field_element.get('showname', ''), 'showname')
        return [show_value, value_value, showname_value]

    def _extract_packet_fields(self, packet, packet_idx):
        """Extract only exact target field matches from a packet"""
        packet_info = {'packet_number': packet_idx + 1}
        packet_type = self._classify_packet_type(packet)
        
        if packet_type not in ['nas', 'rrc']:
            return None
        
        # Get target fields for this packet type
        target_fields = self.nas_target_fields if packet_type == 'nas' else self.rrc_target_fields
        
        nested_packets = packet.findall('packet')
        if nested_packets:
            fields = nested_packets[0].findall('.//field')
        else:
            fields = packet.findall('.//field')
        
        # Process all fields to find exact matches
        self._process_fields_for_targets(fields, '', packet_info, target_fields)
        
        return packet_info
    
    def _process_fields_for_targets(self, fields, parent_path, packet_info, target_fields):
        """Process fields to find exact target matches"""
        for field in fields:
            field_name = field.get('name', '')
            
            if (not field_name or 
                self._should_skip_field(field_name) or
                field.get('hide') == 'yes'):
                continue
            
            full_field_name = f"{parent_path}.{field_name}" if parent_path else field_name
            header = self._slugify(full_field_name)
            
            # Check if this is an exact target field match
            if header in target_fields:
                field_show = field.get('show', '')
                field_value = field.get('value', '')
                
                if field_show or field_value:
                    field_data_array = self._process_field_values(field)
                    self.all_fields.add(header)
                    packet_info[header] = field_data_array
                    continue  # Don't process sub-fields if exact match found
            
            # Process sub-fields with updated path
            sub_fields = field.findall('field')
            if sub_fields:
                self._process_fields_for_targets(sub_fields, full_field_name, packet_info, target_fields)

    def _update_field_set(self, packet_info, field_set):
        """Update field set with packet fields"""
        for key in packet_info.keys():
            if key != 'packet_number':
                field_set.add(key)

    def parse_pdml(self, pdml_file):
        """Parse PDML XML file"""
        try:
            tree = ET.parse(pdml_file)
            root = tree.getroot()
            
            if root.tag == 'pdml_capture':
                packets = []
                for child in root:
                    if child.tag == 'packet' and child.get('number'):
                        nested_packets = child.findall('packet')
                        if nested_packets:
                            packets.append((child.get('number'), nested_packets[0]))
                        else:
                            packets.append((child.get('number'), child))
            else:
                packets = []
                packet_num = 1
                for child in root:
                    if child.tag == 'packet':
                        packets.append((str(packet_num), child))
                        packet_num += 1
            
            for packet_num, packet in packets:
                try:
                    packet_info = self._extract_packet_fields(packet, int(packet_num) - 1)
                    if packet_info:
                        packet_type = self._classify_packet_type(packet)
                        
                        if packet_type == 'nas':
                            self.nas_packets.append(packet_info)
                            self._update_field_set(packet_info, self.nas_fields)
                        elif packet_type == 'rrc':
                            self.rrc_packets.append(packet_info)
                            self._update_field_set(packet_info, self.rrc_fields)
                except Exception as e:
                    print(f"Error processing packet {packet_num}: {e}")
                    continue
            
            return True
        except Exception as e:
            print(f"Error parsing PDML file: {e}")
            return False

    def generate_csv(self, output_file, packet_collection, field_collection, label):
        """Generate CSV file with show, value, and showname for target fields"""
        try:
            if not packet_collection:
                print("No packet data to write to CSV")
                return False
            
            # Filter field_collection to only include target fields that were actually found
            if packet_collection is self.nas_packets:
                target_fields = self.nas_target_fields
            else:
                target_fields = self.rrc_target_fields
            
            actual_fields = sorted(field_collection.intersection(target_fields))
            
            if not actual_fields:
                print(f"No target fields found in {len(packet_collection)} packets")
                return False
            
            # Create headers - show, value, and showname for each field
            headers = []
            for field in actual_fields:
                headers.append(f"{field}_show")
                headers.append(f"{field}_value")
                headers.append(f"{field}_showname")
            
            headers.append('label')
            
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(headers)
                
                for packet in packet_collection:
                    row = []
                    
                    for field in actual_fields:
                        field_array = packet.get(field, None)
                        
                        if field_array is None or not isinstance(field_array, list):
                            row.extend(['-1', '-1', '-1'])  # show, value, showname
                        else:
                            # Expecting [show_value, value_value, showname_value]
                            show_val = field_array[0] if len(field_array) > 0 else '-1'
                            value_val = field_array[1] if len(field_array) > 1 else '-1'
                            showname_val = field_array[2] if len(field_array) > 2 else '-1'
                            row.extend([show_val, value_val, showname_val])
                    
                    row.append(label)
                    writer.writerow(row)
                    print(row)
                    
                    # Add the specification-based detection from here
                    
            
            print(f"Successfully wrote {len(packet_collection)} packets with {len(actual_fields)} target fields to {output_file}")
            return True
        except Exception as e:
            print(f"Error writing CSV file: {e}")
            return False

    def convert_pdml_to_csv(self, pdml_file, csv_file=None):
        """Convert PDML to separate CSV files for NAS and RRC"""
        if csv_file is None:
            csv_file = str(Path(pdml_file).with_suffix('.csv'))
        
        if not self.parse_pdml(pdml_file):
            return False
        
        base_path = Path(csv_file)
        success = True
        
        # Generate separate CSVs
        if self.nas_packets:
            nas_file = str(base_path.parent / (base_path.stem + '_nas' + base_path.suffix))
            success &= self.generate_csv(nas_file, self.nas_packets, self.nas_fields, 1)
        
        if self.rrc_packets:
            rrc_file = str(base_path.parent / (base_path.stem + '_rrc' + base_path.suffix))
            success &= self.generate_csv(rrc_file, self.rrc_packets, self.rrc_fields, 0)
        
        return success


if __name__ == "__main__":
    xml_files = list(Path('.').glob('*.xml'))
    if xml_files:
        xml_file = str(xml_files[0])
        print(f"Converting {xml_file} to CSV...")
        
        converter = PdmlToTableConverter()
        if converter.convert_pdml_to_csv(xml_file):
            print("✅ Conversion completed successfully")
        else:
            print("❌ Conversion failed")
    else:
        print("No XML files found in current directory.")