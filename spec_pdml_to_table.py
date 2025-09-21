#!/usr/bin/env python3.8
# coding: utf8

import xml.etree.ElementTree as ET
import csv
import re
from pathlib import Path
# Essential fields for specification-based detection
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
        """Normalize field values"""
        if value is None or value == '':
            return '-1'
        
        value_str = str(value).strip()
        if value_str.lower() in {'n/a', 'null', 'none'}:
            return '-1'
        
        if field_type == 'name':
            return '1' if value_str else '0'
        elif field_type == 'showname':
            if not value_str:
                return '100'
            hash_val = sum(ord(c) for c in value_str) % 900
            return str(hash_val + 100)
        elif field_type in ['size', 'pos']:
            return value_str if value_str else '0'
        elif field_type == 'show':
            if value_str == 'True':
                return '1'
            elif value_str == 'False':
                return '0'
            if value_str.replace('-', '').replace('.', '').isdigit():
                try:
                    num = abs(int(float(value_str)))
                    return str(min(num, 9))
                except:
                    pass
            hash_val = sum(ord(c) for c in value_str) % 10
            return str(hash_val)
        elif field_type in ['value', 'unmasked']:
            if len(value_str) > 8:
                if all(c in '0123456789abcdefABCDEF' for c in value_str):
                    try:
                        first = int(value_str[:2], 16) if len(value_str) >= 2 else 0
                        last = int(value_str[-2:], 16) if len(value_str) >= 2 else 0
                        result = (first ^ last) % 100
                        return f'{result:02d}'
                    except:
                        return '99'
            if len(value_str) <= 4:
                if value_str.isdigit():
                    return value_str.zfill(2)
                return value_str
            hash_val = sum(ord(c) * (i + 1) for i, c in enumerate(value_str[:10])) % 100
            return f'{hash_val:02d}'
        
        return value_str

    def _should_skip_field(self, field_name):
        """Check if field should be skipped"""
        if not field_name:
            return True
        
        skip_prefixes = ('geninfo.', 'frame.', 'user_dlt.', 'aww.')
        if field_name.startswith(skip_prefixes):
            return True
        
        geninfo_fields = {'num', 'len', 'caplen', 'timestamp'}
        if field_name in geninfo_fields:
            return True
        
        return any(excluded in field_name for excluded in self.excluded_fields)

    def _process_field_values(self, field_element):
        """Process field values with normalization"""
        normalized_attributes = []
        
        field_name = field_element.get('name', '')
        normalized_attributes.append(self._normalize_field_value(field_name, 'name'))
        
        optional_attrs = [
            ('showname', 'showname'),
            ('size', 'size'),
            ('pos', 'pos'),
            ('show', 'show'),
            ('value', 'value'),
            ('unmaskedvalue', 'unmasked')
        ]
        
        for attr_name, field_type in optional_attrs:
            if attr_name in field_element.attrib:
                value = field_element.get(attr_name)
                normalized_value = self._normalize_field_value(value, field_type)
                normalized_attributes.append(normalized_value)
        
        return normalized_attributes

    def _extract_field_recursively(self, field_element, parent_path, packet_info, target_fields):
        """Recursively extract field data - only exact target field matches"""
        field_name = field_element.get('name', '')
        
        if (not field_name or 
            self._should_skip_field(field_name) or
            field_element.get('hide') == 'yes'):
            return
        
        full_field_name = f"{parent_path}.{field_name}" if parent_path else field_name
        header = self._slugify(full_field_name)
        
        # Only process if this is an EXACT target field match
        if header in target_fields:
            field_show = field_element.get('show', '')
            field_value = field_element.get('value', '')
            
            if field_show or field_value:
                field_data_array = self._process_field_values(field_element)
                self.all_fields.add(header)
                packet_info[header] = field_data_array
                return  # Don't recurse into sub-fields if we found exact match
        
        # Only recurse if we haven't found an exact match
        for sub_field in field_element.findall('field'):
            self._extract_field_recursively(sub_field, full_field_name, packet_info, target_fields)

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
        """Process fields to find exact target matches without recursion conflicts"""
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
        """Generate CSV file with only target fields"""
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
            
            # Determine max attributes for each field
            field_max_attrs = {}
            for field in actual_fields:
                max_attrs = 0
                for packet in packet_collection:
                    if field in packet:
                        field_array = packet.get(field, [])
                        if isinstance(field_array, list):
                            max_attrs = max(max_attrs, len(field_array))
                field_max_attrs[field] = max_attrs if max_attrs > 0 else 1
            
            # Create headers
            attr_names = ['_name', '_showname', '_size', '_pos', '_show', '_value', '_unmasked']
            headers = []
            
            for field in actual_fields:
                max_attrs = field_max_attrs[field]
                for i in range(max_attrs):
                    if i < len(attr_names):
                        headers.append(f"{field}{attr_names[i]}")
                    else:
                        headers.append(f"{field}_attr_{i}")
            
            headers.append('label')
            
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(headers)
                
                for packet in packet_collection:
                    row = []
                    
                    for field in actual_fields:
                        field_array = packet.get(field, None)
                        max_attrs = field_max_attrs[field]
                        
                        if field_array is None:
                            row.extend(['-1'] * max_attrs)
                        elif isinstance(field_array, list) and field_array:
                            for i in range(max_attrs):
                                if i < len(field_array):
                                    row.append(field_array[i])
                                else:
                                    row.append('-1')
                        else:
                            row.extend(['-1'] * max_attrs)
                    
                    row.append(label)
                    writer.writerow(row)
            
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