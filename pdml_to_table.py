#!/usr/bin/env python3.8
# coding: utf8

import xml.etree.ElementTree as ET
import csv
import re
from pathlib import Path
from nas_headers import nas_headers
from rrc_headers import rrc_headers


class PdmlToTableConverter:
    def __init__(self, excluded_fields=None):
        self.all_fields = set()
        self.packet_data = []
        self.nas_packets = []
        self.rrc_packets = []
        self.nas_fields = set()
        self.rrc_fields = set()

        # Initialize prioritized field lists
        self.nas_priority_fields = nas_headers
        self.rrc_priority_fields = rrc_headers

        # Create field priority lookup dictionaries for fast checking
        self.nas_field_priority = {field: idx for idx, field in enumerate(self.nas_priority_fields)}
        self.rrc_field_priority = {field: idx for idx, field in enumerate(self.rrc_priority_fields)}

        # Set of field names to exclude from CSV headers
        self.excluded_fields = set(excluded_fields) if excluded_fields else set()
        # Add default exclusions
        self.excluded_fields.update(['MCC_MNC_Digit', 'lte-rrc.bCCH_DL_SCH_Message.message'])

    def _get_field_priority(self, field_name, packet_type):
        """Get priority level of a field based on protocol type (lower number = higher priority)"""
        if packet_type == 'nas':
            return self.nas_field_priority.get(field_name, 999)
        elif packet_type == 'rrc':
            return self.rrc_field_priority.get(field_name, 999)
        return 999  # Default for unknown fields

    def _is_priority_field(self, field_name, packet_type):
        """Check if field is in the priority list for given protocol"""
        if packet_type == 'nas':
            return field_name in self.nas_field_priority
        elif packet_type == 'rrc':
            return field_name in self.rrc_field_priority
        return False

    def _slugify(self, text):
        """Convert text to slug format with underscores"""
        if not text:
            return ""

        # Replace spaces and special characters with underscores
        text = re.sub(r'[^\w\s-]', '_', text)
        # Replace multiple spaces/underscores with single underscore
        text = re.sub(r'[\s_]+', '_', text)
        # Remove leading/trailing underscores
        text = text.strip('_')
        # Convert to lowercase
        return text.lower()

    def _classify_packet_type(self, packet):
        """Classify packet as NAS, RRC, or other based on protocol content"""
        fields = packet.findall('.//field')
        nas_count = 0
        rrc_count = 0

        # Pre-compile patterns for better performance - focus on LTE and 5G/NR protocols
        nas_patterns = {'lte_nas', 'nas', 'emm', 'esm', 'nas-5gs', '5g_nas'}
        rrc_patterns = {'lte_rrc', 'rrc', 'bcch', 'dcch', 'ccch', 'pcch', 'nr-rrc', 'nr_rrc'}

        # Additional patterns to identify LTE and 5G/NR packets
        network_patterns = {'lte', 'lte_nas', 'lte_rrc', 'nr', 'nr-rrc', 'nas-5gs', '5g'}

        # First check if this is a network packet (LTE or 5G/NR)
        is_network_packet = False
        for field in fields:
            field_name = field.get('name', '').lower().replace('-', '_')
            if any(pattern in field_name for pattern in network_patterns):
                is_network_packet = True
                break

        # If not a network packet, classify as 'other' to be ignored
        if not is_network_packet:
            return 'other'

        for field in fields:
            field_name = field.get('name', '').lower().replace('-', '_')
            if not field_name:
                continue

            has_nas = any(pattern in field_name for pattern in nas_patterns)
            has_rrc = any(pattern in field_name for pattern in rrc_patterns)

            # Count pure indicators (avoid double counting mixed fields)
            if has_nas and not has_rrc:
                nas_count += 1
            elif has_rrc and not has_nas:
                rrc_count += 1

        total_classified = nas_count + rrc_count
        if total_classified == 0:
            return 'other'  # Only network packets (LTE/5G/NR) with NAS or RRC content are classified

        # Use majority rule
        if nas_count > rrc_count:
            return 'nas'
        elif rrc_count > nas_count:
            return 'rrc'
        else:
            # If tied, check for specific RRC message types
            for field in fields:
                field_name = field.get('name', '')
                if any(msg in field_name for msg in ['rrcConnection', 'systemInformation', 'paging']):
                    return 'rrc'
            return 'rrc'  # Default for network packets

    def _normalize_field_value(self, value, field_type=None):
        """
        Unified normalization function for all field values
        field_type: 'name', 'showname', 'size', 'pos', 'show', 'value', 'unmasked'
        """
        # Handle None or empty
        if value is None or value == '':
            if field_type == 'name':
                return '-1'
            elif field_type == 'showname':
                return '-1'
            elif field_type in ['size', 'pos']:
                return '-1'
            elif field_type == 'show':
                return '-1'
            elif field_type in ['value', 'unmasked']:
                return '-1'
            return '-1'

        value_str = str(value).strip()

        # Handle invalid markers
        if value_str.lower() in {'n/a', 'null', 'none'}:
            return '-1'

        # Type-specific normalization
        if field_type == 'name':
            # Binary: 1 if present, 0 if empty
            return '1' if value_str else '0'

        elif field_type == 'showname':
            # Hash to 3 digits (100-999)
            if not value_str:
                return '100'
            hash_val = 0
            for i, char in enumerate(value_str):
                hash_val = (hash_val * 31 + ord(char)) % 900
            return str(hash_val + 100)

        elif field_type in ['size', 'pos']:
            # Keep numeric values as-is
            return value_str if value_str else '0'

        elif field_type == 'show':
            # Normalize to single digit
            if value_str == 'True':
                return '1'
            elif value_str == 'False':
                return '0'

            # Handle numeric values
            if value_str.replace('-', '').replace('.', '').isdigit():
                try:
                    num = abs(int(float(value_str)))
                    return str(min(num, 9))
                except:
                    pass

            # Hash text to single digit
            hash_val = sum(ord(c) for c in value_str) % 10
            return str(hash_val)

        elif field_type in ['value', 'unmasked']:
            # Normalize hex payloads and values to 2 digits
            if len(value_str) > 8:
                is_hex = all(c in '0123456789abcdefABCDEF' for c in value_str)
                if is_hex:
                    try:
                        first = int(value_str[:2], 16) if len(value_str) >= 2 else 0
                        last = int(value_str[-2:], 16) if len(value_str) >= 2 else 0
                        result = (first ^ last) % 100
                        return f'{result:02d}'
                    except:
                        return '99'

            # Short values - keep or pad
            if len(value_str) <= 4:
                if value_str.isdigit():
                    return value_str.zfill(2)
                return value_str

            # Hash medium values to 2 digits
            hash_val = sum(ord(c) * (i + 1) for i, c in enumerate(value_str[:10])) % 100
            return f'{hash_val:02d}'

        # Default: return as-is
        return value_str

    def _should_skip_field(self, field_name):
        """Check if a field should be skipped based on its protocol"""
        if not field_name:
            return True

        # Skip fields from these protocol layers
        skip_prefixes = ('geninfo.', 'frame.', 'user_dlt.', 'aww.')
        if field_name.startswith(skip_prefixes):
            return True

        # Skip known geninfo fields
        geninfo_fields = {'num', 'len', 'caplen', 'timestamp'}
        if field_name in geninfo_fields:
            return True

        # Skip fields in the exclusion list
        for excluded_field in self.excluded_fields:
            if excluded_field in field_name:
                return True

        return False

    def _process_field_values(self, field_element):
        """Process field values with normalization - adds -1 for empty attributes"""
        normalized_attributes = []

        # Always process name first (required)
        field_name = field_element.get('name', '')
        normalized_attributes.append(self._normalize_field_value(field_name, 'name'))

        # Check and process optional attributes in order
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
                # Get the value - could be empty string
                value = field_element.get(attr_name)
                # Normalize will convert empty string to -1
                normalized_value = self._normalize_field_value(value, field_type)
                normalized_attributes.append(normalized_value)
            # Note: We don't append -1 here for missing attributes
            # because different fields have different numbers of attributes
            # The -1 padding happens in generate_csv functions

        return normalized_attributes

    def parse_pdml(self, pdml_file, separate_by_protocol=True):
        """Parse PDML XML file and extract field data"""
        try:
            tree = ET.parse(pdml_file)
            root = tree.getroot()

            # Handle both ws_dissector format (pdml_capture) and tshark format (pdml)
            if root.tag == 'pdml_capture':
                # ws_dissector format - packets are nested
                packets = []
                for child in root:
                    if child.tag == 'packet' and child.get('number'):
                        # Find the nested packet element
                        nested_packets = child.findall('packet')
                        if nested_packets:
                            packets.append((child.get('number'), nested_packets[0]))
                        else:
                            packets.append((child.get('number'), child))
            else:
                # tshark format - direct packet elements
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
                        if separate_by_protocol:
                            packet_type = self._classify_packet_type(packet)

                            # Only include NAS and RRC packets, ignore other protocols
                            if packet_type == 'nas':
                                self.nas_packets.append(packet_info)
                                self._update_field_set(packet_info, self.nas_fields)
                            elif packet_type == 'rrc':
                                self.rrc_packets.append(packet_info)
                                self._update_field_set(packet_info, self.rrc_fields)
                            # Ignore 'other' packets - they won't be included in any output
                        else:
                            self.packet_data.append(packet_info)
                            self._update_field_set(packet_info, self.all_fields)
                except Exception as e:
                    print(f"Error processing packet {packet_num}: {e}")
                    continue

            return True
        except Exception as e:
            print(f"Error parsing PDML file: {e}")
            return False

    def _update_field_set(self, packet_info, field_set):
        """Update field set with packet fields (excluding packet_number)"""
        for key in packet_info.keys():
            if key != 'packet_number':
                field_set.add(key)

    def convert_pdml_to_csv(self, pdml_file, csv_file=None, separate_by_protocol=True, expanded=False, simple=False):
        """Convert PDML file to CSV(s) in one step"""
        if csv_file is None:
            csv_file = str(Path(pdml_file).with_suffix('.csv'))

        if self.parse_pdml(pdml_file, separate_by_protocol):
            if separate_by_protocol:
                if simple:
                    return self.generate_separate_simple_csvs(csv_file)
                elif expanded:
                    return self.generate_separate_csvs_expanded(csv_file)
                else:
                    return self.generate_separate_csvs(csv_file)
            else:
                if simple:
                    return self.generate_simple_csv(csv_file, self.packet_data, self.all_fields)
                elif expanded:
                    return self.generate_csv_expanded(csv_file, self.packet_data, self.all_fields)
                else:
                    return self.generate_csv(csv_file, self.packet_data, self.all_fields)

        return False

    def _extract_packet_fields(self, packet, packet_idx):
        """Extract all fields from a single packet with hierarchical naming and field prioritization"""
        packet_info = {'packet_number': packet_idx + 1}

        # Determine packet type for field prioritization
        packet_type = self._classify_packet_type(packet)

        # Find the nested packet that contains the actual data
        nested_packets = packet.findall('packet')
        if nested_packets:
            data_packet = nested_packets[0]
            fields = data_packet.findall('.//field')
        else:
            fields = packet.findall('.//field')

        # Separate priority fields from regular fields
        priority_fields = []
        regular_fields = []

        for field in fields:
            field_name = field.get('name', '')
            if self._is_priority_field(field_name, packet_type):
                priority_fields.append(field)
            else:
                regular_fields.append(field)

        # Process priority fields first (in priority order)
        if packet_type in ['nas', 'rrc']:
            priority_list = self.nas_priority_fields if packet_type == 'nas' else self.rrc_priority_fields

            # Sort priority fields by their priority order
            priority_fields.sort(key=lambda f: self._get_field_priority(f.get('name', ''), packet_type))

            for field in priority_fields:
                self._extract_field_recursively(field, '', packet_info, packet_type)

        # Process remaining regular fields
        for field in regular_fields:
            self._extract_field_recursively(field, '', packet_info, packet_type)

        return packet_info

    def _extract_field_recursively(self, field_element, parent_path, packet_info, packet_type=None):
        """Recursively extract field data with filtering and prioritization"""
        field_name = field_element.get('name', '')

        # Early skip checks
        if (not field_name or
            self._should_skip_field(field_name) or
            field_element.get('hide') == 'yes'):
            return

        # Check for required attributes
        field_show = field_element.get('show', '')
        field_value = field_element.get('value', '')
        if not field_show or not field_value:
            return

        # Build hierarchical field name
        full_field_name = f"{parent_path}.{field_name}" if parent_path else field_name

        # Process field values into combined array format
        field_data_array = self._process_field_values(field_element)

        # Create header (just the field name without suffixes)
        header = self._slugify(full_field_name)
        self.all_fields.add(header)

        # Store the combined array as the field value
        packet_info[header] = field_data_array

        # Recursively process sub-fields with packet type context
        sub_fields = field_element.findall('field')
        for sub_field in sub_fields:
            self._extract_field_recursively(sub_field, full_field_name, packet_info, packet_type)

    def generate_separate_csvs(self, base_filename):
        """Generate separate CSV files for NAS and RRC packets"""
        success = True
        base_path = Path(base_filename)

        # Generate CSVs for each packet type
        csv_configs = [
            (self.nas_packets, self.nas_fields, '_nas'),
            (self.rrc_packets, self.rrc_fields, '_rrc'),
            # (self.packet_data, self.all_fields, '')
        ]

        for packets, fields, suffix in csv_configs:
            if packets:
                filename = str(base_path.parent / (base_path.stem + suffix + base_path.suffix))
                if not self.generate_csv(filename, packets, fields):
                    success = False

        return success

    def generate_separate_csvs_expanded(self, base_filename):
        """Generate separate expanded CSV files for NAS and RRC packets"""
        success = True
        base_path = Path(base_filename)

        # Generate expanded CSVs for each packet type
        csv_configs = [
            (self.nas_packets, self.nas_fields, '_nas_expanded'),
            (self.rrc_packets, self.rrc_fields, '_rrc_expanded'),
            # (self.packet_data, self.all_fields, '_expanded')
        ]

        for packets, fields, suffix in csv_configs:
            if packets:
                filename = str(base_path.parent / (base_path.stem + suffix + base_path.suffix))
                if not self.generate_csv_expanded(filename, packets, fields):
                    success = False

        return success

    def generate_simple_csv(self, output_file, packet_collection=None, field_collection=None):
        """Generate CSV file with simple field names and values (no attributes)"""
        try:
            if packet_collection is None:
                packet_collection = self.packet_data
            if field_collection is None:
                field_collection = self.all_fields

            if not packet_collection:
                print("No packet data to write to CSV")
                return False

            # Create ordered list of fields, excluding packet_number
            field_list = sorted([f for f in field_collection if f != 'packet_number'])

            # Add packet_number at the beginning
            headers = ['packet_number'] + field_list

            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(headers)

                for packet in packet_collection:
                    row = [packet.get('packet_number', '')]

                    for field in field_list:
                        if field in packet:
                            field_array = packet[field]

                            # Extract just the value from the field array (index 5 is the 'value' attribute)
                            if isinstance(field_array, list) and len(field_array) >= 6:
                                # Use the 'value' attribute (index 5) or 'show' attribute (index 4) if value is empty
                                field_value = field_array[5] if field_array[5] else field_array[4]
                                row.append(field_value)
                            else:
                                row.append(str(field_array))
                        else:
                            row.append('')

                    writer.writerow(row)

            print(f"Successfully wrote {len(packet_collection)} packets to simple CSV {output_file}")
            return True

        except Exception as e:
            print(f"Error writing simple CSV file: {e}")
            return False

    def generate_separate_simple_csvs(self, base_filename):
        """Generate separate simple CSV files for NAS and RRC packets"""
        success = True
        base_path = Path(base_filename)

        # Generate simple CSVs for each packet type
        csv_configs = [
            (self.nas_packets, self.nas_fields, '_nas_simple'),
            (self.rrc_packets, self.rrc_fields, '_rrc_simple')
        ]

        for packets, fields, suffix in csv_configs:
            if packets:
                filename = str(base_path.parent / (base_path.stem + suffix + base_path.suffix))
                if not self.generate_simple_csv(filename, packets, fields):
                    success = False

        return success

    def generate_prioritized_csv(self, output_file, packet_collection=None, field_collection=None, protocol_type='all'):
        """Generate CSV with prioritized field ordering based on protocol type - with individual columns"""
        try:
            if packet_collection is None:
                packet_collection = self.packet_data
            if field_collection is None:
                field_collection = self.all_fields

            if not packet_collection:
                print("No packet data to write to CSV")
                return False

            # Get priority fields based on protocol type
            priority_fields = []
            if protocol_type == 'nas':
                priority_fields = self.nas_priority_fields
            elif protocol_type == 'rrc':
                priority_fields = self.rrc_priority_fields

            # Separate priority fields from other fields
            priority_field_set = set(priority_fields)
            priority_present = [f for f in priority_fields if f in field_collection]
            other_fields = [f for f in field_collection if f not in priority_field_set and f != 'packet_number']

            # Create ordered list of fields: packet_number, priority fields, other fields
            field_list = ['packet_number'] + priority_present + sorted(other_fields)

            # Generate CSV with individual columns using expanded format logic
            return self._generate_csv_with_columns(output_file, packet_collection, field_list)

        except Exception as e:
            print(f"Error generating prioritized CSV: {e}")
            return False

    def _generate_csv_with_columns(self, output_file, packet_collection, field_list):
        """Generate CSV with individual columns for each field"""
        try:
            # First pass: determine max attributes for each field
            field_max_attrs = {}
            for field in field_list:
                max_attrs = 0
                for packet in packet_collection:
                    if field in packet:
                        field_array = packet.get(field, [])
                        if isinstance(field_array, list):
                            max_attrs = max(max_attrs, len(field_array))
                # Default to at least 1 attribute if field never appears
                field_max_attrs[field] = max_attrs if max_attrs > 0 else 1

            # Create headers for individual columns
            headers = []
            for field in field_list:
                max_attrs = field_max_attrs[field]
                if max_attrs == 1:
                    headers.append(field)
                else:
                    for i in range(max_attrs):
                        headers.append(f"{field}_{i}")

            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(headers)

                for packet in packet_collection:
                    row = []
                    for field in field_list:
                        field_array = packet.get(field, None)
                        expected_attrs = field_max_attrs[field]

                        if field_array is None:
                            # Field not present in this packet - use -1 for expected number of attributes
                            row.extend(['-1'] * expected_attrs)
                        elif isinstance(field_array, list) and field_array:
                            # Field exists with data - pad if needed
                            padded_array = field_array[:]
                            while len(padded_array) < expected_attrs:
                                padded_array.append('-1')
                            row.extend(str(item) for item in padded_array)
                        else:
                            # Field exists but is empty - use -1 for expected number of attributes
                            row.extend(['-1'] * expected_attrs)

                    writer.writerow(row)

            print(f"Successfully wrote {len(packet_collection)} packets to {output_file}")
            return True

        except Exception as e:
            print(f"Error generating CSV with columns: {e}")
            return False

    def generate_separate_prioritized_csvs(self, base_filename):
        """Generate separate prioritized CSV files for NAS and RRC packets"""
        success = True
        base_path = Path(base_filename)

        # Generate prioritized CSVs for each packet type
        if self.nas_packets:
            nas_csv_file = str(base_path.parent / (base_path.stem + '_nas_prioritized.csv'))
            if not self.generate_prioritized_csv(nas_csv_file, self.nas_packets, self.nas_fields, 'nas'):
                success = False

        if self.rrc_packets:
            rrc_csv_file = str(base_path.parent / (base_path.stem + '_rrc_prioritized.csv'))
            if not self.generate_prioritized_csv(rrc_csv_file, self.rrc_packets, self.rrc_fields, 'rrc'):
                success = False

        return success

    def generate_csv(self, output_file, packet_collection=None, field_collection=None):
        """Generate CSV file with normalized data in structured format"""
        try:
            if packet_collection is None:
                packet_collection = self.packet_data
            if field_collection is None:
                field_collection = self.all_fields

            if not packet_collection:
                print("No packet data to write to CSV")
                return False

            # Determine protocol type for labeling
            if packet_collection is self.rrc_packets:
                protocol_type = "RRC"
                label = 0
            elif packet_collection is self.nas_packets:
                protocol_type = "NAS"
                label = 1
            # else:
            #     # Default to RRC if can't determine
            #     protocol_type = "RRC"
            #     label = 0

            # First pass: determine max attributes for each field
            field_max_attrs = {}
            for field in sorted(field_collection):
                max_attrs = 0
                for packet in packet_collection:
                    if field in packet:
                        field_array = packet.get(field, [])
                        if isinstance(field_array, list):
                            max_attrs = max(max_attrs, len(field_array))
                # Default to at least 1 attribute if field never appears
                field_max_attrs[field] = max_attrs if max_attrs > 0 else 1

            # Create headers: data and label
            headers = ['data', 'label']

            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(headers)

                for packet in packet_collection:
                    # Build data string with all fields
                    data_parts = []
                    for field in sorted(field_collection):
                        field_array = packet.get(field, None)
                        expected_attrs = field_max_attrs[field]

                        if field_array is None:
                            # Field not present in this packet - use -1 for expected number of attributes
                            empty_array = ['-1'] * expected_attrs
                            array_str = '[' + ', '.join(empty_array) + ']'
                            data_parts.append(f"{field} : {array_str}")
                        elif isinstance(field_array, list) and field_array:
                            # Field exists with data - pad if needed
                            padded_array = field_array[:]
                            while len(padded_array) < expected_attrs:
                                padded_array.append('-1')
                            array_str = '[' + ', '.join(str(item) for item in padded_array) + ']'
                            data_parts.append(f"{field} : {array_str}")
                        else:
                            # Field exists but empty or invalid
                            empty_array = ['-1'] * expected_attrs
                            array_str = '[' + ', '.join(empty_array) + ']'
                            data_parts.append(f"{field} : {array_str}")

                    # Join all field data with semicolons
                    field_data_str = '; '.join(data_parts)

                    # Add protocol identifier prefix
                    data_str = f"{protocol_type} - {field_data_str}"

                    # Write row with data and label
                    writer.writerow([data_str, label])

            print(f"Successfully wrote {len(packet_collection)} packets to {output_file}")
            return True
        except Exception as e:
            print(f"Error writing CSV file: {e}")
            return False

    def generate_csv_expanded(self, output_file, packet_collection=None, field_collection=None):
        """Generate CSV file with expanded field attributes as separate columns"""
        try:
            if packet_collection is None:
                packet_collection = self.packet_data
            if field_collection is None:
                field_collection = self.all_fields

            if not packet_collection:
                print("No packet data to write to CSV")
                return False

            # Determine protocol type for labeling
            if packet_collection is self.rrc_packets:
                label = 0
            elif packet_collection is self.nas_packets:
                label = 1
            else:
                # Default to RRC if can't determine
                label = 0

            # First pass: determine which attributes each field actually has
            field_attributes_map = {}
            for field in sorted(field_collection):
                field_attributes_map[field] = set()
                for packet in packet_collection:
                    if field in packet:
                        field_array = packet.get(field, [])
                        if isinstance(field_array, list):
                            # Track actual number of attributes for this field
                            field_attributes_map[field].add(len(field_array))
            
                # Ensure at least 1 attribute column for empty fields
                if not field_attributes_map[field]:
                    field_attributes_map[field].add(1)

            # Define possible attribute names based on position
            attr_position_names = ['_name', '_showname', '_size', '_pos', '_show', '_value', '_unmasked']

            # Create headers based on actual attributes present
            headers = []
            for field in sorted(field_collection):
                max_attrs = max(field_attributes_map[field]) if field_attributes_map[field] else 1
                for i in range(max_attrs):
                    if i < len(attr_position_names):
                        headers.append(f"{field}{attr_position_names[i]}")
                    else:
                        headers.append(f"{field}_attr_{i}")

            # Add label column header
            headers.append('label')

            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(headers)

                for packet in packet_collection:
                    row = []

                    for field in sorted(field_collection):
                        field_array = packet.get(field, None)
                        max_attrs = max(field_attributes_map[field]) if field_attributes_map[field] else 1

                        if field_array is None:
                            # Field not present - fill with -1
                            for _ in range(max_attrs):
                                row.append('-1')
                        elif isinstance(field_array, list) and field_array:
                            # Add actual values from array
                            for i in range(max_attrs):
                                if i < len(field_array):
                                    row.append(field_array[i])
                                else:
                                    row.append('-1')  # Pad missing attributes with -1
                        else:
                            # Field exists but invalid - fill with -1
                            for _ in range(max_attrs):
                                row.append('-1')

                    # Add label to the row
                    row.append(label)
                    writer.writerow(row)

            print(f"Successfully wrote {len(packet_collection)} packets to expanded CSV {output_file}")
            return True
        except Exception as e:
            print(f"Error writing expanded CSV file: {e}")
            return False


if __name__ == "__main__":
    """Example usage demonstrating both regular and expanded CSV formats"""

    # Example usage with an existing XML file
    xml_files = list(Path('.').glob('*.xml'))
    if xml_files:
        xml_file = str(xml_files[0])  # Use first XML file found
        print(f"Converting {xml_file} to CSV formats...")

        converter = PdmlToTableConverter()

        # Generate regular CSV (structured format)
        print("\n1. Generating regular CSV with structured data format:")
        if converter.convert_pdml_to_csv(xml_file, expanded=False):
            csv_file = xml_file.replace('.xml', '.csv')
            print(f"   ✅ Regular CSV: {csv_file}")

        # Generate expanded CSV (separate columns for each field attribute)
        print("\n2. Generating expanded CSV with separate columns:")
        if converter.convert_pdml_to_csv(xml_file, expanded=True):
            expanded_csv_file = xml_file.replace('.xml', '_expanded.csv')
            print(f"   ✅ Expanded CSV: {expanded_csv_file}")

    else:
        print("No XML files found in current directory. Please provide an XML file to convert.")