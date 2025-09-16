#!/usr/bin/env python3
# coding: utf8

import xml.etree.ElementTree as ET
import csv
import os
import re
from pathlib import Path

class PdmlToTableConverter:
    def __init__(self):
        self.all_fields = set()
        self.packet_data = []
        self.nas_packets = []
        self.rrc_packets = []
        self.nas_fields = set()
        self.rrc_fields = set()

    def _slugify(self, text):
        """Convert text to slug format with underscores"""
        if not text:
            return ""

        # Replace spaces and special characters with underscores
        text = re.sub(r'[^\w\s]', '_', text)
        # Replace multiple spaces/underscores with single underscore
        text = re.sub(r'[\s_]+', '_', text)
        # Replace dashes with underscores
        text = re.sub(r'-', '_', text)
        # Remove leading/trailing underscores
        text = text.strip('_')
        # Convert to lowercase
        return text.lower()

    def _classify_packet_type(self, packet):
        """Classify packet as NAS, RRC, or other based on protocol content"""
        # Look for protocol-specific fields to classify the packet
        fields = packet.findall('.//field')

        nas_count = 0
        rrc_count = 0

        for field in fields:
            field_name = field.get('name', '')
            if not field_name:
                continue

            # Count pure NAS indicators
            if ('nas' in field_name.lower() or
                'emm' in field_name.lower() or
                'esm' in field_name.lower() or
                'lte_nas' in field_name.replace('-', '_').lower()):
                # Check if it's NOT also an RRC field (avoid double counting mixed fields)
                has_rrc_in_name = ('rrc' in field_name.lower() or
                                  'bcch' in field_name.lower() or
                                  'dcch' in field_name.lower() or
                                  'ccch' in field_name.lower() or
                                  'pcch' in field_name.lower())
                if not has_rrc_in_name:
                    nas_count += 1

            # Count pure RRC indicators
            if ('rrc' in field_name.lower() or
                'bcch' in field_name.lower() or
                'dcch' in field_name.lower() or
                'ccch' in field_name.lower() or
                'pcch' in field_name.lower()):
                # Check if it's NOT also a NAS field (avoid double counting mixed fields)
                has_nas_in_name = ('nas' in field_name.lower() or
                                  'emm' in field_name.lower() or
                                  'esm' in field_name.lower() or
                                  'lte_nas' in field_name.replace('-', '_').lower())
                if not has_nas_in_name:
                    rrc_count += 1

        # Classify based on majority rule
        total_classified = nas_count + rrc_count

        if total_classified == 0:
            return 'other'

        # Use majority rule: if one type has more than 50% of classified fields
        nas_ratio = nas_count / total_classified
        rrc_ratio = rrc_count / total_classified

        if nas_ratio > 0.5:
            return 'nas'
        elif rrc_ratio > 0.5:
            return 'rrc'
        else:
            # If roughly equal, check for specific RRC message types
            for field in fields:
                field_name = field.get('name', '')
                if ('rrcConnection' in field_name or
                    'systemInformation' in field_name or
                    'paging' in field_name):
                    return 'rrc'
            # Default to RRC for LTE packets (more common)
            return 'rrc'

    def _convert_hex_to_decimal(self, value):
        """Convert various hex formats to decimal"""
        if not value:
            return value

        # Handle different hex formats
        try:
            # Remove common separators and prefixes
            cleaned_value = value.replace(':', '').replace(' ', '').replace('0x', '').replace('0X', '')

            # Check if it's a valid hex string (contains only hex characters)
            if all(c in '0123456789abcdefABCDEF' for c in cleaned_value):
                # Convert to decimal
                return str(int(cleaned_value, 16))
            else:
                # Not a valid hex, return original
                return value
        except (ValueError, TypeError, OverflowError):
            # If conversion fails, return original value
            return value

    def _normalize_field_value(self, value):
        """Normalize field value, converting empty/invalid values to -1"""
        # Handle None values
        if value is None:
            return '-1'

        # Handle empty strings and whitespace-only strings
        if isinstance(value, str):
            if value.strip() == '':
                return '-1'

            # Handle specific invalid values that should be treated as empty
            invalid_values = ['N/A', 'n/a', 'NULL', 'null', 'None', 'none', '-', '--', '---']
            if value.strip().lower() in invalid_values:
                return '-1'

        # Handle other falsy values (but not 0, False, etc. which might be valid)
        # Only treat truly empty cases as -1
        if value == '':
            return '-1'

        # Return the original value if it's not empty/invalid
        return value

    def _extract_mcc_mnc_digits(self, field_element, field_type):
        """Extract and combine MCC/MNC digits into a single value"""
        try:
            # Find all MCC_MNC_Digit fields within this MCC/MNC field
            digit_fields = field_element.findall('.//field[@name="lte-rrc.MCC_MNC_Digit"]')

            if not digit_fields:
                return None

            # Extract the digit values from the show attribute
            digits = []
            for digit_field in digit_fields:
                show_value = digit_field.get('show', '')
                # The show value is already the digit we need
                if show_value and show_value.isdigit():
                    digits.append(show_value)

            if not digits:
                return None

            # Combine digits into MCC/MNC value
            combined = ''.join(digits)

            # For MCC, ensure it's 3 digits, for MNC ensure it's 2-3 digits
            if field_type == 'mcc' and len(combined) == 3:
                return combined
            elif field_type == 'mnc' and 2 <= len(combined) <= 3:
                # Pad MNC with leading zero if needed for 2 digits
                return combined.zfill(2) if len(combined) == 2 else combined

            return None

        except Exception as e:
            # If extraction fails, return None
            return None

    def parse_pdml(self, pdml_file, separate_by_protocol=True):
        """Parse PDML XML file and extract field data

        Args:
            pdml_file: Path to the PDML XML file
            separate_by_protocol: If True, separate packets by NAS/RRC type

        Returns:
            bool: True if parsing successful, False otherwise
        """
        try:
            tree = ET.parse(pdml_file)
            root = tree.getroot()

            # Find only direct packet children to avoid nested packet duplication
            packets = [child for child in root if child.tag == 'packet' and child.get('number')]

            for packet_idx, packet in enumerate(packets):
                packet_info = self._extract_packet_fields(packet, packet_idx)
                if packet_info:
                    if separate_by_protocol:
                        # Classify packet type and store in appropriate collection
                        packet_type = self._classify_packet_type(packet)

                        if packet_type == 'nas':
                            self.nas_packets.append(packet_info)
                            # Update NAS-specific field set
                            for key in packet_info.keys():
                                if key != 'packet_number':
                                    self.nas_fields.add(key)
                        elif packet_type == 'rrc':
                            self.rrc_packets.append(packet_info)
                            # Update RRC-specific field set
                            for key in packet_info.keys():
                                if key != 'packet_number':
                                    self.rrc_fields.add(key)
                        else:
                            # For other packets, add to general collection
                            self.packet_data.append(packet_info)
                            for key in packet_info.keys():
                                if key != 'packet_number':
                                    self.all_fields.add(key)
                    else:
                        # Unified mode - add all packets to general collection
                        self.packet_data.append(packet_info)
                        for key in packet_info.keys():
                            if key != 'packet_number':
                                self.all_fields.add(key)

            return True

        except Exception as e:
            return False

    def convert_pdml_to_csv(self, pdml_file, csv_file=None, separate_by_protocol=True):
        """Convert PDML file to CSV(s) in one step

        Args:
            pdml_file: Path to the PDML XML file
            csv_file: Path to output CSV file. If None, uses pdml_file.csv
            separate_by_protocol: If True, creates separate CSVs for NAS and RRC packets

        Returns:
            bool: True if conversion successful, False otherwise
        """
        if csv_file is None:
            csv_file = str(Path(pdml_file).with_suffix('.csv'))

        if self.parse_pdml(pdml_file, separate_by_protocol):
            if separate_by_protocol:
                return self.generate_separate_csvs(csv_file)
            else:
                return self.generate_csv(csv_file, self.packet_data, self.all_fields)

        return False


    def _extract_packet_fields(self, packet, packet_idx):
        """Extract all fields from a single packet with hierarchical naming"""
        packet_info = {'packet_number': packet_idx + 1}

        # Find the nested packet that contains the actual data
        nested_packets = packet.findall('packet')
        if nested_packets:
            # Use the first nested packet for field extraction
            data_packet = nested_packets[0]
            fields = data_packet.findall('.//field')
        else:
            # Fallback to recursive search if no nested packet
            fields = packet.findall('.//field')

        for field in fields:
            self._extract_field_recursively(field, '', packet_info)

        return packet_info

    def _should_skip_field(self, field_name):
        """Check if a field should be skipped based on its protocol"""
        if not field_name:
            return False

        # Skip fields from these protocol layers
        skip_prefixes = ('geninfo.', 'frame.', 'user_dlt.', 'aww.')
        if field_name.startswith(skip_prefixes):
            return True

        # Also skip known geninfo fields that don't have the geninfo. prefix
        geninfo_fields = {'num', 'len', 'caplen', 'timestamp'}
        if field_name in geninfo_fields:
            return True

        return False

    def _extract_field_recursively(self, field_element, parent_path, packet_info):
        """Recursively extract field data with filtering"""
        field_name = field_element.get('name', '')

        # Skip fields with empty name
        if not field_name:
            return

        # Skip fields from unwanted protocols (geninfo, frame, user_dlt, aww)
        if self._should_skip_field(field_name):
            return

        # Skip fields with hide="yes"
        if field_element.get('hide') == 'yes':
            return

        # Get show and value attributes
        field_show = field_element.get('show', '')
        field_value = field_element.get('value', '')

        # Skip fields that don't have both show and value
        if not field_show or not field_value:
            return

        # Build hierarchical field name
        if parent_path:
            full_field_name = f"{parent_path}.{field_name}"
        else:
            full_field_name = field_name

        # Special handling for MCC/MNC fields - extract and combine digits
        if field_name.endswith('.mcc') or field_name.endswith('.mnc'):
            field_type = 'mcc' if field_name.endswith('.mcc') else 'mnc'
            combined_digits = self._extract_mcc_mnc_digits(field_element, field_type)
            if combined_digits is not None:
                field_show = combined_digits
                field_value = combined_digits

        # Convert hex value to decimal if it's a valid hex number
        field_value = self._convert_hex_to_decimal(field_value)
        field_show = self._convert_hex_to_decimal(field_show)


        # Create slugified headers for show and value
        show_header = self._slugify(f"{full_field_name}_show")
        value_header = self._slugify(f"{full_field_name}_value")

        # Store both field mappings
        self.all_fields.add(show_header)
        self.all_fields.add(value_header)

        # Change True/False to 1/0
        if field_show == 'True':
            field_show = '1'
        elif field_show == 'False':
            field_show = '0'
        if field_value == 'True':
            field_value = '1'
        elif field_value == 'False':
            field_value = '0'

        # If field data is empty or no value, set it to -1
        # Handle various empty/invalid cases comprehensively
        field_show = self._normalize_field_value(field_show)
        field_value = self._normalize_field_value(field_value)
        

        # Store the values
        packet_info[show_header] = field_show
        packet_info[value_header] = field_value
        


        # Recursively process sub-fields (but skip MCC_MNC_Digit fields as they're handled above)
        sub_fields = field_element.findall('field')
        for sub_field in sub_fields:
            sub_field_name = sub_field.get('name', '')
            # Skip MCC_MNC_Digit fields as they're already processed in parent MCC/MNC
            if not sub_field_name.endswith('.MCC_MNC_Digit'):
                self._extract_field_recursively(sub_field, full_field_name, packet_info)

    def generate_separate_csvs(self, base_filename):
        """Generate separate CSV files for NAS and RRC packets

        Args:
            base_filename: Base filename for the CSV files

        Returns:
            bool: True if all conversions successful, False otherwise
        """
        success = True

        # Generate NAS CSV if there are NAS packets
        if self.nas_packets:
            nas_filename = str(Path(base_filename).with_stem(Path(base_filename).stem + '_nas'))
            if not self.generate_csv(nas_filename, self.nas_packets, self.nas_fields):
                success = False

        # Generate RRC CSV if there are RRC packets
        if self.rrc_packets:
            rrc_filename = str(Path(base_filename).with_stem(Path(base_filename).stem + '_rrc'))
            if not self.generate_csv(rrc_filename, self.rrc_packets, self.rrc_fields):
                success = False

        # Generate general CSV if there are other packets
        if self.packet_data:
            if not self.generate_csv(base_filename, self.packet_data, self.all_fields):
                success = False

        return success

    def generate_csv(self, output_file, packet_collection=None, field_collection=None):
        """Generate CSV file from extracted data with show/value columns

        Args:
            output_file: Path to output CSV file
            packet_collection: Collection of packets to write (default: self.packet_data)
            field_collection: Collection of fields to include (default: self.all_fields)

        Returns:
            bool: True if generation successful, False otherwise
        """
        try:
            if packet_collection is None:
                packet_collection = self.packet_data
            if field_collection is None:
                field_collection = self.all_fields

            if not packet_collection:
                return False

            # Create ordered list of fields (packet_number first, then sorted show/value pairs)
            field_list = ['packet_number'] + sorted(field_collection)

            # Write CSV file
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)

                # Write header
                writer.writerow(field_list)

                # Write data rows
                for packet in packet_collection:
                    row = []
                    for field in field_list:
                        value = packet.get(field, '')
                        # Apply normalization to missing/empty fields
                        if field != 'packet_number':  # Don't normalize packet numbers
                            value = self._normalize_field_value(value)
                        row.append(value)
                    writer.writerow(row)

            return True

        except Exception as e:
            return False


