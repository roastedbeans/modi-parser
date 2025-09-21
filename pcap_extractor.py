#!/usr/bin/env python3.8
# coding: utf8
"""
PCAP Packet Extractor with PDML XML Generation and CSV Export

Extracts packets from PCAP files using pyshark, generates PDML XML format,
and converts to CSV files using the existing PdmlToTableConverter.
"""

import logging
import subprocess
import sys
from pathlib import Path
from datetime import datetime
import xml.etree.ElementTree as ET

from pdml_to_table import PdmlToTableConverter


class PCAPExtractor:
    """Extract packets from PCAP files and generate PDML XML and CSV outputs"""

    def __init__(self):
        self.logger = logging.getLogger('pcap_extractor')

        # Configure logging
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def filter_pdml_xml(self, xml_file_path: str) -> bool:
        """
        Filter PDML XML file to remove unwanted protocols, keeping only LTE/5G/NR/NAS/RRC content.

        Args:
            xml_file_path: Path to the PDML XML file to filter

        Returns:
            True if filtering successful, False otherwise
        """
        try:
            self.logger.info(f"Filtering XML to remove unwanted protocols: {xml_file_path}")

            # Parse the XML file
            tree = ET.parse(xml_file_path)
            root = tree.getroot()

            # Protocols to remove (unwanted network layer protocols)
            unwanted_protocols = {
                'geninfo', 'eth', 'ip', 'udp', 'gsmtap',
                'gsmtap_extra', 'fake-field-wrapper', 'ppp', 'ipcp'
            }

            # LTE and 5G/NR related protocols to keep
            lte_protocols = {'lte', 'lte_nas', 'lte_rrc', 'nas-eps', 'nr', 'nr-rrc', 'nas-5gs', '5g'}

            packets_to_keep = []

            for packet in root.findall('packet'):
                protos = packet.findall('proto')
                has_network_content = False
                protos_to_remove = []

                # Check each protocol in the packet
                for proto in protos:
                    proto_name = proto.get('name', '').lower()

                    # Check if this proto contains LTE/5G/NR-related fields
                    if proto_name in lte_protocols:
                        has_network_content = True
                    elif proto_name in unwanted_protocols:
                        protos_to_remove.append(proto)
                    else:
                        # Check if this proto contains LTE or 5G/NR fields within it
                        fields = proto.findall('.//field')
                        for field in fields:
                            field_name = field.get('name', '').lower()
                            if any(network_proto in field_name for network_proto in ['lte', 'nas-eps', 'nr', 'nas-5gs', '5g']):
                                has_network_content = True
                                break

                # If packet has network content (LTE/5G/NR), keep it but remove unwanted protocols
                if has_network_content:
                    # Remove unwanted protocols from this packet
                    for proto_to_remove in protos_to_remove:
                        packet.remove(proto_to_remove)
                    packets_to_keep.append(packet)

            # Replace root content with filtered packets
            root.clear()
            root.set('version', '0')
            root.set('creator', 'wireshark/filtered')
            root.set('time', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            root.set('capture_file', xml_file_path)

            for packet in packets_to_keep:
                root.append(packet)

            # Write filtered XML back to file
            tree.write(xml_file_path, encoding='utf-8', xml_declaration=True)
            self.logger.info(f"Filtered XML: kept {len(packets_to_keep)} packets with LTE/5G/NR content")

            return True

        except Exception as e:
            self.logger.error(f"Error filtering XML: {e}")
            return False

    def pcap_to_pdml(self, pcap_file_path: str, pdml_file_path: str, display_filter: str = "") -> bool:
        """
        Convert PCAP file to PDML XML using tshark

        Args:
            pcap_file_path: Path to input PCAP file
            pdml_file_path: Path to output PDML file
            display_filter: Optional Wireshark display filter

        Returns:
            True if conversion successful, False otherwise
        """
        try:
            self.logger.info(f"Converting PCAP to PDML: {pcap_file_path} -> {pdml_file_path}")

            # Build tshark command with output redirection
            cmd = f"tshark -r '{pcap_file_path}' -T pdml"
            if display_filter:
                cmd += f" -Y '{display_filter}'"
            cmd += f" > '{pdml_file_path}'"

            # Run tshark command
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                self.logger.info("Successfully converted PCAP to PDML")
                return True
            else:
                self.logger.error(f"tshark error: {result.stderr}")
                return False

        except Exception as e:
            self.logger.error(f"Error converting PCAP to PDML: {e}")
            return False

    def process_pcap_to_csv(self, pcap_file: str, output_base: str = None,
                           display_filter: str = "", generate_expanded: bool = True,
                           generate_simple: bool = False, generate_prioritized: bool = False) -> bool:
        """Complete processing pipeline: PCAP -> PDML XML -> CSV files using existing pdml_to_table converter"""
        if output_base is None:
            output_base = Path(pcap_file).stem

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_file = f"{output_base}_{timestamp}.xml"

        # Step 1: Convert PCAP to PDML using tshark
        self.logger.info("Step 1: Converting PCAP to PDML...")
        # Let the PdmlToTableConverter handle protocol filtering - just use user display filter if provided
        if not self.pcap_to_pdml(pcap_file, xml_file, display_filter):
            self.logger.error("Failed to convert PCAP to PDML")
            return False

        # Step 1.5: Filter XML to remove unwanted protocols
        self.logger.info("Step 1.5: Filtering XML to remove unwanted protocols...")
        if not self.filter_pdml_xml(xml_file):
            self.logger.error("Failed to filter XML")
            return False

        # Step 2: Use existing pdml_to_table converter to generate specific CSV files
        self.logger.info("Step 2: Converting PDML to CSV using existing converter...")
        converter = PdmlToTableConverter()

        success = False

        # Generate only NAS and RRC specific files
        if converter.parse_pdml(xml_file, separate_by_protocol=True):
            # Generate prioritized CSV files if requested
            if generate_prioritized:
                if not converter.generate_separate_prioritized_csvs(xml_file):
                    success = False
                else:
                    self.logger.info("✅ Generated prioritized CSV files")

            # Generate NAS simple CSV
            if converter.nas_packets and generate_simple:
                nas_simple_csv_file = f"{output_base}_{timestamp}_nas_simple.csv"
                if converter.generate_simple_csv(nas_simple_csv_file, converter.nas_packets, converter.nas_fields):
                    self.logger.info(f"✅ Generated NAS simple CSV: {nas_simple_csv_file}")
                    success = True

            # Generate RRC simple CSV
            if converter.rrc_packets and generate_simple:
                rrc_simple_csv_file = f"{output_base}_{timestamp}_rrc_simple.csv"
                if converter.generate_simple_csv(rrc_simple_csv_file, converter.rrc_packets, converter.rrc_fields):
                    self.logger.info(f"✅ Generated RRC simple CSV: {rrc_simple_csv_file}")
                    success = True

            # Generate NAS regular CSV
            if converter.nas_packets:
                nas_csv_file = f"{output_base}_{timestamp}_nas.csv"
                if converter.generate_csv(nas_csv_file, converter.nas_packets, converter.nas_fields):
                    self.logger.info(f"✅ Generated NAS CSV: {nas_csv_file}")
                    success = True

            # Generate RRC regular CSV
            if converter.rrc_packets:
                rrc_csv_file = f"{output_base}_{timestamp}_rrc.csv"
                if converter.generate_csv(rrc_csv_file, converter.rrc_packets, converter.rrc_fields):
                    self.logger.info(f"✅ Generated RRC CSV: {rrc_csv_file}")
                    success = True

            # Generate NAS expanded CSV
            if converter.nas_packets and generate_expanded:
                nas_expanded_csv_file = f"{output_base}_{timestamp}_nas_expanded.csv"
                if converter.generate_csv_expanded(nas_expanded_csv_file, converter.nas_packets, converter.nas_fields):
                    self.logger.info(f"✅ Generated NAS expanded CSV: {nas_expanded_csv_file}")
                    success = True

            # Generate RRC expanded CSV
            if converter.rrc_packets and generate_expanded:
                rrc_expanded_csv_file = f"{output_base}_{timestamp}_rrc_expanded.csv"
                if converter.generate_csv_expanded(rrc_expanded_csv_file, converter.rrc_packets, converter.rrc_fields):
                    self.logger.info(f"✅ Generated RRC expanded CSV: {rrc_expanded_csv_file}")
                    success = True

            self.logger.info(f"✅ Generated XML file: {xml_file}")

        if success:
            self.logger.info(f"✅ Successfully processed PCAP file: {pcap_file}")
        else:
            self.logger.error("Failed to generate CSV files from PDML")

        return success


def process_pcap_file(pcap_file: str, output_base: str = None,
                     display_filter: str = "", generate_expanded: bool = True,
                     generate_simple: bool = False, generate_prioritized: bool = False) -> bool:
    """Convenience function for complete PCAP processing pipeline"""
    extractor = PCAPExtractor()
    return extractor.process_pcap_to_csv(pcap_file, output_base, display_filter, generate_expanded, generate_simple, generate_prioritized)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='PCAP Packet Extractor with PDML and CSV Export')
    parser.add_argument('pcap_file', help='Input PCAP file path')
    parser.add_argument('-o', '--output', help='Output base filename (default: same as PCAP file)')
    parser.add_argument('-f', '--filter', help='Wireshark display filter')
    parser.add_argument('--no-expanded', action='store_true', help='Skip expanded CSV generation')
    parser.add_argument('--simple', action='store_true', help='Generate simple CSV files (field names and values only, no attributes)')
    parser.add_argument('--prioritized', action='store_true', help='Generate prioritized CSV files with important fields first')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # Process the PCAP file
    success = process_pcap_file(
        args.pcap_file,
        args.output,
        args.filter if args.filter else "",
        not args.no_expanded,
        args.simple,
        args.prioritized
    )

    if success:
        print("✅ PCAP processing completed successfully!")
    else:
        print("❌ PCAP processing failed!")
        sys.exit(1)
