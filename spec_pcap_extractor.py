#!/usr/bin/env python3.8
# coding: utf8
"""
PCAP Packet Extractor with PDML XML Generation and CSV Export

Extracts packets from PCAP files using tshark, generates PDML XML format,
and converts to CSV files using the existing PdmlToTableConverter.
"""

import logging
import subprocess
import sys
from pathlib import Path
from datetime import datetime
import xml.etree.ElementTree as ET

from spec_pdml_to_table import PdmlToTableConverter


class SpecPCAPExtractor:
    """Extract packets from PCAP files and generate PDML XML and CSV outputs"""

    def __init__(self):
        self.logger = logging.getLogger('spec_pcap_extractor')

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def filter_pdml_xml(self, xml_file_path: str) -> bool:
        """Filter PDML XML file to keep only LTE/5G/NR/NAS/RRC content"""
        try:
            self.logger.info(f"Filtering XML: {xml_file_path}")

            tree = ET.parse(xml_file_path)
            root = tree.getroot()

            unwanted_protocols = {
                'geninfo', 'eth', 'ip', 'udp', 'gsmtap',
                'gsmtap_extra', 'fake-field-wrapper', 'ppp', 'ipcp'
            }

            lte_protocols = {'lte', 'lte_nas', 'lte_rrc', 'nas-eps', 'nr', 'nr-rrc', 'nas-5gs', '5g'}

            packets_to_keep = []

            for packet in root.findall('packet'):
                protos = packet.findall('proto')
                has_network_content = False
                protos_to_remove = []

                for proto in protos:
                    proto_name = proto.get('name', '').lower()

                    if proto_name in lte_protocols:
                        has_network_content = True
                    elif proto_name in unwanted_protocols:
                        protos_to_remove.append(proto)
                    else:
                        fields = proto.findall('.//field')
                        for field in fields:
                            field_name = field.get('name', '').lower()
                            if any(network_proto in field_name for network_proto in ['lte', 'nas-eps', 'nr', 'nas-5gs', '5g']):
                                has_network_content = True
                                break

                if has_network_content:
                    for proto_to_remove in protos_to_remove:
                        packet.remove(proto_to_remove)
                    packets_to_keep.append(packet)

            root.clear()
            root.set('version', '0')
            root.set('creator', 'wireshark/filtered')
            root.set('time', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            root.set('capture_file', xml_file_path)

            for packet in packets_to_keep:
                root.append(packet)

            tree.write(xml_file_path, encoding='utf-8', xml_declaration=True)
            self.logger.info(f"Filtered XML: kept {len(packets_to_keep)} packets")

            return True

        except Exception as e:
            self.logger.error(f"Error filtering XML: {e}")
            return False

    def pcap_to_pdml(self, pcap_file_path: str, pdml_file_path: str, display_filter: str = "") -> bool:
        """Convert PCAP file to PDML XML using tshark"""
        try:
            self.logger.info(f"Converting PCAP to PDML: {pcap_file_path} -> {pdml_file_path}")

            cmd = f"tshark -r '{pcap_file_path}' -T pdml"
            if display_filter:
                cmd += f" -Y '{display_filter}'"
            cmd += f" > '{pdml_file_path}'"

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

    def process_pcap_to_csv(self, pcap_file: str, output_base: str = None, display_filter: str = "") -> bool:
        """Complete processing pipeline: PCAP -> PDML XML -> CSV files"""
        if output_base is None:
            output_base = Path(pcap_file).stem

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_file = f"{output_base}_{timestamp}.xml"

        # Convert PCAP to PDML
        self.logger.info("Step 1: Converting PCAP to PDML...")
        if not self.pcap_to_pdml(pcap_file, xml_file, display_filter):
            self.logger.error("Failed to convert PCAP to PDML")
            return False

        # Filter XML
        self.logger.info("Step 2: Filtering XML...")
        if not self.filter_pdml_xml(xml_file):
            self.logger.error("Failed to filter XML")
            return False

        # Convert to CSV
        self.logger.info("Step 3: Converting PDML to CSV...")
        converter = PdmlToTableConverter()
        
        csv_base = f"{output_base}_{timestamp}"
        success = converter.convert_pdml_to_csv(xml_file, csv_base + ".csv")

        if success:
            self.logger.info(f"✅ Successfully processed PCAP file: {pcap_file}")
            self.logger.info(f"✅ Generated XML file: {xml_file}")
        else:
            self.logger.error("Failed to generate CSV files from PDML")

        return success


def process_pcap_file(pcap_file: str, output_base: str = None, display_filter: str = "") -> bool:
    """Convenience function for complete PCAP processing pipeline"""
    extractor = SpecPCAPExtractor()
    return extractor.process_pcap_to_csv(pcap_file, output_base, display_filter)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='PCAP Packet Extractor with PDML and CSV Export')
    parser.add_argument('pcap_file', help='Input PCAP file path')
    parser.add_argument('-o', '--output', help='Output base filename (default: same as PCAP file)')
    parser.add_argument('-f', '--filter', help='Wireshark display filter')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    success = process_pcap_file(
        args.pcap_file,
        args.output,
        args.filter if args.filter else ""
    )

    if success:
        print("✅ PCAP processing completed successfully!")
    else:
        print("❌ PCAP processing failed!")
        sys.exit(1)