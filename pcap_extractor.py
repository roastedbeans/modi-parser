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
                           display_filter: str = "", generate_expanded: bool = True) -> bool:
        """Complete processing pipeline: PCAP -> PDML XML -> CSV files using existing pdml_to_table converter"""
        if output_base is None:
            output_base = Path(pcap_file).stem

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_file = f"{output_base}_{timestamp}.xml"

        # Step 1: Convert PCAP to PDML using tshark
        self.logger.info("Step 1: Converting PCAP to PDML...")
        if not self.pcap_to_pdml(pcap_file, xml_file, display_filter):
            self.logger.error("Failed to convert PCAP to PDML")
            return False

        # Step 2: Use existing pdml_to_table converter to generate CSV files
        self.logger.info("Step 2: Converting PDML to CSV using existing converter...")
        converter = PdmlToTableConverter()

        success = False

        # Generate regular CSV format
        if converter.convert_pdml_to_csv(xml_file, expanded=False):
            self.logger.info("✅ Generated regular CSV from PDML")
            success = True

        # Generate expanded CSV if requested
        if generate_expanded and converter.convert_pdml_to_csv(xml_file, expanded=True):
            self.logger.info("✅ Generated expanded CSV from PDML")
            success = True

        if success:
            self.logger.info(f"✅ Successfully processed PCAP file: {pcap_file}")
        else:
            self.logger.error("Failed to generate CSV files from PDML")

        return success


def process_pcap_file(pcap_file: str, output_base: str = None,
                     display_filter: str = "", generate_expanded: bool = True) -> bool:
    """Convenience function for complete PCAP processing pipeline"""
    extractor = PCAPExtractor()
    return extractor.process_pcap_to_csv(pcap_file, output_base, display_filter, generate_expanded)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='PCAP Packet Extractor with PDML and CSV Export')
    parser.add_argument('pcap_file', help='Input PCAP file path')
    parser.add_argument('-o', '--output', help='Output base filename (default: same as PCAP file)')
    parser.add_argument('-f', '--filter', help='Wireshark display filter')
    parser.add_argument('--no-expanded', action='store_true', help='Skip expanded CSV generation')
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
        not args.no_expanded
    )

    if success:
        print("✅ PCAP processing completed successfully!")
    else:
        print("❌ PCAP processing failed!")
        sys.exit(1)
