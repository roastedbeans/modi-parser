#!/usr/bin/env python3.8
"""
ws_dissector Python Wrapper

A simplified interface for using ws_dissector with:
1. Automatic platform detection (Android vs Desktop)
2. Packet dissection from JSON input files
3. XML output generation to output/ folder
4. Basic error handling and logging
"""

import struct
import subprocess
import xml.etree.ElementTree as ET
from xml.dom import minidom
import sys
import os
import platform
import argparse
import logging
from datetime import datetime
import time


class WSDissector:
    """Wrapper for ws_dissector tool with automatic platform detection"""

    def __init__(self, dissector_path=None):
        """Initialize ws_dissector wrapper

        Args:
            dissector_path: Path to ws_dissector executable. If None,
                          automatically detects platform and uses appropriate binary:
                          - ws_desktop_dissector for desktop platforms
                          - ws_dissector for Android
        """
        self.logger = logging.getLogger(__name__)
        self.packets_processed = 0
        self.packets_failed = 0

        if dissector_path is None:
            # Detect platform and choose appropriate binary
            platform_type = self._detect_platform()
            if platform_type == 'android':
                binary_name = 'ws_dissector'
            else:
                binary_name = 'ws_desktop_dissector'

            self.dissector_path = os.path.join(os.path.dirname(__file__), 'ws_dissector', binary_name)
            self.logger.info(f"Detected platform: {platform_type}, using binary: {binary_name}")
        else:
            self.dissector_path = dissector_path

        self._validate_dissector()

    def _detect_platform(self):
        """Detect if running on Android or desktop platform

        Returns:
            str: 'android' or 'desktop'
        """
        # Check for Android-specific indicators
        if (platform.system() == 'Linux' and
            (os.path.exists('/system/bin/sh') or
             os.environ.get('ANDROID_ROOT') or
             os.path.exists('/system/build.prop'))):
            return 'android'

        # Default to desktop for macOS, Linux, Windows, etc.
        return 'desktop'

    def _validate_dissector(self):
        """Validate that the dissector executable exists and is accessible"""
        if not os.path.exists(self.dissector_path):
            raise FileNotFoundError(f"ws_dissector not found at {self.dissector_path}")

        if not os.access(self.dissector_path, os.X_OK):
            raise PermissionError(f"ws_dissector at {self.dissector_path} is not executable")

        # Test the dissector with a simple command
        try:
            result = subprocess.run(
                [self.dissector_path],
                input=b'',
                capture_output=True,
                timeout=5
            )
            self.logger.info("ws_dissector validated successfully")
        except subprocess.TimeoutExpired:
            self.logger.warning("ws_dissector validation timed out, but proceeding")
        except Exception as e:
            self.logger.warning(f"ws_dissector validation failed: {e}, but proceeding")

    def format_packet_data(self, protocol_type, data):
        """Format packet data for ws_dissector input

        Args:
            protocol_type: Protocol type number
            data: Raw packet data as bytes

        Returns:
            Formatted binary data ready for ws_dissector input
        """
        # Format: protocol_type (4 bytes, big endian) + data_len (4 bytes, big endian) + data
        protocol_bytes = struct.pack('>I', protocol_type)
        length_bytes = struct.pack('>I', len(data))

        return protocol_bytes + length_bytes + data

    def strip_header(self, data):
        """Strip DIAG headers from packet data

        Args:
            data: Raw packet data as bytes

        Returns:
            Data with headers stripped
        """
        if len(data) < 16:
            return data

        # Try to detect and remove DIAG headers dynamically
        # Look for common DIAG header patterns
        if len(data) >= 16 and data[:4] == b'\x02\x04\x0d\x00':
            # Common DIAG header pattern - remove first 32 bytes
            return data[16:]
        elif len(data) >= 16 and data[0] in [0x02, 0x10, 0x7D]:
            # Other DIAG patterns - remove first 16 bytes
            return data[16:]

        # If no header pattern detected, return original data
        return data

    def dissect_packet(self, protocol_type, data, retry_count=0):
        """Dissect a single packet with error handling and retry logic

        Args:
            protocol_type: Protocol type number or name
            data: Raw packet data as bytes
            retry_count: Current retry attempt (internal use)

        Returns:
            Tuple of (PDML XML string, success boolean)
        """
        try:
            # Validate input
            if not isinstance(data, bytes):
                raise ValueError("Packet data must be bytes")
            if len(data) == 0:
                raise ValueError("Empty packet data")

            # Strip headers before dissection
            clean_data = self.strip_header(data)

            # Convert protocol type to number if it's a string key
            if isinstance(protocol_type, str):
                protocol_type_num = int(protocol_type)
            elif isinstance(protocol_type, int):
                protocol_type_num = protocol_type
            else:
                raise ValueError(f"Invalid protocol type: {protocol_type}")

            # Format the packet data
            formatted_data = self.format_packet_data(protocol_type_num, clean_data)

            # Execute the ws_dissector command with a 60-second timeout
            result = subprocess.run(
                [self.dissector_path],
                input=formatted_data,
                capture_output=True,
                check=True,
                timeout=60
            )

            # ws_dissector outputs PDML followed by separator "===___==="
            output = result.stdout.decode('utf-8', errors='ignore')

            # Extract PDML part (everything before the separator)
            separator = "===___==="
            if separator in output:
                pdml_output = output.split(separator)[0].strip()
            else:
                pdml_output = output.strip()

            # Validate PDML output
            if not pdml_output or len(pdml_output.strip()) == 0:
                raise ValueError("Empty PDML output from dissector")

            self.packets_processed += 1
            return pdml_output, True

        except subprocess.TimeoutExpired:
            self.logger.warning(f"Timeout dissecting packet (protocol: {protocol_type})")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"ws_dissector process error: {e}")
            if e.stderr:
                self.logger.debug(f"stderr: {e.stderr.decode()}")
        except Exception as e:
            self.logger.error(f"Error dissecting packet: {e}")

        # Update failed count
        self.packets_failed += 1

        # Retry logic (simplified)
        if retry_count < 2:  # Max 2 retries
            self.logger.info(f"Retrying packet dissection (attempt {retry_count + 1}/2)")
            return self.dissect_packet(protocol_type, data, retry_count + 1)

        return None, False

    def dissect_multiple_packets(self, packets):
        """Dissect multiple packets

        Args:
            packets: List of tuples (protocol_type, data)

        Returns:
            List of tuples (PDML XML string, success boolean)
        """
        if not packets:
            self.logger.warning("No packets provided for dissection")
            return []

        total_packets = len(packets)
        self.logger.info(f"Processing {total_packets} packets")

        results = []
        for i, (protocol_type, data) in enumerate(packets, 1):
            if i % 10 == 0:  # Progress update every 10 packets
                self.logger.info(f"Processed {i}/{total_packets} packets")

            result, success = self.dissect_packet(protocol_type, data)
            results.append((result, success))

        return results

    def dissect_packets_from_file(self, input_file, output_file=None, output_format='xml'):
        """Dissect packets from file with progress tracking"""
        try:
            # Load and validate input file
            data = input_file

            if isinstance(data, list):
                # packets.json format: array of objects with protocol keys
                packets_data = []
                for item in data:
                    if isinstance(item, dict) and len(item) == 1:
                        protocol_type = list(item.keys())[0]
                        hex_data = item[protocol_type]
                        packets_data.append({
                            'packet_type': protocol_type,
                            'data': hex_data,
                            'data_length': len(hex_data) // 2  # hex string length in bytes
                        })
            elif isinstance(data, dict):
                if any(key.isdigit() for key in data.keys()):
                    packets_data = []
                    for protocol_type, hex_data in data.items():
                        packets_data.append({
                            'packet_type': protocol_type,
                            'data': hex_data,
                            'data_length': len(hex_data) // 2  # hex string length in bytes
                        })
                else:
                    # Expected format: object with packets array
                    packets_data = data.get('packets', [])

            if not packets_data:
                raise ValueError("No packets found in input file")

            # Convert to expected format for processing
            packets = [(int(packet['packet_type']), bytes.fromhex(packet['data'])) for packet in packets_data]

            # Dissect packets
            start_time = time.time()
            results = self.dissect_multiple_packets(packets)
            end_time = time.time()

            # Generate output
            self.logger.info(f"Dissection completed: packets successful")

            if output_file:
                self.save_results(results, packets_data, output_file, output_format)
                self.logger.info(f"Results saved to {output_file}")

            # Print summary
            duration = end_time - start_time
            self.logger.info(f"Processing completed in {duration:.2f} seconds")

            return results

        except Exception as e:
            self.logger.error(f"Error processing file {input_file}: {e}")
            raise

    def save_results(self, results, original_packets, output_file, output_format='xml'):
        """Save dissection results in XML format"""
        if output_format.lower() != 'xml':
            raise ValueError(f"Only XML output format is supported")

        # Create root element
        root = ET.Element("pdml_capture")
        root.set("version", "1.0")
        root.set("creator", "ws_dissector")

        # Add metadata
        metadata = ET.SubElement(root, "metadata")
        ET.SubElement(metadata, "timestamp").text = datetime.now().isoformat()
        ET.SubElement(metadata, "packet_count").text = str(len(results))
        ET.SubElement(metadata, "packets_processed").text = str(self.packets_processed)
        ET.SubElement(metadata, "packets_failed").text = str(self.packets_failed)

        # Add each packet as PDML
        for i, (result, success) in enumerate(results, 1):
            packet_container = ET.SubElement(root, "packet")
            packet_container.set("number", str(i))
            packet_container.set("success", str(success))

            if result and success:
                try:
                    # Parse the PDML result
                    packet_root = ET.fromstring(result)
                    
                      # Filter out unwanted protocols
                    self._filter_protocols(packet_root)
                    
                    packet_container.append(packet_root)
                except ET.ParseError:
                    # Add raw result if parsing fails
                    ET.SubElement(packet_container, "raw_pdml").text = result
            else:
                # Add original packet info for failed dissections
                if i <= len(original_packets):
                    packet_info = original_packets[i-1]
                    ET.SubElement(packet_container, "protocol_type").text = packet_info.get('packet_type', 'unknown')
                    ET.SubElement(packet_container, "data_length").text = str(packet_info.get('data_length', 0))

        # Convert to string and pretty print
        rough_string = ET.tostring(root, encoding='unicode')
        reparsed = minidom.parseString(rough_string)
        pretty_xml = reparsed.toprettyxml(indent="  ")

        # Remove empty lines
        pretty_xml = '\n'.join([line for line in pretty_xml.split('\n') if line.strip()])

        # Save to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(pretty_xml)

    def _filter_protocols(self, packet_root):
        """Filter out unwanted protocols from the PDML"""
        for proto in packet_root.findall('proto'):
            if proto.get('name') in ['geninfo', 'frame', 'user_dlt', 'aww']:
                packet_root.remove(proto)


def setup_logging(log_level='INFO'):
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('ws_dissector.log', mode='w')
        ]
    )


def create_argument_parser():
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="ws_dissector Python Wrapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s packets.json -o dissected.xml    # Process packets and save to custom path
  %(prog)s packets.json                   # Process with auto-generated file in output/ folder
        """
    )

    parser.add_argument('input', help='Input object array or dictionary containing packets')
    parser.add_argument('-o', '--output', help='Output file path. If not specified, saves to output/dissected_<timestamp>.xml')

    return parser


def main():
    """Main function with basic command-line argument support"""
    parser = create_argument_parser()
    args = parser.parse_args()

    # Setup basic logging
    setup_logging('INFO')
    logger = logging.getLogger(__name__)

    try:
        # Generate output filename if not specified
        output_file = args.output
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Use output folder relative to this script's location
            output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'output')
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"dissected_{timestamp}.xml")

        # Initialize dissector
        dissector = WSDissector()

        # Process packets
        dissector.dissect_packets_from_file(args.input, output_file, 'xml')

        logger.info("Processing completed successfully!")

    except KeyboardInterrupt:
        logger.info("Processing interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Processing failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()