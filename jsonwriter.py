#!/usr/bin/env python3
# coding: utf8

import tempfile
import subprocess
import json
import os
import logging
from pathlib import Path

class JsonWriter:
    """Class for converting PCAP files to JSON format using tshark"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def pcap_to_json_with_tshark(self, pcap_file_path, output_json_path=None):
        """
        Convert PCAP file to JSON using tshark

        Args:
            pcap_file_path (str): Path to input PCAP file
            output_json_path (str): Optional output JSON file path

        Returns:
            dict: JSON data from tshark dissection
        """
        try:
            # Build tshark command for detailed dissection
            cmd = [
                'tshark',
                '-r', pcap_file_path,  # Read from PCAP file
                '-T', 'json',         # Output format: JSON
            ]

            self.logger.info(f"Running tshark command: {' '.join(cmd)}")

            # Execute tshark
            result = subprocess.run(
                cmd,
                capture_output=True
            )

            if result.returncode != 0:
                error_msg = f"tshark failed with return code {result.returncode}: {result.stderr}"
                self.logger.error(error_msg)
                return {'error': error_msg, 'stderr': result.stderr}

            if not result.stdout.strip():
                self.logger.warning("tshark produced no output")
                return {'error': 'No data from tshark'}

            # Parse JSON output
            try:
                json_data = json.loads(result.stdout)

                # If output file specified, write to file
                if output_json_path:
                    with open(output_json_path, 'w') as f:
                        json.dump(json_data, f, indent=2)
                    self.logger.info(f"JSON output written to: {output_json_path}")

                return json_data

            except json.JSONDecodeError as e:
                error_msg = f"Failed to parse tshark JSON output: {e}"
                self.logger.error(error_msg)
                return {'error': error_msg, 'raw_output': result.stdout[:1000]}

        except subprocess.TimeoutExpired:
            error_msg = "tshark command timed out"
            self.logger.error(error_msg)
            return {'error': error_msg}

        except Exception as e:
            error_msg = f"Error running tshark: {e}"
            self.logger.error(error_msg)
            return {'error': error_msg}

    def create_json_from_packets(self, packets_data, output_json_path=None):
        """
        Create JSON from packet data directly (alternative to tshark method)

        Args:
            packets_data (list): List of packet dictionaries
            output_json_path (str): Optional output JSON file path

        Returns:
            dict: JSON data
        """
        try:
            json_data = {
                'packets': packets_data,
                'metadata': {
                    'total_packets': len(packets_data),
                    'created_by': 'QmdlReader',
                    'format': 'json'
                }
            }

            # If output file specified, write to file
            if output_json_path:
                with open(output_json_path, 'w') as f:
                    json.dump(json_data, f, indent=2)
                self.logger.info(f"JSON output written to: {output_json_path}")

            return json_data

        except Exception as e:
            error_msg = f"Error creating JSON from packets: {e}"
            self.logger.error(error_msg)
            return {'error': error_msg}

    def process_pcap_with_temp_file(self, packet_processor_func, temp_pcap_name=None):
        """
        Process packets using a temporary PCAP file and convert to JSON

        Args:
            packet_processor_func: Function that writes packets to PcapWriter
            temp_pcap_name (str): Optional temporary PCAP file name prefix

        Returns:
            dict: JSON data from tshark dissection
        """
        temp_pcap = None
        try:
            # Create temporary PCAP file
            temp_dir = tempfile.gettempdir()
            temp_pcap = tempfile.NamedTemporaryFile(
                delete=False,
                suffix='.pcap',
                prefix=temp_pcap_name or 'qmdl_temp_',
                dir=temp_dir
            )
            temp_pcap.close()  # Close so PcapWriter can open it

            self.logger.info(f"Created temporary PCAP file: {temp_pcap.name}")

            # Call the packet processor function
            if packet_processor_func:
                packet_processor_func(temp_pcap.name)

            # Convert PCAP to JSON using tshark
            json_data = self.pcap_to_json_with_tshark(temp_pcap.name)

            return json_data

        except Exception as e:
            error_msg = f"Error processing with temporary PCAP: {e}"
            self.logger.error(error_msg)
            return {'error': error_msg}

        finally:
            # Clean up temporary file
            if temp_pcap and os.path.exists(temp_pcap.name):
                try:
                    os.unlink(temp_pcap.name)
                    self.logger.info(f"Cleaned up temporary PCAP file: {temp_pcap.name}")
                except Exception as e:
                    self.logger.warning(f"Failed to clean up temporary file {temp_pcap.name}: {e}")

    def is_tshark_available(self):
        """Check if tshark is available on the system"""
        try:
            result = subprocess.run(['tshark', '-v'], capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
        except Exception:
            return False
