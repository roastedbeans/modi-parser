"""
QMDL/PCAP File Reader - CSV Export Version
Python module for reading QMDL and PCAP files and exporting to CSV format
Based on scat project FileIO approach
"""

import os
import datetime
import json
import logging
import sys
from pathlib import Path
from fileio import FileIO
from datawriter import DataWriter


class QmdlReader:
    """Class for reading QMDL and PCAP files and exporting to CSV format"""

    def __init__(self):
        self.data_writer = DataWriter()
    
    def _convert_datetime_to_string(self, obj):
        """
        Recursively convert datetime objects and bytes to strings for JSON serialization
        """
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif isinstance(obj, bytes):
            return obj.hex()  # Convert bytes to hex string
        elif isinstance(obj, dict):
            return {key: self._convert_datetime_to_string(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_datetime_to_string(item) for item in obj]
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj  # These types are already JSON serializable
        else:
            return str(obj)  # Convert any other type to string

    def read_qmdl_file_to_csv(self, file_path, min_size_mb=10, output_csv=None, output_pcap=None):
        """
        Read a QMDL or PCAP file and export to PCAP and CSV formats

        Args:
            file_path (str): Path to the QMDL or PCAP file
            min_size_mb (int): Minimum file size in MB (default: 10MB) - only applies to QMDL files
            output_csv (str): Optional CSV output file base path for RRC/NAS data (will create _rrc.csv and _nas.csv)
            output_pcap (str): Optional permanent PCAP output file path

        Returns:
            str: Success message or None if failed
        """
        # Determine file type and check if it exists
        try:
            if not os.path.exists(file_path):
                print(f"File not found: {file_path}")
                return None
                
            file_size = os.path.getsize(file_path)
            file_size_mb = file_size / (1024*1024)
            
            # Check if it's a PCAP file
            is_pcap = file_path.lower().endswith(('.pcap', '.pcapng'))
            
            if is_pcap:
                print(f"Reading PCAP file: {file_path} ({file_size_mb:.4f}MB)")
                return self._process_pcap_file(file_path, output_csv=output_csv)
            else:
                # QMDL file - check size
                min_size_bytes = min_size_mb * 1024 * 1024
                if file_size < min_size_bytes:
                    print(f"QMDL file too small: {file_path} ({file_size_mb:.1f}MB < {min_size_mb}MB)")
                    return None
                print(f"Reading QMDL file: {file_path} ({file_size_mb:.1f}MB)")

        except Exception as e:
            print(f"Error accessing file {file_path}: {e}")
            return None

        # Check if PyShark is available
        if not self.data_writer.is_pyshark_available():
            print("Error: PyShark not available. Install with: pip install pyshark")
            return None

        try:
            # Use DataWriter's CSV processing method
            def packet_processor(data_writer):
                return self._process_qmdl_with_data_writer(file_path, data_writer)

            # Generate PCAP output path if not provided but CSV is requested
            pcap_output_path = output_pcap
            if not pcap_output_path and output_csv:
                # Generate PCAP path based on CSV path
                csv_path = Path(output_csv)
                pcap_output_path = str(csv_path.with_suffix('.pcap'))
                print(f"Auto-generating PCAP output path: {pcap_output_path}")

            success = self.data_writer.process_qmdl_to_csv(
                packet_processor,
                pcap_output_path=pcap_output_path,
                csv_output_path=output_csv
            )

            # Check if processing was successful
            if not success:
                print("Error: QMDL processing failed")
                return None
            
            
            # Inform about CSV output
            if output_csv:
                # Check for separate RRC and NAS CSV files
                rrc_csv_path = f"{output_csv}_rrc.csv"
                nas_csv_path = f"{output_csv}_nas.csv"
                
                if os.path.exists(rrc_csv_path):
                    print(f"RRC CSV output written to: {rrc_csv_path}")
                else:
                    print(f"No RRC data found for CSV export")
                    
                if os.path.exists(nas_csv_path):
                    print(f"NAS CSV output written to: {nas_csv_path}")
                else:
                    print(f"No NAS data found for CSV export")

            # Inform about PCAP output
            if pcap_output_path:
                if os.path.exists(pcap_output_path):
                    print(f"PCAP output written to: {pcap_output_path}")
                else:
                    print(f"PCAP file not created: {pcap_output_path}")

            return "Processing completed successfully"

        except Exception as e:
            print(f"Error in QMDL processing: {e}")
            import traceback
            traceback.print_exc()
            return None

    def _process_qmdl_with_data_writer(self, qmdl_file_path, data_writer):
        """
        Process QMDL file using DataWriter

        Args:
            qmdl_file_path (str): Input QMDL file path
            data_writer (DataWriter): DataWriter instance

        Returns:
            bool: Success status
        """
        try:
            # Use SCAT's correct approach: FileIO + QualcommParser.read_dump()
            io_device = FileIO([qmdl_file_path])

            # Set up QualcommParser with FileIO device
            from qualcomm.qualcommparser import QualcommParser
            parser = QualcommParser()
            parser.set_io_device(io_device)

            # Set up DataWriter as the writer
            parser.set_writer(data_writer)

            # Set SCAT-like parameters
            parser.set_parameter({
                'log_level': logging.INFO,
                'qsr-hash': None,
                'qsr4-hash': None,
                'events': True,
                'msgs': True,
                'cacombos': False,
                'combine-stdout': False,
                'disable-crc-check': False,
                'layer': ['rrc','nas'],
                'format': 'x',
                'gsmtapv3': False
            })

            # Set up logging
            logger = logging.getLogger('scat')
            logger.setLevel(logging.INFO)
            ch = logging.StreamHandler(stream=sys.stdout)
            f = logging.Formatter('%(asctime)s %(name)s (%(funcName)s) %(levelname)s: %(message)s')
            ch.setFormatter(f)
            logger.addHandler(ch)

            qualcomm_logger = logging.getLogger('qualcomm.qualcommparser')
            qualcomm_logger.setLevel(logging.INFO)
            qualcomm_logger.addHandler(ch)

            # Process the dump file
            parser.read_dump()

            return True

        except Exception as e:
            print(f"Error processing QMDL with DataWriter: {e}")
            import traceback
            traceback.print_exc()
            return False



    def _process_pcap_file(self, pcap_file_path, output_csv=None):
        """
        Process PCAP file directly using PyShark

        Args:
            pcap_file_path (str): Path to the PCAP file
            output_csv (str): Optional CSV output file base path for RRC/NAS data

        Returns:
            str: Success message or None if failed
        """
        try:
            # Check if PyShark is available
            if not self.data_writer.is_pyshark_available():
                print("Warning: PyShark not available for PCAP processing")
                return None

            # Extract CSV data from PCAP directly
            if output_csv:
                self.data_writer._extract_csv_from_pcap(pcap_file_path)
                
                # Export RRC and NAS data to separate CSV files
                if self.data_writer._rrc_packets_data or self.data_writer._nas_packets_data:
                    self.data_writer._export_separate_rrc_nas_csv(output_csv)


            
            # Inform about CSV output
            if output_csv:
                # Check for separate RRC and NAS CSV files
                rrc_csv_path = f"{output_csv}_rrc.csv"
                nas_csv_path = f"{output_csv}_nas.csv"
                
                if os.path.exists(rrc_csv_path):
                    print(f"RRC CSV output written to: {rrc_csv_path}")
                else:
                    print(f"No RRC data found for CSV export")
                    
                if os.path.exists(nas_csv_path):
                    print(f"NAS CSV output written to: {nas_csv_path}")
                else:
                    print(f"No NAS data found for CSV export")

            return "PCAP processing completed successfully"

        except Exception as e:
            error_msg = f"Error processing PCAP file: {e}"
            print(error_msg)
            import traceback
            traceback.print_exc()
            return None

    def read_qmdl_file(self, file_path, min_size_mb=10, output_csv=None):
        """
        Read a QMDL file and export to CSV format

        Args:
            file_path (str): Path to the QMDL file
            min_size_mb (int): Minimum file size in MB (default: 10MB)
            output_csv (str): Optional CSV output file base path

        Returns:
            str: Success message or None if file too small/failed
        """
        # Check file size first
        try:
            file_size = os.path.getsize(file_path)
            min_size_bytes = min_size_mb * 1024 * 1024

            if file_size < min_size_bytes:
                print(f"QMDL file too small: {file_path} ({file_size / (1024*1024):.1f}MB < {min_size_mb}MB)")
                return None

            print(f"Reading QMDL file: {file_path} ({file_size / (1024*1024):.1f}MB)")

        except Exception as e:
            print(f"Error accessing file {file_path}: {e}")
            return None

        # Use the CSV conversion method
        return self.read_qmdl_file_to_csv(file_path, min_size_mb, output_csv=output_csv)
    

    
    def list_qmdl_files(self, directory, min_size_mb=10):
        """
        List QMDL files in a directory that are >= specified size
        
        Args:
            directory (str): Directory path
            min_size_mb (int): Minimum file size in MB (default: 10MB)
            
        Returns:
            list: List of QMDL file paths that meet size criteria
        """
        qmdl_files = []
        min_size_bytes = min_size_mb * 1024 * 1024  # Convert MB to bytes
        
        try:
            if os.path.exists(directory) and os.access(directory, os.R_OK):
                for file in os.listdir(directory):
                    if file.endswith('.qmdl') or file.endswith('.QMDL'):
                        file_path = os.path.join(directory, file)
                        try:
                            file_size = os.path.getsize(file_path)
                            if file_size >= min_size_bytes:
                                qmdl_files.append(file_path)
                                print(f"Found QMDL file >= {min_size_mb}MB: {file} ({file_size / (1024*1024):.1f}MB)")
                            else:
                                print(f"Skipping QMDL file < {min_size_mb}MB: {file} ({file_size / (1024*1024):.1f}MB)")
                        except Exception as e:
                            print(f"Could not get size for {file}: {e}")
            else:
                print(f"Directory not accessible: {directory}")
                
        except Exception as e:
            print(f"Error listing QMDL files in {directory}: {e}")
        
        return qmdl_files

    def get_file_info(self, file_path):
        """
        Get information about a QMDL file
        
        Args:
            file_path (str): Path to the QMDL file
            
        Returns:
            dict: File information or None
        """
        try:
            stat = os.stat(file_path)
            return {
                'path': file_path,
                'size': stat.st_size,
                'modified': datetime.datetime.fromtimestamp(stat.st_mtime),
                'created': datetime.datetime.fromtimestamp(stat.st_ctime)
            }
        except Exception as e:
            print(f"Error getting file info for {file_path}: {e}")
            return None
    
    # JSON serialization methods for Java integration
    def read_qmdl_file_json(self, file_path):
        """Read a QMDL file and return JSON serialized result"""
        try:
            result = self.read_qmdl_file(file_path)
            if result:
                # Convert datetime objects and bytes to strings for JSON serialization
                result_serializable = self._convert_datetime_to_string(result)
                return json.dumps(result_serializable)
            else:
                return json.dumps({'error': 'File too small or could not be read'})
        except Exception as e:
            return json.dumps({'error': str(e)})
    
    def process_qmdl_files_from_java_json(self, files_json):
        """Process QMDL files provided by Java (since Java has root access) - JSON version"""
        try:
            files_data = json.loads(files_json)
            result = {
                'directory': files_data.get('directory', 'unknown'),
                'qmdl_files_found': len(files_data.get('files', [])),
                'files': [],
                'source': 'java_with_root_access'
            }
            
            for file_info in files_data.get('files', []):
                # Java already filtered for 10MB+ files
                result['files'].append({
                    'path': file_info['path'],
                    'size': file_info['size'],
                    'modified': file_info.get('modified', 'unknown'),
                    'created': file_info.get('created', 'unknown')
                })
            
            return json.dumps(result)
        except Exception as e:
            return json.dumps({'error': str(e)})

# Global reader instance for Java integration
_reader_instance = None

def get_reader():
    """Get or create the global reader instance"""
    global _reader_instance
    if _reader_instance is None:
        _reader_instance = QmdlReader()
    return _reader_instance

# Convenience functions for Java calls
def read_qmdl_file(file_path):
    """Convenience function for Java to read QMDL file"""
    return get_reader().read_qmdl_file_json(file_path)



def process_qmdl_files_from_java(files_json):
    """Convenience function for Java to process QMDL files list"""
    return get_reader().process_qmdl_files_from_java_json(files_json)

# CSV export convenience functions
def read_qmdl_file_to_csv(file_path, output_csv=None, output_pcap=None):
    """Convenience function to read QMDL or PCAP file and export RRC/NAS CSV data"""
    try:
        result = get_reader().read_qmdl_file_to_csv(file_path, output_csv=output_csv, output_pcap=output_pcap)
        return result is not None
    except Exception as e:
        print(f"Error processing file: {str(e)}")
        return False

def convert_qmdl_to_csv(file_path, csv_output_path=None, pcap_output_path=None):
    """Convenience function to convert QMDL to CSV with optional PCAP export"""
    try:
        result = get_reader().read_qmdl_file_to_csv(file_path, output_csv=csv_output_path, output_pcap=pcap_output_path)
        return result is not None
    except Exception as e:
        print(f"Error converting QMDL: {str(e)}")
        return False

def convert_pcap_to_csv(pcap_file_path, csv_output_path=None):
    """Convenience function specifically for PCAP to CSV conversion"""
    try:
        result = get_reader().read_qmdl_file_to_csv(pcap_file_path, output_csv=csv_output_path)
        return result is not None
    except Exception as e:
        print(f"Error converting PCAP: {str(e)}")
        return False

if __name__ == "__main__":
    # Command-line interface for QMDL/PCAP to CSV conversion
    import argparse
    parser = argparse.ArgumentParser(description='QMDL/PCAP File Reader - CSV Export for RRC/NAS Data')
    parser.add_argument('input_file', help='Input QMDL or PCAP file')
    parser.add_argument('-c', '--csv', type=str, help='Output CSV base path for RRC/NAS data (creates _rrc.csv and _nas.csv)')
    parser.add_argument('-p', '--pcap', type=str, help='Output PCAP file (permanent)')
    parser.add_argument('-s', '--size', type=int, default=10, help='Minimum file size in MB for QMDL files (default: 10)')
    args = parser.parse_args()

    reader = QmdlReader()

    # Determine file type
    input_file = args.input_file
    is_pcap = input_file.lower().endswith(('.pcap', '.pcapng'))
    
    if is_pcap:
        print(f"Processing PCAP file {input_file}...")
        if args.csv:
            print(f"RRC and NAS data will be exported to separate CSV files:")
            print(f"  RRC: {args.csv}_rrc.csv")
            print(f"  NAS: {args.csv}_nas.csv")
        result = reader.read_qmdl_file_to_csv(input_file, output_csv=args.csv)
    else:
        print(f"Processing QMDL file {input_file}...")
        if args.csv:
            print(f"RRC and NAS data will be exported to separate CSV files:")
            print(f"  RRC: {args.csv}_rrc.csv")
            print(f"  NAS: {args.csv}_nas.csv")
        if args.pcap:
            print(f"PCAP file will be exported to: {args.pcap}")
        result = reader.read_qmdl_file_to_csv(input_file, min_size_mb=args.size, output_csv=args.csv, output_pcap=args.pcap)

    if result:
        print("File processing completed successfully!")
        if args.csv:
            print("RRC and NAS CSV export completed!")
        if args.pcap:
            print("PCAP export completed!")
    else:
        print("File processing failed")