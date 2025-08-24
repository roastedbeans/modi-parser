# #!/usr/bin/python3
# # coding: utf8

# """
# Signaling Information Display Module
# Comprehensive cellular signaling data formatter and analyzer
# """

# import struct
# import datetime
# from collections import defaultdict
# import binascii
# from util import lte_band_name, gsm_band_name, wcdma_band_name
# from qualcomm.qualcommparser import QualcommParser


# class SignalingAnalyzer:
#     """
#     Advanced signaling information analyzer and formatter
#     Processes parsed cellular data and displays comprehensive signaling information
#     """

#     def __init__(self):
#         # Initialize the SCAT Qualcomm parser
#         self.parser = QualcommParser()
#         # Enable full parsing capabilities for comprehensive analysis
#         self.parser.parse_msgs = True      # Enable extended message parsing
#         self.parser.parse_events = True    # Enable event report parsing
#         # Keep CRC checking disabled for real-world QMDL files with potential corruption
#         self.parser.check_crc = False
        
#         # Statistics tracking
#         self.stats = {
#             'total_packets': 0,
#             'parsed_packets': 0,
#             'gsm_data_extracted': 0,
#             'umts_data_extracted': 0,
#             'lte_data_extracted': 0,
#             'nr_data_extracted': 0,
#             'system_messages': 0,
#             'events_extracted': 0
#         }
        
#         # Current cellular state tracking
#         self.current_state = {
#             'gsm': {'cell_id': 'Unknown', 'arfcn': 0, 'band': 'Unknown'},
#             'umts': {'cell_id': 'Unknown', 'uarfcn': 0, 'band': 'Unknown'},
#             'lte': {'cell_id': 'Unknown', 'earfcn': 0, 'band': 'Unknown'},
#             'nr': {'cell_id': 'Unknown', 'arfcn': 0, 'band': 'Unknown'}
#         }
        
#         # Signaling information storage
#         self.signaling_info = {
#             'lte': {
#                 'serving_cell': {},
#                 'signal_quality': {},
#                 'mib': {},
#                 'sib1': {},
#                 'sib2': {},
#                 'sib3': {},
#                 'sib4': {},
#                 'sib5': {},
#                 'neighbors': [],
#                 'measurements': [],
#                 'rrc_messages': [],
#                 'physical_layer': {}
#             },
#             'nr': {
#                 'serving_cell': {},
#                 'signal_quality': {},
#                 'mib': {},
#                 'sib1': {},
#                 'sib2': {},
#                 'ssb_info': {},
#                 'beam_management': {},
#                 'bwp_info': {}
#             },
#             'umts': {
#                 'serving_cell': {},
#                 'signal_quality': {},
#                 'mib': {},
#                 'sibs': {},
#                 'rrc_messages': []
#             },
#             'gsm': {
#                 'serving_cell': {},
#                 'signal_quality': {},
#                 'system_info': {},
#                 'channels': {}
#             },
#             'connection': {
#                 'state': {},
#                 'handover': {},
#                 'location_updates': {},
#                 'security': {},
#                 'qos': {},
#                 'volte': {},
#                 'carrier_aggregation': {},
#                 'dual_connectivity': {},
#                 'protocol_stack': {}
#             }
#         }
        
#         # Data storage for signaling information
#         self.all_extracted_data = []
#         self.parsed_by_technology = defaultdict(list)
        
#         # PCAP-like data storage for detailed signaling capture
#         self.cp_packets = []  # Control plane packets (like SCAT's 'cp' channel)
#         self.up_packets = []  # User plane packets (like SCAT's 'up' channel)

#     def setup_scat_integration(self):
#         """Set up integration with SCAT's QualcommParser.run_diag() method"""
#         # Store reference to analyzer for use in custom methods
#         self._analyzer_ref = self

#         # Override the postprocess_parse_result method to capture ALL parsing results
#         original_postprocess = self.parser.postprocess_parse_result
#         def enhanced_postprocess(parse_result):
#             # Call original postprocess first (for GSMTAP output)
#             original_postprocess(parse_result)
#             # Then process the detailed parsing results for measurement extraction
#             if parse_result and ('stdout' in parse_result or 'cp' in parse_result):
#                 self._analyzer_ref._process_detailed_scat_result(parse_result)

#         self.parser.postprocess_parse_result = enhanced_postprocess

#         # Also create a custom writer for GSMTAP data
#         class SignalingWriter:
#             def __init__(self, analyzer):
#                 self.analyzer = analyzer

#             def write_cp(self, sock_content, radio_id, ts):
#                 """Handle control plane data from SCAT"""
#                 # Extract GSMTAP information for display
#                 gsmtap_info = self.analyzer._parse_gsmtap_header(sock_content)
#                 if gsmtap_info:
#                     # Create a display-friendly result
#                     display_result = {
#                         'cp': [sock_content],
#                         'radio_id': radio_id,
#                         'ts': ts,
#                         'gsmtap_info': gsmtap_info,
#                         'technology': self.analyzer._detect_technology_from_arfcn(gsmtap_info.get('arfcn', 0))
#                     }
#                     self.analyzer._process_scat_parse_result(display_result)

#             def write_up(self, sock_content, radio_id, ts):
#                 """Handle user plane data from SCAT"""
#                 parse_result = {
#                     'up': [sock_content],
#                     'radio_id': radio_id,
#                     'ts': ts
#                 }
#                 self.analyzer._process_scat_parse_result(parse_result)

#         # Set the custom writer on the parser
#         self.parser.writer = SignalingWriter(self)

#     def _process_scat_parse_result(self, parse_result):
#         """Process parse result from SCAT's QualcommParser"""
#         try:
#             # Update packet count
#             self.stats['total_packets'] += 1

#             if parse_result:
#                 self.stats['parsed_packets'] += 1

#                 # ✅ NEW: Capture detailed stdout output from parsers
#                 if 'stdout' in parse_result and parse_result['stdout']:
#                     self._process_parser_stdout(parse_result['stdout'])

#                 # Capture PCAP-like control plane and user plane data
#                 self._capture_pcap_like_data(parse_result)

#                 # Extract signaling information based on packet type
#                 signaling_data = self._process_parsed_result(parse_result)

#                 if signaling_data:
#                     # Store signaling data for comprehensive display
#                     self.all_extracted_data.append(signaling_data)
#                     tech = signaling_data.get('technology', 'Unknown')
#                     self.parsed_by_technology[tech].append(signaling_data)

#         except Exception as e:
#             print(f"Error processing SCAT parse result: {e}")
#             import traceback
#             traceback.print_exc()

#     def _process_detailed_scat_result(self, parse_result):
#         """Process detailed parsing results from QualcommParser (contains stdout with measurements)"""
#         try:
#             # Extract measurement data from stdout (this is where detailed info like "LTE SCell: EARFCN 1850..." comes from)
#             if 'stdout' in parse_result and parse_result['stdout']:
#                 self._process_parser_stdout(parse_result['stdout'])

#             # Also process any CP data for GSMTAP information
#             if 'cp' in parse_result:
#                 for cp_data in parse_result['cp']:
#                     # Extract technology from GSMTAP header
#                     gsmtap_info = self._parse_gsmtap_header(cp_data)
#                     if gsmtap_info:
#                         technology = self._detect_technology_from_arfcn(gsmtap_info.get('arfcn', 0))
#                         parse_result['technology'] = technology
#                         parse_result['gsmtap_info'] = gsmtap_info

#             # Create card data from the enhanced parse result
#             signaling_data = self._process_parsed_result(parse_result)
#             if signaling_data:
#                 # Store signaling data for comprehensive display
#                 self.all_extracted_data.append(signaling_data)
#                 tech = signaling_data.get('technology', 'Unknown')
#                 self.parsed_by_technology[tech].append(signaling_data)

#         except Exception as e:
#             print(f"Error processing detailed SCAT result: {e}")
#             import traceback
#             traceback.print_exc()

#     def _detect_technology_from_arfcn(self, arfcn):
#         """Detect technology from ARFCN value"""
#         if not arfcn or arfcn == 0:
#             return 'Unknown'

#         # UMTS UARFCN ranges
#         if 412 <= arfcn <= 687 or 712 <= arfcn <= 1073:
#             return 'UMTS'

#         # GSM ARFCN ranges (900, 1800, 1900 MHz)
#         if 1 <= arfcn <= 124 or 512 <= arfcn <= 885 or 955 <= arfcn <= 1023:
#             return 'GSM'

#         # LTE EARFCN ranges (simplified)
#         if 0 <= arfcn <= 60000:  # LTE typically has much higher EARFCN values
#             return 'LTE'

#         return 'Unknown'

#     def _process_parser_stdout(self, stdout_output):
#         """Process detailed stdout output from Qualcomm parsers"""
#         if not stdout_output or not stdout_output.strip():
#             return

#         # Process each line of stdout output
#         for line in stdout_output.split('\n'):
#             line = line.strip()
#             if not line:
#                 continue

#             # Extract measurement data from parser output
#             measurement_data = self._extract_measurement_from_line(line)
#             if measurement_data:
#                 self._update_measurement_data(measurement_data)

#     def _extract_measurement_from_line(self, line):
#         """Extract measurement data from a single line of parser output"""
#         measurement = {}

#         try:
#             # LTE Serving Cell measurements
#             if line.startswith('LTE SCell:'):
#                 # Format: "LTE SCell: EARFCN 1850, PCI 123, Measured RSRP -85.5, Measured RSSI -75.2"
#                 parts = line.split(',')
#                 for part in parts:
#                     part = part.strip()
#                     if 'EARFCN' in part:
#                         measurement['earfcn'] = int(part.split()[-1])
#                     elif 'PCI' in part:
#                         measurement['pci'] = int(part.split()[-1])
#                     elif 'RSRP' in part:
#                         rsrp_val = float(part.split()[-1])
#                         measurement['rsrp'] = rsrp_val
#                     elif 'RSSI' in part:
#                         rssi_val = float(part.split()[-1])
#                         measurement['rssi'] = rssi_val

#                 if measurement:
#                     measurement['technology'] = 'LTE'
#                     measurement['type'] = 'serving_cell_measurement'
#                     return measurement

#             # LTE Neighbor Cell measurements
#             elif line.startswith('LTE NCell:'):
#                 # Format: "LTE NCell: EARFCN 1850, number of cells: 3"
#                 # Followed by individual cell measurements
#                 if 'EARFCN' in line and 'number of cells' in line:
#                     earfcn = int(line.split('EARFCN')[1].split(',')[0].strip())
#                     return {
#                         'technology': 'LTE',
#                         'type': 'neighbor_cells_header',
#                         'earfcn': earfcn
#                     }

#             # UMTS measurements
#             elif line.startswith('UMTS Cell:'):
#                 # Extract UMTS-specific measurements
#                 if 'UARFCN' in line and 'PSC' in line:
#                     parts = line.split(',')
#                     measurement['technology'] = 'UMTS'
#                     measurement['type'] = 'serving_cell_measurement'
#                     for part in parts:
#                         part = part.strip()
#                         if 'UARFCN' in part:
#                             measurement['uarfcn'] = int(part.split()[-1])
#                         elif 'PSC' in part:
#                             measurement['psc'] = int(part.split()[-1])
#                         elif 'RSCP' in part:
#                             measurement['rscp'] = float(part.split()[-1])
#                         elif 'Ec/No' in part:
#                             measurement['ecno'] = float(part.split()[-1])
#                     return measurement

#             # GSM measurements
#             elif line.startswith('GSM Cell:'):
#                 # Extract GSM-specific measurements
#                 if 'ARFCN' in line:
#                     parts = line.split(',')
#                     measurement['technology'] = 'GSM'
#                     measurement['type'] = 'serving_cell_measurement'
#                     for part in parts:
#                         part = part.strip()
#                         if 'ARFCN' in part:
#                             measurement['arfcn'] = int(part.split()[-1])
#                         elif 'RxLev' in part:
#                             measurement['rxlev'] = float(part.split()[-1])
#                     return measurement

#         except Exception as e:
#             print(f"Error extracting measurement from line '{line}': {e}")
#             return None

#         return None

#     def _update_measurement_data(self, measurement):
#         """Update internal measurement data with extracted values"""
#         tech = measurement.get('technology', 'Unknown')

#         # Update current state with latest measurements
#         if tech == 'LTE':
#             if 'earfcn' in measurement:
#                 self.current_state['lte']['earfcn'] = measurement['earfcn']
#                 self.current_state['lte']['band'] = lte_band_name(measurement['earfcn'])
#             if 'rsrp' in measurement:
#                 self.signaling_info['lte']['signal_quality']['rsrp'] = measurement['rsrp']
#             if 'rssi' in measurement:
#                 self.signaling_info['lte']['signal_quality']['rssi'] = measurement['rssi']

#         elif tech == 'UMTS':
#             if 'uarfcn' in measurement:
#                 self.current_state['umts']['uarfcn'] = measurement['uarfcn']
#                 self.current_state['umts']['band'] = wcdma_band_name(measurement['uarfcn'])
#             if 'rscp' in measurement:
#                 self.signaling_info['umts']['signal_quality']['rscp'] = measurement['rscp']
#             if 'ecno' in measurement:
#                 self.signaling_info['umts']['signal_quality']['ecno'] = measurement['ecno']

#         elif tech == 'GSM':
#             if 'arfcn' in measurement:
#                 self.current_state['gsm']['arfcn'] = measurement['arfcn']
#                 self.current_state['gsm']['band'] = gsm_band_name(measurement['arfcn'])
#             if 'rxlev' in measurement:
#                 self.signaling_info['gsm']['signal_quality']['rxlev'] = measurement['rxlev']

#         # Add to measurement history for trend analysis
#         measurement['timestamp'] = datetime.datetime.now()
#         if not hasattr(self, 'measurement_history'):
#             self.measurement_history = []
#         self.measurement_history.append(measurement)

#         # Keep only last 1000 measurements to prevent memory issues
#         if len(self.measurement_history) > 1000:
#             self.measurement_history = self.measurement_history[-1000:]

#     def get_measurement_history(self, technology=None, limit=100):
#         """Get measurement history for analysis"""
#         if not hasattr(self, 'measurement_history'):
#             return []

#         history = self.measurement_history
#         if technology:
#             history = [m for m in history if m.get('technology') == technology]

#         return history[-limit:] if limit > 0 else history

#     def extract_signaling_from_packet(self, pkt, hdlc_encoded=True, has_crc=True):
#         """
#         Legacy method for manual packet processing
#         Now delegates to SCAT's proper implementation

#         Args:
#             pkt (bytes): Raw packet data
#             hdlc_encoded (bool): Whether packet is HDLC encoded
#             has_crc (bool): Whether packet has CRC

#         Returns:
#             dict: Extracted signaling information or None
#         """
#         # For backward compatibility, process manually if needed
#         return self._process_scat_parse_result(
#             self.parser.parse_diag(pkt, hdlc_encoded, has_crc)
#         )

#     def _capture_pcap_like_data(self, result):
#         """
#         Capture control plane and user plane data like SCAT's PcapWriter
#         This captures the same detailed signaling information found in PCAP files
#         """
#         if not result:
#             return
            
#         # Extract timestamp
#         timestamp = result.get('ts', datetime.datetime.now())
#         radio_id = result.get('radio_id', 0)
        
#         # Capture Control Plane (Signaling) data - this is what creates the detailed PCAP info
#         if 'cp' in result:
#             for cp_packet in result['cp']:
#                 cp_entry = {
#                     'timestamp': timestamp,
#                     'radio_id': radio_id,
#                     'direction': self._determine_direction_from_gsmtap(cp_packet),
#                     'technology': self._determine_technology_from_gsmtap(cp_packet),
#                     'message_type': self._extract_message_type_from_gsmtap(cp_packet),
#                     'raw_data': cp_packet,
#                     'size': len(cp_packet),
#                     'gsmtap_info': self._parse_gsmtap_header(cp_packet) if cp_packet else None
#                 }
#                 self.cp_packets.append(cp_entry)
                
#         # Capture User Plane data
#         if 'up' in result:
#             for up_packet in result['up']:
#                 up_entry = {
#                     'timestamp': timestamp,
#                     'radio_id': radio_id,
#                     'raw_data': up_packet,
#                     'size': len(up_packet)
#                 }
#                 self.up_packets.append(up_entry)

#     def _determine_direction_from_gsmtap(self, gsmtap_packet):
#         """Determine packet direction from GSMTAP header"""
#         if not gsmtap_packet or len(gsmtap_packet) < 16:
#             return "Unknown"
            
#         try:
#             # GSMTAP header structure (simplified)
#             # Look for direction indicators in the packet
#             # This is a simplified approach - real GSMTAP parsing would be more complex
            
#             # Check for common downlink/uplink patterns
#             if b'DL' in gsmtap_packet[:50] or b'Downlink' in gsmtap_packet[:50]:
#                 return "DOWN"
#             elif b'UL' in gsmtap_packet[:50] or b'Uplink' in gsmtap_packet[:50]:
#                 return "UP"
#             else:
#                 # Default based on message patterns
#                 return "UP"  # Most measurement reports are uplink
#         except:
#             return "Unknown"

#     def _determine_technology_from_gsmtap(self, gsmtap_packet):
#         """Determine technology from GSMTAP header"""
#         if not gsmtap_packet or len(gsmtap_packet) < 16:
#             return "Unknown"
            
#         try:
#             # Parse GSMTAP header to determine technology
#             # GSMTAP payload type indicates the technology
#             if len(gsmtap_packet) >= 3:
#                 payload_type = gsmtap_packet[2]  # 3rd byte is payload type
                
#                 # Based on util.gsmtap_type from SCAT
#                 if payload_type == 0x0d:  # LTE_RRC
#                     return "LTE"
#                 elif payload_type == 0x0c:  # UMTS_RRC
#                     return "UMTS"
#                 elif payload_type == 0x01:  # UM (GSM)
#                     return "GSM"
#                 elif payload_type == 0x0e or payload_type == 0x0f:  # LTE_MAC
#                     return "LTE"
#                 else:
#                     return "Unknown"
#         except:
#             return "Unknown"

#     def _extract_message_type_from_gsmtap(self, gsmtap_packet):
#         """Extract message type from GSMTAP packet"""
#         if not gsmtap_packet:
#             return "Unknown Message"
            
#         try:
#             # Look for common signaling message patterns
#             packet_str = str(gsmtap_packet)
            
#             # LTE patterns
#             if 'RRCConnectionReconfiguration' in packet_str:
#                 return "RRC Connection Reconfiguration"
#             elif 'MeasurementReport' in packet_str:
#                 return "Measurement Report"
#             elif 'SystemInformation' in packet_str:
#                 return "System Information"
#             elif 'RRCConnectionSetup' in packet_str:
#                 return "RRC Connection Setup"
            
#             # NR patterns
#             elif 'NR-RRC' in packet_str:
#                 return "NR RRC Message"
#             elif 'SIB' in packet_str:
#                 return "System Information Block"
                
#             # UMTS patterns
#             elif 'RRC-Message' in packet_str:
#                 return "UMTS RRC Message"
                
#             # GSM patterns
#             elif 'GSM-RR' in packet_str:
#                 return "GSM RR Message"
                
#             else:
#                 return "Signaling Message"
#         except:
#             return "Unknown Message"

#     def _parse_gsmtap_header(self, gsmtap_packet):
#         """Parse GSMTAP header for detailed information"""
#         if not gsmtap_packet or len(gsmtap_packet) < 16:
#             return None
            
#         try:
#             import struct
#             # Basic GSMTAP header parsing
#             if len(gsmtap_packet) >= 16:
#                 header = struct.unpack('!BBBBHBBLBBBB', gsmtap_packet[:16])
#                 return {
#                     'version': header[0],
#                     'hdr_len': header[1],
#                     'type': header[2],
#                     'timeslot': header[3],
#                     'arfcn': header[4],
#                     'signal_dbm': header[5],
#                     'snr_db': header[6],
#                     'frame_number': header[7],
#                     'sub_type': header[8],
#                     'antenna_nr': header[9],
#                     'sub_slot': header[10]
#                 }
#         except:
#             return None

#     def _process_parsed_result(self, result):
#         """Process parsed result and extract signaling information"""
#         if not result:
#             return None

#         # Extract basic information
#         timestamp = result.get('ts', datetime.datetime.now())
#         radio_id = result.get('radio_id', 0)

#         # Initialize signaling data
#         signaling_data = {
#             'timestamp': timestamp,
#             'radio_id': radio_id,
#             'type': 'signaling',
#             'technology': result.get('technology', 'Unknown'),
#             'data': {}
#         }

#         # Check if we have GSMTAP information
#         if 'gsmtap_info' in result:
#             gsmtap_info = result['gsmtap_info']
#             technology = result.get('technology', 'Unknown')

#             # Extract technology-specific data based on GSMTAP info
#             if technology == 'LTE':
#                 signaling_data['data'] = {
#                     'earfcn': gsmtap_info.get('arfcn', 0),
#                     'band': lte_band_name(gsmtap_info.get('arfcn', 0)) if gsmtap_info.get('arfcn') else 'Unknown',
#                     'message_type': 'RRC',
#                     'raw_data': result.get('cp', [b''])[0] if result.get('cp') else b''
#                 }
#             elif technology == 'UMTS':
#                 signaling_data['data'] = {
#                     'uarfcn': gsmtap_info.get('arfcn', 0),
#                     'band': wcdma_band_name(gsmtap_info.get('arfcn', 0)) if gsmtap_info.get('arfcn') else 'Unknown',
#                     'message_type': 'RRC',
#                     'raw_data': result.get('cp', [b''])[0] if result.get('cp') else b''
#                 }
#             elif technology == 'GSM':
#                 signaling_data['data'] = {
#                     'arfcn': gsmtap_info.get('arfcn', 0),
#                     'band': gsm_band_name(gsmtap_info.get('arfcn', 0)) if gsmtap_info.get('arfcn') else 'Unknown',
#                     'message_type': 'L3',
#                     'raw_data': result.get('cp', [b''])[0] if result.get('cp') else b''
#                 }

#         # Process control plane data if no GSMTAP info
#         elif 'cp' in result:
#             for cp_data in result['cp']:
#                 tech_info = self._analyze_cp_data(cp_data)
#                 if tech_info:
#                     signaling_data.update(tech_info)
#                     break

#         # Convert to card format if valid signaling data
#         if signaling_data['technology'] != 'Unknown':
#             # Use PCAP-like data for richer card information
#             pcap_data = self._get_latest_pcap_data_for_signaling(signaling_data)
#             card_data = self._convert_to_card_format(signaling_data, pcap_data)
#             signaling_data['card_data'] = card_data
#             return signaling_data

#         return None

#     def _analyze_cp_data(self, cp_data):
#         """Analyze control plane data to extract signaling information"""
#         if len(cp_data) < 16:  # Too short to be meaningful
#             return None
            
#         try:
#             # Try to identify the technology and message type
#             # This is a simplified analysis - in practice, you'd need more sophisticated parsing
            
#             # Check for LTE RRC messages
#             if self._is_lte_rrc_message(cp_data):
#                 return self._extract_lte_signaling(cp_data)
                
#             # Check for NR RRC messages  
#             elif self._is_nr_rrc_message(cp_data):
#                 return self._extract_nr_signaling(cp_data)
                
#             # Check for UMTS RRC messages
#             elif self._is_umts_rrc_message(cp_data):
#                 return self._extract_umts_signaling(cp_data)
                
#             # Check for GSM messages
#             elif self._is_gsm_message(cp_data):
#                 return self._extract_gsm_signaling(cp_data)
                
#         except Exception as e:
#             print(f"Error analyzing CP data: {e}")
            
#         return None

#     def _is_lte_rrc_message(self, data):
#         """Check if data contains LTE RRC message"""
#         # Simplified check - look for LTE RRC message patterns
#         if len(data) > 16:
#             # Check GSMTAP header for LTE RRC payload type
#             if data[2] == 0x0D:  # LTE_RRC payload type
#                 return True
#         return False

#     def _is_nr_rrc_message(self, data):
#         """Check if data contains NR RRC message"""
#         # Placeholder for NR RRC detection
#         return False

#     def _is_umts_rrc_message(self, data):
#         """Check if data contains UMTS RRC message"""
#         if len(data) > 16:
#             # Check GSMTAP header for UMTS RRC payload type
#             if data[2] == 0x0C:  # UMTS_RRC payload type
#                 return True
#         return False

#     def _is_gsm_message(self, data):
#         """Check if data contains GSM message"""
#         if len(data) > 16:
#             # Check GSMTAP header for GSM payload types
#             if data[2] in [0x01, 0x02]:  # UM or ABIS payload type
#                 return True
#         return False

#     def _extract_lte_signaling(self, data):
#         """Extract LTE signaling information"""
#         self.stats['lte_data_extracted'] += 1
        
#         # Parse GSMTAP header
#         gsmtap_info = self._parse_gsmtap_header(data)
        
#         # Extract RRC message content
#         rrc_data = data[16:]  # Skip GSMTAP header
        
#         signaling_info = {
#             'technology': 'LTE',
#             'data': {
#                 'arfcn': gsmtap_info.get('arfcn', 0),
#                 'band': lte_band_name(gsmtap_info.get('arfcn', 0)),
#                 'message_type': 'RRC',
#                 'raw_data': binascii.hexlify(rrc_data[:64]).decode('ascii')  # First 64 bytes as hex
#             }
#         }
        
#         # Update current LTE state
#         if gsmtap_info.get('arfcn'):
#             self.current_state['lte']['earfcn'] = gsmtap_info['arfcn']
#             self.current_state['lte']['band'] = lte_band_name(gsmtap_info['arfcn'])
            
#         # Store in signaling info structure
#         self._update_lte_signaling_info(signaling_info['data'])
        
#         return signaling_info

#     def _extract_nr_signaling(self, data):
#         """Extract NR signaling information"""
#         self.stats['nr_data_extracted'] += 1
        
#         # Placeholder for NR signaling extraction
#         signaling_info = {
#             'technology': 'NR',
#             'data': {
#                 'message_type': 'RRC',
#                 'raw_data': binascii.hexlify(data[:64]).decode('ascii')
#             }
#         }
        
#         return signaling_info

#     def _extract_umts_signaling(self, data):
#         """Extract UMTS signaling information"""
#         self.stats['umts_data_extracted'] += 1
        
#         # Parse GSMTAP header
#         gsmtap_info = self._parse_gsmtap_header(data)
        
#         signaling_info = {
#             'technology': 'UMTS',
#             'data': {
#                 'uarfcn': gsmtap_info.get('arfcn', 0),
#                 'band': wcdma_band_name(gsmtap_info.get('arfcn', 0)),
#                 'message_type': 'RRC',
#                 'raw_data': binascii.hexlify(data[16:80]).decode('ascii')
#             }
#         }
        
#         # Update current UMTS state
#         if gsmtap_info.get('arfcn'):
#             self.current_state['umts']['uarfcn'] = gsmtap_info['arfcn']
#             self.current_state['umts']['band'] = wcdma_band_name(gsmtap_info['arfcn'])
            
#         return signaling_info

#     def _extract_gsm_signaling(self, data):
#         """Extract GSM signaling information"""
#         self.stats['gsm_data_extracted'] += 1
        
#         # Parse GSMTAP header
#         gsmtap_info = self._parse_gsmtap_header(data)
        
#         signaling_info = {
#             'technology': 'GSM',
#             'data': {
#                 'arfcn': gsmtap_info.get('arfcn', 0),
#                 'band': gsm_band_name(gsmtap_info.get('arfcn', 0)),
#                 'message_type': 'L3',
#                 'raw_data': binascii.hexlify(data[16:80]).decode('ascii')
#             }
#         }
        
#         # Update current GSM state
#         if gsmtap_info.get('arfcn'):
#             self.current_state['gsm']['arfcn'] = gsmtap_info['arfcn']
#             self.current_state['gsm']['band'] = gsm_band_name(gsmtap_info['arfcn'])
            
#         return signaling_info

#     def _parse_gsmtap_header(self, data):
#         """Parse GSMTAP header from data"""
#         if len(data) < 16:
#             return {}
            
#         try:
#             # GSMTAP v2 header: !BBBBHBBLBBBB
#             header = struct.unpack('!BBBBHBBLBBBB', data[:16])
#             return {
#                 'version': header[0],
#                 'hdr_len': header[1],
#                 'type': header[2],
#                 'timeslot': header[3],
#                 'arfcn': header[4],
#                 'signal_dbm': header[5],
#                 'snr_db': header[6],
#                 'frame_number': header[7],
#                 'sub_type': header[8],
#                 'antenna_nr': header[9],
#                 'sub_slot': header[10],
#                 'res': header[11]
#             }
#         except:
#             return {}

#     def _update_lte_signaling_info(self, data):
#         """Update LTE signaling information structure"""
#         # Update serving cell info
#         if data.get('arfcn'):
#             self.signaling_info['lte']['serving_cell']['earfcn'] = data['arfcn']
#             self.signaling_info['lte']['serving_cell']['band'] = data['band']
            
#         # Add to RRC messages
#         self.signaling_info['lte']['rrc_messages'].append({
#             'timestamp': datetime.datetime.now(),
#             'type': data.get('message_type', 'Unknown'),
#             'data': data.get('raw_data', '')
#         })

#     def get_extraction_statistics(self):
#         """Get current extraction statistics"""
#         return self.stats.copy()

#     def reset_statistics(self):
#         """Reset all statistics"""
#         self.stats = {
#             'total_packets': 0,
#             'parsed_packets': 0,
#             'gsm_data_extracted': 0,
#             'umts_data_extracted': 0,
#             'lte_data_extracted': 0,
#             'nr_data_extracted': 0,
#             'system_messages': 0,
#             'events_extracted': 0
#         }

#     def get_current_cellular_state(self):
#         """Get current cellular state"""
#         return self.current_state.copy()

#     def display_comprehensive_signaling_info(self):
#         """Display comprehensive signaling information for all extracted data"""
#         if not self.all_extracted_data:
#             print("No signaling data available for display")
#             return
            
#         print("\n" + "="*80)
#         print("COMPREHENSIVE CELLULAR SIGNALING INFORMATION")
#         print("="*80)
        
#         # Display by technology
#         for tech in ['LTE', 'NR', 'UMTS', 'GSM']:
#             if tech in self.parsed_by_technology:
#                 self._display_technology_signaling(tech, self.parsed_by_technology[tech])
                
#         # Display connection and mobility information
#         self._display_connection_info()

#     def _display_technology_signaling(self, technology, data_list):
#         """Display signaling information for a specific technology"""
#         if not data_list:
#             return
            
#         print(f"\n## {technology} Signaling Information")
#         print("-" * 50)
        
#         if technology == 'LTE':
#             self._display_lte_signaling()
#         elif technology == 'NR':
#             self._display_nr_signaling()
#         elif technology == 'UMTS':
#             self._display_umts_signaling()
#         elif technology == 'GSM':
#             self._display_gsm_signaling()
            
#         # Display raw message samples
#         print(f"\n### {technology} Message Samples")
#         for i, data in enumerate(data_list[:5]):  # Show first 5 messages
#             print(f"**Message {i+1}:**")
#             print(f"- Timestamp: {data['timestamp']}")
#             print(f"- Type: {data['data'].get('message_type', 'Unknown')}")
#             print(f"- Raw Data: {data['data'].get('raw_data', '')[:64]}...")
#             print()

#     def _display_lte_signaling(self):
#         """Display comprehensive LTE signaling information"""
#         lte_info = self.signaling_info['lte']
        
#         print("\n### Serving Cell Information")
#         serving_cell = lte_info['serving_cell']
#         if serving_cell:
#             print(f"- **EARFCN**: {serving_cell.get('earfcn', 'Unknown')}")
#             print(f"- **Frequency Band**: {serving_cell.get('band', 'Unknown')}")
#             print(f"- **Cell ID (ECI)**: {serving_cell.get('cell_id', 'Unknown')}")
#             print(f"- **Physical Cell Identity (PCI)**: {serving_cell.get('pci', 'Unknown')}")
#             print(f"- **Tracking Area Code (TAC)**: {serving_cell.get('tac', 'Unknown')}")
#             print(f"- **PLMN ID**: {serving_cell.get('plmn', 'Unknown')}")
#             print(f"- **Bandwidth**: {serving_cell.get('bandwidth', 'Unknown')} MHz")
#             print(f"- **Duplex Mode**: {serving_cell.get('duplex_mode', 'Unknown')}")
#         else:
#             print("- No serving cell information available")
            
#         print("\n### Signal Quality Measurements")
#         signal_quality = lte_info['signal_quality']
#         if signal_quality:
#             print(f"- **RSRP**: {signal_quality.get('rsrp', 'Unknown')} dBm")
#             print(f"- **RSRQ**: {signal_quality.get('rsrq', 'Unknown')} dB")
#             print(f"- **RSSI**: {signal_quality.get('rssi', 'Unknown')} dBm")
#             print(f"- **SINR/SNR**: {signal_quality.get('sinr', 'Unknown')} dB")
#             print(f"- **CQI**: {signal_quality.get('cqi', 'Unknown')}")
#             print(f"- **Tx Power**: {signal_quality.get('tx_power', 'Unknown')} dBm")
#         else:
#             print("- No signal quality measurements available")
            
#         print("\n### System Information")
#         print("#### Master Information Block (MIB)")
#         mib = lte_info['mib']
#         if mib:
#             print(f"- **System Frame Number (SFN)**: {mib.get('sfn', 'Unknown')}")
#             print(f"- **System Bandwidth**: {mib.get('bandwidth', 'Unknown')} RBs")
#             print(f"- **PHICH Duration**: {mib.get('phich_duration', 'Unknown')}")
#             print(f"- **PHICH Resource**: {mib.get('phich_resource', 'Unknown')}")
#         else:
#             print("- No MIB information available")
            
#         print("\n#### System Information Block 1 (SIB1)")
#         sib1 = lte_info['sib1']
#         if sib1:
#             print(f"- **Cell Identity**: {sib1.get('cell_identity', 'Unknown')}")
#             print(f"- **Tracking Area Code**: {sib1.get('tac', 'Unknown')}")
#             print(f"- **Cell Barred**: {sib1.get('cell_barred', 'Unknown')}")
#             print(f"- **Q-RxLevMin**: {sib1.get('q_rxlevmin', 'Unknown')} dBm")
#             print(f"- **Frequency Band Indicator**: {sib1.get('freq_band_indicator', 'Unknown')}")
#         else:
#             print("- No SIB1 information available")

#     def _display_nr_signaling(self):
#         """Display comprehensive NR signaling information"""
#         print("\n### Serving Cell Information")
#         print("- **Physical Cell ID (PCI)**: 0-1007 range")
#         print("- **NR-ARFCN**: SSB and data frequencies")
#         print("- **Cell ID (NCI)**: 36-bit identifier")
#         print("- **Frequency Band**: n1, n2, n3, etc.")
#         print("- **Bandwidth**: 5-400 MHz")
#         print("- **Subcarrier Spacing**: 15, 30, 60, 120, 240 kHz")
        
#         print("\n### Signal Quality Measurements")
#         print("- **SS-RSRP**: Synchronization Signal RSRP")
#         print("- **SS-RSRQ**: Synchronization Signal RSRQ")
#         print("- **SS-SINR**: Synchronization Signal SINR")
        
#         print("\n### SSB (Synchronization Signal Block) Information")
#         print("- **SSB Index**: 0-63 (FR1), 0-255 (FR2)")
#         print("- **SSB Periodicity**: 5, 10, 20, 40, 80, 160 ms")

#     def _display_umts_signaling(self):
#         """Display comprehensive UMTS signaling information"""
#         umts_info = self.signaling_info['umts']
        
#         print("\n### Serving Cell Information")
#         serving_cell = umts_info['serving_cell']
#         if serving_cell:
#             print(f"- **Primary Scrambling Code (PSC)**: {serving_cell.get('psc', 'Unknown')}")
#             print(f"- **UARFCN**: {serving_cell.get('uarfcn', 'Unknown')}")
#             print(f"- **Cell ID**: {serving_cell.get('cell_id', 'Unknown')}")
#             print(f"- **Frequency Band**: {serving_cell.get('band', 'Unknown')}")
#         else:
#             print("- No serving cell information available")
            
#         print("\n### Signal Quality Measurements")
#         signal_quality = umts_info['signal_quality']
#         if signal_quality:
#             print(f"- **RSCP**: {signal_quality.get('rscp', 'Unknown')} dBm")
#             print(f"- **Ec/No**: {signal_quality.get('ecno', 'Unknown')} dB")
#             print(f"- **RSSI**: {signal_quality.get('rssi', 'Unknown')} dBm")
#         else:
#             print("- No signal quality measurements available")

#     def _display_gsm_signaling(self):
#         """Display comprehensive GSM signaling information"""
#         gsm_info = self.signaling_info['gsm']
        
#         print("\n### Serving Cell Information")
#         serving_cell = gsm_info['serving_cell']
#         if serving_cell:
#             print(f"- **ARFCN**: {serving_cell.get('arfcn', 'Unknown')}")
#             print(f"- **BSIC**: {serving_cell.get('bsic', 'Unknown')}")
#             print(f"- **Cell ID**: {serving_cell.get('cell_id', 'Unknown')}")
#             print(f"- **Frequency Band**: {serving_cell.get('band', 'Unknown')}")
#         else:
#             print("- No serving cell information available")
            
#         print("\n### Signal Quality Measurements")
#         signal_quality = gsm_info['signal_quality']
#         if signal_quality:
#             print(f"- **RxLev**: {signal_quality.get('rxlev', 'Unknown')} dBm")
#             print(f"- **RxQual**: {signal_quality.get('rxqual', 'Unknown')}")
#             print(f"- **Timing Advance**: {signal_quality.get('timing_advance', 'Unknown')}")
#         else:
#             print("- No signal quality measurements available")

#     def _display_connection_info(self):
#         """Display connection and mobility information"""
#         print("\n## Connection and Mobility Information")
#         print("-" * 50)
        
#         print("\n### Connection State")
#         print("- **RRC State**: Idle/Connected/Inactive")
#         print("- **MM State**: Location Update/Attach/Detach")
#         print("- **EMM State**: Registered/Deregistered/Roaming")
        
#         print("\n### Security Information")
#         print("- **Encryption Algorithms**: EEA0-EEA3, UEA0-UEA2")
#         print("- **Integrity Algorithms**: EIA0-EIA3, UIA1-UIA2")
#         print("- **Security Mode**: Command/Complete status")

#     def _get_latest_pcap_data_for_signaling(self, signaling_data):
#         """Get the latest PCAP-like data that matches the signaling data"""
#         if not self.cp_packets:
#             return None
            
#         # Find the most recent CP packet that matches this signaling data
#         timestamp = signaling_data.get('timestamp')
#         for cp_packet in reversed(self.cp_packets):  # Start from most recent
#             if cp_packet['timestamp'] == timestamp:
#                 return cp_packet
                
#         # If no exact match, return the latest packet
#         return self.cp_packets[-1] if self.cp_packets else None

#     def _convert_to_card_format(self, signaling_data, pcap_data=None):
#         """Convert signaling data to card format for display"""
#         try:
#             technology = signaling_data.get('technology', 'Unknown')
#             timestamp = signaling_data.get('timestamp', datetime.datetime.now())
#             data = signaling_data.get('data', {})
            
#             # Format timestamp for display
#             if isinstance(timestamp, datetime.datetime):
#                 time_str = timestamp.strftime('%H:%M:%S.%f')[:-3]  # Remove microseconds, keep milliseconds
#             else:
#                 time_str = str(timestamp)
            
#             # Use PCAP data for richer information if available
#             if pcap_data:
#                 message_title = pcap_data.get('message_type', 'Unknown Message')
#                 direction = pcap_data.get('direction', 'UP')
#                 technology = pcap_data.get('technology', technology)  # Override if PCAP has better info
                
#                 # Create description from GSMTAP info
#                 description = self._create_description_from_pcap(pcap_data, data)
#                 full_data = self._create_full_data_from_pcap(pcap_data, data, timestamp)
#             else:
#                 # Fallback to original method
#                 message_title = "Unknown Message"
#                 description = "No data available"
#                 direction = "UP"  # Default direction
#                 full_data = f"{technology} Signaling Data\n\nTimestamp: {timestamp}\n"
                
#                 if technology == 'LTE':
#                     message_title, description, direction, full_data = self._format_lte_card_data(data, timestamp)
#                 elif technology == 'NR':
#                     message_title, description, direction, full_data = self._format_nr_card_data(data, timestamp)
#                 elif technology == 'UMTS':
#                     message_title, description, direction, full_data = self._format_umts_card_data(data, timestamp)
#                 elif technology == 'GSM':
#                     message_title, description, direction, full_data = self._format_gsm_card_data(data, timestamp)
            
#             return {
#                 'technology': technology,
#                 'direction': direction,
#                 'message_title': message_title,
#                 'description': description,
#                 'timestamp': time_str,
#                 'full_data': full_data
#             }
            
#         except Exception as e:
#             print(f"Error converting to card format: {e}")
#             return {
#                 'technology': 'Unknown',
#                 'direction': 'UP',
#                 'message_title': 'Parse Error',
#                 'description': f'Error: {str(e)}',
#                 'timestamp': datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3],
#                 'full_data': f"Error parsing signaling data: {str(e)}"
#             }

#     def _format_lte_card_data(self, data, timestamp):
#         """Format LTE signaling data for card display"""
#         message_title = data.get('message_type', 'LTE Message')

#         # Build description with key metrics - use latest current state data
#         desc_parts = []

#         # Check current state first (from parser stdout processing)
#         current_lte = self.current_state.get('lte', {})
#         if current_lte.get('earfcn'):
#             desc_parts.append(f"EARFCN: {current_lte['earfcn']}")
#         if 'band' in current_lte:
#             desc_parts.append(f"Band: {current_lte['band']}")

#         # Check signal quality from current measurements
#         lte_signal = self.signaling_info.get('lte', {}).get('signal_quality', {})
#         if lte_signal.get('rsrp'):
#             desc_parts.append(f"RSRP: {lte_signal['rsrp']} dBm")
#         if lte_signal.get('rsrq'):
#             desc_parts.append(f"RSRQ: {lte_signal['rsrq']} dB")
#         if lte_signal.get('rssi'):
#             desc_parts.append(f"RSSI: {lte_signal['rssi']} dBm")

#         # Fallback to packet data if no current state
#         if not desc_parts:
#             if 'rsrp' in data:
#                 desc_parts.append(f"RSRP: {data['rsrp']} dBm")
#             if 'rsrq' in data:
#                 desc_parts.append(f"RSRQ: {data['rsrq']} dB")
#             if 'pci' in data:
#                 desc_parts.append(f"PCI: {data['pci']}")
#             if 'earfcn' in data:
#                 desc_parts.append(f"EARFCN: {data['earfcn']}")

#         description = ", ".join(desc_parts) if desc_parts else "LTE signaling data"

#         # Determine direction (simplified logic)
#         direction = "DOWN" if "System" in message_title or "Configuration" in message_title else "UP"

#         # Build comprehensive full data
#         full_data = f"LTE {message_title}\n\nTimestamp: {timestamp}\n\n"

#         # Add current state information
#         if current_lte.get('earfcn'):
#             full_data += f"Current EARFCN: {current_lte['earfcn']}\n"
#         if 'band' in current_lte:
#             full_data += f"Current Band: {current_lte['band']}\n"

#         # Add signal quality information
#         if lte_signal.get('rsrp'):
#             full_data += f"Latest RSRP: {lte_signal['rsrp']} dBm\n"
#         if lte_signal.get('rsrq'):
#             full_data += f"Latest RSRQ: {lte_signal['rsrq']} dB\n"
#         if lte_signal.get('rssi'):
#             full_data += f"Latest RSSI: {lte_signal['rssi']} dBm\n"

#         # Add packet-specific data
#         if 'cell_id' in data:
#             full_data += f"Cell ID: {data['cell_id']}\n"
#         if 'earfcn' in data:
#             full_data += f"Packet EARFCN: {data['earfcn']}\n"
#         if 'pci' in data:
#             full_data += f"PCI: {data['pci']}\n"
#         if 'rsrp' in data:
#             full_data += f"Packet RSRP: {data['rsrp']} dBm\n"
#         if 'rsrq' in data:
#             full_data += f"Packet RSRQ: {data['rsrq']} dB\n"
#         if 'band' in data:
#             full_data += f"Band: {data['band']}\n"

#         return message_title, description, direction, full_data

#     def _format_nr_card_data(self, data, timestamp):
#         """Format 5G NR signaling data for card display"""
#         message_title = data.get('message_type', 'NR Message')
        
#         desc_parts = []
#         if 'ss_rsrp' in data:
#             desc_parts.append(f"SS-RSRP: {data['ss_rsrp']} dBm")
#         if 'ss_rsrq' in data:
#             desc_parts.append(f"SS-RSRQ: {data['ss_rsrq']} dB")
#         if 'pci' in data:
#             desc_parts.append(f"PCI: {data['pci']}")
#         if 'arfcn' in data:
#             desc_parts.append(f"NR-ARFCN: {data['arfcn']}")
            
#         description = ", ".join(desc_parts) if desc_parts else "5G NR signaling data"
#         direction = "DOWN" if "System" in message_title or "SIB" in message_title else "UP"
        
#         full_data = f"5G NR {message_title}\n\nTimestamp: {timestamp}\n\n"
#         if 'cell_id' in data:
#             full_data += f"Cell ID: {data['cell_id']}\n"
#         if 'arfcn' in data:
#             full_data += f"NR-ARFCN: {data['arfcn']}\n"
#         if 'pci' in data:
#             full_data += f"PCI: {data['pci']}\n"
#         if 'band' in data:
#             full_data += f"Band: {data['band']}\n"
            
#         return message_title, description, direction, full_data

#     def _format_umts_card_data(self, data, timestamp):
#         """Format UMTS signaling data for card display"""
#         message_title = data.get('message_type', 'UMTS Message')

#         # Build description with key metrics - use latest current state data
#         desc_parts = []

#         # Check current state first (from parser stdout processing)
#         current_umts = self.current_state.get('umts', {})
#         if current_umts.get('uarfcn'):
#             desc_parts.append(f"UARFCN: {current_umts['uarfcn']}")
#         if 'band' in current_umts:
#             desc_parts.append(f"Band: {current_umts['band']}")

#         # Check signal quality from current measurements
#         umts_signal = self.signaling_info.get('umts', {}).get('signal_quality', {})
#         if umts_signal.get('rscp'):
#             desc_parts.append(f"RSCP: {umts_signal['rscp']} dBm")
#         if umts_signal.get('ecno'):
#             desc_parts.append(f"Ec/No: {umts_signal['ecno']} dB")

#         # Fallback to packet data if no current state
#         if not desc_parts:
#             if 'rscp' in data:
#                 desc_parts.append(f"RSCP: {data['rscp']} dBm")
#             if 'ecno' in data:
#                 desc_parts.append(f"Ec/No: {data['ecno']} dB")
#             if 'psc' in data:
#                 desc_parts.append(f"PSC: {data['psc']}")
#             if 'uarfcn' in data:
#                 desc_parts.append(f"UARFCN: {data['uarfcn']}")

#         description = ", ".join(desc_parts) if desc_parts else "UMTS signaling data"
#         direction = "DOWN" if "System" in message_title else "UP"

#         # Build comprehensive full data
#         full_data = f"UMTS {message_title}\n\nTimestamp: {timestamp}\n\n"

#         # Add current state information
#         if current_umts.get('uarfcn'):
#             full_data += f"Current UARFCN: {current_umts['uarfcn']}\n"
#         if 'band' in current_umts:
#             full_data += f"Current Band: {current_umts['band']}\n"

#         # Add signal quality information
#         if umts_signal.get('rscp'):
#             full_data += f"Latest RSCP: {umts_signal['rscp']} dBm\n"
#         if umts_signal.get('ecno'):
#             full_data += f"Latest Ec/No: {umts_signal['ecno']} dB\n"

#         # Add packet-specific data
#         if 'cell_id' in data:
#             full_data += f"Cell ID: {data['cell_id']}\n"
#         if 'uarfcn' in data:
#             full_data += f"Packet UARFCN: {data['uarfcn']}\n"
#         if 'psc' in data:
#             full_data += f"PSC: {data['psc']}\n"

#         return message_title, description, direction, full_data

#     def _format_gsm_card_data(self, data, timestamp):
#         """Format GSM signaling data for card display"""
#         message_title = data.get('message_type', 'GSM Message')

#         # Build description with key metrics - use latest current state data
#         desc_parts = []

#         # Check current state first (from parser stdout processing)
#         current_gsm = self.current_state.get('gsm', {})
#         if current_gsm.get('arfcn'):
#             desc_parts.append(f"ARFCN: {current_gsm['arfcn']}")
#         if 'band' in current_gsm:
#             desc_parts.append(f"Band: {current_gsm['band']}")

#         # Check signal quality from current measurements
#         gsm_signal = self.signaling_info.get('gsm', {}).get('signal_quality', {})
#         if gsm_signal.get('rxlev'):
#             desc_parts.append(f"RxLev: {gsm_signal['rxlev']} dBm")

#         # Fallback to packet data if no current state
#         if not desc_parts:
#             if 'rxlev' in data:
#                 desc_parts.append(f"RxLev: {data['rxlev']}")
#             if 'arfcn' in data:
#                 desc_parts.append(f"ARFCN: {data['arfcn']}")
#             if 'bsic' in data:
#                 desc_parts.append(f"BSIC: {data['bsic']}")

#         description = ", ".join(desc_parts) if desc_parts else "GSM signaling data"
#         direction = "DOWN" if "System" in message_title else "UP"

#         # Build comprehensive full data
#         full_data = f"GSM {message_title}\n\nTimestamp: {timestamp}\n\n"

#         # Add current state information
#         if current_gsm.get('arfcn'):
#             full_data += f"Current ARFCN: {current_gsm['arfcn']}\n"
#         if 'band' in current_gsm:
#             full_data += f"Current Band: {current_gsm['band']}\n"

#         # Add signal quality information
#         if gsm_signal.get('rxlev'):
#             full_data += f"Latest RxLev: {gsm_signal['rxlev']} dBm\n"

#         # Add packet-specific data
#         if 'cell_id' in data:
#             full_data += f"Cell ID: {data['cell_id']}\n"
#         if 'arfcn' in data:
#             full_data += f"Packet ARFCN: {data['arfcn']}\n"
#         if 'bsic' in data:
#             full_data += f"BSIC: {data['bsic']}\n"
#         if 'lac' in data:
#             full_data += f"LAC: {data['lac']}\n"

#         return message_title, description, direction, full_data

#     def _create_description_from_pcap(self, pcap_data, data):
#         """Create card description from PCAP data"""
#         try:
#             desc_parts = []
            
#             # Add GSMTAP information if available
#             gsmtap_info = pcap_data.get('gsmtap_info')
#             if gsmtap_info:
#                 if gsmtap_info.get('signal_dbm') and gsmtap_info['signal_dbm'] != 0:
#                     desc_parts.append(f"Signal: {gsmtap_info['signal_dbm']} dBm")
#                 if gsmtap_info.get('arfcn') and gsmtap_info['arfcn'] != 0:
#                     desc_parts.append(f"ARFCN: {gsmtap_info['arfcn']}")
#                 if gsmtap_info.get('frame_number') and gsmtap_info['frame_number'] != 0:
#                     desc_parts.append(f"Frame: {gsmtap_info['frame_number']}")
            
#             # Add data size
#             if pcap_data.get('size'):
#                 desc_parts.append(f"Size: {pcap_data['size']} bytes")
                
#             # Add radio ID if multi-SIM
#             if pcap_data.get('radio_id', 0) > 0:
#                 desc_parts.append(f"SIM{pcap_data['radio_id']}")
            
#             # Add original data if available
#             for key in ['rsrp', 'rsrq', 'pci', 'earfcn', 'ss_rsrp', 'ss_rsrq', 'rscp', 'ecno', 'rxlev']:
#                 if key in data and data[key]:
#                     if key in ['rsrp', 'rscp']:
#                         desc_parts.append(f"{key.upper()}: {data[key]} dBm")
#                     elif key in ['rsrq', 'ecno']:
#                         desc_parts.append(f"{key.upper()}: {data[key]} dB")
#                     else:
#                         desc_parts.append(f"{key.upper()}: {data[key]}")
            
#             return ", ".join(desc_parts) if desc_parts else "PCAP signaling data"
            
#         except Exception as e:
#             return f"PCAP data available ({pcap_data.get('size', 0)} bytes)"

#     def _create_full_data_from_pcap(self, pcap_data, data, timestamp):
#         """Create detailed information from PCAP data"""
#         try:
#             technology = pcap_data.get('technology', 'Unknown')
#             message_type = pcap_data.get('message_type', 'Unknown Message')
            
#             full_data = f"{technology} {message_type}\n"
#             full_data += f"Captured from PCAP-like Control Plane Data\n\n"
#             full_data += f"Timestamp: {timestamp}\n"
#             full_data += f"Direction: {pcap_data.get('direction', 'Unknown')}\n"
#             full_data += f"Data Size: {pcap_data.get('size', 0)} bytes\n"
            
#             if pcap_data.get('radio_id', 0) > 0:
#                 full_data += f"Radio ID (SIM): {pcap_data['radio_id']}\n"
            
#             # Add GSMTAP header information
#             gsmtap_info = pcap_data.get('gsmtap_info')
#             if gsmtap_info:
#                 full_data += f"\nGSMTAP Header Information:\n"
#                 full_data += f"- Version: {gsmtap_info.get('version', 'Unknown')}\n"
#                 full_data += f"- Type: {gsmtap_info.get('type', 'Unknown')}\n"
#                 if gsmtap_info.get('arfcn', 0) != 0:
#                     full_data += f"- ARFCN: {gsmtap_info['arfcn']}\n"
#                 if gsmtap_info.get('signal_dbm', 0) != 0:
#                     full_data += f"- Signal: {gsmtap_info['signal_dbm']} dBm\n"
#                 if gsmtap_info.get('snr_db', 0) != 0:
#                     full_data += f"- SNR: {gsmtap_info['snr_db']} dB\n"
#                 if gsmtap_info.get('frame_number', 0) != 0:
#                     full_data += f"- Frame Number: {gsmtap_info['frame_number']}\n"
            
#             # Add original signaling data
#             if data:
#                 full_data += f"\nSignaling Parameters:\n"
#                 for key, value in data.items():
#                     if value:
#                         full_data += f"- {key}: {value}\n"
            
#             # Add raw data information
#             raw_data_size = len(pcap_data.get('raw_data', b''))
#             if raw_data_size > 0:
#                 full_data += f"\nRaw GSMTAP Data: {raw_data_size} bytes available\n"
#                 full_data += f"(Same detailed signaling information as found in PCAP files)\n"
            
#             return full_data
            
#         except Exception as e:
#             return f"Error formatting PCAP data: {str(e)}\n\nBasic Info:\n- Technology: {pcap_data.get('technology', 'Unknown')}\n- Message: {pcap_data.get('message_type', 'Unknown')}\n- Size: {pcap_data.get('size', 0)} bytes"

#     def get_all_extracted_data(self):
#         """Get all extracted signaling data"""
#         return {
#             'all_data': self.all_extracted_data,
#             'by_technology': dict(self.parsed_by_technology),
#             'signaling_info': self.signaling_info
#         }
    
#     def get_card_data(self):
#         """Get signaling data formatted for cards"""
#         card_data = []
#         for data in self.all_extracted_data:
#             if 'card_data' in data:
#                 card_data.append(data['card_data'])
#         return card_data
    
#     def get_pcap_statistics(self):
#         """Get PCAP-like capture statistics"""
#         return {
#             'total_cp_packets': len(self.cp_packets),
#             'total_up_packets': len(self.up_packets),
#             'technologies_detected': list(set(cp['technology'] for cp in self.cp_packets if cp.get('technology') != 'Unknown')),
#             'message_types': list(set(cp['message_type'] for cp in self.cp_packets if cp.get('message_type') != 'Unknown Message')),
#             'total_raw_data_size': sum(cp.get('size', 0) for cp in self.cp_packets),
#             'radio_ids': list(set(cp.get('radio_id', 0) for cp in self.cp_packets)),
#             'direction_breakdown': {
#                 'uplink': len([cp for cp in self.cp_packets if cp.get('direction') == 'UP']),
#                 'downlink': len([cp for cp in self.cp_packets if cp.get('direction') == 'DOWN']),
#                 'unknown': len([cp for cp in self.cp_packets if cp.get('direction') not in ['UP', 'DOWN']])
#             }
#         }