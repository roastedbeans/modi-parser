#!/usr/bin/env python3
# coding: utf8

import tempfile
import pyshark
import xml.etree.ElementTree as ET
import os
import struct
import datetime
import logging
from io import StringIO

class DataWriter:
    """Combined PCAP writing and PDML XML conversion using PyShark - outputs PDML XML only"""

    def __init__(self):
        self.port_cp = 4729
        self.port_up = 47290
        self.ip_id = 0
        self.base_address = 0x7f000001
        self.eth_hdr = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00'
        self.logger = logging.getLogger(__name__)

    def process_qmdl_to_pdml(self, packet_processor_func, temp_pcap_name=None):
        """
        Process QMDL packets and convert to PDML XML using temporary PCAP with PyShark

        Args:
            packet_processor_func: Function that writes packets using this DataWriter
            temp_pcap_name (str): Optional temporary PCAP file name prefix

        Returns:
            str: PDML XML data from PyShark dissection
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
            temp_pcap.close()

            # Initialize PCAP file
            self._init_pcap_file(temp_pcap.name)

            # Call packet processor function
            if packet_processor_func:
                packet_processor_func(self)

            # Close PCAP file
            self._close_pcap_file()

            # Convert PCAP to PDML XML using PyShark
            pdml_data = self._pcap_to_pdml_with_pyshark(temp_pcap.name)

            return pdml_data

        except Exception as e:
            error_msg = f"Error processing QMDL to PDML: {e}"
            self.logger.error(error_msg)
            return f'<pdml><error>{error_msg}</error></pdml>'

        finally:
            # Clean up temporary file
            if temp_pcap and os.path.exists(temp_pcap.name):
                try:
                    os.unlink(temp_pcap.name)
                except Exception as e:
                    self.logger.warning(f"Failed to clean up temporary file {temp_pcap.name}: {e}")

    def _init_pcap_file(self, filename):
        """Initialize PCAP file with global header"""
        self.pcap_file = open(filename, 'wb')
        pcap_global_hdr = struct.pack('<LHHLLLL',
                0xa1b2c3d4,  # magic number
                2,           # version major
                4,           # version minor
                0,           # timezone
                0,           # sigfigs
                0xffff,      # snaplen
                1,           # network
                )
        self.pcap_file.write(pcap_global_hdr)

    def _close_pcap_file(self):
        """Close PCAP file"""
        if hasattr(self, 'pcap_file') and self.pcap_file:
            self.pcap_file.close()

    def write_pkt(self, sock_content, port, radio_id=0, ts=datetime.datetime.now()):
        """Write packet to PCAP file"""
        pcap_hdr = struct.pack('<LLLL',
                int(ts.timestamp()) % 4294967296,
                ts.microsecond,
                len(sock_content) + 8 + 20 + 14,
                len(sock_content) + 8 + 20 + 14,
                )

        dest_address = self.base_address + radio_id if radio_id > 0 else self.base_address

        ip_hdr = struct.pack('!BBHHBBBBHLL',
                0x45,                        # version, IHL, dsf
                0x00,
                len(sock_content) + 8 + 20,  # length
                self.ip_id,                  # id
                0x40,                        # flags/fragment offset
                0x00,
                0x40,                        # TTL
                0x11,                        # proto = udp
                0xffff,                      # header checksum
                0x7f000001,                  # src address
                dest_address,                # dest address
                )

        udp_hdr = struct.pack('!HHHH',
                13337,                 # source port
                port,                  # destination port
                len(sock_content) + 8, # length
                0xffff,                # checksum
                )

        self.pcap_file.write(pcap_hdr + self.eth_hdr + ip_hdr + udp_hdr + sock_content)
        self.ip_id += 1
        if self.ip_id > 65535:
            self.ip_id = 0

    def write_cp(self, sock_content, radio_id=0, ts=datetime.datetime.now()):
        """Write control plane packet"""
        self.write_pkt(sock_content, self.port_cp, radio_id, ts)

    def write_up(self, sock_content, radio_id=0, ts=datetime.datetime.now()):
        """Write user plane packet"""
        self.write_pkt(sock_content, self.port_up, radio_id, ts)

    def _pcap_to_pdml_with_pyshark(self, pcap_file_path):
        """Convert PCAP file to PDML XML using PyShark"""
        try:
            # Open PCAP with PyShark
            cap = pyshark.FileCapture(pcap_file_path, include_raw=False, use_json=False)
            
            # Create PDML root element
            pdml = ET.Element("pdml")
            pdml.set("version", "0")
            pdml.set("creator", "pyshark-datawriter/1.0")
            pdml.set("time", datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y"))
            pdml.set("capture_file", os.path.basename(pcap_file_path))
            
            packet_count = 0
            
            # Process each packet
            for packet in cap:
                packet_count += 1
                packet_elem = ET.SubElement(pdml, "packet")
                
                # Add packet timestamp and frame info
                self._add_packet_metadata(packet_elem, packet, packet_count)
                
                # Process all protocol layers in the packet
                self._process_packet_layers(packet_elem, packet)
            
            cap.close()
            
            if packet_count == 0:
                return '<pdml><error>No packets found in PCAP</error></pdml>'
            
            # Convert XML tree to string
            xml_str = self._xml_to_string_with_header(pdml)
            
            self.logger.info(f"Processed {packet_count} packets with PyShark")
            return xml_str

        except Exception as e:
            error_msg = f"PyShark processing error: {e}"
            self.logger.error(error_msg)
            return f'<pdml><error>{error_msg}</error></pdml>'

    def _add_packet_metadata(self, packet_elem, packet, packet_num):
        """Add packet metadata and frame information"""
        # Get packet size
        packet_size = int(packet.length) if hasattr(packet, 'length') else len(packet.get_raw_packet())
        
        # Add geninfo protocol
        geninfo = ET.SubElement(packet_elem, "proto")
        geninfo.set("name", "geninfo")
        geninfo.set("pos", "0")
        geninfo.set("showname", "General information")
        geninfo.set("size", str(packet_size))
        
        # Packet number
        num_field = ET.SubElement(geninfo, "field")
        num_field.set("name", "num")
        num_field.set("pos", "0")
        num_field.set("show", str(packet_num))
        num_field.set("showname", "Number")
        num_field.set("value", str(packet_num))
        num_field.set("size", str(packet_size))
        
        # Frame length
        len_field = ET.SubElement(geninfo, "field")
        len_field.set("name", "len")
        len_field.set("pos", "0")
        len_field.set("show", str(packet_size))
        len_field.set("showname", "Frame Length")
        len_field.set("value", hex(packet_size)[2:])
        len_field.set("size", str(packet_size))
        
        # Timestamp
        if hasattr(packet, 'sniff_time'):
            timestamp = packet.sniff_time
            timestamp_str = timestamp.strftime("%b %d, %Y %H:%M:%S.%f000")
            ts_field = ET.SubElement(geninfo, "field")
            ts_field.set("name", "timestamp")
            ts_field.set("pos", "0")
            ts_field.set("show", timestamp_str)
            ts_field.set("showname", "Captured Time")
            ts_field.set("value", f"{timestamp.timestamp():.9f}")
            ts_field.set("size", str(packet_size))

    def _process_packet_layers(self, packet_elem, packet):
        """Process all protocol layers in the packet"""
        try:
            # Get all layers
            for layer in packet.layers:
                layer_name = layer.layer_name.lower()
                
                # Create protocol element
                proto_elem = ET.SubElement(packet_elem, "proto")
                proto_elem.set("name", layer_name)
                proto_elem.set("showname", f"{layer_name.upper()} Layer")
                proto_elem.set("size", "0")  # PyShark doesn't always provide size
                proto_elem.set("pos", "0")   # PyShark doesn't provide position info
                
                # Add fields from this layer
                self._add_layer_fields(proto_elem, layer, layer_name)
                
                # Special handling for specific protocols
                if layer_name in ['lte_rrc', 'nr_rrc', 'nas_eps', 'gsm_map']:
                    self._add_specialized_protocol_fields(proto_elem, layer, layer_name)
                    
        except Exception as e:
            # Add error information if layer processing fails
            error_proto = ET.SubElement(packet_elem, "proto")
            error_proto.set("name", "processing_error")
            error_field = ET.SubElement(error_proto, "field")
            error_field.set("name", "error")
            error_field.set("show", f"Layer processing error: {e}")

    def _add_layer_fields(self, proto_elem, layer, layer_name):
        """Add fields from a protocol layer"""
        try:
            field_names = layer.field_names if hasattr(layer, 'field_names') else []
            
            for field_name in field_names:
                try:
                    field_value = getattr(layer, field_name, None)
                    
                    # Skip None values that cause serialization errors
                    if field_value is not None:
                        field_elem = ET.SubElement(proto_elem, "field")
                        field_elem.set("name", f"{layer_name}.{field_name}")
                        field_elem.set("showname", f"{field_name}: {field_value}")
                        field_elem.set("show", str(field_value))
                        field_elem.set("value", str(field_value))
                        field_elem.set("size", "0")
                        field_elem.set("pos", "0")
                            
                except Exception as e:
                    continue
                        
        except Exception as e:
            error_field = ET.SubElement(proto_elem, "field")
            error_field.set("name", "field_error")
            error_field.set("show", f"Field processing error: {e}")

    def _add_specialized_protocol_fields(self, proto_elem, layer, layer_name):
        """Add specialized fields for cellular protocols"""
        try:
            if layer_name == 'lte_rrc':
                self._add_lte_rrc_fields(proto_elem, layer)
            elif layer_name == 'nr_rrc':
                self._add_nr_rrc_fields(proto_elem, layer)
            elif layer_name == 'nas_eps':
                self._add_nas_fields(proto_elem, layer)
        except Exception as e:
            # Add error information for specialized processing
            error_field = ET.SubElement(proto_elem, "field")
            error_field.set("name", f"{layer_name}_specialized_error")
            error_field.set("show", f"Specialized processing error: {e}")

    def _add_lte_rrc_fields(self, proto_elem, layer):
        """Add specific LTE RRC fields with proper structure"""
        try:
            # Add fake-field-wrapper for compatibility
            fake_wrapper = ET.SubElement(proto_elem, "proto")
            fake_wrapper.set("name", "fake-field-wrapper")
            
            # Look for common LTE RRC fields
            rrc_fields = [
                'rrc_messageType', 'systemInformationBlockType1', 
                'cellAccessRelatedInfo', 'cellSelectionInfo',
                'plmn_IdentityList', 'trackingAreaCode', 'cellIdentity'
            ]
            
            for field_name in rrc_fields:
                if hasattr(layer, field_name):
                    field_value = getattr(layer, field_name)
                    field_elem = ET.SubElement(fake_wrapper, "field")
                    field_elem.set("name", f"lte-rrc.{field_name}")
                    field_elem.set("showname", f"{field_name}: {field_value}")
                    field_elem.set("show", str(field_value))
                    field_elem.set("value", str(field_value))
                    
        except Exception as e:
            pass  # Silently handle LTE RRC specific errors

    def _add_nr_rrc_fields(self, proto_elem, layer):
        """Add specific 5G NR RRC fields"""
        try:
            # Look for common NR RRC fields
            nr_fields = [
                'rrcSetup', 'rrcReconfiguration', 'masterCellGroup',
                'servingCellConfig', 'bwp_Dedicated'
            ]
            
            for field_name in nr_fields:
                if hasattr(layer, field_name):
                    field_value = getattr(layer, field_name)
                    field_elem = ET.SubElement(proto_elem, "field")
                    field_elem.set("name", f"nr-rrc.{field_name}")
                    field_elem.set("showname", f"{field_name}: {field_value}")
                    field_elem.set("show", str(field_value))
                    field_elem.set("value", str(field_value))
                    
        except Exception as e:
            pass

    def _add_nas_fields(self, proto_elem, layer):
        """Add specific NAS fields"""
        try:
            # Look for common NAS fields
            nas_fields = [
                'nas_msg_type', 'nas_security_header_type',
                'nas_attach_type', 'nas_eps_bearer_context_status'
            ]
            
            for field_name in nas_fields:
                if hasattr(layer, field_name):
                    field_value = getattr(layer, field_name)
                    field_elem = ET.SubElement(proto_elem, "field")
                    field_elem.set("name", f"nas-eps.{field_name}")
                    field_elem.set("showname", f"{field_name}: {field_value}")
                    field_elem.set("show", str(field_value))
                    field_elem.set("value", str(field_value))
                    
        except Exception as e:
            pass

    def _xml_to_string_with_header(self, root_element):
        """Convert XML element to string with proper PDML header"""
        # Create XML string with header
        xml_str = '<?xml version="1.0" encoding="utf-8"?>\n'
        xml_str += '<?xml-stylesheet type="text/xsl" href="pdml2html.xsl"?>\n'
        
        # Convert element to string
        rough_string = ET.tostring(root_element, encoding='unicode')
        xml_str += rough_string
        
        return xml_str

    def is_pyshark_available(self):
        """Check if PyShark is available"""
        try:
            import pyshark
            # Try to create a simple capture to test functionality
            temp_file = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
            temp_file.close()
            
            # Create minimal PCAP
            with open(temp_file.name, 'wb') as f:
                pcap_hdr = struct.pack('<LHHLLLL', 0xa1b2c3d4, 2, 4, 0, 0, 0xffff, 1)
                f.write(pcap_hdr)
            
            # Test PyShark can read it
            cap = pyshark.FileCapture(temp_file.name)
            cap.close()
            
            os.unlink(temp_file.name)
            return True
            
        except Exception as e:
            self.logger.debug(f"PyShark availability check failed: {e}")
            return False

    def get_tshark_version_info(self):
        """Get version information (PyShark equivalent)"""
        try:
            import pyshark
            return f"PyShark {pyshark.__version__} with Wireshark backend"
        except:
            return "PyShark not available"

# Backward compatibility
class PySharkDataWriter(DataWriter):
    """Alias for backward compatibility"""
    pass