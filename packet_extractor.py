#!/usr/bin/env python3.9
# coding: utf8
"""
QMDL Packet Extractor with Protocol Classification

Extracts packets from QMDL files and correctly classifies them based on the actual
parser logic, not GSMTAP headers. Returns dictionaries with protocol numbers from mapping.json.
"""

import logging
import os
from fileio import FileIO
from qualcomm.qualcommparser import QualcommParser
from ws_dissector.ws_wrapper import WSDissector
from datetime import datetime
from pdml_to_table import PdmlToTableConverter


class ProtocolAnalyzer:
    """Analyzes packets to determine correct protocol numbers from parser logic"""

    def analyze_gsmtap_packet(self, gsmtap_packet):
        """Analyze GSMTAP packet and return the correct protocol number"""
        try:
            if len(gsmtap_packet) < 16:
                return None

            version = gsmtap_packet[0]
            payload_type = gsmtap_packet[2]

            # Get subtype based on version
            if version == 2 and len(gsmtap_packet) > 12:
                subtype = gsmtap_packet[12]  # GSMTAP v2 subtype is at byte 12
            elif version == 3 and len(gsmtap_packet) > 12:
                subtype = gsmtap_packet[12]  # GSMTAP v3 subtype is also at byte 12
            else:
                return None

            # Map based on GSMTAP payload type and subtype
            return self._map_to_protocol_number(payload_type, subtype, gsmtap_packet)

        except Exception as e:
            logging.debug(f"Error analyzing GSMTAP packet: {e}")
            return None

    def _map_to_protocol_number(self, payload_type, subtype, packet_data):
        """Map GSMTAP type/subtype to protocol numbers from mapping.json"""

        # LTE RRC (GSMTAP v2 payload_type = 13, GSMTAP v3 = 1027)
        if payload_type in [13, 1027]:
            # Map GSMTAP LTE RRC subtypes to protocol numbers
            lte_rrc_mapping = {
                # Standard LTE RRC subtypes from util.py gsmtap_lte_rrc_types
                0: 204,  # DL_CCCH -> lte-rrc.dl.ccch
                1: 201,  # DL_DCCH -> lte-rrc.dl.dcch
                2: 205,  # UL_CCCH -> lte-rrc.ul.ccch
                3: 202,  # UL_DCCH -> lte-rrc.ul.dcch
                4: 104,  # BCCH_BCH -> rrc.bcch.bch
                5: 203,  # BCCH_DL_SCH -> lte-rrc.bcch.dl.sch
                6: 200,  # PCCH -> lte-rrc.pcch
                7: None, # MCCH (not in mapping.json)
                # NB-IoT variants
                14: 209, # DL_CCCH_NB -> lte-rrc.dl.ccch.nb
                15: 206, # DL_DCCH_NB -> lte-rrc.dl.dcch.nb
                16: 210, # UL_CCCH_NB -> lte-rrc.ul.ccch.nb
                17: 207, # UL_DCCH_NB -> lte-rrc.ul.dcch.nb
                20: 208, # BCCH_DL_SCH_NB -> lte-rrc.bcch.dl.sch.nb

                # GSMTAP v3 LTE RRC subtypes (from gsmtapv3_lte_rrc_types)
                0x0001: 104,  # BCCH_BCH -> rrc.bcch.bch
                0x0002: 203,  # BCCH_DL_SCH -> lte-rrc.bcch.dl.sch
                0x0006: None, # MCCH (not in mapping.json)
                0x0007: 200,  # PCCH -> lte-rrc.pcch
                0x0008: 204,  # DL_CCCH -> lte-rrc.dl.ccch
                0x0009: 201,  # DL_DCCH -> lte-rrc.dl.dcch
                0x000a: 205,  # UL_CCCH -> lte-rrc.ul.ccch
                0x000b: 202,  # UL_DCCH -> lte-rrc.ul.dcch
                0x000c: None, # SC_MCCH (not in mapping.json)
                # NB-IoT GSMTAP v3
                0x0201: 104,  # BCCH_BCH_NB -> rrc.bcch.bch
                0x0203: 208,  # BCCH_DL_SCH_NB -> lte-rrc.bcch.dl.sch.nb
                0x0204: 200,  # PCCH_NB -> lte-rrc.pcch
                0x0205: 209,  # DL_CCCH_NB -> lte-rrc.dl.ccch.nb
                0x0206: 206,  # DL_DCCH_NB -> lte-rrc.dl.dcch.nb
                0x0207: 210,  # UL_CCCH_NB -> lte-rrc.ul.ccch.nb
                0x0208: None, # SC_MCCH_NB (not in mapping.json)
                0x0209: 207,  # UL_DCCH_NB -> lte-rrc.ul.dcch.nb
            }
            return lte_rrc_mapping.get(subtype)

        # LTE NAS (GSMTAP v2 payload_type = 18, GSMTAP v3 = 1028)
        elif payload_type in [18, 1028]:
            return 250  # nas-eps_plain

        # UMTS RRC (payload_type = 12)
        elif payload_type == 12:
            umts_rrc_mapping = {
                # Basic UMTS RRC channels
                0: 103,  # DL_DCCH -> rrc.dl.dcch
                1: 101,  # UL_DCCH -> rrc.ul.dcch
                2: 102,  # DL_CCCH -> rrc.dl.ccch
                3: 100,  # UL_CCCH -> rrc.ul.ccch
                4: 106,  # PCCH -> rrc.pcch
                8: 104,  # BCCH_BCH -> rrc.bcch.bch

                # System Information Blocks
                16: 150,  # MasterInformationBlock -> rrc.si.mib
                17: 151,  # SysInfoType1 -> rrc.si.sib1
                18: 152,  # SysInfoType2 -> rrc.si.sib2
                19: 153,  # SysInfoType3 -> rrc.si.sib3
                20: 155,  # SysInfoType5 -> rrc.si.sib5
                21: 22,   # SysInfoType5bis (no mapping - could be added)
                22: 23,   # SysInfoType6 (no mapping - could be added)
                23: 157,  # SysInfoType7 -> rrc.si.sib7
                24: 25,   # SysInfoType8 (no mapping - could be added)
                25: 26,   # SysInfoType9 (no mapping - could be added)
                26: 27,   # SysInfoType10 (no mapping - could be added)
                27: 28,   # SysInfoType11 (no mapping - could be added)
                28: 161,  # SysInfoType11 -> rrc.si.sib11 (duplicate)
                29: 22,   # SysInfoType11bis (no mapping - could be added)
                30: 162,  # SysInfoType12 -> rrc.si.sib12
                31: 32,   # SysInfoType13 (no mapping - could be added)
                # Additional SIB types would need more detailed mapping
                58: 181,  # SysInfoTypeSB1 -> rrc.si.sb1
                59: 182,  # SysInfoTypeSB2 (no mapping - could be added)
            }

            protocol_num = umts_rrc_mapping.get(subtype)
            if protocol_num:
                return protocol_num

            # Check for System Information blocks by analyzing payload
            return self._analyze_umts_si_block(packet_data)

        # NR RRC (GSMTAP v3 payload_type = 1283)
        elif payload_type == 1283:
            nr_rrc_mapping = {
                # NR RRC subtypes from gsmtapv3_nr_rrc_types
                1: 402,   # BCCH_BCH -> nr-rrc.bcch.bch
                2: 403,   # BCCH_DL_SCH -> nr-rrc.bcch.dl.sch
                3: 404,   # DL_CCCH -> nr-rrc.dl.ccch
                4: 405,   # DL_DCCH -> nr-rrc.dl.dcch
                5: 406,   # PCCH -> nr-rrc.pcch
                6: 407,   # UL_CCCH -> nr-rrc.ul.ccch
                7: 408,   # UL_CCCH1 -> nr-rrc.ul.ccch1
                8: 409,   # UL_DCCH -> nr-rrc.ul.dcch
                9: 410,   # RRC_RECONF -> nr-rrc.rrc_reconf
                10: None, # RRC_RECONF_COMPLETE (not in mapping.json)
                28: 411,  # UE_MRDC_CAP -> nr-rrc.ue_mrdc_cap
                29: 412,  # UE_NR_CAP -> nr-rrc.ue_nr_cap
                31: 411,  # UE_MRDC_CAP (duplicate)
                32: 412,  # UE_NR_CAP (duplicate)
                33: 412,  # UE_NR_CAP (duplicate)

                # System Information Blocks
                0x0207: None, # SIB1 (not in mapping.json)
                0x0208: None, # SIB2 (not in mapping.json)
                0x0209: None, # SIB3 (not in mapping.json)
                0x020a: None, # SIB4 (not in mapping.json)
                0x020b: None, # SIB5 (not in mapping.json)
                0x020c: None, # SIB6 (not in mapping.json)
                0x020d: None, # SIB7 (not in mapping.json)
                0x020e: None, # SIB8 (not in mapping.json)
                0x020f: None, # SIB9 (not in mapping.json)
                0x0210: None, # SIB10 (not in mapping.json)
                0x0211: None, # SIB11 (not in mapping.json)
                0x0212: None, # SIB12 (not in mapping.json)
                0x0213: None, # SIB13 (not in mapping.json)
                0x0214: None, # SIB14 (not in mapping.json)
                0x0215: None, # SIB15 (not in mapping.json)
                0x0216: None, # SIB16 (not in mapping.json)
                0x0217: None, # SIB17 (not in mapping.json)
                0x0218: None, # SIB18 (not in mapping.json)
                0x0219: None, # SIB19 (not in mapping.json)
                0x021a: None, # SIB20 (not in mapping.json)
                0x021b: None, # SIB21 (not in mapping.json)
                0x021c: None, # SIB22 (not in mapping.json)
                0x021d: None, # SIB23 (not in mapping.json)
                0x021e: None, # SIB24 (not in mapping.json)
                0x021f: None, # SIB25 (not in mapping.json)
                0x0220: None, # SIB17BIS (not in mapping.json)
            }
            return nr_rrc_mapping.get(subtype)

        # 5G NAS (GSMTAP v3 payload_type = 1284)
        elif payload_type == 1284:
            return 416  # nas-5gs

        # GSM (payload_type = 1 or 2)
        elif payload_type in [1, 2]:
            return 190  # gsm_a_dtap

        # PDCP (payload_type = 10, 11)
        elif payload_type in [10, 11]:
            return 300  # pdcp-lte

        return None

    def _analyze_umts_si_block(self, packet_data):
        """Analyze UMTS RRC packet to identify System Information blocks"""
        # This would require deeper packet analysis to identify SI block types
        # For now, return None - would need to implement proper SI block detection
        return None


class PacketExtractor:
    """Extract packets from QMDL and classify with correct protocol numbers"""

    def __init__(self):
        self.packets = []
        self.logger = logging.getLogger('packet_extractor')
        self.analyzer = ProtocolAnalyzer()

    def write_cp(self, sock_content, radio_id=0, ts=None):
        """Capture control plane packets"""
        if len(sock_content) < 8:
            return

        protocol_num = self.analyzer.analyze_gsmtap_packet(sock_content)
        if protocol_num:
            self.packets.append({protocol_num: sock_content})

    def write_up(self, sock_content, radio_id=0, ts=None):
        """Capture user plane packets"""
        if len(sock_content) < 8:
            return

        protocol_num = self.analyzer.analyze_gsmtap_packet(sock_content)
        if protocol_num:
            self.packets.append({protocol_num: sock_content})

    def extract_packets_from_qmdl(self, qmdl_file_path):
        """Extract packets from QMDL file and return array of {protocol_num: payload}"""
        self.packets = []

        try:
            io_device = FileIO([qmdl_file_path])
            parser = QualcommParser()
            parser.set_io_device(io_device)
            parser.set_writer(self)

            parser.set_parameter({
                'log_level': logging.WARNING,
                'qsr-hash': None,
                'qsr4-hash': None,
                'events': False,
                'msgs': True,
                'cacombos': False,
                'combine-stdout': False,
                'disable-crc-check': False,
                'layer': ['rrc', 'nas', 'pdcp'],
                'format': 'x',
                'gsmtapv3': False
            })

            parser.read_dump()
            return self.packets

        except Exception as e:
            self.logger.error(f"Error processing QMDL file: {e}")
            return []


def extract_packets(qmdl_file_path):
    """
    Extract packets from QMDL file

    Returns:
        list: Array of {protocol_number: payload} dictionaries
    """
    extractor = PacketExtractor()
    return extractor.extract_packets_from_qmdl(qmdl_file_path)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python packet_extractor.py <qmdl_file>")
        sys.exit(1)

    packets = extract_packets(sys.argv[1])

    # Export to JSON
    json_data = []
    for packet_dict in packets:
        for protocol_num, payload in packet_dict.items():
            json_data.append({str(protocol_num): payload.hex()})
            
    # Initialize dissector
    dissector = WSDissector()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"dissected_{timestamp}.xml"

    # Process packets
    pdml_data = dissector.dissect_packets_from_file(json_data, output_file, 'xml')

    # Convert PDML to CSV
    converter = PdmlToTableConverter()
    if converter.convert_pdml_to_csv(output_file):
        csv_file = output_file.replace('.xml', '.csv')
        print(f"✅ Successfully converted PDML to CSV: {csv_file}")
    else:
        print("❌ Failed to convert PDML to CSV")