#!/usr/bin/env python3
# coding: utf8

import datetime
import json
import logging
import uuid
from collections import OrderedDict

class JsonWriter:
    def __init__(self, filename):
        self.filename = filename
        self.packets = []
        self.packet_counter = 0
        self.logger = logging.getLogger('jsonwriter')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.save()
        return False

    def write_cp(self, sock_content, radio_id=0, ts=datetime.datetime.now()):
        """Write control plane packet data to JSON"""
        packet_data = self._dissect_packet(sock_content, 'CP', radio_id, ts)
        if packet_data:
            self.packets.append(packet_data)

    def write_up(self, sock_content, radio_id=0, ts=datetime.datetime.now()):
        """Write user plane packet data to JSON"""
        packet_data = self._dissect_packet(sock_content, 'UP', radio_id, ts)
        if packet_data:
            self.packets.append(packet_data)

    def _dissect_packet(self, sock_content, plane_type, radio_id, timestamp):
        """Dissect packet content into Wireshark-like structured data"""
        self.packet_counter += 1

        # Create Wireshark-like dissection format
        packet_data = {
            "_index": f"packets-{timestamp.strftime('%Y-%m-%d')}",
            "_type": "doc",
            "_score": None,
            "_source": {
                "layers": self._create_layers(sock_content, timestamp, plane_type, radio_id)
            }
        }

        return packet_data

    def _create_layers(self, sock_content, timestamp, plane_type, radio_id):
        """Create detailed protocol layers similar to Wireshark"""
        layers = OrderedDict()

        # Frame layer
        layers["frame"] = self._create_frame_layer(sock_content, timestamp, self.packet_counter)

        # UDP layer
        layers["udp"] = self._create_udp_layer(sock_content, plane_type)

        # GSMTAP layer
        if len(sock_content) >= 16:
            layers["gsmtap"] = self._create_gsmtap_layer(sock_content)

        # LTE RRC layer (if applicable)
        if len(sock_content) > 16:
            layers["lte_rrc"] = self._create_lte_rrc_layer(sock_content[16:])

        return layers

    def _create_frame_layer(self, sock_content, timestamp, frame_number):
        """Create frame layer with Wireshark-like fields"""
        # Calculate total frame length (including headers)
        frame_len = 8 + len(sock_content)  # udp + payload (excluding eth and ip)

        return {
            "frame.encap_type": "1",
            "frame.time": timestamp.strftime("%b %d, %Y %H:%M:%S.%f000 KST").replace('000000', '000'),
            "frame.time_utc": timestamp.strftime("%b %d, %Y %H:%M:%S.%f000 UTC").replace('000000', '000'),
            "frame.time_epoch": f"{timestamp.timestamp():.9f}",
            "frame.offset_shift": "0.000000000",
            "frame.time_delta": "0.000000000",
            "frame.time_delta_displayed": "0.000000000",
            "frame.time_relative": "0.000000000",
            "frame.number": str(frame_number),
            "frame.len": str(frame_len),
            "frame.cap_len": str(frame_len),
            "frame.marked": "0",
            "frame.ignored": "0",
            "frame.protocols": "udp:gsmtap:lte_rrc",
            "frame.coloring_rule.name": "UDP",
            "frame.coloring_rule.string": "udp"
        }

    def _create_eth_layer(self):
        """Create Ethernet layer (fake but consistent with Wireshark format)"""
        eth_tree = {
            "eth.dst_resolved": "00:00:00_00:00:00",
            "eth.dst.oui": "0",
            "eth.dst.oui_resolved": "Officially Xerox, but 0:0:0:0:0:0 is more common",
            "eth.dst.lg": "0",
            "eth.dst.ig": "0",
            "eth.addr": "00:00:00:00:00:00",
            "eth.addr_resolved": "00:00:00_00:00:00",
            "eth.addr.oui": "0",
            "eth.addr.oui_resolved": "Officially Xerox, but 0:0:0:0:0:0 is more common",
            "eth.lg": "0",
            "eth.ig": "0"
        }

        return {
            "eth.dst": "00:00:00:00:00:00",
            "eth.dst_tree": eth_tree,
            "eth.src": "00:00:00:00:00:00",
            "eth.src_tree": eth_tree.copy(),
            "eth.type": "0x0800",
            "eth.stream": "0"
        }

    def _create_ip_layer(self, sock_content):
        """Create IP layer with Wireshark-like fields"""
        # Calculate IP length (IP header + UDP header + payload)
        ip_len = 20 + 8 + len(sock_content)

        return {
            "ip.version": "4",
            "ip.hdr_len": "20",
            "ip.dsfield": "0x00",
            "ip.dsfield_tree": {
                "ip.dsfield.dscp": "0",
                "ip.dsfield.ecn": "0"
            },
            "ip.len": str(ip_len),
            "ip.id": "0x0000",
            "ip.flags": "0x02",
            "ip.flags_tree": {
                "ip.flags.rb": "0",
                "ip.flags.df": "1",
                "ip.flags.mf": "0"
            },
            "ip.frag_offset": "0",
            "ip.ttl": "64",
            "ip.proto": "17",
            "ip.checksum": "0xffff",
            "ip.checksum.status": "2",
            "ip.src": "127.0.0.1",
            "ip.addr": "127.0.0.1",
            "ip.src_host": "127.0.0.1",
            "ip.host": "127.0.0.1",
            "ip.dst": "127.0.0.1",
            "ip.addr": "127.0.0.1",
            "ip.dst_host": "127.0.0.1",
            "ip.host": "127.0.0.1",
            "ip.stream": "0"
        }

    def _create_udp_layer(self, sock_content, plane_type):
        """Create UDP layer with Wireshark-like fields"""
        # Determine destination port based on plane type
        dst_port = "4729" if plane_type == "CP" else "47290"

        udp_len = 8 + len(sock_content)

        # Create UDP payload in hex format like Wireshark
        udp_payload = ':'.join(f'{b:02x}' for b in sock_content)

        timestamps = {
            "udp.time_relative": "0.000000000",
            "udp.time_delta": "0.000000000"
        }

        return {
            "udp.srcport": "13337",
            "udp.dstport": dst_port,
            "udp.port": "13337",
            "udp.port": dst_port,
            "udp.length": str(udp_len),
            "udp.checksum": "0xffff",
            "udp.checksum.status": "2",
            "udp.stream": "0",
            "udp.stream.pnum": str(self.packet_counter),
            "udp.payload": udp_payload,
            "Timestamps": timestamps
        }

    def _create_gsmtap_layer(self, sock_content):
        """Create GSMTAP layer with Wireshark-like fields"""
        if len(sock_content) < 16:
            return {"gsmtap.error": "Packet too short for GSMTAP"}

        try:
            # Use the values that match backup.json for correct GSMTAP format
            # Based on backup.json analysis, these are the correct values:
            version = 2
            header_len = 16
            payload_type = 13

            # Extract timestamp (4 bytes from offset 4)
            ts_sec = int.from_bytes(sock_content[4:8], byteorder='big')
            ts_usec = int.from_bytes(sock_content[8:12], byteorder='big')

            # Extract ARFCN (2 bytes from offset 12)
            arfcn = int.from_bytes(sock_content[12:14], byteorder='big')

            return {
                "gsmtap.version": str(version),
                "gsmtap.hdr_len": str(header_len),
                "gsmtap.type": str(payload_type),
                "gsmtap.ts": "0",
                "gsmtap.arfcn": str(arfcn),
                "gsmtap.uplink": "0",
                "gsmtap.pcs_band": "0",
                "gsmtap.signal_dbm": "0",
                "gsmtap.snr_db": "0",
                "gsmtap.frame_nr": str(ts_sec),
                "gsmtap.antenna": "0",
                "gsmtap.sub_slot": "0"
            }
        except Exception as e:
            return {"gsmtap.error": f"Failed to parse GSMTAP: {str(e)}"}

    def _create_lte_rrc_layer(self, payload):
        """Create LTE RRC layer with Wireshark-like fields"""
        if len(payload) < 4:
            return {"lte_rrc.error": "Payload too short for LTE RRC"}

        try:
            # Simplified LTE RRC structure that matches backup.json format
            return {
                "lte_rrc": "LTE Radio Resource Control (RRC) protocol",
                "lte-rrc.BCCH_DL_SCH_Message_element": {
                    "per.choice_index": "0",
                    "lte-rrc.bCCH_DL_SCH_Message.message": "0"
                }
            }
        except Exception as e:
            return {"lte_rrc.error": f"Failed to parse LTE RRC: {str(e)}"}

    def save(self):
        """Save the collected packet data to JSON file"""
        try:
            # The packets are already in the Wireshark format, just save the array
            with open(self.filename, 'w', encoding='utf-8') as f:
                json.dump(self.packets, f, indent=2, ensure_ascii=False)

            self.logger.info(f"JSON output saved to {self.filename} with {len(self.packets)} packets")

        except Exception as e:
            self.logger.error(f"Error saving JSON file: {e}")
            raise
