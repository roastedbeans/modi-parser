rrc_headers = [
    # Essential fields for specification-based detection
    'packet_number',
    'frame.time_epoch',                   # Timestamp for temporal analysis
    'lte-rrc.c1',                        # RRC message type (rrc_connection_request, etc.)
    'lte-rrc.establishmentCause',         # RRC establishment cause
    'lte-rrc.ue_Identity',                # UE identity information
    'lte-rrc.c_RNTI',                     # C-RNTI for UE identification
]