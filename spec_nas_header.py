nas_headers = [
    # Essential fields for specification-based detection
    'packet_number',
    'frame.time_epoch',                   # Timestamp for temporal analysis
    'nas-eps.nas_msg_emm_type',          # EMM message type (attach_request, identity_request, etc.)
    'nas-eps.nas_msg_esm_type',          # ESM message type (attach_accept, identity_response, etc.)
    'nas-eps.emm.cause',                 # EMM cause codes for reject messages
    'nas-eps.security_header_type',      # Security header type for integrity protection
    'nas-eps.emm.eps_att_type',          # EPS attach type for establishment cause
    'e212.gummei.mcc',                   # International Mobile Subscriber Identity (MCC)
    'e212.gummei.mnc',                   # International Mobile Subscriber Identity (MNC)
    'nas-eps.emm.m_tmsi',                # M-TMSI for temporary identity
    'nas-eps.seq_no',                    # Sequence number
]