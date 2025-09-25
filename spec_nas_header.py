nas_headers = [
    # Essential fields for specification-based detection
    'packet_number',
    'frame.time_epoch',                   # Timestamp for temporal analysis

    # Message types and basic information
    'nas-eps.nas_msg_emm_type',          # EMM message type (attach_request, identity_request, etc.)
    'nas-eps.nas_msg_esm_type',          # ESM message type (attach_accept, identity_response, etc.)
    'nas-eps.emm.cause',                 # EMM cause codes for reject messages
    'nas-eps.esm.cause',                 # ESM cause codes for session management

    # Security and authentication
    'nas-eps.security_header_type',      # Security header type for integrity protection
    'nas-eps.msg_auth_code',             # Message Authentication Code
    'nas-eps.emm.nas_key_set_id',        # NAS key set identifier for security context
    'nas-eps.emm.auth_resp_param',       # Authentication response parameter
    'gsm_a.imeisv',                      # IMEISV for device identification
    'e212.imsi',                         # IMSI value (for identity tracking)

    # Message direction and context
    'nas-eps.emm.eps_att_type',          # EPS attach type for establishment cause
    'nas-eps.bearer_id',                 # Bearer context information
    'nas-eps.emm.detach_type_ul',        # Detach type information
    'nas-eps.emm.guti_type',             # GUTI type information
    'lte-rrc.trackingAreaCode',          # Tracking Area Identity (from RRC layer)
    'nas-eps.seq_no',                    # Sequence number

    # Network identity information
    'e212.gummei.mcc',                   # International Mobile Subscriber Identity (MCC)
    'e212.gummei.mnc',                   # International Mobile Subscriber Identity (MNC)
    'nas-eps.emm.m_tmsi',                # M-TMSI for temporary identity
    'nas-eps.emm.mme_grp_id',            # MME Group ID
    'nas-eps.emm.mme_code',              # MME Code
]