rrc_headers = [
    # Essential fields for specification-based detection
    'packet_number',
    'frame.time_epoch',                   # Timestamp for temporal analysis

    # Message types and basic information
    'lte-rrc.c1',                        # RRC message type (rrc_connection_request, etc.)
    'lte-rrc.establishmentCause',         # RRC establishment cause
    'lte-rrc.ue_Identity',                # UE identity information
    'lte-rrc.c_RNTI',                     # C-RNTI for UE identification

    # Connection context and transaction tracking
    'lte-rrc.rrc_transaction_id',         # Transaction tracking for RRC procedures (may be derived from message context)
    'lte-rrc.srb_Identity',               # Signaling Radio Bearer ID
    'lte-rrc.drb_Identity',               # Data Radio Bearer information
    'lte-rrc.cellIdentity',               # Serving cell ID
    'lte-rrc.trackingAreaCode',           # Tracking Area Code for location

    # Security and authentication
    'lte-rrc.securityAlgorithmConfig',    # Integrity/ciphering algorithms
    'lte-rrc.pdcp_SN_Size',               # PDCP layer sequence number size
    'lte-rrc.mmegi',                      # MME Group ID for security context
    'lte-rrc.mmec',                       # MME Code for security context

    # Radio resource information
    'lte-rrc.freqBandIndicator',          # Frequency band information
    'lte-rrc.cellBarred',                 # Cell access restrictions
    'lte-rrc.intraFreqReselection',       # Intra-frequency reselection allowed
    'lte-rrc.plmn_IdentityList',          # Available PLMN identities

    # Message direction indicators (derived from channel type)
    # Note: Direction can be inferred from message structure:
    # UL-CCCH-Message, DL-CCCH-Message, UL-DCCH-Message, DL-DCCH-Message
]