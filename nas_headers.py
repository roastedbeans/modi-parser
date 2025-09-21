nas_headers = [
    # Tier 1: Critical Attack Indicators (1-20)
    'gsm_a_dtap_autn',                    # 1 - Authentication token used in GSM
    'gsm_a_dtap_rand',                    # 2 - Random challenge for authentication
    'nas-eps_msg_auth_code',              # 3 - Message authentication code for NAS-EPS
    'nas-eps_seq_no',                     # 4 - Sequence number for NAS-EPS messages
    'e212_mcc',                           # 5 - Mobile Country Code for E.212
    'e212_mnc',                           # 6 - Mobile Network Code for E.212
    'nas-eps_emm_mme_code',               # 7 - MME identifier in NAS-EPS
    'nas-eps_emm_mme_grp_id',             # 8 - MME group identifier in NAS-EPS
    'nas-eps_security_header_type',       # 9 - Type of security protection level in NAS-EPS
    'nas-eps_emm_nas_key_set_id',         # 10 - Key set identifier for NAS-EPS
    'nas-eps_emm_cause',                  # 11 - Reasons for EMM failure in NAS-EPS
    'nas-eps_emm_tai_tac',                # 12 - Tracking Area Code in NAS-EPS
    'e212_gummei_mcc',                    # 13 - GUMMEI Mobile Country Code
    'e212_gummei_mnc',                    # 14 - GUMMEI Mobile Network Code
    'nas-eps_nas_msg_emm_type',           # 15 - Type of EMM message in NAS-EPS
    'gsm_a_dtap_autn_sqn_xor_ak',         # 16 - Sequence number in AUTN XORed with AK
    'nas-eps_emm_short_mac',              # 17 - Short Message Authentication Code in NAS-EPS
    'nas-eps_emm_tsc',                    # 18 - Type of security context in NAS-EPS
    'e212_tai_mcc',                       # 19 - TAI Mobile Country Code
    'e212_tai_mnc',                       # 20 - TAI Mobile Network Code

    # Tier 2: High Priority Detection (21-60)
    'nas-eps_emm_res',                    # 21 - Authentication response in NAS-EPS
    'gsm_a_dtap_autn_mac',                # 22 - Message Authentication Code in AUTN
    'nas-eps_emm_type_of_id',             # 23 - Type of identity in NAS-EPS
    'nas-eps_emm_m_tmsi',                 # 24 - Temporary Mobile Subscriber Identity in NAS-EPS
    'nas-eps_emm_guti_type',              # 25 - Type of GUTI in NAS-EPS
    'nas-eps_emm_eps_att_type',           # 26 - Attach type in NAS-EPS
    'nas-eps_emm_detach_type_ul',         # 27 - Detach type in NAS-EPS uplink
    'nas-eps_emm_update_type_value',      # 28 - Update type in NAS-EPS
    'gsm_a_l3_protocol_discriminator',    # 29 - Protocol discriminator in GSM Layer 3
    'nas-eps_emm_tai_n_elem',             # 30 - Number of TAI elements in NAS-EPS
    'nas-eps_emm_tai_tol',                # 31 - Type of list in NAS-EPS
    'gsm_a_lac',                          # 32 - Location Area Code in GSM
    'nas-eps_esm_cause',                  # 33 - Reasons for ESM failure in NAS-EPS
    'nas-eps_emm_active_flg',             # 34 - Active flag in NAS-EPS
    'nas-eps_emm_switch_off',             # 35 - Switch off indicator in NAS-EPS
    'nas-eps_seq_no_short',               # 36 - Short sequence number in NAS-EPS
    'nas-eps_spare_bits',                 # 37 - Spare bits in NAS-EPS
    'packet_number',                      # 38 - Packet sequence number
    'nas-eps_nas_msg_esm_type',           # 39 - ESM message type in NAS-EPS
    'nas-eps_emm_odd_even',               # 40 - Odd/even indicator in NAS-EPS
    'e212_imsi',                          # 41 - International Mobile Subscriber Identity
    'e212_assoc_imsi',                    # 42 - Associated IMSI
    'e212_assoc_imsi_e212_mcc',           # 43 - Associated IMSI Mobile Country Code
    'e212_assoc_imsi_e212_mnc',           # 44 - Associated IMSI Mobile Network Code
    'e212_rai_mcc',                       # 45 - RAI Mobile Country Code
    'e212_rai_mnc',                       # 46 - RAI Mobile Network Code
    'gsm_a_dtap_autn_amf',                # 47 - Authentication Management Field in AUTN
    'gsm_a_dtap_autn_gsm_a_dtap_autn_amf', # 48 - AUTN AMF field in GSM
    'gsm_a_dtap_autn_gsm_a_dtap_autn_mac', # 49 - AUTN MAC field in GSM
    'gsm_a_dtap_autn_gsm_a_dtap_autn_sqn_xor_ak', # 50 - AUTN SQN XOR AK field in GSM
    'nas-eps_bearer_id',                  # 51 - Bearer ID in NAS-EPS
    'nas-eps_esm_proc_trans_id',          # 52 - Procedure transaction ID in NAS-EPS
    'nas-eps_emm_eps_attach_result',      # 53 - Attach result in NAS-EPS
    'nas-eps_emm_eps_update_result_value', # 54 - Update result in NAS-EPS
    'nas-eps_emm_ims_vops',               # 55 - IMS Voice over PS in NAS-EPS
    'nas-eps_emm_epc_lcs',                # 56 - EPC Location Services in NAS-EPS
    'nas-eps_emm_cp_ciot',                # 57 - Control Plane CIoT in NAS-EPS
    'nas-eps_emm_up_ciot',                # 58 - User Plane CIoT in NAS-EPS
    'nas-eps_emm_hc_cp_ciot',             # 59 - High Capacity Control Plane CIoT in NAS-EPS
    'nas-eps_emm_s1_u_data',              # 60 - S1-U data in NAS-EPS

    # Tier 3: Medium Priority (61-120)
    'nas-eps_emm_cp_ciot_cap',            # 61 - Control Plane CIoT capability in NAS-EPS
    'nas-eps_emm_up_ciot_cap',            # 62 - User Plane CIoT capability in NAS-EPS
    'nas-eps_emm_hc_cp_ciot_cap',         # 63 - High Capacity Control Plane CIoT capability in NAS-EPS
    'nas-eps_emm_s1u_data_cap',           # 64 - S1-U data capability in NAS-EPS
    'nas-eps_emm_er_wo_pdn',              # 65 - Emergency Registration without PDN in NAS-EPS
    'nas-eps_emm_er_wo_pdn_cap',          # 66 - Emergency Registration without PDN capability in NAS-EPS
    'nas-eps_emm_dcnr_cap',               # 67 - DCNR capability in NAS-EPS
    'nas-eps_emm_n1mode_cap',             # 68 - N1 mode capability in NAS-EPS
    'nas-eps_emm_restrict_dcnr',          # 69 - Restriction on DCNR in NAS-EPS
    'nas-eps_emm_restrict_ec',            # 70 - Restriction on EC in NAS-EPS
    'nas-eps_emm_restrict_ec_cap',        # 71 - Restriction on EC capability in NAS-EPS
    'nas-eps_emm_15_bearers',             # 72 - Support for 15 bearers in NAS-EPS
    'nas-eps_emm_15_bearers_cap',         # 73 - Capability for 15 bearers in NAS-EPS
    'nas-eps_emm_cp_backoff_cap',         # 74 - Control Plane backoff capability in NAS-EPS
    'nas-eps_emm_multiple_drb_cap',       # 75 - Multiple DRB capability in NAS-EPS
    'nas-eps_emm_1xsrvcc_cap',            # 76 - 1xSRVCC capability in NAS-EPS
    'nas-eps_emm_acc_csfb_cap',           # 77 - Access CSFB capability in NAS-EPS
    'nas-eps_emm_lcs_cap',                # 78 - Location Services capability in NAS-EPS
    'nas-eps_emm_lpp_cap',                # 79 - LPP capability in NAS-EPS
    'nas-eps_emm_cs_lcs',                 # 80 - Circuit Switched Location Services in NAS-EPS
    'nas-eps_emm_emc_bs',                 # 81 - Emergency Bearer Services in NAS-EPS
    'nas-eps_emm_epco',                   # 82 - EPCO in NAS-EPS
    'nas-eps_emm_epco_cap',               # 83 - EPCO capability in NAS-EPS
    'nas-eps_emm_prose_cap',              # 84 - ProSe capability in NAS-EPS
    'nas-eps_emm_prose_dc_cap',           # 85 - ProSe Direct Communication capability in NAS-EPS
    'nas-eps_emm_prose_dd_cap',           # 86 - ProSe Direct Discovery capability in NAS-EPS
    'nas-eps_emm_prose_relay_cap',        # 87 - ProSe Relay capability in NAS-EPS
    'nas-eps_emm_v2x_pc5_cap',            # 88 - V2X PC5 capability in NAS-EPS
    'nas-eps_emm_sgc_cap',                # 89 - SGC capability in NAS-EPS
    'nas-eps_emm_nf_cap',                 # 90 - NF capability in NAS-EPS
    'nas-eps_emm_h245_ash_cap',           # 91 - H.245 ASH capability in NAS-EPS
    'nas-eps_emm_iwkn26',                 # 92 - IWKN26 in NAS-EPS
    'nas-eps_emm_esr_ps',                 # 93 - ESR for PS in NAS-EPS
    'nas-eps_emm_ue_ra_cap_inf_upd_need_flg', # 94 - UE RA capability information update needed flag in NAS-EPS
    'nas-eps_emm_emm_ucs2_supp',          # 95 - UCS2 support in NAS-EPS
    'nas-eps_emm_spare_half_octet',       # 96 - Spare half octet in NAS-EPS
    'nas-eps_emm_toc',                    # 97 - Type of Ciphering in NAS-EPS
    'nas-eps_emm_toi',                    # 98 - Type of Integrity in NAS-EPS
    'nas-eps_emm_imeisv_req',             # 99 - IMEISV request in NAS-EPS
    'nas-eps_emm_hash_mme',               # 100 - Hash of MME in NAS-EPS
    'nas-eps_emm_replayed_nas_msg_cont',  # 101 - Replayed NAS message content in NAS-EPS
    'nas-eps_emm_replayed_nas_msg_cont_gsm_a_l3_protocol_discriminator', # 102 - Replayed NAS message content with GSM Layer 3 protocol discriminator
    'nas-eps_emm_replayed_nas_msg_cont_nas-eps_emm_eps_att_type', # 103 - Replayed NAS message content with EPS attach type
    'nas-eps_emm_replayed_nas_msg_cont_nas-eps_emm_nas_key_set_id', # 104 - Replayed NAS message content with NAS key set ID
    'nas-eps_emm_replayed_nas_msg_cont_nas-eps_emm_tsc', # 105 - Replayed NAS message content with security context type
    'nas-eps_emm_replayed_nas_msg_cont_nas-eps_nas_msg_emm_type', # 106 - Replayed NAS message content with EMM message type
    'nas-eps_emm_replayed_nas_msg_cont_nas-eps_security_header_type', # 107 - Replayed NAS message content with security header type
    'nas-eps_emm_replayed_nas_msg_cont_nas-eps_spare_bits', # 108 - Replayed NAS message content with spare bits
    'nas-eps_emm_esm_msg_cont',           # 109 - ESM message content in NAS-EPS
    'nas-eps_emm_esm_msg_cont_gsm_a_l3_protocol_discriminator', # 110 - ESM message content with GSM Layer 3 protocol discriminator
    'nas-eps_emm_esm_msg_cont_nas-eps_bearer_id', # 111 - ESM message content with bearer ID
    'nas-eps_emm_esm_msg_cont_nas-eps_esm_pdn_type', # 112 - ESM message content with PDN type
    'nas-eps_emm_esm_msg_cont_nas-eps_esm_proc_trans_id', # 113 - ESM message content with procedure transaction ID
    'nas-eps_emm_esm_msg_cont_nas-eps_esm_request_type', # 114 - ESM message content with request type
    'nas-eps_emm_esm_msg_cont_nas-eps_nas_msg_esm_type', # 115 - ESM message content with ESM message type
    'gsm_a_ie_mobileid_type',             # 116 - Mobile ID type in GSM
    'gsm_a_oddevenind',                   # 117 - Odd/even indicator in GSM
    'gsm_a_imeisv',                       # 118 - IMEISV in GSM
    'gsm_a_key_seq',                      # 119 - Key sequence in GSM
    'gsm_a_skip_ind',                     # 120 - Skip indicator in GSM

    # Tier 4: Supporting Fields (121-160)
    'nas-eps_emm_eea0',                   # 121 - Encryption algorithm 0 in NAS-EPS
    'nas-eps_emm_eea3',                   # 122 - Encryption algorithm 3 in NAS-EPS
    'nas-eps_emm_eea4',                   # 123 - Encryption algorithm 4 in NAS-EPS
    'nas-eps_emm_eea5',                   # 124 - Encryption algorithm 5 in NAS-EPS
    'nas-eps_emm_eea6',                   # 125 - Encryption algorithm 6 in NAS-EPS
    'nas-eps_emm_eea7',                   # 126 - Encryption algorithm 7 in NAS-EPS
    'nas-eps_emm_eia0',                   # 127 - Integrity algorithm 0 in NAS-EPS
    'nas-eps_emm_eia3',                   # 128 - Integrity algorithm 3 in NAS-EPS
    'nas-eps_emm_eia4',                   # 129 - Integrity algorithm 4 in NAS-EPS
    'nas-eps_emm_eia5',                   # 130 - Integrity algorithm 5 in NAS-EPS
    'nas-eps_emm_eia6',                   # 131 - Integrity algorithm 6 in NAS-EPS
    'nas-eps_emm_5g_ea0',                 # 132 - 5G encryption algorithm 0
    'nas-eps_emm_5g_ea4',                 # 133 - 5G encryption algorithm 4
    'nas-eps_emm_5g_ea5',                 # 134 - 5G encryption algorithm 5
    'nas-eps_emm_5g_ea6',                 # 135 - 5G encryption algorithm 6
    'nas-eps_emm_5g_ea7',                 # 136 - 5G encryption algorithm 7
    'nas-eps_emm_5g_ea8',                 # 137 - 5G encryption algorithm 8
    'nas-eps_emm_5g_ea9',                 # 138 - 5G encryption algorithm 9
    'nas-eps_emm_5g_ea10',                # 139 - 5G encryption algorithm 10
    'nas-eps_emm_5g_ea11',                # 140 - 5G encryption algorithm 11
    'nas-eps_emm_5g_ea12',                # 141 - 5G encryption algorithm 12
    'nas-eps_emm_5g_ea13',                # 142 - 5G encryption algorithm 13
    'nas-eps_emm_5g_ea14',                # 143 - 5G encryption algorithm 14
    'nas-eps_emm_5g_ea15',                # 144 - 5G encryption algorithm 15
    'nas-eps_emm_5g_ia0',                 # 145 - 5G integrity algorithm 0
    'nas-eps_emm_5g_ia4',                 # 146 - 5G integrity algorithm 4
    'nas-eps_emm_5g_ia5',                 # 147 - 5G integrity algorithm 5
    'nas-eps_emm_5g_ia6',                 # 148 - 5G integrity algorithm 6
    'nas-eps_emm_5g_ia7',                 # 149 - 5G integrity algorithm 7
    'nas-eps_emm_5g_ia8',                 # 150 - 5G integrity algorithm 8
    'nas-eps_emm_5g_ia9',                 # 151 - 5G integrity algorithm 9
    'nas-eps_emm_5g_ia10',                # 152 - 5G integrity algorithm 10
    'nas-eps_emm_5g_ia11',                # 153 - 5G integrity algorithm 11
    'nas-eps_emm_5g_ia12',                # 154 - 5G integrity algorithm 12
    'nas-eps_emm_5g_ia13',                # 155 - 5G integrity algorithm 13
    'nas-eps_emm_5g_ia14',                # 156 - 5G integrity algorithm 14
    'nas-eps_emm_5g_ia15',                # 157 - 5G integrity algorithm 15
    'nas-eps_emm_128_5g_ea1',             # 158 - 128-bit 5G encryption algorithm 1
    'nas-eps_emm_128_5g_ea2',             # 159 - 128-bit 5G encryption algorithm 2
    'nas-eps_emm_128_5g_ea3',             # 160 - 128-bit 5G encryption algorithm 3

    # Tier 5: Bearer & ESM Fields (161-200)
    'nas-eps_emm_128_5g_ia1',             # 161 - 128-bit 5G integrity algorithm 1
    'nas-eps_emm_128_5g_ia2',             # 162 - 128-bit 5G integrity algorithm 2
    'nas-eps_emm_128_5g_ia3',             # 163 - 128-bit 5G integrity algorithm 3
    'nas-eps_emm_128eea1',                # 164 - 128-bit EEA1 encryption algorithm
    'nas-eps_emm_128eea2',                # 165 - 128-bit EEA2 encryption algorithm
    'nas-eps_emm_128eia1',                # 166 - 128-bit EIA1 integrity algorithm
    'nas-eps_emm_128eia2',                # 167 - 128-bit EIA2 integrity algorithm
    'nas-eps_emm_eps_upip',               # 168 - EPS User Plane IP
    'nas-eps_esm_apn_ambr_dl',            # 169 - APN Aggregate Maximum Bit Rate for downlink
    'nas-eps_esm_apn_ambr_ul',            # 170 - APN Aggregate Maximum Bit Rate for uplink
    'nas-eps_esm_apn_ambr_dl_ext',        # 171 - Extended APN AMBR for downlink
    'nas-eps_esm_apn_ambr_ul_ext',        # 172 - Extended APN AMBR for uplink
    'nas-eps_esm_apn_ambr_dl_ext2',       # 173 - Second extension of APN AMBR for downlink
    'nas-eps_esm_apn_ambr_ul_ext2',       # 174 - Second extension of APN AMBR for uplink
    'nas-eps_esm_apn_ambr_dl_total',      # 175 - Total APN AMBR for downlink
    'nas-eps_esm_apn_ambr_ul_total',      # 175 - Total APN AMBR for uplink
    'nas-eps_esm_pdn_type',               # 176 - PDN type in NAS-EPS
    'nas-eps_esm_request_type'            # 177 - Request type in NAS-EPS
]