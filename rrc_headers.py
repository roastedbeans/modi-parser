rrc_headers = [
  # Tier 1: Critical Cell Identity & Signal (1-25)
  'lte-rrc_physcellid',                 # 1 - Physical cell ID
  'lte-rrc_cellidentity',               # 2 - Cell identity
  'lte-rrc_mcc',                        # 3 - Mobile Country Code
  'lte-rrc_mnc',                        # 4 - Mobile Network Code
  'lte-rrc_trackingareacode',           # 5 - Tracking area
  'lte-rrc_rsrpresult_r9',              # 6 - Signal strength
  'lte-rrc_rsrqresult_r9',              # 7 - Signal quality
  'lte-rrc_referencesignalpower',       # 8 - Reference signal power
  'lte-rrc_carrierfreq',                # 9 - Carrier frequency
  'lte-rrc_dl_carrierfreq',             # 10 - Downlink frequency
  'lte-rrc_establishmentcause',         # 11 - Connection cause
  'lte-rrc_reestablishmentcause',       # 12 - Reestablishment cause
  'lte-rrc_releasecause',               # 13 - Release cause
  'lte-rrc_connectionfailuretype_r10',  # 14 - Failure type
  'lte-rrc_rlf_cause_r11',              # 15 - Radio link failure
  'lte-rrc_freqbandindicator',          # 16 - Frequency band
  'lte-rrc_cipheringalgorithm',         # 17 - Encryption algorithm
  'lte-rrc_integrityprotalgorithm',     # 18 - Integrity algorithm
  'lte-rrc_shortmac_i',                 # 19 - Short MAC-I
  'lte-rrc_nexthopchainingcount',       # 20 - Security hop count
  'lte-rrc_connestfailcount_r12',       # 21 - Connection failure count
  'lte-rrc_rach_report_r9',             # 22 - Random access report
  'lte-rrc_mobilitystate_r12',          # 23 - Mobility state
  'lte-rrc_ul_carrierfreq',             # 24 - Uplink frequency
  'lte-rrc_selectedplmn_identity',      # 25 - Selected PLMN

  # Tier 2: NR/5G Critical Fields (26-40)
  'nr-rrc_cellidentity',                # 26 - NR cell identity
  'nr-rrc_mcc',                         # 27 - NR MCC
  'nr-rrc_mnc',                         # 28 - NR MNC
  'nr-rrc_trackingareacode',            # 29 - NR tracking area
  'nr-rrc_ss_pbch_blockpower',          # 30 - NR signal power
  'nr-rrc_q_rxlevmin',                  # 31 - NR minimum signal level
  'nr-rrc_carrierbandwidth',            # 32 - NR bandwidth
  'nr-rrc_freqbandindicatornr',         # 33 - NR frequency band
  'nr-rrc_subcarrierspacing',           # 34 - NR subcarrier spacing
  'nr-rrc_subcarrierspacingcommon',     # 35 - NR common subcarrier spacing
  'nr-rrc_offsettocarrier',             # 36 - NR carrier offset
  'nr-rrc_offsettopointa',              # 37 - NR point A offset
  'nr-rrc_referencesubcarrierspacing',  # 38 - NR reference SCS
  'nr-rrc_ssb_subcarrieroffset',        # 39 - NR SSB subcarrier offset
  'nr-rrc_locationandbandwidth',        # 40 - NR location and bandwidth

  # Tier 3: LTE Configuration & Performance (41-80)
  'lte-rrc_timesincefailure_r11',       # 41 - Time since failure
  'lte-rrc_rlf_infoavailable_r10',      # 42 - RLF info available
  'lte-rrc_q_rxlevmin',                 # 43 - LTE minimum signal level
  'lte-rrc_dl_bandwidth',               # 44 - LTE DL bandwidth
  'lte-rrc_ul_bandwidth',               # 45 - LTE UL bandwidth
  'lte-rrc_transmissionmode',           # 46 - Transmission mode
  'lte-rrc_accessstratumrelease',       # 47 - Access stratum release
  'lte-rrc_ue_category',                # 48 - UE category
  'lte-rrc_supportedbandlisteutra',     # 49 - Supported band list
  'lte-rrc_interfreqneedforgaps',       # 50 - Inter-freq gaps needed
  'lte-rrc_interrat_needforgaps',       # 51 - Inter-RAT gaps needed
  'lte-rrc_loggedmeasurementsidle_r10', # 52 - Logged measurements
  'lte-rrc_ims_emergencysupport_r9',    # 53 - Emergency support
  'lte-rrc_en_dc_r15',                  # 54 - EN-DC support
  'lte-rrc_dl_256qam_r12',              # 55 - 256QAM DL support
  'lte-rrc_ul_64qam_r12',               # 56 - 64QAM UL support
  'lte-rrc_ul_256qam_r14',              # 57 - 256QAM UL support
  'lte-rrc_enable64qam',                # 58 - 64QAM enabled
  'lte-rrc_alternativetbs_indices_r12', # 59 - Alternative TBS indices
  'lte-rrc_halfduplex',                 # 60 - Half duplex support
  'lte-rrc_ue_category_v1020',          # 61 - UE category v10.2.0
  'lte-rrc_ue_category_v1170',          # 62 - UE category v11.7.0
  'lte-rrc_ue_categorydl_r12',          # 63 - UE category DL
  'lte-rrc_ue_categoryul_r12',          # 64 - UE category UL
  'lte-rrc_systemframenumber',          # 65 - System frame number
  'lte-rrc_defaultpagingcycle',         # 66 - Default paging cycle
  'lte-rrc_neighcellconfig',            # 67 - Neighbor cell config
  'lte-rrc_t300',                       # 68 - Timer T300
  'lte-rrc_t301',                       # 69 - Timer T301
  'lte-rrc_t310',                       # 70 - Timer T310
  'lte-rrc_t311',                       # 71 - Timer T311
  'lte-rrc_t320',                       # 72 - Timer T320
  'lte-rrc_n310',                       # 73 - Counter N310
  'lte-rrc_n311',                       # 74 - Counter N311
  'lte-rrc_p_max',                      # 75 - Maximum power
  'lte-rrc_alpha',                      # 76 - Alpha parameter
  'lte-rrc_p0_nominalpusch',            # 77 - P0 nominal PUSCH
  'lte-rrc_p0_nominalpucch',            # 78 - P0 nominal PUCCH
  'lte-rrc_deltaf_pucch_format1',       # 79 - Delta F PUCCH format 1
  'lte-rrc_deltaf_pucch_format1b',      # 80 - Delta F PUCCH format 1b

  # Tier 4: System Information & Configuration (81-140)
  'lte-rrc_schedulinginfolist',         # 81 - Scheduling info list
  'lte-rrc_si_windowlength',            # 82 - SI window length
  'lte-rrc_systeminfovaluetag',         # 83 - System info value tag
  'lte-rrc_cellbarred',                 # 84 - Cell barred
  'lte-rrc_cellreservedforoperatoruse', # 85 - Cell reserved
  'lte-rrc_intrafreqreselection',       # 86 - Intra-freq reselection
  'lte-rrc_q_hyst',                     # 87 - Q hysteresis
  'lte-rrc_s_intrasearch',              # 88 - S intra search
  'lte-rrc_s_nonintrasearch',           # 89 - S non-intra search
  'lte-rrc_threshservinglow',           # 90 - Threshold serving low
  'lte-rrc_cellreselectionpriority',    # 91 - Cell reselection priority
  'lte-rrc_q_offsetfreq',               # 92 - Q offset freq
  'lte-rrc_threshx_high',               # 93 - Threshold X high
  'lte-rrc_threshx_low',                # 94 - Threshold X low
  'lte-rrc_t_reselectioneutra',         # 95 - T reselection EUTRA
  'nr-rrc_defaultpagingcycle',          # 96 - NR default paging cycle
  'nr-rrc_modificationperiodcoeff',     # 97 - NR modification period
  'nr-rrc_ssb_periodicityservingcell',  # 98 - NR SSB periodicity
  'nr-rrc_dmrs_typea_position',         # 99 - NR DMRS Type A position
  'nr-rrc_systemframenumber',           # 100 - NR system frame number
  'nr-rrc_t300',                        # 101 - NR Timer T300
  'nr-rrc_t301',                        # 102 - NR Timer T301
  'nr-rrc_t310',                        # 103 - NR Timer T310
  'nr-rrc_t311',                        # 104 - NR Timer T311
  'nr-rrc_t319',                        # 105 - NR Timer T319
  'nr-rrc_n310',                        # 106 - NR Counter N310
  'nr-rrc_n311',                        # 107 - NR Counter N311
  'lte-rrc_rrc_transactionidentifier',  # 108 - RRC transaction ID
  'lte-rrc_c_rnti',                     # 109 - C-RNTI
  'lte-rrc_randomvalue',                # 110 - Random value
  'lte-rrc_ue_identity',                # 110 - UE identity
  'lte-rrc_ue_identity_lte-rrc_randomvalue', # 111 - UE identity random value
  'lte-rrc_m_tmsi',                     # 112 - M-TMSI
  'lte-rrc_mmec',                       # 113 - MME code
  'lte-rrc_mmegi',                      # 114 - MME group ID
  'lte-rrc_eps_beareridentity',         # 115 - EPS bearer identity
  'lte-rrc_drb_identity',               # 116 - DRB identity
  'lte-rrc_srb_identity',               # 117 - SRB identity
  'lte-rrc_logicalchannelidentity',     # 118 - Logical channel identity
  'lte-rrc_gummei_type_r10',            # 119 - GUMMEI type
  'lte-rrc_rat_type',                   # 120 - RAT type
  'lte-rrc_cn_domain',                  # 121 - CN domain
  'lte-rrc_failedpcellid_r10',          # 122 - Failed PCell ID
  'lte-rrc_tac_failedpcell_r12',        # 123 - TAC of failed PCell
  'lte-rrc_rlf_reportreq_r9',           # 124 - RLF report request
  'lte-rrc_rach_reportreq_r9',          # 125 - RACH report request
  'lte-rrc_rlf_infoavailable_r9',       # 126 - RLF info available R9
  'lte-rrc_connestfailoffsetvalidity_r12', # 127 - Connection establishment failure offset
  'lte-rrc_latenoncriticalextension',   # 128 - Late non-critical extension
  'lte-rrc_criticalextensions',         # 129 - Critical extensions
  'lte-rrc_criticalextensions_lte-rrc_c1', # 130 - Critical extensions C1
  'lte-rrc_c1',                         # 131 - C1 choice
  'lte-rrc_dl_ccch_message_message',    # 132 - DL CCCH message
  'lte-rrc_dl_ccch_message_message_lte-rrc_c1', # 133 - DL CCCH message C1
  'lte-rrc_dl_dcch_message_message',    # 134 - DL DCCH message
  'lte-rrc_dl_dcch_message_message_lte-rrc_c1', # 135 - DL DCCH message C1
  'lte-rrc_ul_ccch_message_message',    # 136 - UL CCCH message
  'lte-rrc_ul_ccch_message_message_lte-rrc_c1', # 137 - UL CCCH message C1
  'lte-rrc_ul_dcch_message_message',    # 138 - UL DCCH message
  'lte-rrc_ul_dcch_message_message_lte-rrc_c1', # 139 - UL DCCH message C1
  'lte-rrc_pcch_message_message',       # 140 - PCCH message

  # Tier 5: Advanced Features & Configuration (141-180)
  'lte-rrc_pcch_message_message_lte-rrc_c1', # 141 - PCCH message C1
  'lte-rrc_dedicatedinfonas',           # 142 - Dedicated info NAS
  'lte-rrc_dedicatedinfotype',          # 143 - Dedicated info type
  'lte-rrc_dedicatedinfotype_lte-rrc_dedicatedinfonas', # 144 - Dedicated info type NAS
  'lte-rrc_dedicatedinfonaslist',       # 145 - Dedicated info NAS list
  'lte-rrc_ue_capabilityrequest',       # 146 - UE capability request
  'lte-rrc_ue_capabilityrat_containerlist', # 147 - UE capability RAT container
  'lte-rrc_uecapabilityrat_container',  # 148 - UE capability RAT container
  'lte-rrc_featuregroupindicators',     # 149 - Feature group indicators
  'lte-rrc_interfreqcarrierfreqlist',   # 150 - Inter-freq carrier list
  'lte-rrc_interfreqbandlist',          # 151 - Inter-freq band list
  'lte-rrc_interrat_bandlist',          # 152 - Inter-RAT band list
  'lte-rrc_supportedbandgeran',         # 153 - Supported band GERAN
  'lte-rrc_supportedbandlistgeran',     # 154 - Supported band list GERAN
  'lte-rrc_supportedbandutra_fdd',      # 155 - Supported band UTRA FDD
  'lte-rrc_supportedbandlistutra_fdd',  # 156 - Supported band list UTRA FDD
  'lte-rrc_supportedbandcombination_r10', # 157 - Supported band combination
  'lte-rrc_supportedbandcombinationext_r10', # 158 - Supported band combination ext
  'lte-rrc_bandcombinationlisteutra_r10', # 159 - Band combination list EUTRA
  'lte-rrc_bandcombinationparameters_r10', # 160 - Band combination parameters
  'lte-rrc_ca_bandwidthclassdl_r10',    # 161 - CA bandwidth class DL
  'lte-rrc_ca_bandwidthclassul_r10',    # 162 - CA bandwidth class UL
  'lte-rrc_supportedmimo_capabilitydl_r10', # 163 - Supported MIMO capability DL
  'lte-rrc_fourLayertm3_tm4_r10',       # 164 - Four layer TM3-TM4
  'lte-rrc_tm9_with_8tx_fdd_r10',       # 165 - TM9 with 8TX FDD
  'lte-rrc_ue_specificrefsigssupported', # 166 - UE specific ref signals
  'lte-rrc_ue_transmitantennaselection', # 167 - UE transmit antenna selection
  'lte-rrc_ue_txantennaselectionsupported', # 168 - UE TX antenna selection support
  'lte-rrc_maxharq_tx',                 # 169 - Max HARQ TX
  'lte-rrc_periodicbsr_timer',          # 170 - Periodic BSR timer
  'lte-rrc_retxbsr_timer',              # 171 - Retransmission BSR timer
  'lte-rrc_ttibundling',                # 172 - TTI bundling
  'lte-rrc_mac_mainconfig',             # 173 - MAC main config
  'lte-rrc_mac_contentionresolutiontimer', # 174 - MAC contention resolution timer
  'lte-rrc_maxharq_msg3tx',             # 175 - Max HARQ MSG3 TX
  'lte-rrc_n1pucch_an',                 # 176 - N1 PUCCH AN
  'lte-rrc_deltaf_pucch_format2',       # 177 - Delta F PUCCH format 2
  'lte-rrc_deltaf_pucch_format2a',      # 178 - Delta F PUCCH format 2a
  'lte-rrc_deltaf_pucch_format2b',      # 179 - Delta F PUCCH format 2b
  'lte-rrc_deltapucch_shift',           # 180 - Delta PUCCH shift

  # Tier 6: NR Advanced Configuration (181-200)
  'nr-rrc_schedulinginfolist',          # 181 - NR scheduling info list
  'nr-rrc_si_windowlength',             # 182 - NR SI window length
  'nr-rrc_si_periodicity',              # 183 - NR SI periodicity
  'nr-rrc_sib_mappinginfo',             # 184 - NR SIB mapping info
  'nr-rrc_valuetag',                    # 185 - NR value tag
  'nr-rrc_si_broadcaststatus',          # 186 - NR SI broadcast status
  'nr-rrc_cellbarred',                  # 187 - NR cell barred
  'nr-rrc_cellreservedforoperatoruse',  # 188 - NR cell reserved
  'nr-rrc_intrafreqreselection',        # 189 - NR intra-freq reselection
  'nr-rrc_plmn_identitylist',           # 190 - NR PLMN identity list
  'nr-rrc_plmn_identityinfolist',       # 191 - NR PLMN identity info list
  'nr-rrc_frequencybandlist',           # 192 - NR frequency band list
  'nr-rrc_scs_specificcarrierlist',     # 193 - NR SCS specific carrier list
  'nr-rrc_timealignmenttimercommon',    # 194 - NR time alignment timer
  'nr-rrc_rsrp_thresholdssb',           # 195 - NR RSRP threshold SSB
  'nr-rrc_rach_configcommon',           # 196 - NR RACH config common
  'nr-rrc_ra_responsewindow',           # 197 - NR RA response window
  'nr-rrc_ra_contentionresolutiontimer', # 198 - NR RA contention resolution
  'nr-rrc_powerrampingstep',            # 199 - NR power ramping step
  'nr-rrc_preamblereceivedtargetpower'  # 200 - NR preamble received target power
]