# RRC and NAS Headers Processing

This directory contains scripts and JSON files for processing and organizing RRC (Radio Resource Control) and NAS (Non-Access Stratum) protocol headers for LTE and 5G NR networks.

## Files Created

### JSON Files

- `rrc_headers.json` - Processed and categorized RRC protocol headers
- `nas_headers.json` - Processed and categorized NAS protocol headers

### Processing Scripts

- `process_rrc_headers.py` - Processes RRC headers from CSV to JSON
- `process_nas_headers.py` - Processes NAS headers from CSV to JSON
- `test_headers_simple.py` - Tests the JSON files and field mapping

### Source Files

- `rrc-header.csv` - Original RRC headers (tab-separated)
- `nas-header.csv` - Original NAS headers (tab-separated)

## RRC Headers Structure

The RRC headers are organized into the following categories:

### LTE RRC Fields (847 total)

- **Connection Management** (124 fields): RRC connection establishment, reconfiguration, and release
- **System Information** (60 fields): System information blocks and broadcast messages
- **Measurement** (26 fields): Measurement configuration and reporting
- **Radio Resource Config** (212 fields): Radio resource configuration parameters
- **Security** (20 fields): Security mode and encryption parameters
- **Mobility** (60 fields): Handover and mobility management
- **Paging** (9 fields): Paging and notification messages
- **Capability** (16 fields): UE capability information
- **Other** (320 fields): Miscellaneous RRC fields

### Additional Fields

- **PER Encoding** (60 fields): Protocol encoding related fields
- **Wireshark Expert** (19 fields): Wireshark expert information fields

## NAS Headers Structure

The NAS headers are organized into the following categories:

### NAS EPS Fields (299 total)

- **EMM** (283 fields): EPS Mobility Management - attach, detach, tracking area updates
- **ESM** (0 fields): EPS Session Management - bearer management, PDN connectivity
- **Security** (4 fields): Security mode and encryption parameters
- **Authentication** (3 fields): Authentication and key management
- **Identity** (0 fields): UE identity and identification parameters
- **Other** (9 fields): Miscellaneous NAS fields

### Additional Fields

- **GSM MAP** (81 fields): GSM MAP protocol fields
- **E212** (18 fields): E212 addressing fields
- **Wireshark Expert** (1 field): Wireshark expert information

## Field Information

Each field in the JSON files contains:

- `original_name`: The original field name from the CSV
- `clean_name`: Cleaned and formatted field name (camelCase)
- `field_type`: Type of field (name, value, size, position, display, display_name, element, field)
- `description`: Human-readable description of the field
- `category`: Functional category of the field

## DataWriter Integration

The `datawriter.py` file has been updated to:

1. **Load JSON Headers**: Automatically loads both RRC and NAS headers JSON files
2. **Field Mapping**: Provides methods to map field names to their metadata
3. **Enhanced Field Processing**: Uses structured field information for better PDML output
4. **Protocol Support**: Supports both LTE RRC and 5G NR RRC fields
5. **NAS Support**: Enhanced NAS field processing with proper categorization

### Key Methods Added

- `_load_rrc_headers()`: Loads RRC headers JSON file
- `_load_nas_headers()`: Loads NAS headers JSON file
- `_get_rrc_field_mapping()`: Gets field mapping for RRC protocols
- `_get_nas_field_mapping()`: Gets field mapping for NAS protocols
- `_clean_field_name_for_mapping()`: Cleans field names for mapping lookup

## Usage

### Processing Headers

```bash
# Process RRC headers
python3 process_rrc_headers.py

# Process NAS headers
python3 process_nas_headers.py
```

### Testing

```bash
# Test the JSON files and field mapping
python3 test_headers_simple.py
```

### DataWriter Usage

```python
from datawriter import DataWriter

# Create DataWriter instance (automatically loads headers)
datawriter = DataWriter()

# Get field mappings
lte_mapping = datawriter._get_rrc_field_mapping('lte_rrc')
nas_mapping = datawriter._get_nas_field_mapping('nas_eps')

# Process packets with enhanced field information
pdml_data = datawriter.process_qmdl_to_pdml(packet_processor_func)
```

## Benefits

1. **Structured Data**: Headers are now organized by functional categories
2. **Better Documentation**: Each field has a human-readable description
3. **Enhanced Processing**: DataWriter can provide more meaningful field information
4. **Extensibility**: Easy to add new protocols or field categories
5. **Consistency**: Standardized field naming and categorization across protocols

## Field Categories

### RRC Categories

- **Connection Management**: RRC connection establishment, reconfiguration, and release
- **System Information**: System information blocks and broadcast messages
- **Measurement**: Measurement configuration and reporting
- **Radio Resource Config**: Radio resource configuration parameters
- **Security**: Security mode and encryption parameters
- **Mobility**: Handover and mobility management
- **Paging**: Paging and notification messages
- **Capability**: UE capability information

### NAS Categories

- **EMM**: EPS Mobility Management - attach, detach, tracking area updates
- **ESM**: EPS Session Management - bearer management, PDN connectivity
- **Security**: Security mode and encryption parameters
- **Authentication**: Authentication and key management
- **Identity**: UE identity and identification parameters

## Notes

- The CSV files contain tab-separated headers in a single row
- Field names are cleaned and converted to camelCase for better readability
- The system supports both LTE and 5G NR RRC protocols
- NAS processing includes EPS, GSM MAP, and E212 protocols
- All field mappings are cached for performance
- The system gracefully handles missing JSON files with fallback to basic processing
