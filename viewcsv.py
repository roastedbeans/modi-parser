# view_csv.py
import csv
import sys

def show(csv_path):
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            packet_no = row.get('packet_number', '?')
            # Keep only fields with a real value
            kv = [(k, v) for k, v in row.items()
                  if k != 'packet_number' and v not in ('-1', '', None)]
            if not kv:
                continue
            print(f"\nPacket #{packet_no}")
            for k, v in sorted(kv, key=lambda x: x[0]):
                print(f"  {k}: {v}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python view_csv.py <path_to_csv>")
        sys.exit(1)
    show(sys.argv[1])