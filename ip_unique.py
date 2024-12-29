#!/usr/bin/env python

__author__ = 'The Wolf of Sparta (@WolfofSparta)'
__date__ = '2024-12-29'
__version__ = '0.2'

import csv

def extract_unique_ips(input_csv, output_csv):
    """Extract unique IP addresses from the first column of input CSV 
    and write them into a sorted output CSV."""
    
    ip_addresses = set()  # Using a set to automatically remove duplicates
    
    # Open the input CSV file and read it
    with open(input_csv, 'r') as infile:
        csv_reader = csv.reader(infile)
        
        # Skip header
        next(csv_reader)
        
        # Read through each row and extract IP from the first column
        for row in csv_reader:
            ip = row[0]  # Assuming the IP is in the first column
            ip_addresses.add(ip)
    
    # Sort the IP addresses
    sorted_ips = sorted(ip_addresses)
    
    # Write the sorted IPs into a new output CSV file
    with open(output_csv, 'w', newline='') as outfile:
        csv_writer = csv.writer(outfile)
        
        # Write the header for the new CSV
        csv_writer.writerow(['IP Address'])
        
        # Write the sorted IP addresses to the CSV
        for ip in sorted_ips:
            csv_writer.writerow([ip])
    
    print(f"Unique IPs have been written to {output_csv}.")

def main():
    input_csv = 'report.csv'  # Replace with your input CSV filename
    output_csv = 'inventory.csv'  # Replace with the desired output CSV filename

    # Extract unique IPs from the input CSV and write them to the output CSV
    extract_unique_ips(input_csv, output_csv)

if __name__ == '__main__':
    main()
