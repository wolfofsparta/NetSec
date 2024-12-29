#!/usr/bin/env python

__author__ = 'The Wolf of Sparta (@WolfofSparta)'
__date__ = '2024-12-18'
__version__ = '0.4'
__description__ = """Parses the XML output from a large nmap scan. The user
                  can specify whether the data should be printed,
                  displayed as a list of IP addresses, or output to
                  a csv file. Will append to a csv if the filename
                  already exists.
                  """

import xml.etree.ElementTree as etree
import os
import csv
import argparse
from collections import Counter
from time import sleep

import xml.etree.ElementTree as etree

def get_host_data(filename):
    """Traverses the XML file and builds lists of scan information."""
    host_data = []

    # Use iterparse with the file path
    for _, elem in etree.iterparse(filename, events=("start", "end")):
        # Check if the element is a <host> and it's "up"
        if elem.tag == 'host':
            # Ensure 'status' exists and is 'up'
            status_elem = elem.find('status')
            if status_elem is None or status_elem.attrib.get('state') != 'up':
                continue

            addr_info = []
            
            # Ensure 'address' exists and extract 'addr' attribute
            address_elem = elem.find('address')
            if address_elem is None:
                ip_address = ''
            else:
                ip_address = address_elem.attrib.get('addr', '')

            # Ensure 'hostnames/hostname' exists before accessing it
            host_name_elem = elem.find('hostnames/hostname')
            if host_name_elem is None:
                host_name = ''
            else:
                host_name = host_name_elem.attrib.get('name', '')

            addr_info.extend((ip_address, host_name))

            # Extract OS information if available
            os_name = ''
            os_elem = elem.find('os')
            if os_elem is not None:
                osmatch_elem = os_elem.find('osmatch')
                if osmatch_elem is not None:
                    os_name = osmatch_elem.attrib.get('name', '')

            # Insert the OS information between hostname and protocol
            addr_info.append(os_name)

            # Now, process ports and services under the 'ports' element
            port_info = []
            ports_elem = elem.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    port_data = []

                    # Extract port information: protocol, portid, state
                    protocol = port_elem.attrib.get('protocol', '')
                    port_id = port_elem.attrib.get('portid', '')
                    state_elem = port_elem.find('state')
                    if state_elem is not None:
                        port_state = state_elem.attrib.get('state', '')
                    else:
                        port_state = ''

                    # Extract service information
                    service_elem = port_elem.find('service')
                    if service_elem is not None:
                        service = service_elem.attrib.get('name', '')
                        product = service_elem.attrib.get('product', '')
                    else:
                        service = ''
                        product = ''

                    # Collect port-related data, include IP, Hostname, OS, Protocol, Port, Service, Product, Port State
                    port_data.extend((ip_address, host_name, os_name, protocol, port_id, service, product, port_state))
                    port_info.append(port_data)

            # Append port information if exists
            if port_info:
                host_data.extend(port_info)
            else:
                host_data.append(addr_info)

        # Clear the element after processing to save memory
        elem.clear()

    return host_data

def parse_xml(filename):
    """Reads and parses the XML file, returning the host data."""
    try:
        # No need to parse the tree with etree.parse(), just use iterparse
        data = get_host_data(filename)
        return data
    except Exception as error:
        print("[-] Error occurred while parsing the XML: {}".format(error))
        exit()
# Main function and other parts of the code remain unchanged


# Main function and other parts of the code remain unchanged

    
    # root = tree.getroot()
    # return get_host_data(root)

def list_ip_addresses(data):
    """Parses the input data to return only the IP address information."""
    ip_list = [item[0] for item in data]
    sorted_set = sorted(set(ip_list))
    return sorted_set

def parse_to_csv(data):
    """Write the parsed data to a CSV file."""
    if not os.path.isfile(csv_name):
        with open(csv_name, 'w', newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            top_row = ['IP Address', 'Hostname', 'OS', 'Protocol', 'Port', 'Service', 'Product', 'Port State']
            csv_writer.writerow(top_row)
            print(f"[+] New file {csv_name} created!")
    else:
        with open(csv_name, 'a', newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            print(f"[+] Appending to {csv_name}")
    
    # Write the data to the CSV file
    with open(csv_name, 'a', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        for item in data:
            csv_writer.writerow(item)

def print_data(data):
    """Print the data to the terminal."""
    for item in data:
        print(' '.join(item))

def main():
    """Main function of the script."""
    for filename in args.filename:
        # Check if file exists
        if not os.path.exists(filename):
            parser.print_help()
            print(f"[-] The file {filename} cannot be found.")
            continue

        data = parse_xml(filename)
        if not data:
            print("[-] No hosts found in the file.")
            continue

        if args.csv:
            parse_to_csv(data)
        if args.ip_addresses:
            addrs = list_ip_addresses(data)
            for addr in addrs:
                print(addr)
        if args.print_all:
            print_data(data)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", help="Display error information", action="store_true")
    parser.add_argument("-p", "--print_all", help="Display scan information to the screen", action="store_true")
    parser.add_argument("-ip", "--ip_addresses", help="Display a list of IP addresses", action="store_true")
    parser.add_argument("-csv", "--csv", nargs='?', const='scan.csv', help="Specify the name of a CSV file to write to")
    parser.add_argument("-f", "--filename", nargs='*', help="Specify the file containing the output of an nmap scan in XML format.")
    args = parser.parse_args()

    if not args.filename:
        parser.print_help()
        print("\n[-] Please specify an input file to parse. Use -f <nmap_scan.xml>")
        exit()
    
    if not args.ip_addresses and not args.csv and not args.print_all:
        parser.print_help()
        print("\n[-] Please choose an output option: Use -csv, -ip, or -p")
        exit()

    csv_name = args.csv
    main()
