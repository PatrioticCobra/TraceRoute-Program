import socket
import ctypes
from scapy.all import sr1
import argparse
import os
import sys
from scapy.layers.inet import UDP, IP


def traceroute(destination, max_hops=20, timeout=2):
    port = 33434 #standard port used for traceroute
    ttl = 1

    while ttl <= max_hops:
        # Creates the packet with the current TTL
        packet = IP(dst=destination, ttl=ttl) / UDP(dport=port)
        # Sends the packet and waits for a reply
        reply = sr1(packet, timeout=timeout, verbose=0)

        if reply is None:
            #Did not get a reply
            print(f"{ttl}\t *") # The "*" means that there was no reply
        elif reply.type == 3:  # ICMP type 3 indicates destination reached
            # Destination has been reached.
            print(f"{ttl}\t{reply.src}\n")
            print(f"Total hops: {ttl}")
            break
        else:
            #prints IP address
            print(f"{ttl}\t{reply.src}")

        ttl += 1

    if ttl > max_hops:
        print("Number of hops needed to reach destination are greater than the maximum number of hops.")
        print("Could not reach Destination.")



def main():

    # Checks if you are running the program as administrator therefore allowing cross-platform capability.
    admin = False
    is_windows = False
    try:
        # Checks if Unix system available
        admin = os.getuid() == 0
    except AttributeError:
        # If not Unix system, then  system is assumed to be Windows.
        admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        is_windows = True

    if not admin:
        if is_windows:
            print("This piece of code needs you to run it as the Administrator.")
        else:
            print("This piece of code needs you to run it as the root 'Administrator'.")
        sys.exit(1)

    #Creating the CLI(Command line Interface)
    parser = argparse.ArgumentParser(description="Traceroute implementation in Python.")
    parser.add_argument("destination", nargs='?', default="google.com",
                        help="Destination host or IP address. (Default: google.com)")
    parser.add_argument("-m", "--max-hops", type=int, default=20,
                        help="Maximum number of hops (default: 30).")
    parser.add_argument("-t", "--timeout", type=int, default=1,
                        help="Timeout for each packet in seconds (default: 2).")

    args = parser.parse_args()
    destination_ip = socket.gethostbyname(args.destination)

    print(f"Traceroute to {args.destination}[{destination_ip}]:")
    traceroute(args.destination, max_hops=args.max_hops, timeout=args.timeout)


if __name__ == "__main__":
    main()
