#!/usr/bin/env -S python3 -u

import sys
import socket
import select
import json


def ip_to_int(ip_str):
    """
    This function converts an IP address into a 32-bit integer
    
    Args:
        ip_str (str): IP address
    Returns:
        int: 32-bit integer representation of the IP address
    """
    parts = ip_str.split('.')
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])

def int_to_ip(num):
    """
    This function converts a 32-bit integer into an IP address

    Args:
        num (int): 32-bit integer representation of an IP address
    Returns:
        int: IP address
    """
    parts = []
    for i in range(4):
        # Extract each byte from the number
        part = (num >> (8 * (3 - i))) & 0xFF
        parts.append(str(part))
    # Join the 4 parts with dots
    return ".".join(parts)

def get_prefix_length(netmask_str):
    """
    This function calculates the prefix length of a subset mask.

    Args:
        netmask_str (str): Subnet mask in IP address format ("255.255.255.0")
    Returns:
        int: Number of consecutive 1's
    """
    # Convert the netmask to an integer and count the '1' bits in the binary representation
    return bin(ip_to_int(netmask_str)).count("1")

def prefix_length_to_netmask(prefix_length):
    """
    This function converts a prefix length into a netmask string

    Args:
        prefix_length(int): Prefix length (number of 1 bits)
    Returns:
        str: Corresponding subnet mask
    """
    mask = (0xFFFFFFFF << (32 - prefix_length)) & 0xFFFFFFFF
    return int_to_ip(mask)

# This is the rotuing table entry class
class RouteEntry:
    """
    This class represents an entry in the router's forwarding table.
    
    Attributes:
        network_str (str): The network prefix in dotted-quad notation.
        netmask_str (str): The associated subnet mask in dotted-quad notation.
        network (int): The integer representation of the network prefix.
        netmask (int): The integer representation of the subnet mask.
        prefix_length (int): Number of bits set in the netmask.
        localpref (int): Local preference weight.
        selfOrigin (bool): True if the route is locally originated.
        ASPath (list): List of AS numbers that the route traverses.
        origin (str): Origin type ("IGP", "EGP", or "UNK").
        peer (str): The IP address of the neighbor that advertised the route.
    """
    def __init__(self, network_str, netmask_str, localpref, selfOrigin, ASPath, origin, peer):
        self.network_str = network_str
        self.netmask_str = netmask_str
        self.network = ip_to_int(network_str)
        self.netmask = ip_to_int(netmask_str)
        self.prefix_length = get_prefix_length(netmask_str)
        self.localpref = int(localpref)
        self.selfOrigin = bool(selfOrigin)
        self.ASPath = ASPath[:]  # Make a copy of the ASPath list
        self.origin = origin
        self.peer = peer  # The neighbor IP that sent the update

    def to_dict(self):
        """
        This converts the route entry into a dictionary for JSOn serialization
        """
        return {
            "network": self.network_str,
            "netmask": self.netmask_str,
            "peer": self.peer,
            "localpref": self.localpref,
            "ASPath": self.ASPath,
            "selfOrigin": self.selfOrigin,
            "origin": self.origin
        }
    
    def __repr__(self):
        """
        This represents the string representation of the route entry
        """
        return (f"RouteEntry({self.network_str}/{self.prefix_length}, peer={self.peer}, "
                f"localpref={self.localpref}, selfOrigin={self.selfOrigin}, ASPath={self.ASPath}, "
                f"origin={self.origin})")

# Global routing table (list of RouteEntry objects)
routing_table = []

def process_update(message, src_neighbor, all_neighbors):
    """
    This function processes an update message received from a neighbor

    Args:
        message (dict): The JSON-decoded update message
        src_neighbor (dict): The neighbor configuration from which the update was received
        all_neighbors (list): The lsit of all neighbor configurations
    """
    global routing_table
    update_msg = message["msg"]
    network_str = update_msg["network"]
    netmask_str = update_msg["netmask"]
    localpref = update_msg["localpref"]
    selfOrigin = update_msg["selfOrigin"]
    ASPath = update_msg["ASPath"]
    origin = update_msg["origin"]
    peer_ip = message["src"]

    # Remove any existing route (from this peer and for the same network)
    routing_table = [route for route in routing_table 
                     if not (route.network_str == network_str and route.netmask_str == netmask_str and route.peer == peer_ip)]
    
    # Create and add new route 
    new_route = RouteEntry(network_str, netmask_str, localpref, selfOrigin, ASPath, origin, peer_ip)
    routing_table.append(new_route)
    print(f"Processed update from {peer_ip} for {network_str}/{get_prefix_length(netmask_str)}")
    
    # Determine their relationship of the sender
    src_relationship = src_neighbor["relationship"]
    for nbr in all_neighbors:
        # Skip sending back to the sender.
        if nbr["neighbor_ip"] == peer_ip:
            continue  
        # If update from a customer, send to all;
        # if from a peer or provider, send only to customers.
        if src_relationship == "cust" or (src_relationship in ("peer", "prov") and nbr["relationship"] == "cust"):
            # Prepend OUR_AS to the ASPath before forwarding.
            fwd_ASPath = [OUR_AS] + ASPath
            # Build the forwarded update message and strip private fields
            fwd_update = {
                "network": network_str,
                "netmask": netmask_str,
                "ASPath": fwd_ASPath
            }
            fwd_message = {
                "src": nbr["local_ip"],      # Our local IP for that neighbor.
                "dst": nbr["neighbor_ip"],
                "type": "update",
                "msg": fwd_update
            }
            msg_str = json.dumps(fwd_message)
            # Send thye message to the neighbor and use the loopback "127.0.0.1"
            nbr["socket"].sendto(msg_str.encode(), ("127.0.0.1", nbr["neighbor_port"]))
            print(f"Forwarded update to {nbr['neighbor_ip']}:{nbr['neighbor_port']}")

def process_withdraw(message, src_neighbor, all_neighbors):
    """
    This function processes a withdraw message from a neighbor:

    Args:
        message (dict): The JSON-decoded withdraw message
        src_neighbor (dict): The neighbor configuration from the withdraw
        all_neighbors (list): The list of all neighbor configurations
    """
    global routing_table
    withdraw_list = message["msg"]  # List of dictionaries, each with "network" and "netmask"
    peer_ip = message["src"]
    # Process each withdrawn route and print process
    for item in withdraw_list:
        network_str = item["network"]
        netmask_str = item["netmask"]
        routing_table = [route for route in routing_table 
                         if not (route.network_str == network_str and route.netmask_str == netmask_str and route.peer == peer_ip)]
        print(f"Processed withdraw from {peer_ip} for {network_str}/{get_prefix_length(netmask_str)}")
    
    # Propagate withdraw message to eligible neighbors.
    src_relationship = src_neighbor["relationship"]
    for nbr in all_neighbors:
        if nbr["neighbor_ip"] == peer_ip:
            continue
        if src_relationship == "cust" or (src_relationship in ("peer", "prov") and nbr["relationship"] == "cust"):
            fwd_message = {
                "src": nbr["local_ip"],
                "dst": nbr["neighbor_ip"],
                "type": "withdraw",
                "msg": withdraw_list
            }
            msg_str = json.dumps(fwd_message)
            nbr["socket"].sendto(msg_str.encode(), ("127.0.0.1", nbr["neighbor_port"]))
            print(f"Forwarded withdraw to {nbr['neighbor_ip']}:{nbr['neighbor_port']}")

def compare_routes(r1, r2):
    """
    This function compares two route entries according to the tie-break rules.
    Returns -1 if r1 is better, 1 if r2 is better, or 0 if equal.

    Tie-break order:
      1. Longer prefix length.
      2. Higher localpref.
      3. selfOrigin True wins.
      4. Shorter ASPath length.
      5. Best origin (IGP > EGP > UNK).
      6. Lower peer IP.

    Args:
        r1, r2 (RouteEntry): The two route entries to compare.
    Returns:
        int: -1 if r1 is better, 1 if r2 is better, 0 if equal.
    """
    if r1.prefix_length != r2.prefix_length:
        return -1 if r1.prefix_length > r2.prefix_length else 1
    if r1.localpref != r2.localpref:
        return -1 if r1.localpref > r2.localpref else 1
    if r1.selfOrigin != r2.selfOrigin:
        return -1 if r1.selfOrigin and not r2.selfOrigin else 1
    if len(r1.ASPath) != len(r2.ASPath):
        return -1 if len(r1.ASPath) < len(r2.ASPath) else 1
    origin_rank = {"IGP": 3, "EGP": 2, "UNK": 1}
    if origin_rank.get(r1.origin, 0) != origin_rank.get(r2.origin, 0):
        return -1 if origin_rank.get(r1.origin, 0) > origin_rank.get(r2.origin, 0) else 1
    if ip_to_int(r1.peer) != ip_to_int(r2.peer):
        return -1 if ip_to_int(r1.peer) < ip_to_int(r2.peer) else 1
    return 0

def find_best_route(dest_ip_int):
    """
    This function finds the best route for a given destination IP (as an integer) using
    longest prefix matching and tie-break rules.
    
    Args:
        dest_ip_int (int): The destination IP address as an integer.
    Returns:
        RouteEntry or None: The best matching route, or None if no route matches.
    """
    # Select only the routes where the destination falls within the route's network
    candidates = [route for route in routing_table if (dest_ip_int & route.netmask) == route.network]
    if not candidates:
        return None
    best = candidates[0]
    for r in candidates[1:]:
        if compare_routes(r, best) < 0:
            best = r
    return best

def process_data(message, src_neighbor, neighbors_by_ip):
    """
    This function processes a data message that needs to be forwarded.
    
    Args:
        message (dict): The JSON-decoded data message.
        src_neighbor (dict): The neighbor from which the data message was received.
        neighbors_by_ip (dict): Dictionary mapping neighbor IPs to neighbor configurations.
    """
    dest_ip = message["dst"]
    dest_ip_int = ip_to_int(dest_ip)
    best_route = find_best_route(dest_ip_int)
    if best_route is None:
        # No route available: send a "no route" message
        no_route_msg = {
            "src": src_neighbor["local_ip"],
            "dst": message["src"],
            "type": "no route",
            "msg": {}
        }
        src_neighbor["socket"].sendto(json.dumps(no_route_msg).encode(), (src_neighbor["neighbor_ip"], src_neighbor["neighbor_port"]))
        print(f"No route for data destined to {dest_ip}. Sent no route message.")
        return

    # Determine relationships for transit validation
    incoming_rel = src_neighbor["relationship"]
    outgoing_neighbor = neighbors_by_ip.get(best_route.peer)
    if outgoing_neighbor is None:
        print(f"Outgoing neighbor {best_route.peer} not found. Dropping data.")
        no_route_msg = {
            "src": src_neighbor["local_ip"],
            "dst": message["src"],
            "type": "no route",
            "msg": {}
        }
        src_neighbor["socket"].sendto(json.dumps(no_route_msg).encode(), (src_neighbor["neighbor_ip"], src_neighbor["neighbor_port"]))
        return
    outgoing_rel = outgoing_neighbor["relationship"]
    
    # Do not forward if both incoming and outgoing relationships are "peer" or "prov"
    if incoming_rel in ("peer", "prov") and outgoing_rel in ("peer", "prov"):
        no_route_msg = {
            "src": src_neighbor["local_ip"],
            "dst": message["src"],
            "type": "no route",
            "msg": {}
        }
        src_neighbor["socket"].sendto(json.dumps(no_route_msg).encode(), (src_neighbor["neighbor_ip"], src_neighbor["neighbor_port"]))
        print(f"Data from {message['src']} dropped due to transit restrictions.")
        return

    # Forward the data message unchanged using the outgoing neighbor's socket.
    outgoing_socket = outgoing_neighbor["socket"]
    msg_str = json.dumps(message)
    outgoing_socket.sendto(msg_str.encode(), ("127.0.0.1", outgoing_neighbor["neighbor_port"]))
    print(f"Forwarded data destined to {dest_ip} via {outgoing_neighbor['neighbor_ip']}")

def merge_routes(route1, route2):
    """
    This function attempts to merge two routes if they are adjacent and share identical attributes.
    
    Args:
        route1, route2 (RouteEntry): The two route entries to potentially merge.
    Returns:
        RouteEntry or None: A new aggregated route if mergeable, otherwise None.
    """
    if route1.prefix_length != route2.prefix_length:
        return None
    if route1.peer != route2.peer:
        return None
    if route1.localpref != route2.localpref:
        return None
    if route1.selfOrigin != route2.selfOrigin:
        return None
    if route1.origin != route2.origin:
        return None
    if route1.ASPath != route2.ASPath:
        return None

    # Calculate block size of the current prefix
    block_size = 1 << (32 - route1.prefix_length)
    # Check if route2 immediately follows route1.
    if route2.network != route1.network + block_size:
        return None
    # Aggregated route has prefix one bit shorter to cover both subnets
    aggregated_prefix_length = route1.prefix_length - 1
    aggregated_netmask = (0xFFFFFFFF << (32 - aggregated_prefix_length)) & 0xFFFFFFFF
    aggregated_network = route1.network & aggregated_netmask
    new_route = RouteEntry(int_to_ip(aggregated_network), prefix_length_to_netmask(aggregated_prefix_length),
                           route1.localpref, route1.selfOrigin, route1.ASPath, route1.origin, route1.peer)
    return new_route

def aggregate_routes(routes):
    """
    This function performs route aggregation on the routing table.
    
    Args:
        routes (list): List of RouteEntry objects.
    Returns:
        list: List of dictionaries representing aggregated routes.
    """
    changed = True
    routes_list = routes[:]  # Work on a copy.
    while changed:
        changed = False
        # Sort routes by a tuple of attributes and numeric values to ensure adjacent routes are nearby.
        routes_list.sort(key=lambda r: (r.peer, r.localpref, r.selfOrigin, r.origin, tuple(r.ASPath), r.prefix_length, r.network))
        new_list = []
        i = 0
        while i < len(routes_list):
            # Try merging the current route with the next route.
            if i < len(routes_list) - 1:
                merged = merge_routes(routes_list[i], routes_list[i+1])
                if merged:
                    new_list.append(merged)
                    i += 2
                    changed = True
                    continue
            new_list.append(routes_list[i])
            i += 1
        routes_list = new_list
    # Convert each aggregated route into a dictionary for JSON output.
    aggregated = [r.to_dict() for r in routes_list]
    return aggregated

def process_dump(message, src_socket, src_neighbor):
    """
    This function processes a "dump" message, which requests the current routing table.
    
    Args:
        message (dict): The incoming dump message.
        src_socket (socket.socket): The socket on which the dump message was received.
        src_neighbor (dict): The neighbor configuration for the sender.
    """
    aggregated = aggregate_routes(routing_table)
    table_msg = {
        "src": src_neighbor["local_ip"],
        "dst": message["src"],
        "type": "table",
        "msg": aggregated
    }
    msg_str = json.dumps(table_msg)
    src_socket.sendto(msg_str.encode(), ("127.0.0.1", src_neighbor["neighbor_port"]))
    print(f"Sent routing table dump to {src_neighbor['neighbor_ip']}")
    
def main():
    """
    This function is the main function for the router.
    
    Command-line arguments:
      - First argument: our router's AS number.
      - Remaining arguments: neighbor configurations in the format "port-IP-relationship"
        (e.g., "7833-1.2.3.2-cust").
    """
    if len(sys.argv) < 3:
        print("Usage: ./4700router <asn> <port-ip.add.re.ss-[peer,prov,cust]> ...")
        sys.exit(1)
    
    # Set our AS number as a global variable
    global OUR_AS
    OUR_AS = int(sys.argv[1])

    asn = int(sys.argv[1])
    neighbor_args = sys.argv[2:]
    neighbors = []         # List of neighbor configurations
    neighbors_by_ip = {}   # Dictionary for quick lookup of neighbors by their IP
    sockets = []           # List of all UDP sockets

    # Create a UDP socket for each neighbor
    for arg in neighbor_args:
        parts = arg.split('-')
        if len(parts) != 3:
            continue
        neighbor_port = int(parts[0])
        neighbor_ip = parts[1]
        relationship = parts[2]
        # For our router's IP on this port, use the same IP as the neighbor but with the last octet set to "1"
        ip_parts = neighbor_ip.split('.')
        local_ip = '.'.join(ip_parts[:-1] + ['1'])
        # Create a new UDP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('127.0.0.1', 0)) # Bind to localhost on an OS-selected port
        neighbor = {
            "socket": s,
            "neighbor_port": neighbor_port,
            "neighbor_ip": neighbor_ip,
            "local_ip": local_ip,
            "relationship": relationship
        }
        neighbors.append(neighbor)
        neighbors_by_ip[neighbor_ip] = neighbor
        sockets.append(s)
        # Send initial handshake message.
        handshake_msg = {
            "src": local_ip,
            "dst": neighbor_ip,
            "type": "handshake",
            "msg": {}
        }
        # Use "127.0.0.1" as the destination address for the simulated environment
        s.sendto(json.dumps(handshake_msg).encode(), ("127.0.0.1", neighbor_port))
        print(f"Sent handshake to {neighbor_ip}:{neighbor_port} from {local_ip}")

    # Loop and wait for messages on any of the sockets
    while True:
        # Use select() to wait until at least one socket is readable
        readable, _, _ = select.select(sockets, [], [])
        for sock in readable:
            try:
                data, addr = sock.recvfrom(4096)
                message = json.loads(data.decode())
                # Determine which neighbor this socket corresponds to
                src_neighbor = None
                for nbr in neighbors:
                    if nbr["socket"] == sock:
                        src_neighbor = nbr
                        break
                if src_neighbor is None:
                    continue

                msg_type = message.get("type")

                # Dispatch based on message type
                if msg_type == "handshake":
                    print(f"Received handshake from {message.get('src')}")
                elif msg_type == "update":
                    process_update(message, src_neighbor, neighbors)
                elif msg_type == "withdraw":
                    process_withdraw(message, src_neighbor, neighbors)
                elif msg_type == "data":
                    process_data(message, src_neighbor, neighbors_by_ip)
                elif msg_type == "dump":
                    process_dump(message, sock, src_neighbor)
                elif msg_type in ("table", "no route"):
                    # Print the received table or no route messages
                    print(f"Received {msg_type} message: {message}")
                else:
                    print(f"Unknown message type: {msg_type}")
            except Exception as e:
                print(f"Error processing message: {e}")

if __name__ == "__main__":
    main()
