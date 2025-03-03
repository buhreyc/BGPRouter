# Project 3 - BGP Router
**Brey-Michael Ching**  
Coded in Python

**Description:**  
This project implements a simulated BGP router that manages multiple UDP sockets to communicate with neighboring routers. The router processes JSON-formatted messages (handshake, update, withdraw, data, dump), maintains a forwarding table, applies BGP path selection and propagation rules, and aggregates routes for efficient table compression.

## High-Level Approach
The router follows these steps:
1. **Initialization**:  
   - Parse command-line arguments to set the router's AS number and neighbor configurations.
2. **Socket Setup**:  
   - Open a UDP socket for each neighbor (using the loopback interface) and bind to an OS-selected port.
3. **Handshake Phase**:  
   - Send initial handshake messages to each configured neighbor.
4. **Message Processing**:  
   - Listen for incoming JSON messages on all sockets using `select()`.
   - Handle messages as follows:
     - **Update**: Process route announcements, update the forwarding table, and forward the update (prepending our AS number to the ASPath) to eligible neighbors based on relationship (customer, peer, provider).
     - **Withdraw**: Remove withdrawn routes from the forwarding table and propagate the withdraw.
     - **Data**: Forward data packets using longest prefix matching and detailed tie-break rules; drop packets or send a "no route" message if no valid route is found or transit rules are violated.
     - **Dump**: Respond with the current (aggregated) routing table.
5. **Route Aggregation**:  
   - Merge adjacent routes that share identical attributes to compress the routing table.
6. **Forwarding Logic**:  
   - Enforce BGP transit policies and tie-break rules (longest prefix, local preference, selfOrigin, ASPath length, origin, and peer IP).

## Challenges Faced
### 1. Managing Multiple Sockets
- Coordinating multiple UDP sockets using `select()` and ensuring that each message is correctly dispatched to its handler was initially challenging and showed some difficulty the first few times. With some smaller debugging on the socket communication, I was able to solve this issue.

### 2. Implementing BGP Policies and Tie-Breaking
- Implementing the detailed tie-breaking rules (longest prefix, localpref, selfOrigin, ASPath length, origin, and peer IP) was complex and needed extensive testing which took up a lot of my time in my opinion. I think that also enforcing rules based on a given neighbor relationship was a challenge that I didn't expect to run into as well.

### 3. Route Aggregation
- I also think that aggregating routes dynamically as updates and withdrawals occur was definitely a little harder than expected. I also think that handling edge cases for this proved to be difficult and required a lot of testing to get right.

## Commands & Usage
The router is invoked using the following syntax:

### Example Commands

```sh
./4700router <asn> <port-IP-address-[peer,prov,cust]> [<port-IP-address-[peer,prov,cust]> ...]

This command configures the router as part of the AS 14 with two neighbor connections
./4700router 14 57950-192.168.0.2-cust 39896-172.168.0.2-cust

```

## Error Handling & Edge Cases
- **Malformed Messages** (Validation of JSON messages)
- **No Matching Route** (If no route matches a destination, respond with a no route message)
- **Dynamic Updates** (Handle updates and withdrawals without crashing)

## Running the Program
```sh
./4700router <asn> <port-IP-address-[peer,prov,cust]> ...
```

## Testing Overview
To ensure that the BGP Router works, I tested it on the login.ccs.neu.edu Linux server with the run, test, and config/ files provided on the assignment page. Typical test suite commands would look as follows:
```sh
./run configs/3-2-bad-route.conf
./run configs/6-3-disaggregate.conf 
./test
```