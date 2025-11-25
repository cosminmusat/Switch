1 2 3
Mușat-Mare Cristian-Cosmin
332CD

I started the implementation by reading the switch configuration.
In order to store the vlan value for each interface of the switch I used a VLAN
dictionary where the key is the name of the interface(e.g. r-0), of type string,
and the value is either an int for access vlans or the string "T" for trunk vlans.

I used a CAM dictionary where the key is a MAC address(in the following format: 
"ff:ff:ff:ff:ff:ff", type string) and the value is the interface number of type int.
I also used an LB dictionary where the key is the name of the interface(e.g. r-0),
of type string, and the value is either True/False for listening and
blocking respectively.

Next I initialised the switch according to the pseudocode provided, and then I started
the thread that is going to send BPDU packets every 1 second.
The thread function takes 3 parameters: the VLAN dictionary, switch priority and
an event that when set will tell the thread to stop sending BPDUs(specifically when
the switch is no longer the root bridge).
BPDUs will be sent to all corresponding interfaces before the switch idles for 1 second.

BPDU packets are of the following format:
- destination address MAC(6 bytes)
- source address MAC(6 bytes)
- LLC_LENGTH (2 bytes) will always have the value of 38
- LLC_HEADER (3 bytes) will always be 0x424203
- BPDU_HEADER (4 bytes) will always be 0x00000000: 2 bytes for protocol id, 1 byte for
protocol version id, 1 byte for bpdu type
- BPDU_CONFIG (31 bytes): flags set to 0, root bridge ID (8 bytes), root path cost(4 bytes) and sender bridge ID (8 bytes)
All other fields Port ID, Message Age, etc were set to 0 as their are not of interest.

Next up, the switch receives packets and treats them accordingly.
If the packet is a BPDU then run STP
Else the switch first looks if the packet was received on a blocking port. If so
it drops it. Otherwise the switch learns the new source and looks at the destination
MAC to decide what to do next.
If the switch has previously received a packet from the current destination, then
it knows exactly where to send it, otherwise it floods it to all ports except for
the one that the packet was received on.
For trunk links the 802.1Q tag will be applied.

If the switch hasn't previously received a packet from the current destination
then the packet will pe flooded onto all ports except the one it was received on.
For trunk links the 802.1Q tag will be applied. 

The switch also checks the state of the port before it sends it, and will only send
if the port is listening.
