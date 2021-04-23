/* -*- P4_16 -*- */

/* this is a very basic program to forward an IPv4 packet based on destination IP address*/

/*            P4 reserved keywords

action 	    apply 	    bit 	        bool
const 	    control 	default 	    else
enum 	    error 	    extern 	        exit
false 	    header 	    header_union 	if
in 	        inout 	    int 	        match_kind
package 	parser 	    out 	        return
select 	    state 	    string 	        struct
switch 	    table 	    transition 	    true
tuple 	    typedef 	varbit 	        verify
void 	

*/


/**          numeric literals

    w indicates unsigned numbers
    s indicates signed numbers 


    32w255         // a 32-bit unsigned number with value 255
    32w0d255       // same value as above
    32w0xFF        // same value as above
    32s0xFF        // a 32-bit signed number with value 255
    8w0b10101010   // an 8-bit unsigned number with value 0xAA
    8w0b_1010_1010 // same value as above
    8w170          // same value as above
    8s0b1010_1010  // an 8-bit signed number with value -86
    16w0377        // 16-bit unsigned number with value 377 (not 255!)
    16w0o377       // 16-bit unsigned number with value 255 (base 8)

*/

/**                      naming convention 


    Built-in types are written with lowercase characters—e.g., int<20>,
    User-defined types are capitalized—e.g., IPv4Address,
    Type variables are always uppercase—e.g., parser P<H, IH>(),
    Variables are uncapitalized— e.g., ipv4header,
    Constants are written with uppercase characters—e.g., CPU_PORT, and
    Errors and enumerations are written in camel-case— e.g. PacketTooShort. 

*/

// the core.p4 library should be included in all P4 programs
// details of the p4 core library can be found here: https://p4.org/p4-spec/docs/P4-16-v1.2.1.html#sec-p4-core-lib
#include <core.p4>

//v1model library is to define the switch architecture as "simple_switch". 
// You can find details here: https://github.com/p4lang/behavioral-model/blob/main/docs/simple_switch.md
// actual code for the v1model switch can be found here: https://github.com/p4lang/p4c/blob/master/p4include/v1model.p4

#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;  // This defines a re-usable constant for the specific Ethernet Type of 0x0800 which means IPv4, the first "0" can be omitted

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


/*                  Typical Header Sizes
|--------------|--------------------|--------------------|----------------------|----|
|EthernetHeader|      IP Header     |       TCP Header   |   Application Data   |EthT|  T = Trail
|--------------|--------------------|--------------------|----------------------|----|
|<- 14 octets->|<-    20 octets   ->|<-    20 octets   ->|                      |  4 |
|--------------|--------------------|--------------------|----------------------|----|
|<---------------------------------- Ethernet Frame -------------------------------->|
|              |<----------------- 46 to 1600 bytes --------------------------->|
*/

typedef bit<9> egressSpec_t; // defines a egress type, _t means "type", we'll use this to define egress port in the 'control' logic
typedef bit<48> macAdd_t; // defines a mac address type, _t means "type", MAC are 48 bits
typedef bit<32> ipv4Add_t; // defines an IPv4 address type, _t means "type", IPv4 address are 32 bits

// declare a typical Ethernet Header

/* a ethernet header contains the following at layer 2 as a 'frame'
Note: octet = byte, octet is unambiguous
mac destination: 6 octets ( 48 bits )
mac source: 6 octets ( 48 bits )
802.1ad tag: 4 octects ( 32 bits ), optional (inserted in FRONT of the 802.1Q tag, TPID 0x88A8). Also called QinQ
802.1Q tag: 4 octets ( 32 bits ), optional, (inserted in FRONT of the ethertype header, TPID 0x8100)
ethernet type: 2 octets ( 16 bits ),  
    Values of 1500 and below mean that it is used to indicate the size of the payload in octets
    values of 1536 and above indicate that it is used as an EtherType, to indicate which protocol is encapsulated in the payload of the frame
    EtherType examples: ipv4 = 0x0800, ARP = 0x0806...etc.
*/

header ethernet_h {
    macAdd_t dst_mac;  // define the dst mac field in the header
    macAdd_t src_mac;  // define the src mac field in the header
    bit<16> etherType; // define the EtherType field in the header
}

// declare a typical ipv4 header

/* Typical IPv4 Header

0                              15 16                           31
|----------------------------------------------------------------  ---
| 4 bit | 4 bit  |    8-bit       |        16-bit               |   |
|version|  IHL   |  Diff Serv     |      total length           |   |
|---------------------------------------------------------------|   |
|            16-bit               | 3-bit|     13-bit           |   |
|        Identification           | flags|  fragment offset     |
|---------------------------------------------------------------|   20
|      8-bit     |     8-bit      |        16-bit               |  bytes
|      TTL       |     protocol   |    header checksum          |    
|---------------------------------------------------------------|   |
|                         32-bit source IP                      |   |
|---------------------------------------------------------------|   |
|                      32-bit destination IP                    |   |
|---------------------------------------------------------------|  ---   
|                           options                             |
|---------------------------------------------------------------|
|                             Data                              |
|---------------------------------------------------------------|

*/

header ipv4_h {
    bit<4>    version;
    bit<4>    ihl; // internet header length
    bit<8>    diff_serv; // differentiated service. DSCP (6-bit), ECN (2-bit, optional). Old = TOS
    bit<16>   total_length;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   frag_offset;   // fragment offset
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdr_checksum;  // header checksum
    ipv4Add_t src_ip;  // recall that we used "typedef" to declare "ipv4Add_t" at the beginning. 32-bit
    ipv4Add_t dst_ip;  // recall that we used "typedef" to declare "ipv4Add_t" at the beginning. 32-bit
}

// #TODO, not sure what this is
struct metadata {
    // empty
}

struct parsedHeaders{
    ethernet_h    ethernet;  // we are declaring 'ethernet' variable using the "ethernet_h" header structure
    ipv4_h        ipv4;   // we are declaring 'ipv4' variable using the "ipv4_h" header structure
}


/*************************************************************************
*************************  E R R O R   ***********************************
*************************************************************************/

// User-defined errors that may be signaled during parsing
// 'error' is part of the p4 core library. The following are user defined errors
error {
    IPv4OptionsNotSupported,
    IPv4IncorrectVersion,
    IPv4ChecksumError
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

// declare a parser

/*

At least one state, named start, must be present in any parser. 
A parser may not define two states with the same name. 
It is also illegal for a parser to give explicit definitions for the accept and reject states—those states are logically distinct from the states defined by the programmer. 
It is illegal to instantiate a control block within a parser. 

*/

parser ParseIPV4(packet_in packet,      // packet_in is a pre-defined P4 extern object that represents an incoming packet, declared in the core.p4 library
                 out parsedHeaders hdr,    // The parser writes its output (the 'out' keyword) into the 'hdr' argument. The type of this argument is 'parsedHeaders', defined previously
                 inout metadata meta,      // we are not using metadata here
                 inout standard_metadata_t standard_etadata   // we are not using metadata here
                 ) {
    // start state
    state start{
        // 'transition' means that we want to go to a specific state, key terms are 'accept/reject', accept = terminate and transition to accept, reject = deny (reject is default)
        // transition to 'parse_ethernet' state
        transition parse_ethernet;
        // by default we'll reject all other headers
    }
    
    // we are goig to parse the ethernet header first to extract the "ipv4" header
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){ 
            TYPE_IPV4: parse_ipv4;
            // no default rule, all other packets are rejected
        }  
    }
    
    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition accept;  // terminate the state. We have to specify "accept", defualt is "reject"
    }
    
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout parsedHeaders hdr, inout metadata meta) {   
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
//match-action pipeline control

// The direction 'inout' indicates that this parameter is both an input and an output. 
// 'standard_metadata_t' is a pre-defined structure in the v1model
// simple switch (v1model.py) details can be found here: https://github.com/p4lang/behavioral-model/blob/main/docs/simple_switch.md#standard-metadata

control MyIngress( inout parsedHeaders hdr, 
                       inout metadata meta, 
                       inout standard_metadata_t standard_metadata) {
    
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward (macAdd_t dst_mac, egressSpec_t egressPort) {        
        standard_metadata.egress_spec = egressPort; // set the egress port for the next hop
        hdr.ethernet.dst_mac = dst_mac;           // Updates the ethernet destination address with the address of the next hop
        
        // updates the ethernet source address with the address of the switch
        // 'hdr.ethernet.dst_mac' is always the MAC of the switch that received the packet
        // 'hdr.ethernet.src_mac' is always the MAC of the switch that will send the back
        hdr.ethernet.src_mac = hdr.ethernet.dst_mac;  
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;    // decrement TTL
    }
    ipv4Add_t NextHop;
    // THIS IS NOT IMPLEMENTED, MEANING NOT INCLUDED IN ANY TABLE, YET
    action SetNextHop (ipv4Add_t dstIPAdd, egressSpec_t egressPort) {
        NextHop = dstIPAdd;                         // set the NextHop IP address
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;    //decrement TTL
        standard_metadata.egress_spec = egressPort;     // set the egress port
    }

    /**
      * A table describes a match-action unit, in the following steps:

      * Key construction.
      * Key lookup in a lookup table (the “match” step). The result of key lookup is an “action”.
      * Action execution (the “action step”) over the input data, resulting in mutations of the data. 

      * The 'key' is a table property which specifies the data plane values that should be used to look up an entry. 
      * A 'key' is a list of pairs of the form (e : m), where e is an expression that describes the data to be matched in the table, 
      * and m is a 'match_kind' constant that describes the algorithm used to perform the lookup
      * There are 3 'match_kind' defined in the "core.p4" file:
           exact    // match bits exactly
           ternary  // Ternary match using a mask
           lpm      // Longest Prefix Match
      * The match_kind constants serve three purposes:

            They specify the algorithm used to match data plane values against the entries in the table at runtime.
            They are used to synthesize the control-plane API that is used to populate the table.
            They are used by the compiler back-end to allocate resources for the implementation of the table. 

      * Architectures may support additional 'match_kinds'. 
      * The declaration of new 'match_kinds' can only occur within model description files; 
      * P4 programmers cannot declare new match kinds. 

      * If a table has no key property, then it contains no look-up table, just a default action—i.e., the associated lookup table is always the empty map. 
    */

    
    /**
     * Computes address of next IPv4 hop and output port based on the IPv4 destination of the current packet.
     * nextHop IPv4 address of next hop
     */


    /**
      * IMPORTANT: 'ipv4_lpm' table name is what the control plane looks for !!!
    */
    table ipv4_lpm {
        key = { hdr.ipv4.dst_ip: lpm; } // LPM
        actions = {
            ipv4_forward;
            drop;
        }
        size = 1024;                // 'size': an integer specifying the desired size of the table. 
        default_action = drop;  // 'default_action': an action to execute when the lookup in the lookup table fails to find a match for the key used. 
    }

    /**

    The method isValid() returns the value of the “validity” bit of the header.
    The method setValid() sets the header's validity bit to “true”. It can only be applied to an l-value.
    The method setInvalid() sets the header's validity bit to “false”. It can only be applied to an l-value. 

    */
    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();     // if LPM match, apply the actions defined in "ipv4_match"
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout parsedHeaders hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout parsedHeaders hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diff_serv,
              hdr.ipv4.total_length,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.frag_offset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.src_ip,
              hdr.ipv4.dst_ip },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

// 'packet_out' is predefined in the core library as an extern object, it is used 

control DeparseIPV4(packet_out packet, in parsedHeaders hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
ParseIPV4(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
DeparseIPV4()
) main;


/*************************************************************************
***********************  Challenges  *******************************
*************************************************************************/

/**
Other questions to consider:

    How would you enhance your program to respond to ARP requests?
    How would you enhance your program to support traceroute?
    How would you enhance your program to support next hops?
    Is this program enough to replace a router? What's missing?
*/