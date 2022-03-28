#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#define MAX_LEN 11

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;
typedef bit<32> chunk_size_1;
typedef bit<8> chunk_size_2;
typedef bit<40> chunk_size_3;
typedef bit<16> token_size;

const bit<16> ETHERTYPE_IPV4 = 0x800;
const bit<8> IP_PROTOCOLS_TCP = 6;
const bit<8> IP_PROTOCOLS_UDP = 17;




/*************************************************************************
*********************** D E F I N E  ***********************************
*************************************************************************/
#define MAX_LEN 11 
#define TRUE 1
#define FALSE 0 
#define SHIM_TCP 77 //NETRE reserved IPv4 Protocol ID
#define SHIM_UDP 78 //NETRE reserved IPv4 Protocol ID
#define IPV4_PROTOCOL_TCP 6
#define IPV4_PROTOCOL_UDP 17
#define FLOW_REGISTER_SIZE 65536
#define FLOW_HASH_BASE_0 16w0
#define FLOW_HASH_MAX_0 16w16383
#define FLOW_HASH_BASE_1 16w16384
#define FLOW_HASH_MAX_1 16w32767
#define FLOW_HASH_BASE_2 16w32768
#define FLOW_HASH_MAX_2 16w49151
#define FLOW_HASH_BASE_3 16w49152
#define FLOW_HASH_MAX_3 16w65535
#define THRESHOLD 64
#define CONTROLLER_PORT 10
#define ENTRY_SIZE 65536


#define FLOW_HASH_MAX 16w3
#define MAX_WINDOW 64
#define ACTIVE_THRESHOLD 10
#define LONG_THRESHOLD 128


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    bit<48>   dstAddr;
    bit<48>   srcAddr;
    bit<16>   etherType;
}


header ipv4_t {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  totalLen;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  fragOffset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdrChecksum;
    bit<32>  srcAddr;
    bit<32>  dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<4> res;
    bit<8> flags;
    bit<16> windows;
    bit<16> checksum;
    bit<16> urgenPtr;
}


struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}

struct metadata {
    bit<1> isOn;
    bit<1> isLong;
    // bit<16>  active_flow;
}

header chunk_t {
    chunk_size_1 chunk_1; //32
    chunk_size_2 chunk_2;
    chunk_size_1 chunk_3;
    chunk_size_2 chunk_4; //8
}

header token_t {
    token_size token_index; //16
}

struct custom_metadata_t {
    token_size idx;
    chunk_size_1 tmp_size_1;
    chunk_size_2 tmp_size_2;
    chunk_size_1 value_sub_1;
    chunk_size_2 value_sub_2;
    chunk_size_1 val;
    chunk_size_1 val2;
    chunk_size_3 val3;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
		        inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            IP_PROTOCOLS_TCP : parse_tcp;
            default : accept;
        }
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta
) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
		          inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    Register<bit<32>, bit<32>>(32w65536) couting_bloom_filter0;
    RegisterAction<bit<32>, bit<32>, bit<32>>(couting_bloom_filter0) counting_bloom_filter0_read = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
            }
        };

    register<bit<32>>(FLOW_REGISTER_SIZE) couting_bloom_filter;
    register<bit<32>>(10) num_active_flow;
    register<bit<32>>(1) pointer_reg;

    register<bit<32>>(MAX_WINDOW) window_reg_hash0;
    register<bit<32>>(MAX_WINDOW) window_reg_hash1;
    register<bit<32>>(MAX_WINDOW) window_reg_hash2;

    bit<32> bf0; 
    bit<32> bf1; 
    bit<32> bf2;
    bit<32> bf0_idx; 
    bit<32> bf1_idx; 
    bit<32> bf2_idx;
    bit<32> window_h0_idx;
    bit<32> window_h1_idx;
    bit<32> window_h2_idx;
    bit<32> active_flow;


    register<bit<10>>(FLOW_REGISTER_SIZE) hot_flow_counter;

    bit<16> l4_srcPort;
    bit<16> l4_dstPort;

    action select_queue(bit<3> qid){
        standard_metadata.priority = qid;
    }

    table select_priority_table {
        key = {
            meta.isOn : exact;
            meta.isLong : exact;
        }
        actions = {
            select_queue;
            NoAction();
        }
        default_action = NoAction;
        const entries = {
            (0,0) : select_queue(1); // off, short  -> high
            (0,1) : select_queue(1); // off, long -> high
            (1,0) : select_queue(1); // on, short -> high
            (1,1) : select_queue(2); // on, long -> low
        }

    }


apply{
    

    // Read from Bloom Filter
    if(!hdr.tcp.isValid() && !hdr.udp.isValid()){
        standard_metadata.egress_spec = 1;
        hdr.ipv4.identification = 999;        
    }
    else{
        if(hdr.tcp.isValid()){
            l4_srcPort = hdr.tcp.srcPort;
            l4_dstPort = hdr.tcp.dstPort;
        }
        else if(hdr.udp.isValid()){
            l4_srcPort = hdr.udp.srcPort;
            l4_dstPort = hdr.udp.dstPort;
        }


/* 1.  Window Register Operation*/
        // Read pointer
        bit<32> pointer; // 0-> .. -> MAX_WINDOW -> 0
        bit<32> value0;
        bit<32> value1;
        bit<32> value2;
        bit<32> decrease_flag0; // Indicate whether the value of CBF is decreased
        bit<32> decrease_flag1;
        bit<32> decrease_flag2;

        pointer_reg.read(pointer, 0);
        
        // Read value from current pointer (to decrease 1 from window)
        window_reg_hash0.read(window_h0_idx, pointer);
        window_reg_hash1.read(window_h1_idx, pointer);
        window_reg_hash2.read(window_h2_idx, pointer);
        couting_bloom_filter.read(value0, window_h0_idx);
        couting_bloom_filter.read(value1, window_h1_idx);
        couting_bloom_filter.read(value2, window_h2_idx);
        if (value0 > 0){
            value0 = value0 - 1;
            if (value0 == 0 ){
                decrease_flag0 = 1;
            }
        }
        if (value1 > 0){
            value1 = value1 - 1;
            if (value1 == 0 ){
                decrease_flag1 = 1;
            }
        }
        if (value2 > 0){
            value2 = value2 - 1;
            if (value2 == 0 ){
                decrease_flag2 = 1;
            }
        }

        // Calculate Active Flow
        num_active_flow.read(active_flow, 0);
        // If entry is deleted from CBF -> decrease num_active_flow
        if (decrease_flag0 == 1 || decrease_flag1 == 1 || decrease_flag2 == 1)
            if (active_flow > 0){
                active_flow = active_flow - 1;
            }
            num_active_flow.write(0, active_flow);

        // Update CBF
        couting_bloom_filter.write(window_h0_idx,value0);
        couting_bloom_filter.write(window_h1_idx,value1);
        couting_bloom_filter.write(window_h2_idx,value2);


/* 2. Update curent packet to CBF  */
        hash(bf0_idx, HashAlgorithm.crc32, FLOW_HASH_BASE_0, 
            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, l4_srcPort, l4_dstPort },
            FLOW_HASH_MAX_3);
        couting_bloom_filter.read(bf0, (bit<32>)bf0_idx);

        hash(bf1_idx, HashAlgorithm.crc16, FLOW_HASH_BASE_0, 
            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, l4_srcPort, l4_dstPort },
            FLOW_HASH_MAX_3);
        couting_bloom_filter.read(bf1, (bit<32>)bf1_idx);

        hash(bf2_idx, HashAlgorithm.csum16, FLOW_HASH_BASE_0, 
            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, l4_srcPort, l4_dstPort },
            FLOW_HASH_MAX_3);
        couting_bloom_filter.read(bf2, (bit<32>)bf2_idx);


        if (bf0 != 0 && bf1 != 0 && bf2 != 0 ){ // If element exists
            // Increase 1 to corresponding buckets of CBF
            couting_bloom_filter.write(bf0_idx, bf0+1); // Couting bloom filter operation
            couting_bloom_filter.write(bf1_idx, bf1+1);
            couting_bloom_filter.write(bf2_idx, bf2+1);
        }
        else{  // If element is firstly joined

            // increase the number of active flows
            active_flow = active_flow + 1;  
            num_active_flow.write(0, active_flow);

            // Increase 1 to corresponding buckets of CBF
            couting_bloom_filter.write(bf0_idx, bf0+1); // Couting bloom filter operation
            couting_bloom_filter.write(bf1_idx, bf1+1);
            couting_bloom_filter.write(bf2_idx, bf2+1);
        }

        // Update Window : Write new hash index to (current pointer-1)th index
        if (pointer > 0){
            window_reg_hash0.write(pointer-1, bf0_idx);
            window_reg_hash1.write(pointer-1, bf1_idx);
            window_reg_hash2.write(pointer-1, bf2_idx);
        }
        else{ // current pointer is 0
            window_reg_hash0.write(MAX_WINDOW-1, bf0_idx);
            window_reg_hash1.write(MAX_WINDOW-1, bf1_idx);
            window_reg_hash2.write(MAX_WINDOW-1, bf2_idx);    
        }

        // Update pointer + 1 for next processing
        pointer = pointer + 1;
        if (pointer == MAX_WINDOW){
            pointer = 0; // Initialize to 0
        }    
        pointer_reg.write(0, pointer);

        // Determine whether current time is on/off
        if (active_flow > ACTIVE_THRESHOLD){
            meta.isOn = 1;
        }
        else {
            meta.isOn = 0;
        }


/* 3. Count Min Sketch */

        bit<10> tmp = 0;
        bit<10> min_count = 0;


        hash(bf0_idx, HashAlgorithm.crc32, FLOW_HASH_BASE_0, 
            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, l4_srcPort, l4_dstPort }, 
            FLOW_HASH_MAX_0);
        hot_flow_counter.read(tmp, bf0_idx);
        hot_flow_counter.write(bf0_idx, tmp + 1);
        min_count = tmp + 1;

        hash(bf1_idx, HashAlgorithm.crc32, FLOW_HASH_BASE_1, 
            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, l4_srcPort, l4_dstPort }, 
            FLOW_HASH_MAX_1);
        hot_flow_counter.read(tmp, bf1_idx);
        hot_flow_counter.write(bf1_idx, tmp + 1);
        if (min_count > tmp + 1) { min_count = tmp + 1; }

        hash(bf2_idx, HashAlgorithm.crc32, FLOW_HASH_BASE_2, 
            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, l4_srcPort, l4_dstPort }, 
            FLOW_HASH_MAX_2);
        hot_flow_counter.read(tmp, bf2_idx);
        hot_flow_counter.write(bf2_idx, tmp + 1);
        if (min_count > tmp + 1) { min_count = tmp + 1; }

        // Determine whether this packet is long/short
        if (min_count >= LONG_THRESHOLD){
            meta.isLong = 1;
        }
        else{
            meta.isLong = 0;
        }
        select_priority_table.apply();


/* For Test */
        hdr.ipv4.identification = (bit<16>)active_flow;
        hdr.ipv4.version = (bit<4>)meta.isOn;
        hdr.ipv4.ihl = (bit<4>)meta.isLong;
        hdr.ipv4.diffserv = (bit<8>)standard_metadata.priority;        


        standard_metadata.egress_spec = 1;

    }
} // apply
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
		         inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
       
    }

}



/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {

    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);      
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}


/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;