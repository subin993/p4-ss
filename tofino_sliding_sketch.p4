#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;
typedef bit<32> chunk_size_1;
typedef bit<8> chunk_size_2;
typedef bit<40> chunk_size_3;
typedef bit<16> token_size;

// const bit<16> ETHERTYPE_IPV4 = 0x800;
// const bit<8> IP_PROTOCOLS_TCP = 6;
// const bit<8> IP_PROTOCOLS_UDP = 17;




/*************************************************************************
*********************** D E F I N E  ***********************************
*************************************************************************/
#define MAX_LEN 11 
#define TRUE 1
#define FALSE 0 
#define SHIM_TCP 77 //NETRE reserved IPv4 Protocol ID
#define SHIM_UDP 78 //NETRE reserved IPv4 Protocol ID
// #define IPV4_PROTOCOL_TCP 6
// #define IPV4_PROTOCOL_UDP 17
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
    bit<32> pointer; // 0-> .. -> MAX_WINDOW -> 0
    bit<32> decrease_flag0;
    bit<32> decrease_flag1;
    bit<32> decrease_flag2;
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
    bit<10> tmp;
    bit<10> min_count;
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

parser ParserI(packet_in packet,
               out headers hdr,
               out metadata meta,
               out ingress_intrinsic_metadata_t ig_intr_md) {

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

control IngressP(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    
    // register<bit<32>>(FLOW_REGISTER_SIZE) couting_bloom_filter;

    Register<bit<32>, bit<32>>(32w65536) couting_bloom_filter0;
    RegisterAction<bit<32>, bit<32>, bit<32>>(couting_bloom_filter0) counting_bloom_filter0_action_flow = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            if (value > 0){
                value = value -1;
                if (value == 0 ){
                    meta.decrease_flag0 = 1;
                }
            }
            read_value = value;
        }
    };
    // 이후에 apply할때 counting_bloom_filter0_read_flow.execute(meta.window_h0_idx) 으로 실행하는 것.

    Hash<bit<32>> (HashAlgorithm_t.CRC32) hash_crc32;
    RegisterAction<bit<32>, bit<32>, bit<32>>(couting_bloom_filter0) counting_bloom_filter0_read_packet = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
            }
        };   
    action bloom_filter0_action(){
        meta.bf0_idx = hash_crc32.get({ hdr.ipv4.protocol, 
                                                  hdr.ipv4.srcAddr, 
                                                  hdr.ipv4.dstAddr, 
                                                  hdr.tcp.srcPort, 
                                                  hdr.tcp.dstPort })[17:0];
        meta.bf0 = counting_bloom_filter0_read_packet.execute(meta.bf0_idx);
    }

    RegisterAction<bit<32>, bit<32>, bit<32>>(couting_bloom_filter0) counting_bloom_filter0_write_packet = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value+1;
            read_value = value;
        }
    };
    // 나중에 recirculation 적용 필요, hash 함수로 받아온 index로 read를 execute하고, 
    //read에서 저장한 value에 대한 metadata(bf0 등)를 조건문에 활용하여 write할 수 있도록 수정
    
    Register<bit<32>, bit<32>>(32w65536) couting_bloom_filter1;
    RegisterAction<bit<32>, bit<32>, bit<32>>(couting_bloom_filter1) counting_bloom_filter1_action_flow = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            if (value > 0){
                value = value -1;
                if (value == 0 ){
                    meta.decrease_flag0 = 1;
                }
            }
            read_value = value;
        }
    };
    // 이후에 apply할때 counting_bloom_filter1_read_flow.execute(meta.window_h1_idx) 으로 실행하는 것.

    Hash<bit<16>> (HashAlgorithm_t.CRC16) hash_crc16;
    RegisterAction<bit<32>, bit<32>, bit<32>>(couting_bloom_filter1) counting_bloom_filter1_read_packet = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
            }
        };   
    action bloom_filter1_action(){
        meta.bf1_idx = hash_crc16.get({ hdr.ipv4.protocol, 
                                                  hdr.ipv4.srcAddr, 
                                                  hdr.ipv4.dstAddr, 
                                                  hdr.tcp.srcPort, 
                                                  hdr.tcp.dstPort })[17:0];
        meta.bf1 = counting_bloom_filter1_read_packet.execute(meta.bf1_idx);
    }

    RegisterAction<bit<32>, bit<32>, bit<32>>(couting_bloom_filter1) counting_bloom_filter1_write_packet = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value+1;
            read_value = value;
        }
    };
    // 나중에 recirculation 적용 필요, hash 함수로 받아온 index로 read를 execute하고, 
    //read에서 저장한 value에 대한 metadata(bf1 등)를 조건문에 활용하여 write할 수 있도록 수정
    
    Register<bit<32>, bit<32>>(32w65536) couting_bloom_filter2;
    RegisterAction<bit<32>, bit<32>, bit<32>>(couting_bloom_filter2) counting_bloom_filter2_action_flow = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            if (value > 0){
                value = value -1;
                if (value == 0 ){
                    meta.decrease_flag0 = 1;
                }
            }
            read_value = value;
        }
    };
    // 이후에 apply할때 counting_bloom_filter2_read_flow.execute(meta.window_h2_idx) 으로 실행하는 것.

    Hash<bit<32>> (HashAlgorithm_t.IDENTITY) hash_csum16;
    RegisterAction<bit<32>, bit<32>, bit<32>>(couting_bloom_filter2) counting_bloom_filter2_read_packet = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
            }
        };   
    action bloom_filter2_action(){
        meta.bf2_idx = hash_csum16.get({ hdr.ipv4.protocol, 
                                                  hdr.ipv4.srcAddr, 
                                                  hdr.ipv4.dstAddr, 
                                                  hdr.tcp.srcPort, 
                                                  hdr.tcp.dstPort })[17:0];
        meta.bf2 = counting_bloom_filter2_read_packet.execute(meta.bf2_idx);
    }

    RegisterAction<bit<32>, bit<32>, bit<32>>(couting_bloom_filter2) counting_bloom_filter2_write_packet = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value+1;
            read_value = value;
        }
    };
    // 나중에 recirculation 적용 필요, hash 함수로 받아온 index로 read를 execute하고, 
    //read에서 저장한 value에 대한 metadata(bf2 등)를 조건문에 활용하여 write할 수 있도록 수정


    // register<bit<32>>(10) num_active_flow;
    // register<bit<32>>(1) pointer_reg;

    Register<bit<32>, _>(10) num_active_flow;
    RegisterAction<bit<32>, _, bit<32>>(num_active_flow) num_active_flow_action_decrease = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            if (value > 0) {
                value = value - 1;
            }
            read_value = value;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(num_active_flow) num_active_flow_write_increase = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            if (value > 0) {
                value = value + 1;
            }
            read_value = value;
        }
    };

    // 나중에 if (decrease_flag0 == 1 || decrease_flag1 == 1 || decrease_flag2 == 1) 이면, num_active_flow_action_decrease 실행
    // if (bf0 != 0 && bf1 != 0 && bf2 != 0 ) 이면, num_active_flow_write_increase 실행

    Register<bit<32>, bit<32>>(64) window_reg_hash0;
    RegisterAction<bit<32>, bit<32>, bit<32>>(window_reg_hash0) window_reg_hash0_read_update = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    Register<bit<32>, bit<32>>(64) window_reg_hash1;
    RegisterAction<bit<32>, bit<32>, bit<32>>(window_reg_hash1) window_reg_hash1_read_update = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    Register<bit<32>, bit<32>>(64) window_reg_hash2;
    RegisterAction<bit<32>, bit<32>, bit<32>>(window_reg_hash2) window_reg_hash2_read_update = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    // 이 부분은 Recirculation이 필요. 혹은 두개 Register 사용?? -> 아래쪽 action pointer_reg_updat()에서 한번 read를 해온 다음에, 
    // 인덱스(pointer)를 -1 한 자리에 value를 집어넣어야 함. 혹은 pointer가 0이면, MAX_WINDOW-1 인덱스에 value를 집어넣어야 한다.
    // 즉, 아래쪽 execute(meta.pointer)는 무조건 해야하고, 그 다음에 같은 레지스터를 execute(meta.pointer - 1) 하는것도 무조건 해야함.
    

    Register<bit<32>, _>(1) pointer_reg;
    RegisterAction<bit<32>, _, bit<32>>(pointer_reg) pointer_reg_read = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
            value = value + 1 ;
            if (value == MAX_WINDOW){
                value = 0;
            }
            }
        };
    action pointer_reg_update(){
        meta.pointer = pointer_reg_read.execute(0);
        meta.window_h0_idx = window_reg_hash0_read_update.execute(meta.pointer);
        meta.window_h1_idx = window_reg_hash1_read_update.execute(meta.pointer);
        meta.window_h2_idx = window_reg_hash2_read_update.execute(meta.pointer);
    }
    
    

    // bit<32> bf0; 
    // bit<32> bf1; 
    // bit<32> bf2;
    // bit<32> bf0_idx; 
    // bit<32> bf1_idx; 
    // bit<32> bf2_idx;
    // bit<32> window_h0_idx;
    // bit<32> window_h1_idx;
    // bit<32> window_h2_idx;
    // bit<32> active_flow;


    Register<bit<10>, bit<32>>(32w65536) hot_flow_counter0;
    RegisterAction<bit<10>, bit<32>, bit<10>>(hot_flow_counter0) hot_flow_counter0_read = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
            value = value + 1;
        }
    };
    action hot_flow_action0(){
        meta.bf0_idx = hash_crc32.get({ hdr.ipv4.protocol, 
                                                  hdr.ipv4.srcAddr, 
                                                  hdr.ipv4.dstAddr, 
                                                  hdr.tcp.srcPort, 
                                                  hdr.tcp.dstPort })[17:0];
        meta.tmp = hot_flow_counter0_read.execute(meta.bf0_idx);
        meta.min_count = meta.tmp + 1;
    }
    
    Register<bit<10>, bit<32>>(32w65536) hot_flow_counter1;
    RegisterAction<bit<10>, bit<32>, bit<10>>(hot_flow_counter1) hot_flow_counter1_read = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
            value = value + 1;
        }
    };
    action hot_flow_action1(){
        meta.bf1_idx = hash_crc32.get({ hdr.ipv4.protocol, 
                                                  hdr.ipv4.srcAddr, 
                                                  hdr.ipv4.dstAddr, 
                                                  hdr.tcp.srcPort, 
                                                  hdr.tcp.dstPort })[17:0];
        meta.tmp = hot_flow_counter1_read.execute(meta.bf1_idx);
        if (meta.min_count > meta.tmp + 1) {
            meta.min_count = meta.tmp + 1;
        }
    }
    
    Register<bit<10>, bit<32>>(32w65536) hot_flow_counter2;
    RegisterAction<bit<10>, bit<32>, bit<10>>(hot_flow_counter2) hot_flow_counter2_read = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
            value = value + 1;
        }
    };
    action hot_flow_action2(){
        meta.bf2_idx = hash_crc32.get({ hdr.ipv4.protocol, 
                                                  hdr.ipv4.srcAddr, 
                                                  hdr.ipv4.dstAddr, 
                                                  hdr.tcp.srcPort, 
                                                  hdr.tcp.dstPort })[17:0];
        meta.tmp = hot_flow_counter2_read.execute(meta.bf2_idx);
        if (meta.min_count > meta.tmp + 1) {
            meta.min_count = meta.tmp + 1;
        }
    }
    
    action long_short_update(){
        if (meta.min_count >= LONG_THRESHOLD) {
            meta.isLong = 1;
        }
        else{
            meta.isLong = 0;
        }
    }

    
    bit<16> l4_srcPort;
    bit<16> l4_dstPort;

    action select_queue(bit<5> qid){
        ig_intr_tm_md.qid = qid;
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
        ig_intr_tm_md.ucast_egress_port = 1;
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
    }
    pointer_reg_update();
    counting_bloom_filter0_action_flow.execute(meta.window_h0_idx);
    counting_bloom_filter1_action_flow.execute(meta.window_h1_idx);
    counting_bloom_filter2_action_flow.execute(meta.window_h2_idx);
    if (meta.decrease_flag0 == 1 || meta.decrease_flag1 == 1 || meta.decrease_flag2 == 1) {
        num_active_flow_action_decrease.execute(0);
    }
    if (meta.bf0 != 0 && meta.bf1 != 0 && meta.bf2 != 0 ){
        bloom_filter0_action();
        bloom_filter1_action();
        bloom_filter2_action();
    }
    else{
        num_active_flow_write_increase.execute(0);
        bloom_filter0_action();
        bloom_filter1_action();
        bloom_filter2_action();
    }
    pointer_reg_update();
    hot_flow_action0();
    hot_flow_action1();
    hot_flow_action2();
    select_priority_table.apply();
} // apply
}

control DeparserI(
        packet_out b,
        inout headers hdr,
        in metadata meta,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
    apply {
        b.emit(hdr.ethernet);
        b.emit(hdr.ipv4);
        b.emit(hdr.tcp);
    }
}

parser ParserE(packet_in b,
               out headers hdr,
               out metadata meta,
               out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        b.extract(hdr.ethernet);
        transition accept;
    }
}

control EgressP(
        inout headers hdr,
        inout metadata meta,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply { }
}

control DeparserE(packet_out b,
                  inout headers hdr,
                  in metadata meta,
                  in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply {
        b.emit(hdr.ethernet);
    }
}

Pipeline(ParserI(), IngressP(), DeparserI(), ParserE(), EgressP(), DeparserE()) pipe;
Switch(pipe) main;

