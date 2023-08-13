#pragma once
#include "utils.h"
#include"pcap.h"

#define MAXMIUM_FILTER_LENGTH 200


HANDLE hThread;

enum {

    // NULL + ALLOCATION ERRORS
    NULL_ADAPTER,
    NULL_SNIFFER,
    NULL_CALLBACK_FUNCTION,
    MEMORY_ALLOCATION_FAULT,

    // SNIFFER ERRORS
    WSDATA_INIT_ERROR,
    FILTER_COMPILE_ERROR,
    PCAP_INIT_ERROR,
    FILTER_SETTING_ERROR,


    // Packet Collection Errors
    PACKETCOLLECTION_CREATION_FAULT,
    PACKETCOLLECTION_INSERTION_ERROR,
    PACKETCOLLECTION_DELETION_ERROR,
    PACKETCOLLECTION_CLEARING_ERROR,



    // Succes Results



};


enum SniffingType {
    ASYNC,
    SYNC
};
typedef struct  {

    u_char ether_dest_host[42]; //the destination host address
    u_char ether_src_host[24]; //the source host address
    u_short ether_type; //to check if its ip etc


} ether_header;

typedef struct  {


    unsigned char ip_vhl; //assuming its ipv4 and header length more than 2
    unsigned char service; //type of service
    unsigned short total_len; //total length
    unsigned short identification; // identification
    u_short ip_off; //offset field
    u_char ttl; // time to live value
    u_char ip_protocol; // the protocol
    u_short sum; //the checksum
    unsigned long ip_src;
    unsigned long ip_dst;

#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)


}ip_header;


typedef struct  {
    u_short src_port;   /* source port */
    u_short dst_port;   /* destination port */
} tcp_h;

typedef struct {
    pcap_t* handle;
    struct bpf_program fProgram;
    char FilterExpression[MAXMIUM_FILTER_LENGTH];
    void (*call_back)(u_char* user_data, const struct pcap_pkthdr* packet_header, const u_char* packet_data);
    AdapterInfo* Device;
    WSADATA SocketData;
    char errbuf[PCAP_ERRBUF_SIZE];
    char isStopped;

}Sniffer;


typedef struct {
    unsigned int PacketID;
    tcp_h TcpHeader;
    ether_header EthHeader;
    ip_header IPHeader;
    u_char* Payload;
    int payloadSize;

} TCPPacket;

 struct Node{
    TCPPacket packet;
    struct Node* next;
};


typedef struct {
    struct Node* head;
    size_t size;
} PacketCollection;

// Thread Method

DWORD WINAPI StartingThreadRoutine(LPVOID params);

// Sniffer Methods
Sniffer* CreateSniffer(unsigned int* result,AdapterInfo* adapter);
u_char CompileSnifferFilter(Sniffer* sniffer);
u_char UseSnifferFilter(Sniffer* sniffer);
u_char StartSniffer(Sniffer* sniffer, enum SniffingType type);

// Conversion Method..

u_char GetPacketDesIP(TCPPacket* packet, char* buffer);
u_char GetPacketSourceIP(TCPPacket* packet, char* buffer);
void DisplayPayloadAsString(TCPPacket* packet);
void DisplayPayloadAsHEX(TCPPacket* packet);

// Packet Collection Methods...

PacketCollection* CreatePacketCollection();
struct Node* CreateNode(TCPPacket packet);
u_char AddPacket(PacketCollection* collection, TCPPacket packet);
u_char DeleteCollection(PacketCollection* collection);
void DisplayCollection(PacketCollection* collection);

