#include "sniffer.h"
#include <WinSock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")


// Thread Method

DWORD WINAPI StartingThreadRoutine(LPVOID params)
{
	Sniffer* sniffer = (Sniffer*)params;

	printf("Started Sniffing....\n");
	while(sniffer->isStopped == 0)
		pcap_dispatch(sniffer->handle, 0, sniffer->call_back, NULL);
	pcap_close(sniffer->handle);
	
	return 1;
}

// Sniffer Methods
Sniffer* CreateSniffer(unsigned int* result, AdapterInfo* adapter)
{
	if (adapter == NULL)
	{
		*result = NULL_ADAPTER;
		return NULL;
	}

	Sniffer* sniffer = (Sniffer*)calloc(1, sizeof(Sniffer));

	if (sniffer == NULL)
	{
		*result = MEMORY_ALLOCATION_FAULT;
		return NULL;
	}

	sniffer->Device = adapter;
	sniffer->isStopped = 0;
	// Putting this line in your code is necessary to init winsocks in your project
	if (WSAStartup(MAKEWORD(2, 2), &sniffer->SocketData) != 0)
	{
		*result = WSDATA_INIT_ERROR;
		return NULL;
	}

	sniffer->handle = pcap_open_live(sniffer->Device->Name, 65536, 1, 100, sniffer->errbuf);
	if (sniffer->handle == NULL)
	{
		WSACleanup();
		*result = PCAP_INIT_ERROR;
		return sniffer;
	}


	*result = SUCCESS;
	return sniffer;
}
u_char CompileSnifferFilter(Sniffer* sniffer)
{
	if (sniffer == NULL)
		return NULL_SNIFFER;


	if (pcap_compile(sniffer->handle, &sniffer->fProgram, sniffer->FilterExpression, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		*sniffer->errbuf = pcap_geterr(sniffer->handle);
		pcap_close(sniffer->handle);
		WSACleanup();
		return FILTER_COMPILE_ERROR;
	}
	return SUCCESS;
}
u_char UseSnifferFilter(Sniffer* sniffer)
{
	if (sniffer == NULL)
		return NULL_SNIFFER;


	if (pcap_setfilter(sniffer->handle, &sniffer->fProgram) == -1) {
		*sniffer->errbuf = pcap_geterr(sniffer->handle);
		pcap_close(sniffer->handle);
		WSACleanup();
		return FILTER_SETTING_ERROR;
	}
	return SUCCESS;
}
u_char StartSniffer(Sniffer* sniffer, enum SniffingType type)
{
	if (sniffer == NULL)
		return NULL_SNIFFER;
	else if (sniffer->call_back == NULL)
		return NULL_CALLBACK_FUNCTION;

	hThread = CreateThread(NULL, 0, StartingThreadRoutine, (LPVOID)sniffer, 0, NULL);
	if (hThread == NULL)
		return MEMORY_ALLOCATION_FAULT;

	if (type == SYNC)
		WaitForSingleObject(hThread, INFINITE);

	return SUCCESS;

}

// Conversion Method..

u_char GetPacketDesIP(TCPPacket* packet, char* buffer)
{
	if (packet == NULL || buffer == NULL)
		return NULL_PARAMTER;

	char dst_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(packet->IPHeader.ip_dst), dst_ip, INET_ADDRSTRLEN);
	memcpy(buffer, dst_ip, INET_ADDRSTRLEN);
	return SUCCESS;
}
u_char GetPacketSourceIP(TCPPacket* packet, char* buffer)
{
	if (packet == NULL || buffer == NULL)
		return NULL_PARAMTER;

	char src_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(packet->IPHeader.ip_src), src_ip, INET_ADDRSTRLEN);
	memcpy(buffer, src_ip, INET_ADDRSTRLEN);
	return SUCCESS;
}
void DisplayPayloadAsString(TCPPacket* packet)
{
	if (packet == NULL)
		return;

	printf("\n%s\n\n\n", packet->Payload);
}
void DisplayPayloadAsHEX(TCPPacket* packet)
{
	if (packet->payloadSize < -1)
		packet->payloadSize = packet->payloadSize * -1;
	printf("Payload (Packet Body):\n");
	for (int i = 0; i < packet->payloadSize; ++i) {
		printf("%02X ", packet->Payload[i]);
		if ((i + 1) % 16 == 0 || i == packet->payloadSize - 1) {
			printf("\n");
		}
	}
	printf("\n\n");
}

// Packet Collection Methods...

PacketCollection* CreatePacketCollection()
{
	PacketCollection* collection = (PacketCollection*)malloc(sizeof(PacketCollection));

	if (collection == NULL)
		return NULL;

	collection->head = NULL;
	collection->size = 0;

	return collection;

}
struct Node* CreateNode(TCPPacket packet)
{
	struct Node* NewNode = (struct Node*)malloc(sizeof(struct Node));
	if (NewNode == NULL)
		return NULL;

	NewNode->packet = packet;
	NewNode->next = NULL;

	return NewNode;
}
u_char AddPacket(PacketCollection* collection, TCPPacket packet)
{
	if (collection == NULL)
		return NULL_PARAMTER;

	struct Node* newNode = CreateNode(packet);
	if (newNode == NULL)
		return PACKETCOLLECTION_INSERTION_ERROR;

	if (collection->head == NULL)
	{
		collection->head = newNode;
		return SUCCESS;
	}

	struct Node* current = collection->head;

	while (current->next != NULL) {
		current = current->next;
	}

	current->next = newNode;

	return SUCCESS;

}

u_char DeleteCollection(PacketCollection* collection)
{
	if (collection == NULL)
		return NULL_PARAMTER;
	else if (collection->head == NULL)
		return NULL_PARAMTER;

	while (collection->head != NULL)
	{
		struct Node* temp = collection->head;
		collection->head = collection->head->next;
		free(temp);
	}

	return SUCCESS;
}

void DisplayCollection(PacketCollection* collection)
{
	if (collection == NULL)
		return;

	struct Node* current = collection->head;

	while (current != NULL)
	{
		uint16_t srcport = ntohs(current->packet.TcpHeader.src_port);
		uint16_t destprot = ntohs(current->packet.TcpHeader.dst_port);

		char* dst_ip = (char*)malloc(INET_ADDRSTRLEN);
		char* src_ip = (char*)malloc(INET_ADDRSTRLEN);
		if (dst_ip != NULL)
		{
			if (GetPacketDesIP(&current->packet, dst_ip) == NULL_PARAMTER)
				memcpy(dst_ip, "NULL", INET_ADDRSTRLEN);
		}
		else {
			printf("MEMORY ALLOCAITON ERROR\n");
			return;
		}


		if (src_ip != NULL)
		{
			if (GetPacketSourceIP(&current->packet, src_ip) == NULL_PARAMTER)
				memcpy(src_ip, "NULL", INET_ADDRSTRLEN);
		}
		else {
			printf("MEMORY ALLOCAITON ERROR\n");
			return;
		}

		printf("-------------- Packet ID : %d --------------\n\n", current->packet.PacketID);
		printf("Source IP: %s:%d\n", src_ip, srcport);
		printf("Destination IP: %s:%d\n", dst_ip, destprot);
		if (strlen(current->packet.Payload) > 0)
			DisplayPayloadAsHEX(&current->packet);
		else
			printf("\n\nPayload:\n(Empty)\n\n");
		free(dst_ip);
		free(src_ip);

		current = current->next;
	}
}

