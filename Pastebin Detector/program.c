#include<stdio.h>

#include "sniffer.h"
#include "pcap.h"
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

#define INVALID_ARGS 1



PacketCollection* colletion;

Sniffer* pcapHandle;
unsigned int packetscount;

char InitArgs(int argc, char** argv)
{

	if (argc != 2)
		return INVALID_ARGS;

	if (PathFileExistsA(argv[1]) == FALSE)
		return INVALID_ARGS;
	return SUCCESS;

}


void packet_handler(u_char* user_data, const struct pcap_pkthdr* packet_header, const u_char* packet_data) {
	
	if (pcapHandle->isStopped == 1)
		return;

	static int id = 0;
	system("cls");
	packetscount++;

	ip_header* ip_header = (struct ip_header*)(packet_data + 14);
	int ip_header_size = ip_header->ip_vhl * 4;
	const char* payload = (char*)packet_data + 14 + ip_header_size;
	int payload_size = packet_header->caplen - 14 - ip_header_size;
	tcp_h* tcpHeader = (tcp_h*)(packet_data + 14 + ip_header->ip_vhl * 4);

	TCPPacket packet;
	packet.IPHeader = *ip_header;
	packet.Payload = (u_char*)payload;
	packet.TcpHeader = *tcpHeader;
	packet.PacketID = id;
	packet.payloadSize = payload_size;
	id++;


	AddPacket(colletion, packet);

	printf("[+] Packets Captured (%d)!\n", packetscount);
}



int main(int argc, char** argv)
{
	
	
	printf("\n\n\t\t Mental Pastebin Detector 1.0.0 Alpha\n\t\t- Still under Development.\n\n");


	
	if (InitArgs(argc, argv) == INVALID_ARGS)
	{
		printf("[+] Invaild args input...\n");
		system("pause");
		exit(-1);
	}
	

	
	AdapterInfo* info = (AdapterInfo*)calloc(1, sizeof(AdapterInfo));
	if (info == NULL)
	{
		printf("Error: Cannot Allocate Memory for the adapter info\n");
		system("pause");
		return -1;
	}

	printf("[+] Choose an Adapter:\n\n");
	if (GetAllAdapters(info) != SUCCESS)
	{
		printf("Error: Cannot choose an Adapter\n");
		system("pause");
		return -1;
	}


	printf("---------- Device Info (Used) ----------\n\n");
	printf("Name: %s\n", info->Name);
	printf("Description: %s\n\n", info->Description);

	printf("[+] Enter the host name: ");
	char host[MAXMIUM_FILTER_LENGTH];
	char combinedHost[MAXMIUM_FILTER_LENGTH] = "host ";
	fgets(host, sizeof(host), stdin);


	printf("[Note] this sniffer is programmed to capture the whole system packets.\nPlease make sure to not connect to the host you are trying to capture packts from.\nI recommend using this application in a clean VM.\n\n");
	system("pause");
	
	unsigned int result;
	Sniffer* sniffer = CreateSniffer(&result, info);

	if (result == NULL_ADAPTER)
	{

		printf("[Null Adapter] Can't create a sniffer... exiting..\n");
		system("pause");
		return -1;
	}
	else if (result == MEMORY_ALLOCATION_FAULT)
	{
		printf("[-] Can't Allocate Memory to create a sniffer... exiting..\n");
		system("pause");
		return -1;
	}
	else if (result == WSDATA_INIT_ERROR)
	{
		printf("[-] WSDATA Init Error... exiting..\n");
		system("pause");
		return -1;
	}
	else if (result != SUCCESS)
	{
		printf("%s\n", sniffer->errbuf);
		printf("[-] Can't create a sniffer... exiting..\n");
		system("pause");
		return -1;
	}
	pcapHandle = sniffer;
	sniffer->call_back = packet_handler;
	strcat(combinedHost, host);
	memcpy(sniffer->FilterExpression, combinedHost, sizeof(sniffer->FilterExpression));

	if (CompileSnifferFilter(sniffer) != SUCCESS)
	{
		printf("[-] Error: unable to compile the filter.. Make sure its correct..\n ");
		printf("%s\n", sniffer->errbuf);
		system("pause");
		return -1;

	}

	if (UseSnifferFilter(sniffer) != SUCCESS)
	{
		printf("[-] Error: unable to use the filter.. Make sure its correct..\n ");
		printf("%s\n", sniffer->errbuf);
		system("pause");
		return -1;
	}

	colletion = CreatePacketCollection();

	if (colletion == NULL)
	{
		printf("[-] Error: unable to create a packet collection... exiting...\n ");
		system("pause");
		return -1;
	}



	PROCESS proc;
	if (LaunchEXE(argv[1], &proc) != SUCCESS)
	{
		printf("[-] Can't create a process... exiting..\n");
		system("pause");
		return -1;
	}



	StartSniffer(sniffer, ASYNC);

	while (1)
	{
		DWORD status;
		GetExitCodeProcess(proc.ProcessHandle, &status);
		if (status != STILL_ACTIVE)
		{
			pcapHandle->isStopped = 1;
			break;
		}
	}
	system("cls");
	printf("[+] Process terminated.. Press anykey to show the captured packets...\n");
	system("pause");

	DisplayCollection(colletion);
	DeleteCollection(colletion);
	free(info);
	system("pause");
}
