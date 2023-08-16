
// Checking if windows.h is included or not
#include "pcap.h"
#ifndef _WINDOWS_
#include <windows.h>
#endif

#include<winsock.h>
#include<iphlpapi.h>
#include<stdio.h>
#include "utils.h"
#include<string.h>
#include <assert.h>
#include <malloc.h>


#pragma comment(lib, "iphlpapi.lib")



void InitAdapterInfo(AdapterInfo* info)
{

	info->Name = (char*)calloc(DEFAULT_ADAPTER_NAME_LENGTH,sizeof(char));
	info->Description = (char*)calloc(MAXIMUM_DESCRIPTION_LENGTH,sizeof(char));
}



BOOLEAN LaunchEXE(char* exepath, PROCESS* ProcessInfo)
{
	if (exepath == NULL)
		return NULL_PARAMTER;

	PROCESS_INFORMATION ProcessInformation;
	STARTUPINFOA startupInfo = { sizeof(startupInfo) };
	if (CreateProcessA(
		exepath,
		NULL,
		NULL,
		NULL,
		TRUE,
		0,
		NULL,
		NULL,
		&startupInfo,
		&ProcessInformation
	))
	{
		ProcessInfo->PID = ProcessInformation.dwProcessId;
		ProcessInfo->ProcessHandle = ProcessInformation.hProcess;
		ProcessInfo->ThreadsHandle = ProcessInformation.hThread;

		return SUCCESS;
	}


	return PROCESS_CREATION_ERROR;
}



char GetAllAdapters(AdapterInfo* info)
{
	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Error finding adapters: %s\n", errbuf);
		return ADAPTER_GATHER_ERROR;
	}

	AdapterInfo allAdapters[30];
	int counter = -1;
	for (pcap_if_t* dev = alldevs; dev != NULL; dev = dev->next) {

		counter++;

		InitAdapterInfo(&(allAdapters[counter]));
		allAdapters[counter].ID = counter;
		memcpy(allAdapters[counter].Name, dev->name, DEFAULT_ADAPTER_NAME_LENGTH);
		if (dev->description) 
			memcpy(allAdapters[counter].Description, dev->description, strlen(dev->description));
		else 
			memcpy(allAdapters[counter].Description, "NULL Description", MAXIMUM_DESCRIPTION_LENGTH);
		printf("Adapter ID : %d\n", counter);
		printf("Adapter name: %s\n", allAdapters[counter].Name);
		printf("Adapter Description: %s\n", allAdapters[counter].Description);

		printf("\n");
	}


	// Taking input from the user

	char input[50];
	int choice;
	InputLabel:
	printf("Enter the Adapter ID: ");
	if (fgets(input,sizeof(input),stdin) == NULL)
	{
		printf("Can't take the user input.\n");
		goto InputLabel;
	}

	input[strcspn(input, "\n")] = '\0';

	int length = strlen(input);
	for (int i = 0; i < length; i++) {
		if (input[i] < '0' || input[i] > '9') {
			printf("Invalid input: Not an integer.\n");
			goto InputLabel;
		}
	}

	choice = atoi(input);
	 if (choice > counter || choice < 0)
	{
		printf("Invalid ID Input!\n");
		goto InputLabel;
	}

	memcpy(info, &allAdapters[choice], sizeof(AdapterInfo));
	pcap_freealldevs(alldevs);
	return SUCCESS;
}

