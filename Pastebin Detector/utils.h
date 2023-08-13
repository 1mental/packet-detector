#pragma once


// Errors

#define ADAPTER_GATHER_ERROR 1
#define ADAPTER_GATHER_SUCCESS 2
#define NULL_ADAPTER_INFO 3
#define DEFAULT_ADAPTER_NAME_LENGTH 260
#define IP_DEFAUlT_LENGTH 16
#define NULL_PARAMTER 0x10
#define SUCCESS 0x21
#define PROCESS_CREATION_ERROR 0x11
#define ALLOCATION_FAULT 0x300
#define PORT_GATHER_ERROR 0x270

#include "utils.h"


// Structures

typedef struct {
	char* Name;
    char* IP;
    char* Gateway;
}AdapterInfo;

typedef struct {
    unsigned int PID;
    void* ProcessHandle;
    void* ThreadsHandle;
}PROCESS;


// Functions

// A Function to get the default Network Adapter.
char GetDefaultNICAdapter(AdapterInfo* info);

void InitAdapterInfo(AdapterInfo* info);

// A Function to create a process and launch it
char LaunchEXE(char* exepath, PROCESS* ProcessInfo);


// Combine the device name with its path
void ValidateDeviceName(AdapterInfo* info);




