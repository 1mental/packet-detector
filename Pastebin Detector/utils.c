
// Checking if windows.h is included or not
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




BOOLEAN GetDefaultNICAdapter(AdapterInfo* info)
{
	if (info == NULL)
		return NULL_ADAPTER_INFO;

	PIP_ADAPTER_INFO pAdapterInfo;

	ULONG ulOutBuflen = 0;

	DWORD dwRetVal;

	pAdapterInfo = (PIP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBuflen) == ERROR_BUFFER_OVERFLOW) { 
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBuflen); 
	}

	dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBuflen);
	if (dwRetVal != NO_ERROR) {
		free(pAdapterInfo);
		return ADAPTER_GATHER_ERROR;
	}


	if (pAdapterInfo->GatewayList.IpAddress.String[0] != '\0')
	{
		memcpy(info->Name, pAdapterInfo->AdapterName, DEFAULT_ADAPTER_NAME_LENGTH);
		memcpy(info->IP, pAdapterInfo->IpAddressList.IpAddress.String, IP_DEFAUlT_LENGTH);
		memcpy(info->Gateway, pAdapterInfo->GatewayList.IpAddress.String, IP_DEFAUlT_LENGTH);

		ValidateDeviceName(info);
		free(pAdapterInfo);
		return ADAPTER_GATHER_SUCCESS;
	}
	else {
			free(pAdapterInfo);
		return ADAPTER_GATHER_ERROR;
	}

}


void InitAdapterInfo(AdapterInfo* info)
{

	info->Name = (char*)calloc(DEFAULT_ADAPTER_NAME_LENGTH,sizeof(char));
	info->IP = (char*)calloc(IP_DEFAUlT_LENGTH,sizeof(char));
	info->Gateway = (char*)calloc(IP_DEFAUlT_LENGTH,sizeof(char));
}


void ValidateDeviceName(AdapterInfo* info)
{
	char temp[DEFAULT_ADAPTER_NAME_LENGTH] = "\\Device\\NPF_";
    strcat_s(temp, sizeof(temp), info->Name);
	memcpy(info->Name, temp, DEFAULT_ADAPTER_NAME_LENGTH);
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


