#include"dns.h"


BYTE GetDomainIP(char* domain, char* buffer, int bufferSize)
{
	DNS_RECORD* pDnsRecord = NULL;

	WORD dwError = DnsQuery_A(domain, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &pDnsRecord, NULL);

    if (dwError == 0 && pDnsRecord != NULL) {
        memcpy(buffer,inet_ntoa(*((struct in_addr*)&pDnsRecord->Data.A.IpAddress)), bufferSize);
        DnsRecordListFree(pDnsRecord, DnsFreeRecordList);

        return DNS_CONNECITON_SUCCESS;
    }
    else {

        return DNS_CONNECTION_ERROR;
    }


}

