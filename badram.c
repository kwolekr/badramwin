/*-
 * Copyright (c) 2012 Ryan Kwolek
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright notice, this list of
 *     conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright notice, this list
 *     of conditions and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* 
 * badmem.c - 
 *    Driver for Windows XP, Server 2003, Vista, Server 2008, 7, Server 2008R2 that loads on boot,
 *    reads the bad memory descriptor string from REG_PATH_BADMEM, then calls
 *    MmMarkPhysicalMemoryAsBad, or if not available, MmRemovePhysicalMemory, on the memory regions
 *    specified in the descriptor.
 */

#include <ntddk.h>
#include <stdarg.h>
#include <limits.h>
#include "logmsgs.h"

#define QUERY_BUF_SIZE 256
#define REG_PATH_BADMEM L"\\Registry\\Machine\\HARDWARE\\RESOURCEMAP\\System Resources\\PhysicalMemory"
#define REG_KEY_BADMEM  L"badmem"

PWCHAR QueryStringFromRegistry(PWCHAR path, PWCHAR key, void *sbuf, unsigned long qbuflen,
							 unsigned long *datalen, void **alloced_buf);
PWCHAR ParseRamStringEntry(PWCHAR str, unsigned int len, PLARGE_INTEGER pli);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
void WriteEventLog(PVOID pio_obj, NTSTATUS msgcode, int nfmtstrs, ...);
int MarkBadMemory(PDRIVER_OBJECT DriverObject);

typedef NTSTATUS (NTAPI *MM_MARK_PHYSICAL_MEMORY_AS_BAD)(IN PPHYSICAL_ADDRESS, IN OUT PLARGE_INTEGER);
MM_MARK_PHYSICAL_MEMORY_AS_BAD MmMarkPhysicalMemoryAsBad;


///////////////////////////////////////////////////////////////////////////////


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	KdPrint(("badram v1.0"));

	DriverObject->DriverUnload = DriverUnload;

	WriteEventLog(DriverObject, EVT_HELLO_MESSAGE, 0);
	if (!MarkBadMemory(DriverObject))
		WriteEventLog(DriverObject, EVT_ERROR_MESSAGE, 0);
	
	//KeBugCheckEx(0x1337, 'Hell', 'o wo', 'rld!', 0);
	return STATUS_SUCCESS;
}


VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	KdPrint(("Bye!"));
}


void WriteEventLog(PVOID pio_obj, NTSTATUS msgcode, int nfmtstrs, ...) {
	PIO_ERROR_LOG_PACKET plogbuf;
	PCHAR pclbuf;
	va_list vl;
	unsigned int logsize = sizeof(IO_ERROR_LOG_PACKET);
	int i, nusablestrs;

	va_start(vl, nfmtstrs);
	for (i = 0; i != nfmtstrs; i++) {
		PUNICODE_STRING ustr = va_arg(vl, PUNICODE_STRING);
		logsize += ustr->Length + sizeof(WCHAR);
		if (logsize > UCHAR_MAX) {
			logsize -= ustr->Length + sizeof(WCHAR);
			break;
		}
	}
	va_end(vl);
	nusablestrs = i;

	plogbuf = IoAllocateErrorLogEntry(pio_obj, logsize);
	if (!plogbuf) {
		KdPrint(("IoAllocateErrorLogEntry failed."));
		return;
	}
	
	RtlZeroMemory(plogbuf, sizeof(IO_ERROR_LOG_PACKET));
	plogbuf->ErrorCode       = msgcode;
	plogbuf->StringOffset    = sizeof(IO_ERROR_LOG_PACKET);
	plogbuf->NumberOfStrings = nusablestrs;

	pclbuf = (PCHAR)plogbuf + plogbuf->StringOffset;
	va_start(vl, nfmtstrs);
	for (i = 0; i != nfmtstrs; i++) {
		PUNICODE_STRING ustr = va_arg(vl, PUNICODE_STRING);

		wcsncpy((PWCHAR)pclbuf, ustr->Buffer, ustr->Length / sizeof(WCHAR));
		pclbuf += ustr->Length;
		*(PWCHAR *)pclbuf = L'\0';
		pclbuf += sizeof(WCHAR);
	}
	va_end(vl);

	IoWriteErrorLogEntry(plogbuf);
}


PWCHAR QueryStringFromRegistry(IN PWCHAR path, IN PWCHAR key, IN OUT void *sbuf,
							 IN unsigned long qbuflen, OUT unsigned long *datalen,
							 OUT void **alloced_buf) {
	UNICODE_STRING upath, ukey;
	OBJECT_ATTRIBUTES objattrib;
	void *pquerybuf = NULL;
	unsigned long resultlen;
	PKEY_VALUE_FULL_INFORMATION pkvfi = (PKEY_VALUE_FULL_INFORMATION)sbuf;
	HANDLE hKey;
	NTSTATUS status;

	if (!sbuf || !datalen || !alloced_buf)
		return NULL;

	RtlInitUnicodeString(&upath, path);
	RtlInitUnicodeString(&ukey, key);
	InitializeObjectAttributes(&objattrib, &upath, 0, NULL, NULL);
	
	status = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &objattrib);
	if (!NT_SUCCESS(status)) {
		KdPrint(("ZwOpenKey failed."));
		return NULL;
	}

	status = ZwQueryValueKey(hKey, &ukey, KeyValueFullInformation, pkvfi, qbuflen, &resultlen);
	if (!NT_SUCCESS(status)) {
		if (status == STATUS_BUFFER_OVERFLOW) {
			do {
				qbuflen <<= 1;
				if (pquerybuf)
					ExFreePoolWithTag(pquerybuf, 'derp');

				pquerybuf = ExAllocatePoolWithTag(PagedPool, qbuflen, 'derp');
				if (!pquerybuf) {
					KdPrint(("ExAllocatePoolWithTag failed, insufficient paged memory."));
					ZwClose(hKey);
					return NULL;
				}

				status = ZwQueryValueKey(hKey, &ukey, KeyValueFullInformation,
							pquerybuf, qbuflen, &resultlen);
			} while (status == STATUS_BUFFER_OVERFLOW);

			if (!NT_SUCCESS(status)) {
				KdPrint(("ZwQueryValueKey failed."));
				if (pquerybuf)
					ExFreePoolWithTag(pquerybuf, 'derp');
				ZwClose(hKey);
				return NULL;
			}
			
			pkvfi = pquerybuf;
		} else {
			KdPrint(("ZwQueryValueKey failed."));
			ZwClose(hKey);
			return NULL;
		}
	}

	ZwClose(hKey);

	if (pkvfi->Type != REG_SZ) {
		KdPrint(("Registry key is not of type REG_SZ."));
		if (pquerybuf)
			ExFreePoolWithTag(pquerybuf, 'derp');
		return NULL;
	}

	*datalen = pkvfi->DataLength;
	if (pquerybuf)
		*alloced_buf = pkvfi;

	return (PWCH)((char *)pkvfi + pkvfi->DataOffset);
}


int MarkBadMemory(PDRIVER_OBJECT DriverObject) {
	wchar_t strbuf[64];
	UNICODE_STRING procname, str_nregions;
	NTSTATUS status;
	unsigned char squerybuf[QUERY_BUF_SIZE];
	long datalen;
	unsigned int i;
	void *allocedbuf;
	PWCH ramstr, newstr;

	ramstr = QueryStringFromRegistry(REG_PATH_BADMEM, REG_KEY_BADMEM, squerybuf,
				QUERY_BUF_SIZE, &datalen, &allocedbuf);
	if (!ramstr)
		return 0;

	RtlInitUnicodeString(&procname, L"MmMarkPhysicalMemoryAsBad");
	MmMarkPhysicalMemoryAsBad = MmGetSystemRoutineAddress(&procname);
	if (!MmMarkPhysicalMemoryAsBad) {
		KdPrint(("Can't find MmMarkPhysicalMemoryAsBad. "
				 "Falling back to MmRemovePhysicalMemory."));
		MmMarkPhysicalMemoryAsBad = MmRemovePhysicalMemory;
	}

	i = 0;
	while (datalen > 0) { 
		PHYSICAL_ADDRESS physaddr;
		LARGE_INTEGER nbytes;

		newstr = ParseRamStringEntry(ramstr, datalen, &physaddr);
		if (!newstr)
			return 0;
		datalen -= (newstr - ramstr);
		ramstr = newstr;

		newstr = ParseRamStringEntry(ramstr, datalen, &nbytes);
		if (!newstr)
			return 0;
		datalen -= (newstr - ramstr);
		ramstr = newstr;

		// also could use MmMapIoSpace to reserve it
		status = MmMarkPhysicalMemoryAsBad(&physaddr, &nbytes);
		if (!NT_SUCCESS(status)) {
			KdPrint(("MmRemovePhysicalMemory %x %x failed.",
				physaddr.HighPart, physaddr.LowPart));
			continue;
		}

		i++;
	}

	KdPrint(("Marked %d regions of physical memory as bad.", i));

	RtlInitEmptyUnicodeString(&str_nregions, strbuf, sizeof(strbuf));
	status = RtlIntegerToUnicodeString(i, 10, &str_nregions);
	if (NT_SUCCESS(status))
		WriteEventLog(DriverObject, EVT_MARKED_MESSAGE, 1, &str_nregions);

	if (allocedbuf)
		ExFreePoolWithTag(allocedbuf, 'derp');

	return 1;
}


PWCHAR ParseRamStringEntry(PWCHAR str, unsigned int len, PLARGE_INTEGER pli) {
	UNICODE_STRING ustr;
	NTSTATUS status;
	unsigned int i;

	ustr.MaximumLength = 16;
	ustr.Buffer        = str;

	i = 0;
	while (i < len / sizeof(WCHAR) && str[i] != L',')
		i++;
	str[i] = L'\0';

	if (i > 8) {
		ustr.Length = (i - 8) * sizeof(WCHAR);

		status = RtlUnicodeStringToInteger(&ustr, 16, &pli->HighPart);
		if (!NT_SUCCESS(status)) {
			KdPrint(("RtlUnicodeStringToInteger failed."));
			return NULL;
		}

		ustr.Buffer += 8;
	} else {
		pli->HighPart = 0;
	}

	status = RtlUnicodeStringToInteger(&ustr, 16, &pli->LowPart);
	if (!NT_SUCCESS(status)) {
		KdPrint(("RtlUnicodeStringToInteger failed."));
		return NULL;
	}

	i++;

	return str + i;
}
