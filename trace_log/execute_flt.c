/*
 * Copyright 2010-2024 JiJie.Shi.
 *
 * This file is part of bittrace.
 * Licensed under the Gangoo License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common.h"
#include <fltKernel.h>

typedef enum _FILE_TYPE_
{
	FILE_UNKNOWN_TYPE = 0x0080,
	FILE_EXE_TYPE,
	FILE_DLL_TYPE,
	FILE_SYS_TYPE,
}
FILE_TYPE,*PFILE_TYPE;

FILE_TYPE GetFileFileType (IN PUNICODE_STRING FileName)
{
	if (FileName)
	{
		ULONG Length = FileName->Length / sizeof (WCHAR);

		if (Length >= 3)
		{
			if ((FileName->Buffer[Length - 1] == L'E' || FileName->Buffer[Length - 1] == L'e') &&\
				(FileName->Buffer[Length - 2] == L'X' || FileName->Buffer[Length - 2] == L'x') &&\
				(FileName->Buffer[Length - 3] == L'E' || FileName->Buffer[Length - 3] == L'e')\
				)
			{
				return FILE_EXE_TYPE;
			}

			if ((FileName->Buffer[Length - 1] == L'L' || FileName->Buffer[Length - 1] == L'l') &&\
				(FileName->Buffer[Length - 2] == L'L' || FileName->Buffer[Length - 2] == L'l') &&\
				(FileName->Buffer[Length - 3] == L'D' || FileName->Buffer[Length - 3] == L'd')\
				)
			{
				return FILE_DLL_TYPE;
			}

			if ((FileName->Buffer[Length - 1] == L'S' || FileName->Buffer[Length - 1] == L's') &&\
				(FileName->Buffer[Length - 2] == L'Y' || FileName->Buffer[Length - 2] == L'y') &&\
				(FileName->Buffer[Length - 3] == L'S' || FileName->Buffer[Length - 3] == L's')\
				)
			{
				return FILE_SYS_TYPE;
			}
		}
	}

	return FILE_UNKNOWN_TYPE;
}


typedef struct _PROCESS_NOTIFY_WORK_ITEM_
{
	HANDLE Pid;

	WORK_QUEUE_ITEM WorkItem;
}
PROCESS_NOTIFY_WORK_ITEM,*PPROCESS_NOTIFY_WORK_ITEM;

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
    );

VOID CreateProcessNotify (IN HANDLE ParentId,IN HANDLE ProcessId,IN BOOLEAN Create)
{
}

typedef struct _FLUSH_CACHE_WORK_ITEM_
{
	WORK_QUEUE_ITEM WorkItem;
	PUNICODE_STRING FilePath;
}
FLUSH_CACHE_WORK_ITEM,*PFLUSH_CACHE_WORK_ITEM;

VOID FlushLoadWorkItemRoutine (IN PFLUSH_CACHE_WORK_ITEM FlushCacheWorkItem)
{
	NTSTATUS               Status;
	HANDLE                 hFile;
	OBJECT_ATTRIBUTES      oa;
	IO_STATUS_BLOCK        IoStatus;

	LARGE_INTEGER          DelayTime; 

	LARGE_INTEGER          ByteOffset = {0};

	DelayTime.QuadPart = 2;//s
	DelayTime.QuadPart = DelayTime.QuadPart * 1000;//ms
	DelayTime.QuadPart = DelayTime.QuadPart * 1000000;//ns
	DelayTime.QuadPart = DelayTime.QuadPart / 100; //s

	DelayTime.QuadPart = DelayTime.QuadPart / 100;//ms
	DelayTime.QuadPart = DelayTime.QuadPart * (-1);
	KeDelayExecutionThread (KernelMode,TRUE,&DelayTime);

	ERROR ("Ex: %wZ",FlushCacheWorkItem->FilePath);

	InitializeObjectAttributes (&oa,FlushCacheWorkItem->FilePath,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,NULL,NULL);
	Status = ZwCreateFile (&hFile,
		FILE_READ_DATA|GENERIC_WRITE,
		&oa,
		&IoStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE,
		NULL,
		0
		);
	if (!NT_SUCCESS (Status))
	{
		ERROR ("Ex: %08x",Status);	

		KFfree (FlushCacheWorkItem);
		return;
	}

	Status = ZwReadFile (hFile,NULL,NULL,NULL,&IoStatus,&DelayTime,sizeof (DelayTime),&ByteOffset,NULL);
	if (!NT_SUCCESS (Status))
	{
		ERROR ("Ex: %08x",Status);
	}

	ZwClose (hFile);
	KFfree (FlushCacheWorkItem);
}

NTSTATUS FlushLoadDllCache (IN PUNICODE_STRING FilePath)
{
	PFLUSH_CACHE_WORK_ITEM FlushCacheWorkItem = NULL;

	ULONG                  Length;

	if (FilePath == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	FlushCacheWorkItem = (PFLUSH_CACHE_WORK_ITEM)KFalloc (sizeof (FLUSH_CACHE_WORK_ITEM));
	if (FlushCacheWorkItem)
	{
		Length = sizeof (UNICODE_STRING) + FilePath->Length + sizeof (WCHAR);

		FlushCacheWorkItem->FilePath = (PUNICODE_STRING)KFalloc (Length);
		if (FlushCacheWorkItem->FilePath == NULL)
		{
			KFfree (FlushCacheWorkItem);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		memset (FlushCacheWorkItem->FilePath,0,Length);

		FlushCacheWorkItem->FilePath->MaximumLength = (USHORT)(Length - sizeof (UNICODE_STRING));
		FlushCacheWorkItem->FilePath->Length = FilePath->Length;
		FlushCacheWorkItem->FilePath->Buffer = (PWCHAR)((PUCHAR)FlushCacheWorkItem->FilePath + sizeof (UNICODE_STRING));
		memcpy (FlushCacheWorkItem->FilePath->Buffer,FilePath->Buffer,FilePath->Length);

		ExInitializeWorkItem (&FlushCacheWorkItem->WorkItem,FlushLoadWorkItemRoutine,FlushCacheWorkItem);
		ExQueueWorkItem (&FlushCacheWorkItem->WorkItem,DelayedWorkQueue);

		return STATUS_SUCCESS;
	}

	return STATUS_UNSUCCESSFUL;
}

VOID ImageLoadNotify (IN PUNICODE_STRING FullImageName,IN HANDLE ProcessId,IN PIMAGE_INFO ImageInfo)
{
	NTSTATUS          Status;
	HANDLE            hProcess;
	CLIENT_ID         CliendId = {0}; 
	OBJECT_ATTRIBUTES oa = {0};

	UNICODE_STRING    NameString = {0};

	PMDL              Mdl = NULL;
	PVOID             LockAddress;

	ULONG             Policy = 0;
	ULONG             NeedPolicySize = 0;

	PREPLY_CONTEXT    ReplyContext = NULL;

	ULONG             Length;

	if (ProcessExecuteIsCanWork () == FALSE)
	{
		return;
	}

	ReplyContext = ExAllocateFromPagedLookasideList (&FsXdhyData.ReplyLookAsize);
	if (ReplyContext == NULL)
	{
		ERROR ("Ex: %08x",STATUS_INSUFFICIENT_RESOURCES);
		return;
	}
	memset (ReplyContext,0,sizeof (REPLY_CONTEXT));

	__try
	{
		switch (GetFileFileType (FullImageName))
		{
		case FILE_EXE_TYPE:
			{
				ERROR ("Ex: %wZ",FullImageName);

				Status = SendRequestToClientDpcForGetPolicy (FullImageName,FILE_EXECUTE_TYPE,PLOICY_MASK_CAN_EXECUTE,NULL,&Policy,sizeof (ULONG),&NeedPolicySize);
				if (!NT_SUCCESS (Status))
				{
					ERROR ("Ex: %08x",Status);
					__leave;
				}
				
				if (BooleanFlagOn (Policy,PLOICY_MASK_CAN_EXECUTE) == FALSE)
				{
					CliendId.UniqueProcess = ProcessId;
					Status = ZwOpenProcess (&hProcess,PROCESS_ALL_ACCESS,&oa,&CliendId);
					if (!NT_SUCCESS (Status))
					{
						ERROR ("Ex: %08x",Status);

						__leave;
					}

					ZwTerminateProcess (hProcess,STATUS_ACCESS_DENIED);
					ZwClose (hProcess);
				}

				break;
			}
		case FILE_DLL_TYPE:
			{
				ERROR ("Ex: %wZ",FullImageName);

				Status = SendRequestToClientDpcForGetPolicy (FullImageName,FILE_EXECUTE_TYPE,PLOICY_MASK_CAN_EXECUTE,NULL,ReplyContext,sizeof (REPLY_CONTEXT),&NeedPolicySize);
				if (!NT_SUCCESS (Status))
				{
					ERROR ("Ex: %08x",Status);
					__leave;
				}

				Policy = *((PULONG)ReplyContext);
				if (BooleanFlagOn (Policy,PLOICY_MASK_CAN_EXECUTE) == FALSE)
				{
					Length = 10;
					Mdl = (PMDL)KFalloc (MmSizeOfMdl (ImageInfo->ImageBase,Length));
					if (Mdl == NULL)
					{
						__leave;
					}

					MmInitializeMdl(Mdl,ImageInfo->ImageBase,Length);
					MmProbeAndLockPages (Mdl,KernelMode,IoReadAccess); 
					LockAddress = MmMapLockedPagesSpecifyCache (Mdl,KernelMode,MmCached,NULL,FALSE,NormalPagePriority);
					if (LockAddress == NULL)
					{
						MmUnlockPages (Mdl);
						__leave;
					}

					Status = MmProtectMdlSystemAddress (Mdl,PAGE_EXECUTE_READWRITE);
					if (!NT_SUCCESS (Status))
					{
						MmUnmapLockedPages (LockAddress,Mdl);
						MmUnlockPages (Mdl);
						__leave;
					}

					memset (LockAddress,0,Length);

					MmUnmapLockedPages (LockAddress,Mdl);
					MmUnlockPages (Mdl);

					NameString.MaximumLength = MAX_PATH;
					Length = wcslen ((PWCHAR)((PUCHAR)ReplyContext + sizeof (ULONG))) * sizeof (WCHAR);

					NameString.Length = (USHORT)Length;
					NameString.Buffer = KFalloc (NameString.MaximumLength);
					if (NameString.Buffer == NULL)
					{
						ERROR ("Ex: %08x",STATUS_INSUFFICIENT_RESOURCES);
						__leave;
					}
					memset (NameString.Buffer,0,NameString.MaximumLength);
					memcpy (NameString.Buffer,(PUCHAR)ReplyContext + sizeof (ULONG),NameString.Length);

					Status = FlushLoadDllCache (&NameString);
					if (!NT_SUCCESS (Status))
					{
						ERROR ("Ex: %08x",Status);
						__leave;
					}
				}

				break;
			}
		case FILE_SYS_TYPE:
			{
				ERROR ("Ex: %wZ",FullImageName);
				break;
			}
		default:
			{
				ERROR ("Ex: %wZ",FullImageName);
				break;
			}
		}

		__leave;
	}
	__finally
	{
		if (ReplyContext != NULL)
		{
			ExFreeToPagedLookasideList (&FsXdhyData.ReplyLookAsize,ReplyContext);
		}

		if (NameString.Buffer != NULL)
		{
			KFfree (NameString.Buffer);
		}

		if (Mdl != NULL)
		{
			KFfree (Mdl);
		}
	}

	return;
}

NTSTATUS RegistryCreateProcessNotify ()
{
	NTSTATUS Status = STATUS_SUCCESS;

	Status = PsSetLoadImageNotifyRoutine (ImageLoadNotify);
	if (!NT_SUCCESS (Status))
	{
		ERROR ("Ex: %08x",Status);
		return Status;
	}

	Status = PsSetCreateProcessNotifyRoutine (CreateProcessNotify,FALSE);
    if (!NT_SUCCESS (Status))
	{
		ERROR ("Ex: %08x",Status);
		PsRemoveLoadImageNotifyRoutine (ImageLoadNotify);
		return Status;
	}

	return Status;
}