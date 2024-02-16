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

#ifdef TEST_IN_RING3
#include "common_func.h"
#include "ring0_2_ring3.h"
#define ExFreePoolWithTag( pool, tag ) FREE_TAG_POOL( pool ) 
#else
#include "common.h"
#endif 

#include "infolist.h"

VOID InitSafeList( PINFO_LIST SafeList, GET_INFO_FROM_ID CreateInfoFactory )
{
	ASSERT( NULL != SafeList ); 
	InitializeListHead( &SafeList->InfoList );
	KeInitializeSpinLock( &SafeList->SpLock );
	SafeList->CreateInfoFactory = CreateInfoFactory; 
}

VOID ReleaseSafeList( PINFO_LIST SafeList )
{
	KIRQL OldIrql; 
	PLIST_ENTRY ListEntry; 
	PLIST_ENTRY ListEntryPrev; 

	ASSERT( NULL != SafeList ); 

	KeAcquireSpinLock( &SafeList->SpLock, &OldIrql ); 

	ListEntry = SafeList->InfoList.Flink; 
	
	for( ; ; )
	{
		if( ListEntry == &SafeList->InfoList )
		{
			goto _RETURN;
		}
		
		ListEntryPrev = ListEntry->Flink; 

		RemoveEntryList( ListEntry ); 
		ExFreePoolWithTag( ListEntry, 0 ); 

		ListEntry = ListEntryPrev; 
	}

_RETURN:
	KeReleaseSpinLock( &SafeList->SpLock, OldIrql ); 
	return; 
}

PINFO_HEAD FindSafeListItem( PINFO_LIST SafeList, ULONG Id, ULONG Flags )
{
	KIRQL OldIrql; 
	PLIST_ENTRY ListEntry; 
	PINFO_HEAD InfoHead; 

	ASSERT( NULL != SafeList ); 

	KeAcquireSpinLock( &SafeList->SpLock, &OldIrql ); 

	ListEntry = SafeList->InfoList.Flink; 
	
	for( ; ; )
	{
		if( ListEntry == &SafeList->InfoList )
		{
			goto NOT_EXIST;
		}

		InfoHead = ( PINFO_HEAD )ListEntry; 
		
		if( InfoHead->InfoId == Id )
		{
			goto _FOUND_EXIST; 
		}
		ListEntry = ListEntry->Flink; 
	}

_FOUND_EXIST:
	if( Flags & DEL_EXIST )
	{
		RemoveEntryList( ListEntry ); 
	}
	KeReleaseSpinLock( &SafeList->SpLock, OldIrql ); 
	return InfoHead;

NOT_EXIST:
	if( !( Flags & ADD_NEW ) )
	{
		goto _RETURN_NULL; 
	}

	if( NULL == SafeList->CreateInfoFactory )
	{
		goto _RETURN_NULL; 
	}

	{
		NTSTATUS ntstatus; 
		
		ntstatus = SafeList->CreateInfoFactory( ( ULONG )Id, &InfoHead ); 
		if( !NT_SUCCESS( ntstatus ) )
		{
			goto _RETURN_NULL; 
		}

		goto _RETURN; 
	}

_RETURN_NULL:
	KeReleaseSpinLock( &SafeList->SpLock, OldIrql ); 
	return NULL; 

_RETURN:
	KeReleaseSpinLock( &SafeList->SpLock, OldIrql ); 
	return InfoHead; 
}