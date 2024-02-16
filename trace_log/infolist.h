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

#ifndef __INFO_LIST_H__
#define __INFO_LIST_H__

#define ADD_NEW 0x01
#define DEL_EXIST 0x02 

typedef NTSTATUS ( *GET_INFO_FROM_ID )( ULONG Id, PINFO_HEAD *InfoHead ); 

typedef struct __INFO_LIST
{
	LIST_ENTRY InfoList; 
	KSPIN_LOCK SpLock; 
	GET_INFO_FROM_ID CreateInfoFactory;
} INFO_LIST, *PINFO_LIST; 

INLINE VOID AddSafeListItem( PINFO_LIST SafeList, PINFO_HEAD Info )
{
	KIRQL OldIrql; 

	KeAcquireSpinLock( &SafeList->SpLock, &OldIrql ); 

	InsertHeadList( &SafeList->InfoList, ( PLIST_ENTRY )Info ); 

	KeReleaseSpinLock( &SafeList->SpLock, OldIrql ); 
}

INLINE VOID DelSafeListItem( PINFO_LIST SafeList, PINFO_HEAD Info )
{
	KIRQL OldIrql; 

	KeAcquireSpinLock( &SafeList->SpLock, &OldIrql ); 

	RemoveEntryList( &Info->ListEntry ); 

	KeReleaseSpinLock( &SafeList->SpLock, OldIrql ); 
	
	ExFreePoolWithTag( Info, 0 ); 
}

VOID InitSafeList( PINFO_LIST SafeList, GET_INFO_FROM_ID CreateInfoFactory );
VOID ReleaseSafeList( PINFO_LIST SafeList );
PINFO_HEAD FindSafeListItem( PINFO_LIST SafeList, ULONG Id, ULONG Flags );

#endif //__INFO_LIST_H__
