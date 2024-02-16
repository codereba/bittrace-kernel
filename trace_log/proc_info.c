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
#include "proc_info.h"

KSPIN_LOCK process_info_lock;
ERESOURCE proc_info_data_lock; 
LIST_ENTRY all_process_info;

#define PROCESS_INFO_INIT_REFERRENCE 2

NTSTATUS convert_native_name_2_dos_name( LPCWSTR native_name, 
										ULONG cc_name_len, 
										LPWSTR name_output, 
										ULONG cc_buf_len, 
										ULONG *cc_ret_len ); 

NTSTATUS init_proc_info( PROCESS_INFO *proc_info, PEPROCESS eproc, ULONG flags )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG proc_name_len; 

	do 
	{
		InitializeListHead( &proc_info->entry ); 
		InitializeListHead( &proc_info->tmp_entry ); 

		proc_info->eproc = eproc;

		proc_info->proc_id = ( DWORD )PsGetProcessId( eproc ); 

		proc_info->trace_data_size = INVALID_TRACE_DATA_SIZE; 

		do 
		{
			*proc_info->proc_name = L'\0'; 
			proc_info->proc_name_len = 0;  

			proc_info->proc_name_inited = FALSE; 

			if( 0 == ( flags & NEED_RETRIEVE_PROC_NAME ) )
			{
				log_trace( ( MSG_FATAL_ERROR, "%s:%u do not need to retrieve process(%u) information flags=0x%0.8x\n", __FUNCTION__, __LINE__, 
					proc_info->proc_id, 
					flags ) ); 

				break; 
			}

			if( KeGetCurrentIrql() != PASSIVE_LEVEL )
			{
				dbg_message_ex( MSG_FATAL_ERROR, "%s:%u interrupt level too high\n", __FUNCTION__, __LINE__ ); 

				ntstatus = get_system_process_name( proc_info->proc_id, 
					proc_info->proc_name, 
					sizeof( proc_info->proc_name ), 
					&proc_name_len ); 

				if( !NT_SUCCESS( ntstatus ) 
					&& STATUS_BUFFER_TOO_SMALL != ntstatus )
				{
					dbg_message_ex( MSG_FATAL_ERROR, "%s:%u get process name information error 0x%0.8x\n", __FUNCTION__, __LINE__, ntstatus ); 
				}
				else
				{
					ASSERT( proc_name_len < ARRAYSIZE( proc_info->proc_name ) );

					proc_info->proc_name_len = ( proc_name_len >> 1 ) - 1; 
					proc_info->proc_name_inited = TRUE; 
				}

				break; 
			}

			ntstatus = _get_process_image_file_name( proc_info->proc_id, 
				proc_info->proc_name, 
				sizeof( proc_info->proc_name ), 
				&proc_name_len ); 

			if( !NT_SUCCESS( ntstatus ) 
				&& STATUS_BUFFER_TOO_SMALL != ntstatus )
			{
				dbg_message_ex( MSG_FATAL_ERROR, "%s:%u get process name information error 0x%0.8x\n", __FUNCTION__, __LINE__, ntstatus );
			}
			else if( ntstatus == STATUS_CAN_NOT_RETRIEVE_PROCESS_NAME )
			{
				dbg_message_ex( MSG_FATAL_ERROR, "%s:%u can not retrieve process name\n", __FUNCTION__, __LINE__ ); 

				proc_info->proc_name_inited = TRUE; 
			}	
			else
			{
				ASSERT( proc_name_len <= sizeof( proc_info->proc_name ) ); 

				if( L'\0' != proc_info->proc_name[ ( proc_name_len >> 1 ) - 1 ] )
				{
					if( proc_name_len + sizeof( WCHAR ) <= sizeof( proc_info->proc_name ) )
					{
						proc_info->proc_name[ ( proc_name_len >> 1 ) ] = L'\0'; 
						proc_name_len += 2; 
					}
					else
					{
						proc_info->proc_name[ ( proc_name_len >> 1 ) - 1 ] = L'\0'; 
					}
				}

				proc_info->proc_name_len = ( proc_name_len >> 1 ) - 1; 

				{
					ULONG cc_ret_len; 

					/************************************************************************
					if name converted, need change the name length.
					else name and name length must don't change anything.
					************************************************************************/

					ntstatus = convert_native_name_2_dos_name( proc_info->proc_name, 
						proc_info->proc_name_len, 
						proc_info->proc_name, 
						ARRAYSIZE( proc_info->proc_name ) - 1, 
						&cc_ret_len ); 

					if( ntstatus != STATUS_SUCCESS )
					{
						dbg_message_ex( MSG_FATAL_ERROR, "convert the native name of the process to dos name error(%ws:%u)\n", 
							proc_info->proc_name, 
							proc_info->proc_name_len );
					}
					else
					{
						proc_info->proc_name[ cc_ret_len ] = L'\0'; 
						proc_info->proc_name_len = cc_ret_len; 
					}
				}

				proc_info->proc_name_inited = TRUE; 
			
				log_trace( ( MSG_INFO, "%s: prcess name was %ws\n", __FUNCTION__, proc_name ) ); 
				
				if( proc_info->proc_name[ 0 ] == L'\0' )
				{
					dbg_message_ex( MSG_FATAL_ERROR, "process name is retrieved but which is still null (%u)\n", 
						proc_info->proc_name_len ); 
				}
			}
		}while( FALSE ); 

		proc_info->ref_count = PROCESS_INFO_INIT_REFERRENCE;

	}while( FALSE );

	return ntstatus; 
}

NTSTATUS retrieve_proc_name_info( PROCESS_INFO *proc_info )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG proc_name_len; 
	LPWSTR proc_name = NULL; 

	do 
	{
		if( proc_info->proc_name_inited == TRUE )
		{
			break; 
		}

		if( KeGetCurrentIrql() > PASSIVE_LEVEL )
		{
			dbg_message_ex( MSG_FATAL_ERROR, "%s:%u interrupt level too high\n", __FUNCTION__, __LINE__ ); 

			ntstatus = get_system_process_name( proc_info->proc_id, 
				proc_info->proc_name, 
				sizeof( proc_info->proc_name ), 
				&proc_name_len ); 

			if( !NT_SUCCESS( ntstatus ) 
				&& STATUS_BUFFER_TOO_SMALL != ntstatus )
			{
				dbg_message_ex( MSG_FATAL_ERROR, "%s:%u get process name information error 0x%0.8x\n", __FUNCTION__, __LINE__, ntstatus ); 
			}
			else
			{
				ASSERT( proc_name_len < ARRAYSIZE( proc_info->proc_name ) );

				proc_info->proc_name_len = ( proc_name_len >> 1 ) - 1; 
				proc_info->proc_name_inited = TRUE; 
			}
			break; 
		}
		
		proc_name = ( LPWSTR )ALLOC_PAGED_TAG_POOL( sizeof( proc_info->proc_name ) ); 
		if( NULL == proc_name )
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			break; 
		}

		ntstatus = _get_process_image_file_name( proc_info->proc_id, 
			proc_name, 
			sizeof( proc_info->proc_name ), 
			&proc_name_len ); 

		if( !NT_SUCCESS( ntstatus ) 
			&& STATUS_BUFFER_TOO_SMALL != ntstatus )
		{
			dbg_message_ex( MSG_FATAL_ERROR, "%s:%u retrieve process(%u) name error(%u)\n", __FUNCTION__, __LINE__, 
				proc_info->proc_id, 
				proc_name_len );
		}
		else if( ntstatus == STATUS_CAN_NOT_RETRIEVE_PROCESS_NAME )
		{
			if( proc_name[ 0 ] == L'\0' )
			{
				dbg_message_ex( MSG_FATAL_ERROR, "%s:%u process name can not retrieve(%u)\n", __FUNCTION__, __LINE__, 
					proc_name_len ); 
			}

			*proc_info->proc_name = L'\0'; 
			proc_info->proc_name_inited = TRUE; 
		}	
		else
		{
			ASSERT( proc_name_len <= sizeof( proc_info->proc_name ) );

			hold_w_res_lock( proc_info_data_lock ); 

			memcpy( proc_info->proc_name, 
				proc_name, 
				proc_name_len ); 

			release_res_lock( proc_info_data_lock ); 

			if( L'\0' != proc_info->proc_name[ ( proc_name_len >> 1 ) - 1 ] )
			{
				ASSERT( ntstatus == STATUS_BUFFER_TOO_SMALL ); 

				if( proc_name_len + sizeof( WCHAR ) <= sizeof( proc_info->proc_name ) )
				{
					proc_info->proc_name[ ( proc_name_len >> 1 ) ] = L'\0'; 
					proc_name_len += 2; 
				}
				else
				{
					proc_info->proc_name[ ( proc_name_len >> 1 ) - 1 ] = L'\0'; 
				}
			}

			proc_info->proc_name_len = ( proc_name_len >> 1 ) - 1; 

			{
				ULONG cc_ret_len;

				/************************************************************************
				if name converted, need change the name length.
				else name and name length must don't change anything.
				************************************************************************/

				ntstatus = convert_native_name_2_dos_name( proc_info->proc_name, 
					proc_info->proc_name_len, 
					proc_info->proc_name, 
					ARRAYSIZE( proc_info->proc_name ) - 1, 
					&cc_ret_len ); 

				if( ntstatus != STATUS_SUCCESS )
				{
					dbg_message_ex( MSG_FATAL_ERROR, "%s:%u convert the native name of the process to dos name error(%ws:%u)\n", 
						__FUNCTION__, 
						__LINE__, 
						proc_info->proc_name, 
						proc_info->proc_name_len );
				}
				else
				{
					proc_info->proc_name[ cc_ret_len ] = L'\0'; 
					proc_info->proc_name_len = cc_ret_len; 
				}

				if( proc_info->proc_name[ 0 ] == L'\0' )
				{
					dbg_message_ex( MSG_FATAL_ERROR, "%s:%u process name is retrieve but which is still null (%u)\n", __FUNCTION__, __LINE__, 
						proc_info->proc_name_len ); 
				}
			}

			proc_info->proc_name_inited = TRUE; 

			log_trace( ( MSG_INFO, "%s: process name was %ws\n", __FUNCTION__, proc_info->proc_name ) ); 
		}
	}while( FALSE ); 

	if( NULL != proc_name )
	{
		FREE_TAG_POOL( proc_name ); 
	}

	return ntstatus; 
}

DWORD release_proc_info( PROCESS_INFO *proc_info )
{
	NTSTATUS ntstatus;
	ULONG ref_count;

	ASSERT( NULL != proc_info );
	ASSERT( TRUE == MmIsAddressValid( proc_info ) );

	log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

	ref_count = InterlockedExchangeAdd( &proc_info->ref_count, -1 );

	if( 1 == ref_count )
	{
		ASSERT( IsListEmpty( &proc_info->entry ) == TRUE );
		FREE_TAG_POOL( proc_info );
	}
	else
	{
		ASSERT( ref_count > 1 );
	}

	log_trace( ( MSG_INFO, "leave %s\n", __FUNCTION__ ) );
	return ref_count - 1;
}

NTSTATUS dump_all_proc_infos()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	PLIST_ENTRY entry; 
	BOOLEAN lock_held = FALSE; 
	KIRQL old_irql; 
	PROCESS_INFO *proc_info; 
	LIST_ENTRY proc_infos; 

	do 
	{
		InitializeListHead( &proc_infos ); 

		hold_sp_lock( process_info_lock, old_irql );
		lock_held = TRUE; 

		entry = all_process_info.Flink;

		for ( ; ; )
		{
			if( entry == &all_process_info )
			{
				break;
			}

			proc_info = CONTAINING_RECORD( entry, PROCESS_INFO, entry ); 

			ASSERT( proc_info->ref_count >= 1 ); 
			InterlockedExchangeAdd( &proc_info->ref_count, 1 ); 

			InsertHeadList( &proc_infos, &proc_info->tmp_entry ); 

			entry = entry->Flink;
		}

		release_sp_lock( process_info_lock, old_irql ); 
		lock_held = FALSE; 

		entry = proc_infos.Flink; 

		for( ; ; )
		{
			if( entry == &proc_infos )
			{
				break; 
			}
			
			RemoveEntryList( entry ); 

			proc_info = CONTAINING_RECORD( entry, PROCESS_INFO, tmp_entry ); 

			dbg_message_ex( MSG_IMPORTANT, "****\nentry %p:%p\nreference count %u\neprocess %p\nprocess id %u\nimage file name initialized:%u\nimage file name:%ws\n name length %u\ntrace data size:%u\n*****\n", 
				proc_info->entry.Flink, 
				proc_info->entry.Blink, 
				proc_info->ref_count, 
				proc_info->eproc, 
				proc_info->proc_id, 
				proc_info->proc_name_inited, 
				proc_info->proc_name_inited == TRUE ? proc_info->proc_name : L"", 
				proc_info->proc_name_len, 
				proc_info->trace_data_size ); 

			release_proc_info( proc_info ); 
		}

	}while( FALSE );

	return ntstatus; 
}

PROCESS_INFO* get_proc_info( PEPROCESS eproc, ULONG flags, ULONG *status ) 
{
	KIRQL old_irql;
	PLIST_ENTRY entry;
	PROCESS_INFO* proc_info = NULL;
	PROCESS_INFO* new_proc_info = NULL;
	BOOLEAN lock_held = FALSE; 

	ASSERT( NULL != eproc ); 
	if( status != NULL )
	{
		*status = 0; 
	}

	if ( NULL == eproc )
	{
		dbg_print( MSG_FATAL_ERROR, "%s eprocess is null\n", __FUNCTION__ ); 
		return NULL;
	}

	hold_sp_lock( process_info_lock, old_irql );
	lock_held = TRUE; 

	entry = all_process_info.Flink;

	for ( ; ; )
	{
		if( entry == &all_process_info )
		{
			proc_info = NULL; 
			break;
		}

		proc_info = ( PROCESS_INFO* )entry;

		{
			if( proc_info->eproc == eproc )
			{
				ASSERT( proc_info->ref_count >= 1 );

				if( proc_info->proc_id == 0 )
				{
					proc_info->proc_id = ( ULONG )PsGetProcessId( eproc ); 
				}

				InterlockedExchangeAdd( &proc_info->ref_count, 1 ); 

				release_sp_lock( process_info_lock, old_irql ); 
				lock_held = FALSE; 

				if( flags & NEED_RETRIEVE_PROC_NAME )
				{
					retrieve_proc_name_info( proc_info ); 
				}

				goto _return; 
			}
		}

		entry = entry->Flink;
	}

	release_sp_lock( process_info_lock, old_irql ); 
	lock_held = FALSE; 

	new_proc_info = ( PROCESS_INFO* )ALLOC_TAG_POOL( sizeof( PROCESS_INFO ) );
	if( NULL == new_proc_info )
	{
		dbg_print( MSG_FATAL_ERROR, "%s allocate process information error\n", __FUNCTION__ ); 
		goto _return;
	}

	init_proc_info( new_proc_info, eproc, flags ); 

	hold_sp_lock( process_info_lock, old_irql ); 
	lock_held = TRUE; 

	entry = all_process_info.Flink;

	for ( ; ; )
	{
		if( entry == &all_process_info )
		{
			InsertHeadList( &all_process_info, &new_proc_info->entry );	
			break;
		}

		proc_info = ( PROCESS_INFO* )entry; 

		if( proc_info->eproc == eproc )
		{
			ASSERT( proc_info->ref_count >= 1 );

			if( proc_info->proc_id == 0 )
			{
				proc_info->proc_id = ( ULONG )PsGetProcessId( eproc ); 
			}

			InterlockedExchangeAdd( &proc_info->ref_count, 1 ); 

			release_sp_lock( process_info_lock, old_irql ); 
			lock_held = FALSE; 

			if( flags & NEED_RETRIEVE_PROC_NAME )
			{
				retrieve_proc_name_info( proc_info ); 
			}

			goto _return; 
		}

		entry = entry->Flink;
	}

	release_sp_lock( process_info_lock, old_irql );
	lock_held = FALSE; 

	log_trace( ( PROCESS_NEW_IO_INFO, "netmon Insert new process io information 0x%0.8x \n", new_proc_info ) );

	if( status != NULL )
	{
		*status = CREATE_NEW_PROCESS_INFO; 
	}

	proc_info = new_proc_info; 
	new_proc_info = NULL; 

_return:
	if( lock_held == TRUE )
	{
		release_sp_lock( process_info_lock, old_irql );
	}

	//if( proc_info == NULL )
	//{
	if( NULL != new_proc_info )
	{
		dbg_message_ex( MSG_IMPORTANT, "process information for %p already inserted\n", eproc ); 

		FREE_TAG_POOL( new_proc_info );
	}
	//}

	return proc_info;
}

NTSTATUS reset_proc_name_record( PEPROCESS eproc ) 
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	KIRQL old_irql;
	PLIST_ENTRY entry;
	PROCESS_INFO* proc_info = NULL;
	BOOLEAN lock_held = FALSE; 

	ASSERT( NULL != eproc );

	if ( NULL == eproc )
	{
		dbg_message_ex( MSG_FATAL_ERROR, "%s eprocess is null\n", __FUNCTION__ ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	hold_sp_lock( process_info_lock, old_irql );
	lock_held = TRUE; 

	entry = all_process_info.Flink;

	for ( ; ; )
	{
		if( entry == &all_process_info )
		{
			ntstatus = STATUS_NOT_FOUND; 
			break;
		}

		proc_info = ( PROCESS_INFO* )entry;

		{
			if( proc_info->eproc == eproc )
			{
				ASSERT( proc_info->ref_count >= 1 ); 

				proc_info->proc_name_inited = FALSE; 

				release_sp_lock( process_info_lock, old_irql ); 
				lock_held = FALSE; 

				goto _return; 
			}
		}

		entry = entry->Flink;
	}

	release_sp_lock( process_info_lock, old_irql ); 
	lock_held = FALSE; 

_return:
	if( lock_held == TRUE )
	{
		release_sp_lock( process_info_lock, old_irql );
	}

	return ntstatus;
}

PROCESS_INFO* get_proc_info_by_proc_id( ULONG proc_id )
{
	KIRQL old_irql;
	PLIST_ENTRY entry;
	PROCESS_INFO* proc_info = NULL;
	BOOLEAN lock_held = FALSE; 

	ASSERT( 0xffffffff != proc_id );

	hold_sp_lock( process_info_lock, old_irql );
	lock_held = TRUE; 

	_try
	{
		entry = all_process_info.Flink;

		for ( ; ; )
		{
			if( entry == &all_process_info )
			{
				proc_info = NULL; 
				break;
			}

			proc_info = ( PROCESS_INFO* )entry;

			if( proc_info->proc_id == 0 )
			{
				ASSERT( proc_info->eproc != NULL ); 
				proc_info->proc_id = ( ULONG )PsGetProcessId( proc_info->eproc ); 
			}

			if( proc_info->proc_id == proc_id )
			{
				ASSERT( proc_info->ref_count >= 1 );

				InterlockedExchangeAdd( &proc_info->ref_count, 1 );
				goto _return; 
			}

			entry = entry->Flink;
		}

		release_sp_lock( process_info_lock, old_irql ); 
		lock_held = FALSE; 
	}
	_except( EXCEPTION_EXECUTE_HANDLER )
	{
	}

_return:
	if( lock_held == TRUE )
	{
		release_sp_lock( process_info_lock, old_irql );
	}

	return proc_info;
}

NTSTATUS release_all_proc_info()
{
	NTSTATUS ntstatus = STATUS_SUCCESS;
	LIST_ENTRY *entry; 
	PROCESS_INFO *proc_info; 
	KIRQL irql; 

	log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

	hold_sp_lock( process_info_lock, irql ); 

	for( ; ; )
	{
		entry = all_process_info.Flink; 

		if( entry == &all_process_info )
		{
			break; 
		}

		RemoveEntryList( entry ); 

		proc_info = ( PROCESS_INFO* )CONTAINING_RECORD( entry, PROCESS_INFO, entry ); 

#ifdef DBG
		{
			ULONG ref_count;
			ref_count = proc_info->ref_count; //InterlockedExchangeAdd( &proc_traffic->ref_count, -1 );

			log_trace( ( MSG_INFO, "release the traffic record of one process 0x%0.8x, its reference count is %u\n", 
				proc_info, 
				ref_count ) ); 
		}
#endif //DBG

		FREE_TAG_POOL( proc_info ); 
	}
	
	release_sp_lock( process_info_lock, irql ); 

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) );
	return ntstatus;
}

NTSTATUS find_proc_info_lock_free( ULONG proc_id, PROCESS_INFO** found )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	PROCESS_INFO* proc_info; 
	PLIST_ENTRY entry; 

	log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

	ASSERT( found != NULL );

	entry = all_process_info.Flink;

	for( ; ; )
	{
		if( entry == &all_process_info )
		{
			ntstatus = STATUS_NOT_FOUND; 
			proc_info = NULL; 
			break;
		}

		proc_info = ( PROCESS_INFO* )CONTAINING_RECORD( 
			entry, 
			PROCESS_INFO, 
			entry ); 

		log_trace( ( PROCESS_START_THREAD_INFO, 
			"target process id %d, current process id %d\n", 
			proc_id, 
			proc_info->proc_id ) );

		if( proc_info->proc_id == 0 )
		{
			ASSERT( proc_info->eproc != NULL ); 
			proc_info->proc_id = ( ULONG )PsGetProcessId( proc_info->eproc ); 
		}

		if( proc_id = proc_info->proc_id )
		{
			break; 
		}

		entry = entry->Flink;
	}

	*found = proc_info; 

	return ntstatus;
}

NTSTATUS remove_all_proc_info( IN HANDLE proc_id )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	NTSTATUS _ntstatus; 
	KIRQL old_irql;
	ULONG ref_count; 
	PROCESS_INFO *proc_info; 
	ULONG found_count; 
	BOOLEAN lock_held = FALSE; 

	do 
	{
		// remove entry from plist

		log_trace( ( MSG_INFO, "ProcessNotifyProc: remove process with proc_id:%u\n", proc_id ) );

		hold_sp_lock( process_info_lock, old_irql ); 

		lock_held = TRUE; 

		found_count = 0; 
		for( ; ; )
		{
			_ntstatus = find_proc_info_lock_free( ( ULONG )proc_id, &proc_info ); 

			if( !NT_SUCCESS( _ntstatus ) )
			{
				break; 
			}

			found_count ++;

			ASSERT( proc_info != NULL ); 

			RemoveEntryList( &proc_info->entry ); 

#ifdef DBG
			log_trace( ( MSG_INFO, "process %ws is removing\n", proc_info->proc_name ) ); 
#endif //DBG

			ref_count = InterlockedExchangeAdd( &proc_info->ref_count, -1 );
			if ( 1 == ref_count )
			{
				FREE_TAG_POOL( proc_info );
			}
			else
			{
				ASSERT( ref_count > 1 );
			}
		}

		if( found_count == 0 )
		{
			ntstatus = STATUS_NOT_FOUND; 
		}
		else if( found_count > 1 )
		{
			dbg_message_ex( MSG_IMPORTANT, "found the same process id %u more time %u\n", proc_id, found_count ); 
		}

	}while( FALSE );

	if( lock_held == TRUE )
	{
		release_sp_lock( process_info_lock, old_irql ); 
	}

	return ntstatus; 
}

NTSTATUS remove_proc_info( IN HANDLE proc_id )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	KIRQL old_irql;
	ULONG ref_count; 
	PROCESS_INFO *proc_info; 
	BOOLEAN lock_held = FALSE; 

	do 
	{
		// remove entry from plist

		log_trace( ( MSG_INFO, "ProcessNotifyProc: remove process with proc_id:%u\n", proc_id ) );

		hold_sp_lock( process_info_lock, old_irql ); 

		lock_held = TRUE; 

		ntstatus = find_proc_info_lock_free( ( ULONG )proc_id, &proc_info ); 

		if( !NT_SUCCESS( ntstatus ) )
		{
			break; 
		}

		ASSERT( proc_info != NULL ); 

		RemoveEntryList( &proc_info->entry ); 

#ifdef DBG
		log_trace( ( MSG_INFO, "process %ws is removing\n", proc_info->proc_name ) ); 
#endif //DBG

		ref_count = InterlockedExchangeAdd( &proc_info->ref_count, -1 );
		if ( 1 == ref_count )
		{
			FREE_TAG_POOL( proc_info );
		}
		else
		{
			ASSERT( ref_count > 1 );
		}
	}while( FALSE );

	if( lock_held == TRUE )
	{
		release_sp_lock( process_info_lock, old_irql ); 
	}

	return ntstatus; 
}

NTSTATUS init_proc_info_manage()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	KeInitializeSpinLock( &process_info_lock ); 
	InitializeListHead( &all_process_info ); 
	ntstatus = init_res_lock( &proc_info_data_lock ); 

	return ntstatus; 
}

NTSTATUS uninit_proc_info_manage()
{
	release_all_proc_info(); 
	uninit_res_lock( &proc_info_data_lock ); 

	return STATUS_SUCCESS; 
}