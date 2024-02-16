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
#define release_pool( mem ) free( mem )
#define alloc_pool( type, size ) malloc( size )
#define KeSetEvent( event, alertable, reason )
#define KeInitializeEvent( event, type, manual ) 
#define KeWaitForSingleObject( a, b, c, d, e ) STATUS_SUCCESS
#define ObReferenceObjectByHandle( a, b, c, d, e, f ) STATUS_SUCCESS
#define ObReferenceObjectByHandleWithTag( a, b, c, d, e, f, g ) STATUS_SUCCESS
#define ObDereferenceObjectWithTag( a, b )
#define ObDereferenceObject( a ) 
#define ExFreePoolWithTag( pool, tag ) FREE_TAG_POOL( pool ) 
#include "trace_log_api.h"

INLINE NTSTATUS __allocate_relating_data( HANDLE proc_handle, /*ULONG protect, */data_alloc_mode mode, ULONG data_len, relating_data *data_buf_out )
{
	return STATUS_SUCCESS; 
}

#else
#include "common.h"
#endif //TEST_IN_RING3

#include "Ntstrsafe.h"
#include "trace_log_api.h"
#include "hash_table.h"
#include "data_flow_trace.h"
#include "notify_event.h" 
#include "flt_msg.h"
#include "cbuffer.h"
#include "r3_shared_vm.h"
#include "r3_shared_cbuffer.h"
#include "unit_cbuffer.h"

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
extern r3_shared_cbuf all_r3_cbuf[ MAX_R3_CBUFFER_TYPE ];  
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

common_hash_table data_flow_trace; 

#define is_valid_tracing_level( level ) ( level >= MESSAGE_TRACING && level < MAX_TRACING_LEVEL )

BOOLEAN output_log_to_cbuffer = FALSE; 

NTSTATUS filter_trace_data( ULONG proc_id, ULONG thread_id, TRACING_LEVEL level, OUT data_trace_option *option )
{
	ASSERT( option != NULL ); 
	ASSERT( TRUE == is_valid_tracing_level( level ) ); 
	option->tracing_size = 0; 

	return STATUS_NOT_FOUND; 
}

INLINE VOID init_flt_settings( PMSG_FLT_SETTINGS settings )
{
	settings->flt_lvl = common_flt; 
	settings->proc_id = PROC_ID_NONE; 
	settings->thread_id = THREAD_ID_NONE; 
	*settings->proc_name = '\0'; 
}

INLINE INT32 flt_settings_same( PMSG_FLT_SETTINGS flt_setting, ULONG flt_lvl, ULONG proc_id, ULONG thread_id, WCHAR *proc_name )
{
	INT32 ret = FALSE; 
	ASSERT( flt_setting != NULL ); 

	if( proc_name == NULL && proc_id == PROC_ID_NONE )
	{
		goto _return; 
	}

	if( flt_setting->proc_id != proc_id )
	{
		goto _return; 
	}

	if( flt_setting->thread_id != thread_id )
	{
		goto _return; 
	}

	if( proc_name != NULL )
	{
		if( 0 != wcsncmp( flt_setting->proc_name, proc_name, NT_PROCNAMELEN ) )
		{
			goto _return; 
		}
	}

	ret = TRUE; 

_return:
	return ret; 
}

INLINE INT32 trace_log_same( PUNI_TRACE trace_log, ULONG name )
{

	ASSERT( trace_log != NULL ); 

	return trace_log->name == name; 
}

PUNI_TRACE find_trace_log( ULONG name )
{
	PLIST_ENTRY entry; 
	ULONG hash_code; 

	hash_code = calc_flt_name_hash_code( name ); 

	ASSERT( hash_code < data_flow_trace.size ); 

	hold_hash_table_r_lock( &data_flow_trace ); 

	entry = data_flow_trace.hash_table[ hash_code ].Flink; 

	for( ; ; )
	{
		if( entry == &data_flow_trace.hash_table[ hash_code ] )
		{
			entry = NULL; 
			break; 
		}

		if( trace_log_same( ( PUNI_TRACE )entry, name ) == TRUE )
		{
			break; 
		}
	}

	release_hash_table_lock( &data_flow_trace ); 

	return ( PUNI_TRACE )entry; 
}

INLINE PUNI_TRACE find_trace_log_unlocked( ULONG name )
{
	KIRQL old_irql; 
	PLIST_ENTRY entry; 
	ULONG hash_code; 

	hash_code = calc_flt_name_hash_code( name ); 

	ASSERT( hash_code < data_flow_trace.size ); 

	entry = data_flow_trace.hash_table[ hash_code ].Flink; 

	for( ; ; )
	{
		if( entry == &data_flow_trace.hash_table[ hash_code ] )
		{
			entry = NULL; 
			break; 
		}

		if( trace_log_same( ( PUNI_TRACE )entry, name ) == TRUE )
		{
			break; 
		}
	}

	return ( PUNI_TRACE )entry; 
}

INLINE PUNI_TRACE _find_trace_log( ULONG name )
{
	return find_trace_log_unlocked( name ); 
}

ULONG calc_flt_setting_hash_code( ULONG proc_id, ULONG thread_id, CHAR *proc_name )
{
	ULONG hash_code; 
	INT32 i; 

	ASSERT( data_flow_trace.size > 0 ); 
	if( proc_id != PROC_ID_NONE )
	{
		hash_code = proc_id % data_flow_trace.size; 
	}
	else if ( thread_id != THREAD_ID_NONE )
	{
		hash_code = thread_id % data_flow_trace.size; 
	}
	else if( proc_name != NULL )
	{
		ULONG proc_name_len; 

		hash_code = 0; 

		for( i = 0; i < sizeof( ULONG ); i ++ )
		{
			if( proc_name[ i ] == '\0')
			{
				break; 
			}

			hash_code |= proc_name[ i ] << ( ( sizeof( ULONG ) - i - 1 ) * 8 ); 
		}

		DUMP_MEM( proc_name, strlen( proc_name ) ); 
		DBGPRINT( ( "flt proc name is %s, hash code is 0x%0.8x \n", proc_name, hash_code ) ); 

		hash_code = hash_code % data_flow_trace.size; 
	}

	return hash_code; 
}

INLINE NTSTATUS init_trace_env()
{
	return init_common_hash_table_def_lock( &data_flow_trace, LOGGER_HASH_TABLE_SIZE ); 
}

ULONG calc_flt_name_hash_code( ULONG name )
{
	return name % data_flow_trace.size; ; 
}

ULONG calc_flt_id_hash_code( ULONG flt_id )
{
	ULONG hash_code; 

	hash_code = flt_id % data_flow_trace.size; 

	return hash_code; 
}

NTSTATUS del_trace_log( ULONG logger_name )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	PUNI_TRACE trace_log; 

	ntstatus = hold_hash_table_lock( &data_flow_trace ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	trace_log = find_trace_log_unlocked( logger_name ); 

	if( trace_log == NULL )
	{
		ntstatus = STATUS_NOT_FOUND; 
		release_hash_table_lock( &data_flow_trace ); 		
		goto _return; 
	}

	RemoveEntryList( &trace_log->entry ); 

	data_flow_trace.count --; 
	release_hash_table_lock( &data_flow_trace ); 

	release_trace_logger( &trace_log->entry ); 

_return:
	return ntstatus; 
}

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
#ifdef DRIVER
#ifdef SUPPORT_LOGGER_FILTER
NTSTATUS add_new_log( ULONG logger_name, FLT_LEVEL flt_lvl, action_context *context, sys_action_desc *cur_action, PVOID data, ULONG data_len, ULONG flags )
#else
NTSTATUS add_new_log( ULONG logger_name, 
					 action_context *context, 
					 sys_action_desc *cur_action, 
					 //HANDLE data_out_proc, 
					 PVOID data, 
					 ULONG data_len, 
					 ULONG flags )
#endif //SUPPORT_LOGGER_FILTER
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 flted; 
	PUNI_TRACE trace_logger; 
	PTRACE_LOGGER logger; 
	POOL_TYPE alloc_pool_type; 
	BOOLEAN log_added = FALSE;

#ifdef DBG
	KIRQL irql;
#endif //DBG

	DBGPRINT( ( "enter %s \n", __FUNCTION__ ) ); 

	ASSERT( context != NULL ); 
	ASSERT( cur_action != NULL ); 

	trace_logger = find_trace_log( logger_name ); 
	if( trace_logger == NULL )
	{
		ntstatus = STATUS_NOT_FOUND; 
		goto _return; 
	}

	logger = &trace_logger->logger; 

	if( logger->trace_log_count >= MAX_TRACE_MSG_COUNT )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		goto _return;
	}

#ifdef SUPPORT_LOGGER_FILTER

	if( logger_name == TRACE_LOGGER_SYSTEM )
	{
		flted = flt_msg( &trace_logger->flt_setting, context->proc_id, context->thread_id, context->proc_name ); 
		if( flted == FALSE )
		{
			ntstatus = STATUS_UNSUCCESSFUL; 
			goto _return; 
		}	
	}

#endif //SUPPORT_LOGGER_FILTER

	if( data == NULL )
	{
		if( data_len != 0 )
		{
			ASSERT( FALSE && "data is null but still have length?" ); 
			data_len = 0; 
		}
	}
#ifdef DBG
	else
	{
		if( data_len == 0 )
		{
			ASSERT( FALSE && "data is null but have not length?" ); 
		
			data = NULL; 
		}
	}
#endif //DBG

	if( data_len > DEFAULT_OUTPUT_DATA_REGION_SIZE )
	{
		data_len = DEFAULT_OUTPUT_DATA_REGION_SIZE;
	}

#ifdef DBG
	irql = KeGetCurrentIrql(); 
#endif //DBG

#define SUPPORT_RING3_CBUFFER 1

#ifdef SUPPORT_RING3_CBUFFER
	if( output_log_to_cbuffer == TRUE )
	{
		if( data_len > 0 )
		{
			ASSERT( data != NULL );
			if( flags & NEED_COPY_DATA )
			{
				do
				{
#ifdef DBG
					if( all_r3_cbuf[ SYS_LOG_BUF ].cbuf.cbuf == NULL )
					{
						ASSERT( FALSE ); 
						break; 
					}
#endif //DBG

					ntstatus = safe_cbuffer_write_from_datas( &all_r3_cbuf[ SYS_LOG_BUF ].cbuf, cur_action, sizeof( sys_action_desc ), data, data_len ); 
					if( ntstatus != STATUS_SUCCESS )
					{
						break; 
					}

					log_added = TRUE; 

#ifdef ACTION_LOG_ALLOC_FROM_R3_MAPPED_BUF
					action_log->desc.data.data_off = ( ULONG_PTR )sizeof( action_trace_log ); 
					action_log->desc.data.data_len = data_len; 
					action_log->desc.data.mode = DATA_BUF_NONE; 
#endif //ACTION_LOG_ALLOC_FROM_R3_MAPPED_BUF

				}while( FALSE );
			}
			else 
			{
				ASSERT( FALSE ); 

				ntstatus = STATUS_NOT_IMPLEMENTED; 
				goto _return; 
			}

		}
		else
		{
			do 
			{
#ifdef DBG
				if( all_r3_cbuf[ SYS_LOG_BUF ].cbuf.cbuf == NULL )
				{
					ASSERT( FALSE ); 
					break; 
				}
#endif //DBG
				ntstatus = safe_cbuffer_write_from_datas( &all_r3_cbuf[ SYS_LOG_BUF ].cbuf, cur_action, sizeof( sys_action_desc ), NULL, 0 ); 
				if( ntstatus != STATUS_SUCCESS )
				{
					break; 
				}

				log_added = TRUE; 

			}while( FALSE );
		}

		if( log_added == TRUE )
		{
			signal_notify_event( SYS_LOG_EVENT ); 
		}
#endif //SUPPORT_RING3_CBUFFER

	}
	else
	{
		action_trace_log *action_log = NULL; 

		do 
		{
			if( KeGetCurrentIrql() >= DISPATCH_LEVEL )
			{
				action_log = ( action_trace_log* )alloc_pool( NonPagedPool, 
					sizeof( action_trace_log ) + DEFAULT_OUTPUT_DATA_REGION_SIZE );
			}
			else
			{
				action_log = ( action_trace_log* )alloc_pool( PagedPool, 
					sizeof( action_trace_log ) + DEFAULT_OUTPUT_DATA_REGION_SIZE );
			}

			if( action_log == NULL )
			{
				ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
				goto _return; 
			}
			action_log->action_output.magic = SYS_ACTION_OUTPUT_MAGIC; 
			action_log->action_output.size = calc_action_output_size( data_len ); 

			memcpy( &action_log->action_output.action, 
				cur_action, 
				sizeof( sys_action_desc ) ); 

			if( data_len > 0 )
			{
				memcpy( action_log->action_output.data, data, data_len ); 
			}

			ntstatus = hold_hash_table_lock( &data_flow_trace ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				goto _return; 
			}

			ASSERT( logger != NULL ); 

			InsertHeadList( &logger->trace_logs, &action_log->entry ); 

			release_hash_table_lock( &data_flow_trace ); 

			logger->trace_log_count ++;

			log_added  = TRUE; 

			signal_notify_event( SYS_LOG_EVENT ); 

		}while( FALSE );

		if( ntstatus != STATUS_SUCCESS )
		{
			if( action_log != NULL )
			{
#ifdef DBG
				if( TRUE == log_added )
				{
					ASSERT( FALSE && "release logged data buffer" ); 
				}
#endif //DBG

				free_pool( action_log ); 
				//free_action_log( data_out_proc, action_log ); 
			}
		}
	}

	//KdPrint( ( "Add trace msg: %s, %d \n", TraceMsg->TraceMsg, TraceMsg->Length ) ); 

_return:

	DBGPRINT( ( "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 
	return ntstatus; 
}

#endif //DRIVER
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

NTSTATUS reference_trace_logger( PUNI_TRACE trace_logger, PMSG_FLT setting )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	if( trace_logger->flt_setting.ref_count == MAX_TRACE_LOGGER_REF_NUM )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		goto _return; 
	}

	trace_logger->flt_setting.release_notify[ trace_logger->flt_setting.ref_count ] = setting->release_notify_func; 
	trace_logger->flt_setting.ref_count ++; 

_return:
	return ntstatus; 
}

NTSTATUS _get_trace_logger( PMSG_FLT logger_setting, PULONG logger_id )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	PUNI_TRACE trace_log; 

	*logger_id = LOGGER_ID_NONE; 
	hold_hash_table_r_lock( &data_flow_trace ); 
	trace_log = find_trace_log_unlocked( logger_setting->name ); 

	if( trace_log == NULL )
	{
		ntstatus = STATUS_NOT_FOUND; 
		release_hash_table_lock( &data_flow_trace ); 		
		goto _return; 
	}

	//error: can't reference the object, if not have write lock.

	ntstatus = reference_trace_logger( trace_log, logger_setting ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		release_hash_table_lock( &data_flow_trace ); 
		goto _return; 
	}

	release_hash_table_lock( &data_flow_trace ); 

	*logger_id = trace_log->id; 
_return:
	return ntstatus; 
}

NTSTATUS set_trace_setting( ULONG flt_lvl, ULONG proc_id, ULONG thread_id, WCHAR *proc_name, release_flt_notify_func release_notify, ULONG logger_name )
{
	PUNI_TRACE logger; 
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	logger = find_trace_log( logger_name ); 
	if( logger == NULL )
	{
		ntstatus = STATUS_NOT_FOUND; 
		goto _return; 
	}

	if( logger->flt_setting.flt_lvl != flt_lvl )
	{
		logger->flt_setting.flt_lvl = ( FLT_LEVEL )flt_lvl; 
	}

	if( logger->flt_setting.proc_id != proc_id )
	{
		logger->flt_setting.proc_id = proc_id; 
	}

	if( logger->flt_setting.thread_id != thread_id )
	{
		logger->flt_setting.thread_id = thread_id; 
	}

	if( proc_name == NULL )
	{
		logger->flt_setting.proc_name[ 0 ] = L'\0'; 
	}
	else
	{
		wcsncpy( logger->flt_setting.proc_name, proc_name, NT_PROCNAMELEN ); 
		if( logger->flt_setting.proc_name[ NT_PROCNAMELEN - 1 ] != '\0' )
		{
			logger->flt_setting.proc_name[ NT_PROCNAMELEN - 1 ] = '\0'; 
		}
	}

_return:
	return ntstatus; 
}

NTSTATUS init_trace_log( PTRACE_LOGGER logger )
{

	ASSERT( logger != NULL ); 

	logger->TraceMsgCount = 0;
	InitializeListHead( &logger->TraceMsgs );
	logger->trace_log_count = 0; 
	InitializeListHead( &logger->trace_logs );

	return STATUS_SUCCESS;
}

NTSTATUS _add_new_trace( ULONG flt_lvl, ULONG proc_id, ULONG thread_id, WCHAR *proc_name, release_flt_notify_func release_notify, ULONG name, PULONG flt_id )
{
	NTSTATUS ntstatus = STATUS_SUCCESS;  
	ULONG hash_code; 
	PLIST_ENTRY entry; 
	PUNI_TRACE old_logger; 
	PUNI_TRACE new_logger = NULL; 

	ASSERT( flt_id != NULL ); 

	*flt_id = LOGGER_ID_NONE; 

	old_logger = find_trace_log( name ); 
	if( old_logger != NULL )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		goto _return; 
	}

	new_logger = ( PUNI_TRACE )alloc_pool( NonPagedPool, sizeof( UNI_TRACE ) ); 
	if( new_logger == NULL )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		goto _return; 
	}

	new_logger->name = name; 

	new_logger->flt_setting.release_notify[ 0 ] = release_notify; 
	new_logger->flt_setting.ref_count = 1; 

	new_logger->flt_setting.flt_lvl = ( FLT_LEVEL )flt_lvl; 
	new_logger->flt_setting.proc_id = proc_id; 
	new_logger->flt_setting.thread_id = thread_id; 
	if( proc_name == NULL )
	{
		new_logger->flt_setting.proc_name[ 0 ] = L'\0'; 
	}
	else
	{
		wcsncpy( new_logger->flt_setting.proc_name, proc_name, NT_PROCNAMELEN ); 
	}

	new_logger->id = data_flow_trace.count ++; 

	init_trace_log( &new_logger->logger ); 

	hash_code = calc_flt_id_hash_code( new_logger->name ); 

	ASSERT( hash_code < data_flow_trace.size ); 
	ntstatus = hold_hash_table_lock( &data_flow_trace ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	InsertHeadList( &data_flow_trace.hash_table[ hash_code ], &new_logger->entry ); 

	release_hash_table_lock( &data_flow_trace ); 

	*flt_id = new_logger->id; 

_return:

	if( !NT_SUCCESS( ntstatus ) )
	{
		if( new_logger != NULL )
		{
			release_pool( new_logger ); 
		}
	}

	return ntstatus; 
}


INLINE NTSTATUS add_new_trace( PMSG_FLT_SETTINGS flt_settings, ULONG name, PULONG flt_id )
{
	ASSERT( flt_settings != NULL ); 

	return _add_new_trace( flt_settings->flt_lvl, flt_settings->proc_id, flt_settings->thread_id, flt_settings->proc_name, flt_settings->release_notify[ 0 ], name, flt_id ); 
}

/**
notice: the two params is in the same buffer, so can't manipulate them same time.
*/
NTSTATUS output_trace_msgs( ULONG logger_name, PTRACE_INFO_OUTPUT TraceOut, ULONG out_len )
{
	PTRACE_LOGGER logger; 
	PUNI_TRACE trace_logger; 
	PTRACE_MSG TraceMsg;
	LIST_ENTRY *ListEntry;
	LIST_ENTRY *PrevListEntry; 
	ULONG Outputed;
	NTSTATUS ntstatus;

	ASSERT( TraceOut != NULL ); 

	DBGPRINT( ( "enter %s \n", __FUNCTION__ ) ); 
	Outputed = 0;
	ntstatus = STATUS_UNSUCCESSFUL;

	ntstatus = hold_hash_table_lock( &data_flow_trace ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	trace_logger = _find_trace_log( logger_name ); 
	if( trace_logger == NULL )
	{
		release_hash_table_lock( &data_flow_trace ); 
		goto _return; 
	}

	logger = &trace_logger->logger; 

	ListEntry = logger->TraceMsgs.Flink;

	for( ; ; )
	{
		if( ListEntry == &logger->TraceMsgs )
		{
			TraceOut->Msgs[ Outputed - 1 ] = '\0';
			break;
		}

		TraceMsg = ( PTRACE_MSG )ListEntry;

		if( TraceMsg->Length + 1 + Outputed + sizeof( ULONG ) >= out_len - 1 )
		{
			TraceOut->Msgs[ Outputed - 1 ] = '\0';
			break;
		}

		PrevListEntry = ListEntry->Flink;

		RemoveEntryList( ListEntry );
		logger->TraceMsgCount --;
		ASSERT( logger->TraceMsgCount >= -1 );
		*( ULONG* )( TraceOut->Msgs + Outputed ) = TraceMsg->Length + 1; 
		RtlCopyMemory( TraceOut->Msgs + Outputed + sizeof( ULONG ), TraceMsg->TraceMsg,	TraceMsg->Length );
		*( TraceOut->Msgs + Outputed + sizeof( ULONG ) + TraceMsg->Length ) = '\0';
		Outputed += sizeof( ULONG ) + TraceMsg->Length + 1;

		release_pool( ListEntry );
		ListEntry = PrevListEntry;
	}

	release_hash_table_lock( &data_flow_trace ); 
	TraceOut->Size = Outputed; 

	ntstatus = STATUS_SUCCESS; 

_return:
	DBGPRINT( ( "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 
	return ntstatus;
}

NTSTATUS copy_log_data( BYTE *log_output, sys_action_output *action, ULONG *output_size )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	sys_log_unit *log_unit; 

	do 
	{
		ASSERT( log_output != NULL ); 
		ASSERT( action != NULL ); 
		ASSERT( output_size != NULL ); 

		*output_size = 0; 

		log_unit = ( sys_log_unit* )log_output; 

		if( action->magic != SYS_ACTION_OUTPUT_MAGIC )
		{
			ASSERT( FALSE ); 
			ntstatus = STATUS_INVALID_PARAMETER_1; 
			break; 
		}

		if( action->size < sizeof( sys_action_output ) 
			|| action->size > MAX_SYS_ACTION_UNIT_SIZE )
		{
			ASSERT( FALSE ); 
			ntstatus = STATUS_INVALID_PARAMETER_2; 
			break; 
		}

		memcpy( &log_unit->action_log, action, action->size ); 

		*output_size = sizeof( sys_log_unit ); 
	}while( FALSE );

	return ntstatus; 
}

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
#ifdef DRIVER
NTSTATUS output_trace_logs( ULONG logger_name, sys_log_output *log_output, ULONG out_len )
{
	PTRACE_LOGGER logger; 
	PUNI_TRACE trace_logger; 
	LIST_ENTRY *ListEntry; 
	LIST_ENTRY *PrevListEntry; 
	ULONG log_unit_size; 
	register ULONG Outputed;
	register ULONG outputed_data_size; 
	action_trace_log *log; 
	NTSTATUS ntstatus = STATUS_SUCCESS;
	ULONG remain_len; 

	ASSERT( log_output != NULL ); 
	ASSERT( out_len >= sizeof( sys_log_output ) + sizeof( sys_action_output ) ); 

	//__asm int 3; 
	DBGPRINT( ( "enter %s \n", __FUNCTION__ ) ); 
	outputed_data_size = 0; 
	Outputed = 0;
	log_output->size = 0; 

	log_unit_size = sizeof( sys_log_unit ); 

	remain_len = out_len - sizeof( sys_log_output ); 

	if( output_log_to_cbuffer == FALSE )
	{
		ntstatus = hold_hash_table_lock( &data_flow_trace ); 
		if( !NT_SUCCESS( ntstatus ) )
		{
			goto _return; 
		}

		trace_logger = _find_trace_log( logger_name ); 
		if( trace_logger == NULL )
		{
			release_hash_table_lock( &data_flow_trace ); 
			ntstatus = STATUS_NOT_FOUND; 
			goto _return; 
		}

		logger = &trace_logger->logger; 

		ListEntry = logger->trace_logs.Flink; 
		KdPrint( ( "Begin get trace logs %d, output size %d\n", logger->trace_log_count, remain_len ) );

		if( ListEntry == &logger->trace_logs )
		{
			release_hash_table_lock( &data_flow_trace ); 
			ntstatus = STATUS_NO_MORE_ENTRIES; 
			goto _return; 
		}

		for( ; ; )
		{
			if( ListEntry == &logger->trace_logs )
			{
#ifdef DBG
				if( logger->trace_log_count != 0 )
				{
					log_trace( ( MSG_ERROR, "logger trace message count is not zero (%d), when all is output!\n", logger->trace_log_count ) ); 
				}
#endif //DBG	
				break;
			}

			log = ( action_trace_log* )CONTAINING_RECORD( ListEntry, action_trace_log, entry ); 

			if( ( Outputed + 1 ) * sizeof( sys_log_unit ) > remain_len )
			{
				break; 
			}

			PrevListEntry = ListEntry->Flink;

			RemoveEntryList( ListEntry );
			logger->trace_log_count --;
			ASSERT( logger->trace_log_count >= -1 ); 

#ifdef ACTION_LOG_ALLOC_FROM_R3_MAPPED_BUF
			ASSERT( TRUE == is_valid_data_alloc_mode( log->desc.data.mode ) ); 
#endif //ACTION_LOG_ALLOC_FROM_R3_MAPPED_BUF

#ifdef ACTION_LOG_ALLOC_FROM_R3_MAPPED_BUF
			if( log->desc.data.mode == DATA_BUF_MAPPED_TO_USER )
			{
				memcpy( &log_output->trace_logs[ Outputed ], &log->desc, sizeof( sys_action_desc ) ); 
				Outputed += 1; 
			}
			else
#endif //ACTION_LOG_ALLOC_FROM_R3_MAPPED_BUF

			{
				ULONG log_output_size; 
				ntstatus = copy_log_data( ( BYTE* )&log_output->trace_logs[ Outputed ], &log->action_output, &log_output_size ); 
				if( ntstatus == STATUS_SUCCESS )
				{
					ASSERT( log_output_size >= sizeof( sys_action_output ) ); 

					outputed_data_size += log_output_size; 
					Outputed += 1; 
				}
			}

			release_pool( ListEntry );
			ListEntry = PrevListEntry;
		}

		release_hash_table_lock( &data_flow_trace ); 
		log_output->size = Outputed; 
	}
	else
	{
		do 
		{
			for( ; ; )
			{
				ntstatus = cbuffer_copy_sys_action_desc( &all_r3_cbuf[ SYS_LOG_BUF ].cbuf, 
					&log_output->trace_logs[ outputed_data_size ].action_log, 
					sizeof( sys_log_unit ) ); 
				if( ntstatus != STATUS_SUCCESS )
				{
					if( ntstatus == STATUS_NO_MORE_ENTRIES )
					{
						ntstatus = STATUS_SUCCESS; 
					}

					break; 
				}

				Outputed += 1; 
			}

			log_output->size = Outputed; 
		}while( FALSE );
	}

	if( ( remain_len - Outputed * sizeof( sys_log_unit ) ) > 0 )
	{
		memset( &log_output->trace_logs[ Outputed ], 0xcc, remain_len - Outputed * sizeof( sys_log_unit ) ); 
	}

_return:
	DBGPRINT( ( "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 
	return ntstatus;
}
#endif //DRIVER
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

NTSTATUS init_data_flow_trace()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	
	ntstatus = init_common_hash_table_def_lock( &data_flow_trace, LOGGER_HASH_TABLE_SIZE ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

_return:
	return ntstatus; 
}

NTSTATUS release_data_flow_trace()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	ntstatus = release_common_hash_table_def_lock( &data_flow_trace, release_trace_logger ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		log_trace( ( MSG_ERROR, "*** release data trace table failed ***\n") ); 
	}

	return ntstatus; 
};

INLINE NTSTATUS set_flt_settings( PMSG_FLT flt_setting, ULONG buf_len, PMSG_FLT_SETTINGS flt_settings )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 i; 
	PFLT_SETTING setting; 
	ULONG setting_len = 0; 

	for( i = 0; ( ULONG )i < flt_setting->setting_num; i ++ )
	{
		setting = &flt_setting->settings[ i ]; 

		if( MmIsAddressValid( setting ) == FALSE )
		{
			DBGPRINT( ( "error at :%d if( MmIsAddressValid( setting ) == FALSE )\n" , __LINE__ ) ); 
			ntstatus =  STATUS_INVALID_PARAMETER; 
			goto _return; 
		}

		setting_len += sizeof( FLT_SETTING ); 

		if( FIELD_OFFSET( MSG_FLT, settings ) + setting_len > buf_len )
		{
			DBGPRINT( ( "error at :%d if( FIELD_OFFSET( MSG_FLT, setting ) + setting_len > buf_len ) setting_len %d, buf_len %d\n" , 
				__LINE__, 
				setting_len, 
				buf_len ) ); 

			ntstatus =  STATUS_INVALID_PARAMETER; 
			goto _return; 
		}

		if( setting->mode == proc_id_flt )
		{
			DBGPRINT( ( "proc id flt setting\n") ); 
			flt_settings->proc_id = setting->value.proc_id; 
		}
		else if( setting->mode == thread_id_flt )
		{
			DBGPRINT( ( "thread id flt setting\n") ); 
			flt_settings->thread_id = setting->value.thread_id; 
		}
		else if( setting->mode == proc_name_flt )
		{
			ULONG proc_name_len; 

			DBGPRINT( ( "proc name flt setting\n") ); 

			proc_name_len = NT_PROCNAMELEN; 

			memcpy( flt_settings->proc_name, setting->value.proc_name, proc_name_len ); 
			flt_settings->proc_name[ proc_name_len - 1 ] = '\0'; 

		}
	}

_return:
	return ntstatus; 
}

void release_trace_log( PTRACE_LOGGER logger )
{
	KIRQL old_irql;
	PLIST_ENTRY ListEntry;
	PLIST_ENTRY PrevListEntry;

	ASSERT( logger != NULL ); 

	ListEntry = logger->TraceMsgs.Flink; 
	for( ; ; )
	{
		if( ListEntry == &logger->TraceMsgs )
		{
			break;
		}

		PrevListEntry = ListEntry->Flink;
		RemoveEntryList( ListEntry );
		logger->TraceMsgCount --;
		ASSERT( logger->TraceMsgCount >= 0 );

		ExFreePoolWithTag( ListEntry, 0 );
		ListEntry = PrevListEntry; 
	}

	ASSERT( logger->TraceMsgCount == 0 ); 

	ListEntry = logger->trace_logs.Flink; 
	for( ; ; )
	{
		if( ListEntry == &logger->trace_logs )
		{
			break;
		}

		PrevListEntry = ListEntry->Flink;
		RemoveEntryList( ListEntry );
		logger->trace_log_count --;
		ASSERT( logger->trace_log_count >= 0 );

		ExFreePoolWithTag( ListEntry, 0 );
		ListEntry = PrevListEntry; 
	}

	ASSERT( logger->trace_log_count == 0 );

	return;
}

NTSTATUS CALLBACK  release_trace_logger( PLIST_ENTRY element )
{
	PUNI_TRACE logger; 
	INT32 i; 

	logger = ( PUNI_TRACE )element; 

	for( i = 0; ( ULONG )i < logger->flt_setting.ref_count; i ++ )
	{
		if( logger->flt_setting.release_notify[ i ] !=  NULL )
		{
			logger->flt_setting.release_notify[ i ]( logger->id, logger->name ); 
		}
	}

	release_trace_log( &logger->logger ); 

	release_pool( logger ); 

	return STATUS_SUCCESS; 
}

INT32 add_new_msg( ULONG logger_name, FLT_LEVEL flt_lvl, ULONG proc_id, ULONG thread_id, WCHAR *proc_name, ULONG length, CHAR *Fmt, va_list va )
{
	NTSTATUS ntstatus; 
	INT32 flted; 
	PTRACE_MSG TraceMsg;
	CHAR *TraceMsgEnd; 
	ULONG RemainLength;
	PUNI_TRACE trace_logger; 
	PTRACE_LOGGER logger; 

	DBGPRINT( ( "enter %s \n", __FUNCTION__ ) ); 

	trace_logger = find_trace_log( logger_name ); 
	if( trace_logger == NULL )
	{
		ASSERT( logger_name != TRACE_LOGGER_SYSTEM ); 
		ntstatus = STATUS_NOT_FOUND; 
		goto _return; 
	}

	if( logger_name != TRACE_LOGGER_SYSTEM )
	{
		flted = flt_msg( &trace_logger->flt_setting, proc_id, thread_id, proc_name ); 
		if( flted == FALSE )
		{
			ntstatus = STATUS_UNSUCCESSFUL; 
			goto _return; 
		}
	}

	logger = &trace_logger->logger;

	if( logger->TraceMsgCount >= MAX_TRACE_MSG_COUNT )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		goto _return;
	}

	TraceMsg = ( PTRACE_MSG )alloc_pool( NonPagedPool, sizeof( TRACE_MSG ) + length );
	if( TraceMsg == NULL )
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		goto _return; 
	}

	ntstatus = RtlStringCchVPrintfExA(
		TraceMsg->TraceMsg, 
		length - 1, 
		&TraceMsgEnd, 
		( size_t* )( LONG* )&RemainLength, 
		STRSAFE_IGNORE_NULLS, 
		Fmt, 
		va
		);
	if( !NT_SUCCESS( ntstatus ) &&  
		ntstatus != STATUS_BUFFER_OVERFLOW )
	{
		release_pool( TraceMsg );
		goto _return;
	}

	*TraceMsgEnd = '\0'; 
	TraceMsg->Length = ( ULONG )( ULONG_PTR )( TraceMsgEnd - TraceMsg->TraceMsg );

	ntstatus = hold_hash_table_lock( &data_flow_trace ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	InsertHeadList( &logger->TraceMsgs, &TraceMsg->ListEtnry ); 
	release_hash_table_lock( &data_flow_trace ); 

	logger->TraceMsgCount ++;

_return:
	DBGPRINT( ( "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 
	return ntstatus;
}

NTSTATUS change_trace_logger( PMSG_FLT flt_setting, ULONG buf_len )
{
	NTSTATUS ntstatus = STATUS_SUCCESS;  
	PUNI_TRACE old_logger; 
	INT32 hold_lock = FALSE; 

	ASSERT( flt_setting != NULL ); 

	ntstatus = hold_hash_table_lock( &data_flow_trace ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	hold_lock = TRUE; 

	if( flt_setting->name == TRACE_LOGGER_SYSTEM )
	{
		ntstatus = STATUS_ACCESS_DENIED; 
		goto _return; 
	}

	old_logger = find_trace_log_unlocked( flt_setting->name ); 
	if( old_logger == NULL )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		goto _return; 
	}

	ntstatus = set_flt_settings( flt_setting, buf_len, &old_logger->flt_setting ); 

_return:
	if( hold_lock == TRUE )
	{
		release_hash_table_lock( &data_flow_trace ); 
	}

	return ntstatus; 
}

NTSTATUS add_trace_logger( PMSG_FLT flt_setting, ULONG buf_len, PULONG flt_id )
{
	//INT32 i; 
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	PFLT_SETTING setting; 
	ULONG setting_len = 0; 
	MSG_FLT_SETTINGS flt_settings; 

	DBGPRINT( ( "enter %s \n", __FUNCTION__ ) ); 

	ASSERT( flt_id != NULL ); 

	*flt_id = LOGGER_ID_NONE; 

	init_flt_settings( &flt_settings ); 

	flt_settings.flt_lvl = flt_setting->lvl; 
	flt_settings.release_notify[ 0 ] = flt_setting->release_notify_func; 

	ntstatus = set_flt_settings( flt_setting, buf_len, &flt_settings ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	if( flt_setting->name == LOGGER_NAME_NONE )
	{
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	ntstatus = add_new_trace( &flt_settings, flt_setting->name, flt_id ); 

_return:
	if( !NT_SUCCESS( ntstatus ) )
	{
		init_flt_settings( &flt_settings ); 
	}

	return ntstatus; 
}
