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

#ifdef MAPPING_CELL_BUFFER 
#include "mem_map_io.h"
NTSTATUS release_user_mem_map( user_mem_map *user_map )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	return ntstatus; 
}

NTSTATUS create_user_mem_map( user_mem_map *user_map )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	return ntstatus; 
}
#endif //MAPPING_CELL_BUFFER 

#else
#include "common.h"
#include "seven_fw_common.h"

#ifdef MAPPING_CELL_BUFFER 
#include "mem_map_io.h"
#endif //MAPPING_CELL_BUFFER 

#endif //TEST_IN_RING3

#include "safe_list.h"
#include "rbtree.h"
#include "hash_table.h"
#include "acl_define.h"
#include "trace_log_api.h"
#include "sys_event_define.h"
#include "notify_event.h"
#include "sys_event.h"
#include <stdarg.h>
#include <ntstrsafe.h>
#include "r3_shared_vm.h"
//#include "cbuffer.h"
#include "buf_array.h"
#include "r3_shared_buf_array.h"

#ifdef TEST_IN_RING3
r3_shared_buf_arr all_r3_arr[ MAX_R3_ARRAY_TYPE ] = { 0 }; 
//r3_shared_cbuf all_r3_cbuf[ MAX_R3_CBUFFER_TYPE ] = { 0 }; 
#endif //TEST_IN_RING3

/*************************************************************
notice: can realize the system action event list to one none
block queue.
*************************************************************/

#ifdef NBQUEUE_SYS_EVENT_LIST
#include "nbqueue.h"
NBQUEUE_HEADER sys_events = { 0 }; 
#endif //NBQUEUE_SYS_EVENT_LIST

SAFE_LIST sys_events = { 0 }; 
SAFE_LIST pending_sys_events = { 0 }; 
PKTHREAD wait_events_thread = NULL; 
KEVENT pending_events_notify; 
INT32 stop_events_thread = FALSE; 
ULONG events_list_flags = 0; 
ULONG stop_events_queue = FALSE; 

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
extern r3_shared_buf_arr all_r3_arr[ MAX_R3_ARRAY_TYPE ];
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

//#ifdef WIN7
#define MAX_SYS_EVENT_REPONSE_TIME_WIN7 -60000000
//#else
#define MAX_SYS_EVENT_REPONSE_TIME -260000000
#define MAX_SYS_SOCKET_EVENT_REPONSE_TIME -150000000
//#endif //WIN7

FORCEINLINE PLIST_ENTRY get_next_pending_sys_event()
{
	return remove_cur_safe_list_entry( &sys_events ); 
}

FORCEINLINE NTSTATUS add_pending_sys_event( event_notifier_item *sys_event )
{
	NTSTATUS ntstatus; 
	ntstatus = add_safe_list_entry_no_create( &sys_event->entry, &pending_sys_events ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		ASSERT( FALSE ); 
		goto _return; 
	}

	KeSetEvent( &pending_events_notify, 
		IO_NO_INCREMENT, 
		FALSE ); 

_return:
	return ntstatus; 
}

BOOLEAN compare_param_conclude( param_all_desc *param_src, param_all_desc *param_dest )
{
	BOOLEAN ret = FALSE; 

	do 
	{
		ASSERT( param_src != NULL ); 
		ASSERT( param_dest != NULL ); 
		if( param_src->type != param_dest->type )
		{
			break; 
		}

		switch( param_src->type )
		{
		case URL_DEFINE:
			if( NULL != find_sub_str( param_src->url.url, wcslen( param_src->url.url ), param_dest->url.url, wcslen( param_dest->url.url ), 1 ) )
			{
				ret = TRUE; 
			}
			break; 
		case IP_DEFINE: 
			if( param_src->ip.ip_begin <= param_dest->ip.ip_begin && param_src->ip.ip_end >= param_dest->ip.ip_end )
			{
				ret = TRUE; 
			}
			break; 
		case PORT_DEFINE:
			if( param_src->port.type != param_dest->port.type )
			{
				break; 
			}

			if( param_src->port.port_begin <= param_dest->port.port_begin && param_src->port.port_end >= param_dest->port.port_end )
			{
				ret = TRUE; 
			}
			break; 
		case FILE_DEFINE:
			if( NULL != find_sub_str( param_src->url.url, wcslen( param_src->url.url ), param_dest->url.url, wcslen( param_dest->url.url ), 1 ) )
			{
				ret = TRUE; 
			}
			break; 
		case REG_DEFINE:
			if( NULL != find_sub_str( param_src->reg.reg_path, wcslen( param_src->reg.reg_path ), param_dest->reg.reg_path, wcslen( param_dest->reg.reg_path ), 1 ) )
			{
				ret = TRUE; 
			}
			break; 
		case COM_DEFINE:
			if( 0 == compare_str( param_src->com.com_name, wcslen( param_src->com.com_name ), param_dest->com.com_name, wcslen( param_dest->com.com_name ) ) )
			{
				ret = TRUE; 
			}			
			break; 
		case APP_DEFINE:
			if( 0 == compare_str( param_src->app.app_name, wcslen( param_src->app.app_name ), param_dest->app.app_name, wcslen( param_dest->app.app_name ) ) )
			{
				ret = TRUE; 
			}
			break; 
		case COMMON_DEFINE:
			if( 0 == compare_str( param_src->common.name, wcslen( param_src->common.name ), param_dest->common.name, wcslen( param_dest->common.name ) ) )
			{
				ret = TRUE; 
			}
			break; 
		default: 
			break; 
		}
	} while ( FALSE );

	return ret; 
}

NTSTATUS compare_sys_event_desc( sys_action_desc *sys_event_src, sys_action_desc *sys_event_dest, ULONG compare_type )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	LPCWSTR src_name; 
	LPCWSTR dest_name; 
	access_rule_type rule_type; 
	ULONG param_count; 
	INT32 i; 
	BOOLEAN ret; 

	do 
	{
		ASSERT( NULL != sys_event_src ); 
		ASSERT( NULL != sys_event_dest ); 

		ASSERT( TRUE == is_valid_action_type( sys_event_dest->type ) );

		switch( compare_type )
		{
		case COMPARE_APP:
			ASSERT( sys_event_src->desc.params[ 0 ]->type == APP_DEFINE && sys_event_dest->desc.params[ i ]->type == APP_DEFINE ); 
			if( 0 != compare_define_name_no_case( sys_event_src->desc.params[ 0 ]->app.app_name, 
				sys_event_dest->desc.params[ 0 ]->app.app_name ) )
			{
				ntstatus = STATUS_IS_NOT_SAME_ACTION_DEFINE; 
			}
			break; 
		case COMPARE_APP_AND_TYPE:
			if( sys_event_dest->type != sys_event_src->type )
			{
				ntstatus = STATUS_IS_NOT_SAME_ACTION_TYPE; 
				break; 
			}

			ASSERT( sys_event_src->desc.params[ 0 ]->type == APP_DEFINE && sys_event_dest->desc.params[ i ]->type == APP_DEFINE ); 
			if( 0 != compare_define_name_no_case( sys_event_src->desc.params[ 0 ]->app.app_name, 
				sys_event_dest->desc.params[ 0 ]->app.app_name ) )
			{
				ntstatus = STATUS_IS_NOT_SAME_ACTION_DEFINE; 
			}
			break; 
		case COMPARE_APP_AND_PARAM:
			rule_type = acl_type( sys_event_src->type ); 
			param_count = get_access_rule_param_count( rule_type ); 

			for( i = 0; ( ULONG )i < param_count; i ++ )
			{
				ret = compare_param_conclude( sys_event_src->desc.params[ i ], sys_event_dest->desc.params[ i ] ); 

				if( ret == FALSE )
				{
					ntstatus = STATUS_IS_NOT_SAME_ACTION_DEFINE; 
					break; 
				}
			}		
			break; 
		default: 
			ASSERT( FALSE ); 
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}
		

	}while( FALSE );

	return ntstatus; 
}

/********************************************************************
determine remain system events response by type response immediately.
********************************************************************/
#ifdef LINKED_SYS_EVENT
//NTSTATUS release_remain_sys_events_by_type_response( event_notifier_item *sys_event, action_response_type resp, ACTION_RECORD_TYPE record_type )
NTSTATUS release_remain_sys_events_by_type_response( sys_action_desc *sys_action, action_response_type resp, ACTION_RECORD_TYPE record_type )
{
	NTSTATUS ntstatus = STATUS_SUCCESS;
	DEFINE_LOCK_STATE()
	PLIST_ENTRY list_entry; 
	PLIST_ENTRY entry_find; 
	event_notifier_item *_sys_event;

	do 
	{
		if( RECORD_APP_ACTION != record_type )
		{
			if( sys_action != NULL )
			{
				DBG_BP(); 
			}

			ntstatus = STATUS_NOT_SUPPORTED; 
			break; 
		}

		if( sys_action == NULL )
		{
			DBG_BP(); 
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		if( FALSE == is_valid_response_type( resp ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		if( FALSE == is_valid_record_mode( record_type ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

#ifdef DBG
		if( check_sys_action_input_valid( sys_action/*, FALSE */) == FALSE )
		{
			ASSERT( FALSE && "is not valid system event for response" ); 

			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}
#endif //DBG

		//res_w_lock( &safe_list->lock ); 
		R_LOCK_SAFE_LIST( &sys_events ); 

		list_entry = sys_events.entrys.Flink; 

		for( ; ; )
		{	
			if( list_entry == &sys_events.entrys )
			{
				break; 
			}

			_sys_event = CONTAINING_RECORD( list_entry, event_notifier_item, entry ); 

			ntstatus = compare_sys_event_desc( sys_action, &_sys_event->action->action, ( param_compare_type )record_type ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				_sys_event->action->action.resp = resp; 
				_sys_event->need_record = RECORD_NONE; 
				//_sys_event->desc.
#ifdef _DRIVER
				KeSetEvent( &_sys_event->notify, 0, FALSE ); 
#else
				SetEvent( _sys_event->notify ); 
#endif //_DRIVER
			}

			list_entry = list_entry->Flink; 
		}

		UNLOCK_SAFE_LIST( &sys_events );

	} while ( FALSE );
	return ntstatus; 
}
#else

NTSTATUS release_remain_sys_events_by_type_response( sys_action_desc *sys_action, action_response_type resp, ACTION_RECORD_TYPE record_type )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{

	}while( FALSE );

	return ntstatus; 
}
#endif //LINKED_SYS_EVENT

#ifdef LINKED_SYS_EVENT
VOID thread_wait_pending_events( PVOID param )
{
	NTSTATUS ntstatus; 
	PLIST_ENTRY entry; 
	event_notifier_item *sys_event; 
	KIRQL old_irql; 
	action_response_type response; 
	LARGE_INTEGER wait_event_respon_time; 

	log_trace( ( MSG_INFO, "enter %s \n", __FUNCTION__ ) ); 

	wait_event_respon_time.LowPart = MAX_SYS_EVENT_REPONSE_TIME;
	wait_event_respon_time.HighPart = 0xFFFFFFFF; 

	for( ; ; )
	{
		ntstatus = KeWaitForSingleObject( &pending_events_notify, 
			Executive, 
			KernelMode,
			FALSE, 
			NULL ); 

		for( ; ; )
		{
			R_LOCK_SAFE_LIST( &pending_sys_events ); 

			entry = pending_sys_events.entrys.Flink; 

			if( entry == &pending_sys_events.entrys )
			{
				entry = NULL; 
				UNLOCK_SAFE_LIST( &pending_sys_events ); 
				break; 
			}

			UNLOCK_SAFE_LIST( &pending_sys_events ); 

			sys_event = ( event_notifier_item* )CONTAINING_RECORD( entry, event_notifier_item, entry ); 

			KdPrint( ( "wait event %d, type %ws\n", sys_event->action->action.id, get_action_desc( sys_event->action->action.type ) ) ); 
			signal_notify_event( SYS_ACTION_EVENT ); 

			ntstatus = KeWaitForSingleObject( &sys_event->notify, Executive, KernelMode, FALSE, &wait_event_respon_time );
			if( ntstatus == STATUS_SUCCESS )
			{
				ASSERT( sys_event->action->action.resp == ACTION_ALLOW 
					|| sys_event->action->action.resp == ACTION_BLOCK ); 
				response = sys_event->action->action.resp; 
			}
			else
			{
				ASSERT( ntstatus == STATUS_TIMEOUT ); 
				ASSERT( sys_event->need_record == RECORD_NONE ); 

				response = ACTION_ALLOW; 
			}

			if( sys_event->need_record != RECORD_NONE )
			{
				ntstatus = _add_action_response_record( sys_event->action->action.type, 
					sys_event->action->action.resp, 
					sys_event->action->action.desc.common.app.app.app_name, 
					wcslen( sys_event->action->action.desc.common.app.app.app_name ) + 1 ); 
				//ntstatus = input_action_rule_from_desc( &sys_event->desc, MODIFY_RULE ); 
				if( !NT_SUCCESS( ntstatus ) )
				{
					log_trace( ( MSG_ERROR, "!!!input action rule form this action description failed\n" ) ); 
				}
			}

			W_LOCK_SAFE_LIST( &pending_sys_events ); 
			RemoveEntryList( entry ); 
			pending_sys_events.item_count --; 
			UNLOCK_SAFE_LIST( &pending_sys_events ); 

			log_trace( ( MSG_INFO, "release the pending system event buffer 0x%0.8x\n", sys_event ) ); 

			InitializeListHead( entry ); 

			release_sys_event( &sys_event->entry ); 

			ASSERT( ( LONG )pending_sys_events.item_count >= 0 ); 

			if( sys_event->need_record != RECORD_NONE )
			{
				NTSTATUS _ntstatus; 
				_ntstatus = release_remain_sys_events_by_type_response( &sys_event->action->action, response, ( ACTION_RECORD_TYPE )sys_event->need_record ); 
			}
		}

#ifdef DBG
		W_LOCK_SAFE_LIST( &pending_sys_events ); 

		if( !IsListEmpty( &pending_sys_events.entrys ) )
		{
			log_trace( ( 0, "***all pending events processed, events still is not empty! ***\n" ) ); 
		}

		UNLOCK_SAFE_LIST( &pending_sys_events ); 
#endif //DBG

		if( stop_events_thread != FALSE )
		{
			PsTerminateSystemThread( STATUS_SUCCESS ); 
			break; 
		}
	} /* end first for( ; ; ) */

	return; 
}
#else
VOID thread_wait_pending_events( PVOID param )
{
	PsTerminateSystemThread( STATUS_SUCCESS ); 
}
#endif //LINKED_SYS_EVENT

#ifndef TEST_IN_RING3
NTSTATUS start_wait_pending_events()
{
	NTSTATUS ntstatus; 
	
	stop_events_thread = FALSE; 
	KeInitializeEvent( &pending_events_notify, SynchronizationEvent, FALSE ); 

	ntstatus = start_thread( thread_wait_pending_events, 
		NULL, 
		&wait_events_thread ); 

	return ntstatus; 
}

NTSTATUS stop_wait_pending_events()
{
	stop_events_thread = TRUE; 
	return stop_thread( wait_events_thread, &pending_events_notify ); 
}
#else
NTSTATUS start_wait_pending_events()
{
	return STATUS_SUCCESS; 
}

NTSTATUS stop_wait_pending_events()
{
	return STATUS_SUCCESS; 
}

#endif //TEST_IN_RINNG3

INLINE INT32 sys_events_inited( PSAFE_LIST safe_list )
{
	if( safe_list->create_entry_func == NULL ||  
		safe_list->list_find_func == NULL || 
		safe_list->release_entry_func == NULL ) 
	{
		return FALSE; 
	}

	return TRUE; 
}

INLINE VOID dump_sys_event( sys_action_desc *sys_event )
{
	ASSERT( ( sys_event != NULL ) ); 
	DBGPRINT( ( "action %d \n type %d \n", 
		sys_event->resp, sys_event->type ) ); 

	return; 
}

INLINE VOID dump_sys_event_item( event_notifier_item* sys_event )
{
	ASSERT( ( sys_event != NULL ) );

	DBGPRINT( ( "notify event 0x%0.8x \n, waiting %d \n id %u \n", 
		&sys_event->notify, 
		sys_event->waiting, 
		sys_event->action->action.id ) ); 

	dump_sys_event( &sys_event->action->action ); 

	return; 
}

PLIST_ENTRY find_sys_event( PLIST_ENTRY list_entry, PVOID compare_to )
{
	event_notifier_item* sys_event; 
	event_notifier_item* sys_event_find; 

	DBGPRINT( ( "enter find_sys_event \n" ) ); 
	sys_event = ( event_notifier_item* )list_entry; 
	sys_event_find = ( event_notifier_item* )compare_to; 

	dump_sys_event_item( sys_event ); 
	dump_sys_event_item( sys_event_find ); 

	if( sys_event->action->action.id == sys_event_find->action->action.id )
	{
		return &sys_event->entry; 
	}

	return NULL; 
}

PLIST_ENTRY find_sys_event_entry( PLIST_ENTRY list_entry, PVOID compare_to )
{
	event_notifier_item* sys_event; 
	event_notifier_item* sys_event_find; 

	DBGPRINT( ( "enter find_sys_event \n" ) ); 
	sys_event = ( event_notifier_item* )list_entry; 
	sys_event_find = ( event_notifier_item* )compare_to; 

	dump_sys_event_item( sys_event ); 
	dump_sys_event_item( sys_event_find ); 

	if( sys_event == sys_event_find )
	{
		return &sys_event->entry; 
	}

	return NULL; 
}

INT32 release_sys_event( PLIST_ENTRY list_entry )
{
	event_notifier_item *event_item; 

	ASSERT( IsListEmpty( list_entry ) == TRUE ); 

	event_item = CONTAINING_RECORD( list_entry, event_notifier_item, entry ); 

#ifdef MAPPING_CELL_BUFFER
	if( event_item->map2user != NULL )
	{
		release_user_mem_map( event_item->map2user ); 
	}
#endif //MAPPING_CELL_BUFFER

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
	if( event_item->action != NULL )
	{
		_release_buf_to_array( &all_r3_arr[ SYS_ACTION_BUF_ARRAY ].arr, event_item->action ); 
	}
	else
	{
		ASSERT( FALSE && "notify event have not action information" ); 
	}
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

	release_pool( event_item ); 
	return 0; 
}

PLIST_ENTRY create_sys_event( PLIST_ENTRY list_entry )
{
	event_notifier_item *sys_event; 
	event_notifier_item *new_sys_event; 

	sys_event = ( event_notifier_item* )list_entry; 

	new_sys_event = ( event_notifier_item* )alloc_pool( NonPagedPool, sizeof( event_notifier_item ) ); 
	if( new_sys_event == NULL )
	{
		return NULL; 
	}

	memcpy( new_sys_event, sys_event, sizeof( event_notifier_item ) ); 

#ifdef MAPPING_CELL_BUFFER
	if( sys_event->map2user != NULL )
	{
		ASSERT( FALSE ); 
		release_user_mem_map( sys_event->map2user ); 
	}

	new_sys_event->map2user = NULL; 
#endif //MAPPING_CELL_BUFFER

	return &new_sys_event->entry; 
}

INLINE VOID dump_sys_event_respon( event_action_response *event_respon )
{
	KdPrint( ( "dump event response 0x%0.8x:\n", event_respon ) ); 

	KdPrint( ( "event action %d \n event id %d \n", 
		event_respon->action, 
		event_respon->id ) ); 

	return; 
}

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
NTSTATUS notify_dest_sys_event( PLIST_ENTRY entry, PVOID param, PVOID context )
{
	event_notifier_item* sys_event; 
	event_action_response *event_respon; 

	ASSERT( entry != NULL ); 
	ASSERT( param != NULL ); 

	DBGPRINT( ( "enter notify_dest_sys_event\n" ) ); 

	//__asm int 3; 
	sys_event = ( event_notifier_item* )entry; 
	event_respon = ( event_action_response* )param; 

	//ASSERT( sys_event->notify != NULL ); 

	if( is_valid_response_type( event_respon->action ) == FALSE 
		|| event_respon->action == ACTION_LEARN )
	{
		log_trace( ( MSG_ERROR, "*** input invalid response type %d *** \n", event_respon->action ) ); 
		sys_event->action->action.resp = ACTION_ALLOW; 
	}
	else
	{
		sys_event->action->action.resp = ( action_response_type )event_respon->action; 
	}

	if( FALSE == is_valid_record_mode( event_respon->need_record ) )
	{
		log_trace( ( MSG_ERROR, "*** input invalid record tip value that's a boolean value %d *** \n", event_respon->need_record ) ); 
		sys_event->need_record = RECORD_NONE; 
	}
	else
	{
		sys_event->need_record = event_respon->need_record; 
	}

	ASSERT( sys_event->action != NULL ); 
	ASSERT( TRUE == MmIsAddressValid( ( BYTE* )sys_event->action - sizeof( array_cell_head ) ) ); 
	ASSERT( ( ( array_cell_head* )( ( BYTE* )sys_event->action - sizeof( array_cell_head ) ) )->ref_count > 0 ); 

	_release_buf_to_array( &all_r3_arr[ SYS_ACTION_BUF_ARRAY ].arr, sys_event->action ); 

#ifdef DBG
	dump_sys_event_respon( event_respon ); 
#endif //DBG

#ifdef _DRIVER
	KeSetEvent( &sys_event->notify, 0, FALSE ); 
#else
	SetEvent( sys_event->notify ); 
#endif //_DRIVER

	DBGPRINT( ( "leave notify_dest_sys_event\n" ) ); 

	return STATUS_SUCCESS; 
}
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

NTSTATUS init_sys_events_list( ULONG flags )
{
	NTSTATUS ntstatus; 
	//KeInitializeEvent( &sys_event_added, SynchronizationEvent, FALSE ); 
	ntstatus = init_safe_list( &sys_events, find_sys_event, release_sys_event, create_sys_event ); 
	
	if( !NT_SUCCESS( ntstatus ) )
	{
		log_trace( ( MSG_ERROR, "initialize the sys events failed\n" ) ); 
		goto _return; 
	}

	events_list_flags = flags; 

	if( flags == HAVE_PENDING_EVENT )
	{
		ntstatus = init_safe_list( &pending_sys_events, find_sys_event_entry, release_sys_event, create_sys_event ); 
		if( !NT_SUCCESS( ntstatus ) )
		{
			log_trace( ( MSG_ERROR, "initialize the pending sys events failed\n" ) ); 
			goto _return; 
		}

		ntstatus = start_wait_pending_events(); 
		if( !NT_SUCCESS( ntstatus ) )
		{
			goto _return; 
		}
	}

_return:
	if( !NT_SUCCESS( ntstatus ) )
	{
		if( sys_events_inited( &sys_events ) )
		{
			release_safe_list( &sys_events ); 
		}

		if( sys_events_inited( &pending_sys_events ) )
		{
			release_safe_list( &pending_sys_events ); 
		}
	}

	return ntstatus; 
}

#ifdef SUPPORT_VA_REGION_MAPPING_R3_TO_R0
VOID release_sys_events_list( ULONG flags )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	LARGE_INTEGER wait_remove_delay; 
	INT32 try_time; 

#define MAX_WAIT_EVENTS_RESPONSE_TIME 20

	PAGED_CODE(); 

	log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

	stop_events_queue = TRUE; 

	wait_remove_delay.QuadPart = ( LONGLONG )-24 * 100000;

	/*************************************************
	good release mechanism:
	stop adding, stop output events to user application\
	then waiting remain all user response
	until all waiting events have response.
	notify remain events.
	wait all events removed by other system thread which do 
	some action on the system.

	but now,because here is running in the unloading function,
	just notify all events,no wait the response of user .
	*************************************************/
	for( try_time = 0; try_time < MAX_WAIT_EVENTS_RESPONSE_TIME; try_time ++ )
	{
		ntstatus = release_pending_sys_action(); 


		R_LOCK_SAFE_LIST( &sys_events ); 

		if( FALSE == IsListEmpty( &sys_events.entrys ) )
		{
			ASSERT( sys_events.item_count > 0 ); 

			UNLOCK_SAFE_LIST( &sys_events ); 

			KeDelayExecutionThread( KernelMode, FALSE, &wait_remove_delay ); 
		}
		else
		{
			ASSERT( sys_events.item_count == 0 ); 

			UNLOCK_SAFE_LIST( &sys_events ); 
			break; 
		}
	}

	if( try_time == MAX_WAIT_EVENTS_RESPONSE_TIME )
	{
		release_safe_list( &sys_events ); 
	}

	if( flags == HAVE_PENDING_EVENT )
	{
		NTSTATUS ntstatus; 

		ASSERT( events_list_flags == HAVE_PENDING_EVENT ); 
		ASSERT( TRUE == sys_events_inited( &pending_sys_events ) ); 
		
		ntstatus = stop_wait_pending_events(); 
		if( !NT_SUCCESS( ntstatus ) )
		{
			ASSERT( FALSE && "stop the pending system events thread failed" ); 
		}

		release_safe_list( &pending_sys_events ); 
	}
#ifdef DBG
	else
	{
		ASSERT( FALSE == sys_events_inited( &pending_sys_events ) ); 		
	}
#endif //DBG

	log_trace( ( MSG_INFO, "leave %s\n", __FUNCTION__ ) ); 
}
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

PLIST_ENTRY compare_sys_event_id( PLIST_ENTRY entry, PVOID obj )
{
	event_notifier_item *sys_event_src; 
	event_notifier_item* sys_event; 

	ASSERT( entry != NULL ); 
	ASSERT( obj != NULL ); 

	sys_event_src = ( event_notifier_item* )obj; 
	sys_event = ( event_notifier_item* )entry; 

	if( sys_event->action->action.id == sys_event_src->action->action.id )
	{
		return &sys_event->entry; 
	}

	return NULL; 
}


PLIST_ENTRY is_same_event_id( PLIST_ENTRY entry, PVOID obj )
{
	event_action_response *event_respon; 
	event_notifier_item* sys_event; 

	ASSERT( entry != NULL ); 
	ASSERT( obj != NULL ); 

	event_respon = ( event_action_response* )obj; 
	sys_event = ( event_notifier_item* )entry; 

	if( sys_event->action->action.id == event_respon->id )
	{
		return &sys_event->entry; 
	}

	return NULL; 
}

PLIST_ENTRY all_events_check( PLIST_ENTRY entry, PVOID obj )
{
	event_notifier_item* sys_event; 

	ASSERT( entry != NULL ); 

	sys_event = ( event_notifier_item* )entry; 
	
	return &sys_event->entry; 
}

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
NTSTATUS response_action_event( event_action_response *sys_event_respon )
{
	NTSTATUS ntstatus; 
	PLIST_ENTRY entry; 

	if( FALSE == is_valid_response_type( sys_event_respon->action ) )
	{
		ASSERT( FALSE ); 
		log_trace( ( MSG_ERROR, "sys reponse record mode is invalid\n" ) ); 
		sys_event_respon->need_record = RECORD_APP_ACTION;
	}

	if( FALSE == is_valid_record_mode( sys_event_respon->need_record ) )
	{
		ASSERT( FALSE ); 
		log_trace( ( MSG_ERROR, "sys reponse record mode is invalid\n" ) ); 
		sys_event_respon->need_record = RECORD_APP_ACTION;
	}

	ntstatus = do_safe_list_action( &sys_events, sys_event_respon, notify_dest_sys_event, is_same_event_id ); 
	if( ntstatus == STATUS_ENTRY_NOT_FOUND )
	{
		if( events_list_flags == HAVE_PENDING_EVENT )
		{
			ASSERT( pending_sys_events.entrys.Flink != NULL ); 

			ntstatus = do_safe_list_action( &pending_sys_events, 
				sys_event_respon, 
				notify_dest_sys_event, 
				is_same_event_id ); 
		}
	}
#ifdef DBG_PENDING_EVENTS
	else
	{
		entry = find_safe_list_entry_compare( sys_event_respon, 
			&pending_sys_events, 
			is_same_event_id ); 

		ASSERT( entry == NULL ); 
	}
#endif //DBG_PENDING_EVENTS

	return ntstatus; 
}
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

PLIST_ENTRY is_no_waiting_event( PLIST_ENTRY entry )
{
	event_notifier_item* sys_event; 

	ASSERT( entry != NULL ); 

	sys_event = ( event_notifier_item* )entry; 

	if( sys_event->waiting == FALSE )
	{
		sys_event->waiting = TRUE; 
		return &sys_event->entry; 
	}

	return NULL; 
}

#ifdef MAPPING_CELL_BUFFER 
NTSTATUS map_next_sys_event( sys_action_map* sys_event_map, PULONG out_length )
{
	NTSTATUS ntstatus; 
	ULONG _out_length;
	PLIST_ENTRY entry_find; 
	event_notifier_item *sys_event_find; 

	ASSERT( out_length != NULL ); 

	DBGPRINT( ( "enter map_next_sys_event \n" ) ); 

	_out_length = *out_length; 

	ASSERT( sys_event_map != NULL ); 

	ntstatus = STATUS_SUCCESS; 

	if( _out_length < sizeof( sys_action_map ) )
	{
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	entry_find = find_safe_list_entry_check( &sys_events, is_no_waiting_event ); 

	if( entry_find == NULL )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		*out_length = 0; 
		goto _return; 
	}

	sys_event_find = ( event_notifier_item* )entry_find; 

	dump_sys_event_item( sys_event_find ); 

	ntstatus = create_user_mem_map( NULL, &sys_event_find->action, 
		sizeof( sys_action_desc ), 
		&sys_event_find->map2user, 
		0 ); 

	if( ntstatus != STATUS_SUCCESS )
	{
		NTSTATUS _ntstatus; 
		event_action_response event_response; 

		event_response.action = ACTION_ALLOW; 
		event_response.id = sys_event_find->action->action.id; 
		event_response.need_record = FALSE; 

		_ntstatus = response_action_event( &event_response ); 
		if( _ntstatus != STATUS_SUCCESS )
		{
			log_trace( ( MSG_ERROR, "response the waiting response system action error 0x%0.8x\n", _ntstatus ) ); 
		}
		goto _return; 
	}

	ASSERT( sys_event_find->map2user != NULL ); 
	ASSERT( sys_event_find->map2user->user_addr != NULL ); 
	ASSERT( sys_event_find->map2user->user_buf_len != 0 ); 
	ASSERT( sys_event_find->map2user->user_buf_mdl != NULL );

	*out_length = sizeof( sys_action_map ); 

_return:
	DBGPRINT( ( "leave map_next_sys_event status 0x%0.8x\n", ntstatus ) ); 
	return ntstatus; 
}
#endif //MAPPING_CELL_BUFFER 

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
NTSTATUS get_next_sys_event( sys_action_output_map* sys_event, PULONG out_length )
{
	NTSTATUS ntstatus;
	ULONG _out_length;
	PLIST_ENTRY entry_find; 
	event_notifier_item *sys_event_find; 

	ASSERT( out_length != NULL ); 

	DBGPRINT( ( "enter %s \n", __FUNCTION__ ) ); 

	_out_length = *out_length; 

	ASSERT( sys_event != NULL ); 

	ntstatus = STATUS_SUCCESS; 

	if( _out_length < sizeof( sys_action_output_map ) )
	{
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	entry_find = find_safe_list_entry_check( &sys_events, is_no_waiting_event ); 

	if( entry_find == NULL )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		*out_length = 0; 
		goto _return; 
	}

	sys_event_find = CONTAINING_RECORD( entry_find, event_notifier_item, entry ); 

#ifdef DBG
	dump_sys_event_item( sys_event_find ); 
#endif //DBG

	
	ASSERT( ( ( array_cell_head* )( ( BYTE* )sys_event_find->action - sizeof( array_cell_head ) ) )->ref_count > 0 ); 

//#ifdef SUPPORT_RING3_BUF_ARRAY
	ntstatus = reference_buf_from_array( &all_r3_arr[ SYS_ACTION_BUF_ARRAY ].arr, ( PVOID )sys_event_find->action ); 
	if( ntstatus != STATUS_SUCCESS )
	{
		ASSERT( FALSE && "refercence buffer in array error" ); 

		dbg_print( MSG_ERROR, "convert ring 0 address to ring 3 address error 0x%0.8x in buffer array\n", ntstatus ); 
		goto _return; 
	}

	ntstatus = convert_r0_to_r3_in_arr( &all_r3_arr[ SYS_ACTION_BUF_ARRAY ], sys_event_find->action, ( PVOID* )&sys_event->action ); 
	if( ntstatus != STATUS_SUCCESS )
	{
		dbg_print( MSG_ERROR, "convert ring 0 address to ring 3 address error 0x%0.8x in buffer array\n", ntstatus ); 
		goto _return; 
	}

#ifdef DBG
	if( sys_event_find->action->size > DEFAULT_OUTPUT_DATA_REGION_SIZE + sizeof( sys_action_output ) )
	{
#ifdef DRIVER
		KeBugCheck( STATUS_BUFFER_OVERFLOW ); 
#else
		ASSERT( FALSE && "system action event size is incorrectly." ); 
#endif //DRIVER
	}
#endif //DBG

	*out_length = sizeof( sys_action_output_map ); 

_return:
	DBGPRINT( ( "leave get_next_sys_event status 0x%0.8x\n", ntstatus ) ); 
	return ntstatus; 
}

#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

#ifdef SUPPORT_MSG_EVENT
NTSTATUS __cdecl add_msg_sys_event( action_response_type *response, USHORT type, ULONG Length, CHAR *Fmt, ... )
{
	NTSTATUS ntstatus; 
	INT32 ret;  
	event_msg_notifier_item* sys_event; 
	va_list Args;
	CHAR *sys_msg_end; 
	ULONG remain_len;
	LARGE_INTEGER wait_event_respon_time; 

	ASSERT( response != NULL ); 
	wait_event_respon_time.LowPart = MAX_SYS_EVENT_REPONSE_TIME;
	wait_event_respon_time.HighPart = 0xFFFFFFFF;

	va_start( Args, Fmt );

	ASSERT( sys_events_inited( &sys_events ) == TRUE ); 

	sys_event = ( event_msg_notifier_item* )alloc_pool( NonPagedPool, sizeof( event_msg_notifier_item ) + Length );

	if( NULL == sys_event )
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		goto err_return; 
	}

	sys_event->waiting = FALSE; 
	sys_event->id = sys_events.item_count; 
	sys_event->type = type; 
	KeInitializeEvent( &sys_event->notify, SynchronizationEvent, FALSE ); 

	ntstatus = RtlStringCchVPrintfExA(
		sys_event->Msgs, 
		Length - 1, 
		&sys_msg_end, 
		&remain_len, 
		STRSAFE_IGNORE_NULLS, 
		Fmt, 
		Args
		);

	va_end( Args );

	if( !NT_SUCCESS( ntstatus ) &&  
		ntstatus != STATUS_BUFFER_OVERFLOW )
	{
		goto err_return; 
	}

	*sys_msg_end = '\0'; 
	sys_event->Size = sys_msg_end - sys_event->Msgs + sizeof( CHAR ); 
	KdPrint( ( "Insert new sys event msg %s \n", sys_event->Msgs ) );
	ret = add_safe_list_entry_no_create( &sys_event->entry, &sys_events ); 

	if( ret < 0 )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		goto err_return; 
	}

	//KeSetEvent( &sys_event_added, 0, FALSE ); 

	KdPrint( ( "wait event %d, %s, %d \n", sys_event->id, sys_event->Msgs, sys_event->Size ) ); 

	ntstatus = KeWaitForSingleObject( &sys_event->notify, Executive, KernelMode, FALSE, &wait_event_respon_time );

	if( ntstatus == STATUS_SUCCESS )
	{
		ASSERT( sys_event->action == ACTION_ALLOW 
			|| sys_event->action == ACTION_BLOCK ); 
	}
	else
	{
		ASSERT( ntstatus == STATUS_TIMEOUT ); 
	}

	del_safe_list_entry( &sys_event->entry, &sys_events ); 
	*response = sys_event->action; 
	return ntstatus; 

err_return:
	if( sys_event )
	{
		release_pool( sys_event ); 
	}

	return ntstatus; 
}
#endif //SUPPORT_MSG_EVENT

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
NTSTATUS release_pending_sys_action()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	PLIST_ENTRY entry; 
	event_action_response response; 

	do 
	{
		response.action = ACTION_ALLOW; 
		response.id = 0; 
		response.need_record = RECORD_NONE; 

		ntstatus = do_safe_list_action( &sys_events, &response, notify_dest_sys_event, all_events_check ); 
		if( ntstatus == STATUS_ENTRY_NOT_FOUND )
		{
			if( events_list_flags == HAVE_PENDING_EVENT )
			{
				ASSERT( pending_sys_events.entrys.Flink != NULL ); 

				ntstatus = do_safe_list_action( &pending_sys_events, 
					&response, 
					notify_dest_sys_event, 
					all_events_check ); 
			}
		}
#ifdef DBG_PENDING_EVENTS
		else
		{
			entry = find_safe_list_entry_compare( &response, 
				&pending_sys_events, 
				all_events_check ); 

			ASSERT( entry == NULL ); 
		}
#endif //DBG_PENDING_EVENTS

	} while ( FALSE );

	return ntstatus; 
}
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

/*****************************************************************************************
event buffer method:
1.using array, all used event which flags is set the value that mean using.
2.using 3 offset double list, 1 free list. 2 notify list 3 check list so not need locking
when checking event.
3.using 2 offset double list, 2 free list, 2 using list. need locking using list when read using cell,
or set a flags that mean checking.
4.using 1 offset double list, free list.just like malloc, free, allocate one buffer, release
it when not need using.
5.using the array of the buffer, but also have a flags array, checking flags array determine
free buffer cell in the buffer array.
*****************************************************************************************/

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
#ifdef TEST_IN_RING3
NTSTATUS _receive_ring3_response( sys_action_desc *cur_action, PVOID data, ULONG data_len, action_response_type *response, ULONG flags, HANDLE app_notify )
#else
NTSTATUS _receive_ring3_response( sys_action_desc *cur_action, PVOID data, ULONG data_len, action_response_type *response, ULONG flags )
#endif
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	event_notifier_item* sys_event = NULL; 
	sys_action_output *action_output = NULL; 
	LARGE_INTEGER wait_event_respon_time; 
	ULONG event_id; 

	ASSERT( cur_action != NULL ); 
	ASSERT( response != NULL ); 

	log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) );

	if( data == NULL )
	{
		if( data_len != 0 )
		{
			ASSERT( FALSE && "data is null length is not 0"); 
			data_len = 0; 
		}
	}
	else
	{
		if( data_len == 0 )
		{
			ASSERT( FALSE && "data is not null length is 0"); 
			data = NULL; 
		}
		else if( data_len > DEFAULT_OUTPUT_DATA_REGION_SIZE )
		{
			dbg_print( MSG_IMPORTANT, "notice: output data size is greater than %u\n", DEFAULT_OUTPUT_DATA_REGION_SIZE ); 
			data_len = DEFAULT_OUTPUT_DATA_REGION_SIZE; 
		}
	}

	if( stop_events_queue == TRUE )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		goto _return; 
	}

	if( flags & SMALLER_WAIT_TIME )
	{
		wait_event_respon_time.LowPart = MAX_SYS_EVENT_REPONSE_TIME_WIN7;
	}
	else
	{
		if( TRUE == is_socket_action( cur_action->type ) )
		{
			wait_event_respon_time.LowPart = MAX_SYS_SOCKET_EVENT_REPONSE_TIME;			
		}
		else
		{
			wait_event_respon_time.LowPart = MAX_SYS_EVENT_REPONSE_TIME;
		}
	}
	wait_event_respon_time.HighPart = 0xFFFFFFFF;

	ASSERT( sys_events_inited( &sys_events ) == TRUE ); 

	sys_event = ( event_notifier_item* )alloc_pool( NonPagedPool, sizeof( event_notifier_item ) );

	if( NULL == sys_event )
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		goto _return; 
	}

	InitializeListHead( &sys_event->entry ); 

	sys_event->action = NULL; 

	event_id = sys_events.item_count; 
	cur_action->id = event_id;

	ntstatus = get_buf_from_array( &all_r3_arr[ SYS_ACTION_BUF_ARRAY ].arr, ( PVOID* )&action_output ); 
	if( ntstatus != STATUS_SUCCESS )
	{
		ASSERT( action_output == NULL ); 

		dbg_print( MSG_ERROR, "get the buffer from the buffer array error 0x%0.8x\n", ntstatus ); 
		goto _return; 
	}

	ASSERT( action_output != NULL ); 

	sys_event->action = action_output;

	action_output->magic = SYS_ACTION_OUTPUT_MAGIC; 
	action_output->size = calc_action_output_size( data_len ); 

	memcpy( &action_output->action, cur_action, sizeof( sys_action_desc ) ); 
	memcpy( action_output->data, data, data_len ); 

	_init_action_desc_param_ptr( action_output->action.type, &action_output->action ); 

	sys_event->action->action.id = event_id; 
	ASSERT( ( LONG )sys_events.item_count >= 0 ); 

	sys_event->need_record = RECORD_NONE; 
	sys_event->waiting = FALSE; 

#ifdef _DRIVER
	KeInitializeEvent( &sys_event->notify, 
		NotificationEvent/*SynchronizationEvent*/, 
		FALSE ); 
#else
	sys_event->notify = CreateEvent( NULL, FALSE, FALSE, NULL ); 
	if( sys_event->notify == NULL )
	{
		ntstatus = GetLastError(); 
		goto _return; 
	}
#endif //_DRIVER

	KdPrint( ( "insert new sys event id %d type %ws \n", 
		sys_event->action->action.id, 
		get_action_desc( action_output->action.type ) ) );

	ntstatus = add_safe_list_entry_no_create( &sys_event->entry, &sys_events ); 

	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	KdPrint( ( "wait event %d, type %ws\n", sys_event->action->action.id, get_action_desc( sys_event->action->action.type ) ) ); 
	signal_notify_event( SYS_ACTION_EVENT ); 

#ifdef _DRIVER
	ntstatus = KeWaitForSingleObject( &sys_event->notify, Executive, KernelMode, FALSE, &wait_event_respon_time );
	if( ntstatus == STATUS_SUCCESS )
	{
		ASSERT( sys_event->action->action.resp == ACTION_ALLOW 
			|| sys_event->action->action.resp == ACTION_BLOCK ); 
		
		log_trace( ( MSG_INFO, "the pending system event have responded %d\n", 
			sys_event->action->action.resp ) ); 

		*response = sys_event->action->action.resp; 
	}
	else
	{
		ASSERT( ntstatus == STATUS_TIMEOUT ); 
		ASSERT( sys_event->need_record == RECORD_NONE ); 

		*response = ACTION_ALLOW; 
	}
#else
	ntstatus = WaitForSingleObject( sys_event->notify, 200000 ); 
	if( ntstatus == WAIT_OBJECT_0 )
	{
		ASSERT( sys_event->action->action.resp == ACTION_ALLOW 
			|| sys_event->action->action.resp == ACTION_BLOCK ); 
		
		*response = sys_event->action->action.resp; 
	}
	else
	{
		ASSERT( ntstatus == WAIT_TIMEOUT ); 
		ASSERT( sys_event->need_record == RECORD_NONE ); 

		*response = ACTION_ALLOW; 
	}
#endif //_DRIVER

	ASSERT( TRUE == is_valid_record_mode( sys_event->need_record ) ); 

	switch( sys_event->need_record )
	{
	case RECORD_APP_ACTION_TYPE: 
		log_trace( ( MSG_INFO, "*** add app action type record %ws*** \n", 
			cur_action->desc.common.app.app.app_name ) ); 
		
		ntstatus = _add_action_response_record( cur_action->type, 
			sys_event->action->action.resp, 
			cur_action->desc.common.app.app.app_name, 
			wcslen( cur_action->desc.common.app.app.app_name ) + 1 ); 
		//ntstatus = input_action_rule_from_desc( &sys_event->desc, MODIFY_RULE ); 
		if( !NT_SUCCESS( ntstatus ) )
		{
			log_trace( ( MSG_ERROR, "!!!record action type form this action description failed\n" ) ); 
		}
		break; 
	case RECORD_APP_ACTION:
		log_trace( ( MSG_INFO, "*** add app action rule %ws*** \n", 
			cur_action->desc.common.app.app.app_name ) ); 

		ntstatus = input_action_rule_from_desc( cur_action, MODIFY_RULE ); 
		if( !NT_SUCCESS( ntstatus ) )
		{
			log_trace( ( MSG_ERROR, "!!!record action form this action description failed\n" ) ); 
		}
		break; 

	case RECORD_APP:
		log_trace( ( MSG_INFO, "*** add app record %ws*** \n", 
			cur_action->desc.common.app.app.app_name ) ); 

		ntstatus = add_app_response_record( cur_action->resp, 
			cur_action->desc.common.app.app.app_name, 
			wcslen( cur_action->desc.common.app.app.app_name ) + 1 ); 

		if( !NT_SUCCESS( ntstatus ) )
		{
			log_trace( ( MSG_ERROR, "!!!record action form this action description failed\n" ) ); 
		}
		break; 
	}

#ifdef _DRIVER
	if( ntstatus != STATUS_SUCCESS 
		&& ( flags & SMALLER_WAIT_TIME ) )
#else		
	if( ntstatus != WAIT_OBJECT_0 
		&& ( flags & SMALLER_WAIT_TIME ) )
#endif //_DRIVER
	{
		PLIST_ENTRY entry; 
		KIRQL old_irql; 

		W_LOCK_SAFE_LIST( &sys_events );

#ifdef DBG
		entry = find_safe_list_entry_unlock( &sys_event->entry, &sys_events ); 
		if( NULL == entry )
		{
			ASSERT( FALSE && "where remove the event entry?" ); 
		}
#endif //DBG

		RemoveEntryList( &sys_event->entry ); 
		InitializeListHead( &sys_event->entry ); 

		UNLOCK_SAFE_LIST( &sys_events ); 

		ntstatus = add_pending_sys_event( sys_event ); 
		if( !NT_SUCCESS( ntstatus ) )
		{
			ASSERT( IsListEmpty( &sys_event->entry ) == TRUE ); 
			release_sys_event( &sys_event->entry ); 
		}

		ntstatus = STATUS_SUCCESS; 
	}
	else
	{
		if( sys_event->need_record != RECORD_NONE )
		{
			NTSTATUS _ntstatus; 
			_ntstatus = release_remain_sys_events_by_type_response( cur_action, *response, ( ACTION_RECORD_TYPE )sys_event->need_record ); 
		}

		ntstatus = del_safe_list_entry( &sys_event->entry, &sys_events ); 
		ASSERT( NT_SUCCESS( ntstatus ) ); 
		ntstatus = STATUS_SUCCESS; 
	}

_return:

	cur_action->resp = *response; 

	log_trace( ( MSG_INFO, "leave %s\n", __FUNCTION__ ) ); 

	if( !NT_SUCCESS( ntstatus ) )
	{
		if( sys_event != NULL )
		{
			ASSERT( IsListEmpty( &sys_event->entry ) == TRUE ); 
			release_sys_event( &sys_event->entry ); 
		}
	}
	return ntstatus; 
}

#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0