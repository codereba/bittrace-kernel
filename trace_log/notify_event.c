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
#else
#include "common.h"
#include "seven_fw_common.h"
#endif 

#include "trace_log_api.h"
#include "notify_event.h"

notify_event_record all_notify_events[ MAX_EVENT_TYPE ] = { 0 }; 
KSPIN_LOCK events_lock; 

NTSTATUS signal_notify_event( notify_event_type type )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	KIRQL old_irql; 

	log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

	log_trace( ( MSG_INFO, "notify event type is %d %ws\n", 
		( ULONG )type, 
		get_notify_event_type( type ) ) ); 
 
	if( is_valid_notify_event_type( type ) == FALSE )
	{
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	log_trace( ( MSG_INFO, "notifier event is 0x%0.8x\n", all_notify_events[ type ].notifier  ) ); 
	hold_sp_lock( events_lock, old_irql ); 

	if( all_notify_events[ type ].notifier != NULL )
	{
		KeSetEvent( all_notify_events[ type ].notifier, 0, FALSE ); 
	}

	release_sp_lock( events_lock, old_irql ); 

	log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

_return:
	return ntstatus; 
}

#define TRACE_EVENT_TAG 'ecrt'
#define MIN_MSG_SIZE 1

#ifdef DBG
PKTHREAD event_test_thread = NULL; 
INT32 stop_event_test = FALSE; 
#endif //DBG

NTSTATUS release_notify_event( notify_event_type type )
{
	NTSTATUS ntstatus = STATUS_SUCCESS;  
	notify_event_record *target_event = NULL; 

	log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

	ASSERT( is_valid_param_define_type( type ) == TRUE ); 

#ifdef _DRIVER
#ifdef DBG
	if( KeGetCurrentIrql() > DISPATCH_LEVEL )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		DBG_BP(); 
		goto _return; 
	}
#endif //DBG
#endif //_DRIVER

	target_event = &all_notify_events[ type ]; 
	if( target_event->notifier != NULL )
	{
		ASSERT( target_event->file_obj != NULL ); 
		log_trace( ( MSG_WARNING, "!!reset the system log notify event\n" ) ); 

#if (NTDDI_VERSION >= NTDDI_WIN7)
		ObDereferenceObjectWithTag( target_event->notifier, TRACE_EVENT_TAG ); 
#else
		ObDereferenceObject( target_event->notifier ); 
#endif 
		target_event->notifier = NULL; 
		target_event->file_obj = NULL; 
	}
	else
	{
		ASSERT( target_event->file_obj == NULL ); 
	}

	goto _return; 

_return: 
	log_trace( ( MSG_INFO, "leave %s\n", __FUNCTION__ ) ); 

	return ntstatus; 
}

VOID release_all_events()
{
	INT32 i; 
	KIRQL old_irql; 

#ifdef DBG
	if( event_test_thread != NULL )
	{
		stop_event_test = TRUE; 
		stop_thread( event_test_thread, NULL ); 
	}
#endif //DBG

	hold_sp_lock( events_lock, old_irql ); 
	for( i = 0; i < MAX_EVENT_TYPE; i ++ )
	{
		release_notify_event( i ); 
	}

	release_sp_lock( events_lock, old_irql ); 
}

NTSTATUS set_notify_event( event_to_notify *input_event, KPROCESSOR_MODE requestor_mode, PFILE_OBJECT dev_file_obj )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	KIRQL old_irql; 
	notify_event_record *target_event = NULL; 
	PKEVENT event_obj; 

	ASSERT( input_event != NULL ); 
	ASSERT( dev_file_obj != NULL ); 
	ASSERT( requestor_mode == KernelMode || requestor_mode == UserMode ); 

	if( is_valid_notify_event_type( input_event->type ) == FALSE )
	{
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	target_event = &all_notify_events[ input_event->type ]; 

#if (NTDDI_VERSION >= NTDDI_WIN7)
	ntstatus = ObReferenceObjectByHandleWithTag( input_event->event_handle,
		SYNCHRONIZE | EVENT_MODIFY_STATE,
		*ExEventObjectType,
		requestor_mode,
		TRACE_EVENT_TAG, 
		&event_obj,
		NULL ); 
#else 
	ntstatus = ObReferenceObjectByHandle( input_event->event_handle,
		SYNCHRONIZE | EVENT_MODIFY_STATE,
		*ExEventObjectType,
		requestor_mode,
		&event_obj,
		NULL ); 
#endif //(NTDDI_VERSION >= NTDDI_WIN7)

	if( !NT_SUCCESS( ntstatus ) )
	{
		log_trace( ( MSG_ERROR, "reference the object falied\n" ) ); 
		goto _return; 
	}

#ifndef _DRIVER
	event_obj = NULL; 
#endif //_DRIVER

	ASSERT( event_obj != NULL ); 

	hold_sp_lock( events_lock, old_irql ); 

	ntstatus = release_notify_event( input_event->type ); 
	if( !NT_SUCCESS( ntstatus ) ) 
	{
		ASSERT( FALSE && "release the notify event error." ); 
		log_trace( ( MSG_ERROR, "release the notify event (type:%u) error.\n", input_event->type ) ); 

		release_sp_lock( events_lock, old_irql ); 
		goto _return; 
	}

	target_event->notifier = event_obj; 
	target_event->file_obj = dev_file_obj; 

	release_sp_lock( events_lock, old_irql ); 
_return:
	return ntstatus; 
}

#ifdef DBG
VOID CALLBACK thread_notify_event_test( PVOID param )
{
	INT32 i; 
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	for( ; ; )
	{
		if( stop_event_test == TRUE )
		{
			break; 
		}
	
		for( i = 0; i < MAX_EVENT_TYPE; i ++ )
		{
			ntstatus = signal_notify_event( ( notify_event_type )i ); 
			log_trace( ( MSG_ERROR, "signal notify event error\n" ) ); 
		}
	}

	PsTerminateSystemThread( ntstatus ); 

	return; 
}
#endif //DBG

NTSTATUS set_notify_events( notify_events_set *event_set, ULONG buf_len, KPROCESSOR_MODE requestor_mode, PFILE_OBJECT dev_file_obj )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	NTSTATUS _ntstatus; 
	event_to_notify *input_event; 
	INT32 i; 

	ASSERT( dev_file_obj != NULL ); 
	ASSERT( event_set != NULL ); 

	log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

	//DBG_BP(); 

	if( event_set->event_num * sizeof( event_to_notify ) + FIELD_OFFSET( notify_events_set, events ) > buf_len )
	{
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	for( i = 0; ( ULONG )i < event_set->event_num; i ++ )
	{
		input_event = &event_set->events[ i ]; 

		_ntstatus = set_notify_event( input_event, requestor_mode, dev_file_obj ); 
		if( !NT_SUCCESS( _ntstatus ) )
		{
			ntstatus = _ntstatus; 
			goto _return; 
		}
	}

_return:
	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 
	return ntstatus; 
}
