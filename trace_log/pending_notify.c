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
#include "acl_define.h"
#include "output_buffer_manage.h"
#include "trace_log_api.h"
#include "trace_log_help.h"
#include "pending_notify.h"
#include "trace_verifier.h"

action_notify_queue notify_queue = { 0 }; 

INLINE NTSTATUS hold_notify_queue_lock( action_notify_queue *queue, KIRQL *old_irql )
{
	ASSERT( queue != NULL ); 


	hold_sp_lock( queue->lock, *old_irql ); 

	return STATUS_SUCCESS; 
}

INLINE NTSTATUS release_notify_queue_lock( action_notify_queue *queue, KIRQL *old_irql )
{
	ASSERT( queue != NULL ); 

	release_sp_lock( queue->lock, *old_irql ); 

	return STATUS_SUCCESS; 
}

INLINE VOID release_notify_work_item( action_notify_work *work_item )
{
	ASSERT( work_item != NULL ); 

	ASSERT( NULL != work_item->action ); 
	
	//if( NULL != work_item->trace_context )
	//{
	//	FREE_TAG_POOL( work_item->trace_context ); 
	//}

	deallocate_action_notify( work_item->action ); 

	FREE_TAG_POOL( work_item ); 
}

#ifdef EVENT_NOTIFY_FROM_WPP
VOID async_event_notify_thread( PVOID all_work_item )
{
	NTSTATUS ntstatus; 
	action_notify_queue *notify_queue; 
	KIRQL old_irql; 
	PLIST_ENTRY entry; 
	action_notify_work *work_item; 

	PAGED_CODE(); 

	do 
	{
		if( all_work_item == NULL )
		{
			ASSERT( FALSE && __FUNCTION__ "how can input the null to the parameter" ); 
			break; 
		}

		notify_queue = ( action_notify_queue* )all_work_item; 

		for( ; ; )
		{
			KeWaitForSingleObject( &notify_queue->work_notify, 
				Executive, 
				KernelMode, 
				FALSE, 
				NULL ); 

			if( notify_queue->stop_working == TRUE )
			{
				break; 
			}

			for( ; ; )
			{
				hold_notify_queue_lock( notify_queue, &old_irql ); 

				entry = notify_queue->queue.Flink; 

				if( entry == &notify_queue->queue )
				{
					release_notify_queue_lock( notify_queue, &old_irql ); 

					break; 
				}

				RemoveEntryList( entry ); 

				release_notify_queue_lock( notify_queue, &old_irql ); 

				work_item = CONTAINING_RECORD( entry, action_notify_work, entry ); 

				ntstatus = i_notify_action_post( work_item->action, 
					work_item->action->action.ctx.last_result, 
					NULL //work_item->trace_context 
					); 

				if( ntstatus == STATUS_EVENT_NOTIFY_PENDING )
				{
					KeBugCheck( STATUS_UNSUCCESSFUL ); 
				}

				if( ntstatus != STATUS_SUCCESS )
				{
					dbg_print( MSG_ERROR, "post the pended event error 0x%0.8x\n", ntstatus ); 
				}

#ifdef MEMORY_LEAK_DEBUG
				debug_buffer_stop_pending( ( PVOID )work_item->action ); 
#endif //MEMORY_LEAK_DEBUG
				release_notify_work_item( work_item ); 

				notify_queue->count -= 1; 
			}
		}
	} while ( FALSE );

	PsTerminateSystemThread( STATUS_SUCCESS ); 
	return; 
}
#endif //EVENT_NOTIFY_FROM_WPP

NTSTATUS stop_event_notify_worker()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	KIRQL old_irql; 
	LIST_ENTRY *entry; 
	action_notify_work *work_item; 

	PAGED_CODE(); 

	do 
	{
#ifdef EVENT_NOTIFY_FROM_WPP
		if( notify_queue.work_thread == NULL )
		{
			ASSERT( FALSE ); 
		}

		notify_queue.stop_working = TRUE; 

		KeSetEvent( &notify_queue.work_notify, IO_NO_INCREMENT, FALSE ); 

		if( notify_queue.work_thread != NULL )
		{
			KeWaitForSingleObject( notify_queue.work_thread, Executive, KernelMode, FALSE, NULL ); 

			notify_queue.work_thread = NULL; 
		}
#else
		if( notify_queue.work_notify != NULL )
		{
			ObDereferenceObject( notify_queue.work_notify ); 
			notify_queue.work_notify = NULL; 
		}
#endif //EVENT_NOTIFY_FROM_WPP

		ASSERT( NULL != notify_queue.queue.Blink ); 
		hold_notify_queue_lock( &notify_queue, &old_irql ); 

		for( ; ; )
		{
			entry = notify_queue.queue.Flink; 

			if( entry == &notify_queue.queue )
			{
				break; 
			}

			work_item = CONTAINING_RECORD( entry, action_notify_work, entry ); 

			RemoveEntryList( entry ); 

#ifdef MEMORY_LEAK_DEBUG
			debug_buffer_stop_pending( ( PVOID )work_item->action ); 
#endif //MEMORY_LEAK_DEBUG

			release_notify_work_item( work_item ); 
			notify_queue.count -= 1; 
		}

		release_notify_queue_lock( &notify_queue, &old_irql ); 

		ASSERT( notify_queue.count == 0 ); 

	}while( FALSE );

	return ntstatus; 
}

NTSTATUS notify_list_is_not_full()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		if( notify_queue.count >= MAX_PENDING_NOTIFY_COUNT )
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			break; 
		}
	}while( FALSE );

	return ntstatus; 
}

NTSTATUS add_action_notify_work( r3_action_notify *event_notify, 
								BOOLEAN inited )
{
	NTSTATUS ntstatus = STATUS_EVENT_NOTIFY_PENDING; 
	action_notify_work *work_item = NULL; 
	KIRQL old_irql; 
	//BOOLEAN work_item_issued = FALSE; 
	//ULONG action_info_size; 
	//ULONG data_size; 

	//PAGED_CODE(); 

	do 
	{
		if( notify_queue.count >= MAX_PENDING_NOTIFY_COUNT )
		{
			ntstatus = STATUS_NO_MORE_ENTRIES; 
			break; 
		}

		if( FALSE == is_valid_action_type( event_notify->action.action.type ) )
		{
			ASSERT( FALSE ); 
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		work_item = ( action_notify_work* )ALLOC_TAG_POOL( sizeof( *work_item ) ); 

		if( work_item == NULL )
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			break; 
		}

		work_item->action = event_notify; 
		work_item->inited = inited;

		hold_notify_queue_lock( &notify_queue, &old_irql ); 

		InsertTailList( &notify_queue.queue, &work_item->entry ); 

		notify_queue.count += 1; 

#ifdef DEBUG_PENDING_BUFFER_MANAGE
		if( TRUE == debug_pending_buffer_manage )
		{
			work_item->action->id.QuadPart = FLAGS_EVENT_INSERTED; 
		}
#endif //DEBUG_PENDING_BUFFER_MANAGE

#ifdef MEMORY_LEAK_DEBUG
		debug_buffer_start_pending( ( PVOID )work_item->action ); 
#endif //MEMORY_LEAK_DEBUG

		release_notify_queue_lock( &notify_queue, &old_irql ); 

#ifdef EVENT_NOTIFY_FROM_WPP
		KeSetEvent( &notify_queue.work_notify, IO_NO_INCREMENT, FALSE ); 
#else
		if( NULL != notify_queue.work_notify )
		{
			KeSetEvent( notify_queue.work_notify, IO_NO_INCREMENT, FALSE ); 
		}
#endif //EVENT_NOTIFY_FROM_WPP
	} while ( FALSE ); 

	return ntstatus; 
}

NTSTATUS get_action_pending_notify( r3_action_notify **event_notify, 
								   BOOLEAN *inited )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	action_notify_work *work_item; // = NULL; 
	PLIST_ENTRY entry; 
	KIRQL old_irql;
	
	do 
	{
		ASSERT( NULL != event_notify ); 
		ASSERT( NULL != inited ); 

		*event_notify = NULL; 
		*inited = FALSE; 

		if( notify_queue.count == 0 )
		{
			ntstatus = STATUS_NO_MORE_ENTRIES; 
			break; 
		}

		hold_notify_queue_lock( &notify_queue, &old_irql ); 

		do 
		{
			entry = notify_queue.queue.Flink; 

			if( entry == &notify_queue.queue )
			{
				work_item = NULL; 
				break; 
			}

			work_item = CONTAINING_RECORD( entry, action_notify_work, entry ); 

			RemoveEntryList( entry ); 
			notify_queue.count -= 1; 

#ifdef MEMORY_LEAK_DEBUG
			debug_buffer_stop_pending( ( PVOID )work_item->action ); 
#endif //MEMORY_LEAK_DEBUG

			ASSERT( notify_queue.count >= 0 ); 
		}while( FALSE );

		release_notify_queue_lock( &notify_queue, &old_irql ); 

#ifdef DEBUG_PENDING_BUFFER_MANAGE
		if( TRUE == debug_pending_buffer_manage )
		{
			work_item->action->id.QuadPart = 0; 
		}
#endif //DEBUG_PENDING_BUFFER_MANAGE

		if( work_item != NULL )
		{
			*inited = work_item->inited; 
			*event_notify = work_item->action; 
			FREE_TAG_POOL( work_item ); 
		}
		else
		{
			ntstatus = STATUS_NOT_FOUND; 
		}

	} while ( FALSE ); 

	return ntstatus; 
}

NTSTATUS start_event_notify_worker()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	HANDLE thread_handle = NULL; 
	OBJECT_ATTRIBUTES oa; 

	do 
	{
		init_sp_lock( notify_queue.lock ); 
		InitializeListHead( &notify_queue.queue ); 
		notify_queue.count = 0; 

#ifdef EVENT_NOTIFY_FROM_WPP
		notify_queue.work_thread = NULL; 
		notify_queue.stop_working = FALSE; 

		KeInitializeEvent( &notify_queue.work_notify, SynchronizationEvent, FALSE ); 

		InitializeObjectAttributes( &oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL ); 

		ntstatus = PsCreateSystemThread( &thread_handle, 
			THREAD_ALL_ACCESS, 
			&oa, 
			NULL, 
			NULL, 
			async_event_notify_thread, 
			&notify_queue ); 

		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		ASSERT( thread_handle != NULL ); 

		ntstatus = ObReferenceObjectByHandle( thread_handle, 
			THREAD_ALL_ACCESS, 
			NULL, 
			KernelMode, 
			( PVOID* )&notify_queue.work_thread, 
			NULL ); 

		if( ntstatus != STATUS_SUCCESS )
		{
			notify_queue.stop_working = TRUE; 
			KeSetEvent( &notify_queue.work_notify, IO_NO_INCREMENT, FALSE ); 
			ZwWaitForSingleObject( thread_handle, FALSE, NULL ); 
			break; 
		}

		ASSERT( notify_queue.work_thread != NULL ); 
#else
		notify_queue.work_notify = NULL; 
#endif //EVENT_NOTIFY_FROM_WPP

	} while( FALSE ); 

#ifdef EVENT_NOTIFY_FROM_WPP
	if( thread_handle != NULL )
	{
		ZwClose( thread_handle ); 
	}
#endif //EVENT_NOTIFY_FROM_WPP

	if( ntstatus != STATUS_SUCCESS )
	{
#ifdef EVENT_NOTIFY_FROM_WPP
		if( notify_queue.work_thread != NULL )
		{
			ASSERT( FALSE ); 
		}
#endif //EVENT_NOTIFY_FROM_WPP
	}

	return ntstatus; 
}
