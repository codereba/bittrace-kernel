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

#ifndef __PENDING_NOTIFY_H__
#define __PENDING_NOTIFY_H__

typedef struct _action_notify_work
{
	LIST_ENTRY entry; 
	r3_action_notify *action; 
	BOOLEAN inited; 
	//data_trace_context *trace_context; 
} action_notify_work, *paction_notify_work; 

#define MAX_PENDING_NOTIFY_COUNT 512

typedef struct _action_notify_queue
{
	LIST_ENTRY queue; 
	KSPIN_LOCK lock; 
#ifdef EVENT_NOTIFY_FROM_WPP
	KEVENT work_notify; 
	BOOLEAN stop_working; 
	PKTHREAD *work_thread; 
#else
	PKEVENT work_notify; 
#endif //EVENT_NOTIFY_FROM_WPP
	LONG count; 
}action_notify_queue, *paction_notify_queue; 

NTSTATUS notify_list_is_not_full(); 
VOID async_event_notify_thread( PVOID all_work_item ); 
NTSTATUS stop_event_notify_worker(); 
NTSTATUS add_action_notify_work( r3_action_notify *event_notify, 
								BOOLEAN inited ); 
NTSTATUS get_action_pending_notify( r3_action_notify **event_notify, 
								   BOOLEAN *inited ); 
NTSTATUS start_event_notify_worker(); 

#endif //__PENDING_NOTIFY_H__