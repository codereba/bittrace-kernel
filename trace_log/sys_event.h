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

#ifndef __SYS_EVENT_H__
#define __SYS_EVENT_H__

#include "sys_event_define.h"

#define LINKED_SYS_EVENT 1

typedef struct _event_action_msg
{
	USHORT type; 
	ULONG id; 
	USHORT action; 
	ULONG Size;
	BYTE Msgs[ 0 ];
} event_action_msg, *pevent_action_msg; 

/****************************************************
event response notify method:
1.one action have one event to waiting response.user send
the id of the event,then kernel find the event of the 
action and set it to signal state.

2.all action have one event to waiting response.user just
to set the event to signal state when one action is replying.
kernel will traverse all event to find that have replying.
****************************************************/
typedef struct _event_notifier_item
{
	LIST_ENTRY entry; 
#ifdef _DRIVER
	KEVENT notify; 
#else
	HANDLE notify; 
#endif

	BOOLEAN waiting; 
	BYTE need_record; 
	//ULONG id; 
	
#ifdef LINKED_SYS_EVENT
	
	/**************************************************
	converting address between ring 3 and ring 0 methods:
	1.use the ring 0 address subtract the base address 
	to get the offset.then use offset and ring 0 base 
	address.
	2.record the 2 addresses or the offset directly.
	**************************************************/
	sys_action_output *action; 
	//sys_action_output *desc_r3; 
#endif //LINKED_SYS_EVENT

#ifdef MAPPING_CELL_BUFFER
	user_mem_map *map2user; 
#endif //MAPPING_CELL_BUFFER

}event_notifier_item, *pevent_notifier_item; 

#ifndef __cplusplus
typedef struct _event_msg_notifier_item
{
	LIST_ENTRY entry; 
	KEVENT notify; 
	BOOLEAN waiting; 
	event_action_msg; 
} event_msg_notifier_item, *pevent_msg_notifier_item; 
#else
typedef struct _event_msg_notifier_item
{
	LIST_ENTRY entry; 
	KEVENT notify; 
	BOOLEAN waiting; 
	event_action_msg action_msg; 
} event_msg_notifier_item, *pevent_msg_notifier_item; 
#endif //__cplusplus

#ifdef __cplusplus
extern "C" {
#endif 

	INT32 release_sys_event( PLIST_ENTRY list_entry ); 
	NTSTATUS get_next_sys_event( sys_action_output_map* sys_event, PULONG out_length ); 
	NTSTATUS map_next_sys_event( sys_action_map* sys_event_map, PULONG out_length ); 
#define HAVE_PENDING_EVENT 0x00000001

	VOID release_sys_events_list( ULONG flags ); 
	NTSTATUS init_sys_events_list( ULONG flags ); 
	NTSTATUS response_action_event( event_action_response* sys_event_respon );

#define SMALLER_WAIT_TIME 0x0000001

	NTSTATUS release_pending_sys_action(); 

#ifdef TEST_IN_RING3
	NTSTATUS _receive_ring3_response( sys_action_desc *cur_action, PVOID data, ULONG data_len, action_response_type *response, ULONG flags, HANDLE app_notify ); 
#else
	NTSTATUS _receive_ring3_response( sys_action_desc *cur_action, PVOID data, ULONG data_len, action_response_type *response, ULONG flags ); 
	NTSTATUS release_remain_sys_events_by_type_response( sys_action_desc *sys_event, action_response_type resp, ACTION_RECORD_TYPE record_type )
		; 
#endif

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //__SYS_EVENT_H__