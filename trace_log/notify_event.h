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

#ifndef __NOTIFY_EVENT_H__
#define __NOTIFY_EVENT_H__

#define TRACE_EVENT_TAG 'ecrt'

typedef struct _notify_event_record
{
	PKEVENT notifier; 
	PFILE_OBJECT file_obj; 
} notify_event_record, *pnotify_event_record; 

extern KSPIN_LOCK events_lock; 
extern notify_event_record all_notify_events[ MAX_EVENT_TYPE ]; 

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

NTSTATUS signal_notify_event( notify_event_type type ); 
NTSTATUS release_notify_event( notify_event_type type ); 
VOID release_all_events(); 
NTSTATUS set_notify_event( event_to_notify *input_event, KPROCESSOR_MODE requestor_mode, PFILE_OBJECT dev_file_obj ); 
NTSTATUS set_notify_events( notify_events_set *event_set, ULONG buf_len, KPROCESSOR_MODE requestor_mode, PFILE_OBJECT dev_file_obj ); 
INLINE NTSTATUS release_notify_event_by_file_obj( PFILE_OBJECT file_obj )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	KIRQL old_irql; 
	INT32 i; 

	hold_sp_lock( events_lock, old_irql ); 
	for( i = 0; i < MAX_EVENT_TYPE; i ++ )
	{ 
		if( all_notify_events[ i ].file_obj == file_obj )
		{
			release_notify_event( ( notify_event_type )i ); 
		}
	}

	release_sp_lock( events_lock, old_irql ); 
	
	return ntstatus; 
}

#ifdef __cplusplus
}
#endif //__cplusplus
#endif //__NOTIFY_EVENT_H__