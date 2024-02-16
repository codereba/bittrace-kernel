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

#ifndef __EVENT_TRACE_CONFIG_H__
#define __EVENT_TRACE_CONFIG_H__

NTSTATUS trace_proc_all_data( HANDLE proc_id ); 

#ifndef EVENT_TRACE_CONFIG_DEFINED
#define EVENT_TRACE_CONFIG_DEFINED
#pragma pack( push )
#pragma pack( 1 )

typedef struct _event_trace_config
{
	ULONG proc_id; 
	ULONG trace_data_size; 
} event_trace_config, *pevent_trace_config; 

#pragma pack( pop ) 

#endif //EVENT_TRACE_CONFIG_DEFINED

extern event_trace_config trace_config; 

NTSTATUS config_trace_data_size( event_trace_config *config ); 
NTSTATUS adjust_trace_data_size( ULONG proc_id, ULONG *data_size ); 
ULONG get_max_trace_data_size( ULONG proc_id, ULONG data_size ); 
#endif //__EVENT_TRACE_CONFIG_H__