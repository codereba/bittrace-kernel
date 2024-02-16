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

#ifndef __TRACE_LOG_H__
#define __TRACE_LOG_H__

#define PRE_FILTER_ENABLED 0x00000001
#define POST_FILTER_ENABLED 0x00000002

ULONG filter_enabled(); 

NTSTATUS notify_action_pre_ex( r3_action_notify *action_notify, 
						   data_trace_context *trace_context, 
						   action_response_type *action_resp, 
						   ULONG flags ); 

INLINE NTSTATUS notify_action_pre( r3_action_notify *action_notify, 
						   action_response_type *action_resp, 
						   ULONG flags )
{
	return notify_action_pre_ex( action_notify, NULL, action_resp, flags ); 
}

NTSTATUS r3_notify_action_post_ex( r3_action_notify *action_notify, 
								  data_trace_context *trace_context ); 

INLINE NTSTATUS r3_notify_action_post( r3_action_notify *action_notify )
{
	return r3_notify_action_post_ex( action_notify, NULL ); 
}

NTSTATUS collect_action_related_info( relation_info_request_type type, action_info_request *request ); 

NTSTATUS prepare_action_notify( sys_action_info *action_info, 
							   data_trace_context *data_context, 
							   r3_action_notify **action_out ); 

/********************************************************************************
notice:
action data have 2 type:
1.the data before one action common for setting. 
2.the data after one action common for querying.

the data opponent is meaningless.
********************************************************************************/
NTSTATUS prepare_action_notify_data( data_trace_context *data_context, 
									r3_action_notify *action_out ); 
#endif //__TRACE_LOG_H__