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

#include "hash_table.h"

#define LOGGER_HASH_TABLE_SIZE 128

typedef struct __TRACE_LOGGER
{
	LONG TraceMsgCount;
	LONG trace_log_count;
	LIST_ENTRY TraceMsgs;
	LIST_ENTRY trace_logs;
} TRACE_LOGGER, *PTRACE_LOGGER;

typedef struct _UNI_TRACE
{
	LIST_ENTRY entry; 
	ULONG id; 
	ULONG name;  
	MSG_FLT_SETTINGS flt_setting; 
	TRACE_LOGGER logger; 
} UNI_TRACE, *PUNI_TRACE;  

typedef struct __TRACE_MSG
{
	LIST_ENTRY ListEtnry;
	ULONG Length;
	CHAR TraceMsg[ 0 ];
} TRACE_MSG, *PTRACE_MSG; 

typedef struct _action_trace_log
{
	LIST_ENTRY entry; 
	//ULONG data_len; 
	sys_action_output action_output; 
} action_trace_log, *paction_trace_log; 
typedef NTSTATUS ( *GET_INFO_FROME_HANDLE )( PINFO_HEAD Info ); 

/*FORCEINLINE */
INLINE NTSTATUS free_action_log( HANDLE data_trace_proc, action_trace_log *log )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	ASSERT( log != NULL ); 

	do 
	{
#ifdef ACTION_LOG_ALLOC_FROM_R3_MAPPED_BUF
		if( log->desc.data.data != NULL )
		{
			ntstatus = release_relating_data_buf( data_trace_proc, &log->desc.data );
		}
#endif //ACTION_LOG_ALLOC_FROM_R3_MAPPED_BUF

		free_pool( log ); 
	} while ( FALSE );

	return ntstatus; 
}

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

	extern common_hash_table data_flow_trace; 

ULONG calc_flt_setting_hash_code( ULONG proc_id, ULONG thread_id, CHAR *proc_name ); 
ULONG calc_flt_name_hash_code( ULONG name ); 
ULONG calc_flt_id_hash_code( ULONG flt_id ); 

#define NEED_COPY_DATA 0x00000001
#define NEED_SET_DATA_PTR 0x00000002
#define COPY_DATA_TO_USER_SPACE 0x00000004
#define COPY_DATA_TO_KERNEL_SPACE 0x00000008

#define LOGGING_TO_NONPAGED_BUF 0x00000004
#define LOGGING_TO_PAGED_BUF 0x00000008

NTSTATUS add_new_log( ULONG logger_name, 
					 action_context *context, 
					 sys_action_desc *cur_action, 
					 PVOID data, 
					 ULONG data_len, 
					 ULONG flags ); 

NTSTATUS reference_trace_logger( PUNI_TRACE trace_logger, PMSG_FLT setting ); 
NTSTATUS _get_trace_logger( PMSG_FLT logger_setting, PULONG logger_id ); 
NTSTATUS set_trace_setting( ULONG flt_lvl, ULONG proc_id, ULONG thread_id, WCHAR *proc_name, release_flt_notify_func release_notify, ULONG logger_name ); 
NTSTATUS _add_new_trace( ULONG flt_lvl, ULONG proc_id, ULONG thread_id, WCHAR *proc_name, release_flt_notify_func release_notify, ULONG name, PULONG flt_id ); 
NTSTATUS output_trace_msgs( ULONG logger_name, PTRACE_INFO_OUTPUT TraceOut, ULONG out_len ); 

NTSTATUS output_trace_logs( ULONG logger_name, sys_log_output *log_output, ULONG out_len ); 

NTSTATUS init_data_flow_trace(); 
NTSTATUS release_data_flow_trace(); 
void release_trace_log( PTRACE_LOGGER logger ); 
NTSTATUS CALLBACK release_trace_logger( PLIST_ENTRY element ); 
INT32 add_new_msg( ULONG logger_name, FLT_LEVEL flt_lvl, ULONG proc_id, ULONG thread_id, WCHAR *proc_name, ULONG length, CHAR *Fmt, va_list va ); 
NTSTATUS change_trace_logger( PMSG_FLT flt_setting, ULONG buf_len ); 
NTSTATUS add_trace_logger( PMSG_FLT flt_setting, ULONG buf_len, PULONG flt_id ); 
NTSTATUS del_trace_log( ULONG logger_name ); 

#ifdef _DRIVER
NTSTATUS get_trace_log_if( PI_TRACE_LOG_TRACE trace_log_if, ULONG name, ULONG flt_id ); 
#endif //_DRIVER

PUNI_TRACE find_trace_log( ULONG name ); 
NTSTATUS filter_trace_data( ULONG proc_id, ULONG thread_id, TRACING_LEVEL level, OUT data_trace_option *option ); 

INLINE VOID release_trace_env()
{
	release_common_hash_table_def_lock( &data_flow_trace, release_trace_logger ); 
}

#ifdef __cplusplus
}
#endif //__cplusplus
