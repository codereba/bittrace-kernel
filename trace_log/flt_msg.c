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
#define get_proc_name_from_eproc( x, y ) ( memcpy( y , "123.exe", 8 ) ); TRUE; 
#define PsGetCurrentThreadId( x ) 1
#define PsGetCurrentProcessId( x ) 1
#define PsGetCurrentProcess( x ) NULL
#define ZwCurrentProcess() ( HANDLE )( -1 )

NTSTATUS get_proc_id_and_name( PEPROCESS EProcess, 
							  HANDLE proc_handle, 
							  ULONG *ProcessId, 
							  WCHAR* name, 
							  ULONG buf_len, 
							  ULONG *ret_len )
{
	return STATUS_SUCCESS; 
}

#else
#include "common.h"
#endif
#include "trace_log_api.h"
#include "flt_msg.h"

INT32 flt_msg( PMSG_FLT_SETTINGS flt_settings, ULONG proc_id, ULONG thread_id, WCHAR *proc_name )
{
	INT32 ret; 
	NTSTATUS ntstatus; 
	ULONG _proc_id; 
	ULONG _thread_id; 
	WCHAR _proc_name[ NT_PROCNAMELEN ]; 
	ULONG name_len; 

	if( flt_settings->proc_id != PROC_ID_NONE )
	{
		if( proc_id == PROC_ID_NONE )
		{
			_proc_id = ( ULONG )PsGetCurrentProcessId(); 
		}
		else
		{
			_proc_id = proc_id; 
		}

		if( flt_settings->proc_id != _proc_id )
		{
			ret = FALSE; 
			goto _return; 
		}
	}
	else if( *flt_settings->proc_name != L'\0')
	{
		if( *proc_name == L'\0')
		{
			ULONG proc_id; 
			PEPROCESS eprocess; 

			eprocess = PsGetCurrentProcess(); 
			if( eprocess == NULL )
			{
				ret = FALSE; 
				goto _return; 
			}

			ntstatus = get_proc_id_and_name( eprocess, ZwCurrentProcess(), &proc_id, _proc_name, sizeof( _proc_name ), &name_len ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				ret = FALSE; 
				goto _return; 
			}

			if( wcsncmp( _proc_name, flt_settings->proc_name, name_len >> 1 ) != 0 )
			{
				ret = FALSE; 
				goto _return; 
			}
		}
		else
		{
			if( wcsncmp( proc_name, flt_settings->proc_name, NT_PROCNAMELEN ) != 0 )
			{
				ret = FALSE; 
				goto _return; 
			}
		}
	}

	if( flt_settings->thread_id != THREAD_ID_NONE )
	{
		if( thread_id == THREAD_ID_NONE )
		{
			_thread_id = ( ULONG )PsGetCurrentThreadId(); 
		}
		else
		{
			_thread_id = thread_id; 
		}

		if( flt_settings->thread_id != _thread_id )
		{
			ret = FALSE; 
			goto _return; 
		}
	}

	ret = TRUE; 

_return:
	return ret; 
}
