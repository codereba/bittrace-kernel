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
#include "proc_info.h"
#include "event_trace_config.h"
#include "trace_log_api.h"
#include "hash_table.h"
#include "output_buffer_manage.h"
#include "data_flow.h"

event_trace_config trace_config = { 0xffffffff, DEFAULT_MAX_TRACE_DATA_SIZE }; 
common_hash_table proc_trace_conf_table; 
static ULONG max_trace_data_size = MAX_TRACE_DATA_SIZE; //R3_NOTIFY_BUF_SIZE

/*****************************************************************

数据跟踪的配置分为两种:

全局的，对所有程序的数据流量的跟踪长度，为了节约性能，默认不进行所
有数据的跟踪。

局部的，对某一个程序的数据流量的跟踪长度。

有如下方式：
1.通过进程ID
2.通过进程名
3.通过进程组。

*****************************************************************/
NTSTATUS init_trace_config()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
	}while( FALSE );

	return ntstatus; 
}

NTSTATUS uninit_trace_config()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
	}while( FALSE );

	return ntstatus; 
}

NTSTATUS trace_proc_all_data( HANDLE proc_id )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{

	}while( FALSE );

	return ntstatus; 
}

NTSTATUS config_trace_data_size( event_trace_config *config )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		ASSERT( config != NULL ); 

		if( config->proc_id == ( ULONG )INVALID_PROCESS_ID )
		{
			if( config->trace_data_size > max_trace_data_size )
			{
				trace_config.trace_data_size = max_trace_data_size; 
			}
			else
			{
				trace_config.trace_data_size = config->trace_data_size; 
			}
		}
		else
		{
			PROCESS_INFO *proc_info; 
			proc_info = get_proc_info_by_proc_id( config->proc_id ); 
			
			if( proc_info != NULL )
			{
				if( config->trace_data_size > max_trace_data_size )
				{
					proc_info->trace_data_size = max_trace_data_size; 
				}
				else
				{
					proc_info->trace_data_size = config->trace_data_size; 
				}

				release_proc_info( proc_info ); 
			}
		}
	}while( FALSE );

	return ntstatus; 
}

NTSTATUS adjust_trace_data_size( ULONG proc_id, ULONG *data_size )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	PROCESS_INFO *proc_info; 

	do 
	{
		proc_info = get_proc_info_by_proc_id( proc_id ); 

		if( proc_info == NULL )
		{ 
			if( *data_size > trace_config.trace_data_size )
			{
				*data_size = trace_config.trace_data_size; 
			}
		}
		else
		{
			if( proc_info->trace_data_size < 0 )
			{
				if( *data_size > trace_config.trace_data_size )
				{
					*data_size = trace_config.trace_data_size; 
				}
			}
			else
			{
				if( ( LONG )*data_size > proc_info->trace_data_size )
				{
					*data_size = proc_info->trace_data_size; 
				}
			}

			release_proc_info( proc_info ); 
		}


	}while( FALSE ); 

	if( *data_size > MAX_TRACE_DATA_SIZE )
	{
		*data_size = MAX_TRACE_DATA_SIZE; 
	}

	return ntstatus; 
}

ULONG get_max_trace_data_size( ULONG proc_id, ULONG data_size )
{
	ULONG _data_size; 
	PROCESS_INFO *proc_info; 

	do 
	{
		proc_info = get_proc_info_by_proc_id( proc_id ); 

		if( proc_info == NULL )
		{ 
			if( data_size > trace_config.trace_data_size )
			{
				_data_size = trace_config.trace_data_size; 
			}
			else
			{
				_data_size = data_size; 
			}
		}
		else
		{
			if( proc_info->trace_data_size < 0 )
			{
				if( data_size > trace_config.trace_data_size )
				{
					_data_size = trace_config.trace_data_size; 
				}
				else
				{
					_data_size = data_size; 
				}
			}
			else
			{
				if( ( LONG )data_size > proc_info->trace_data_size )
				{
					_data_size = proc_info->trace_data_size; 
				}
				else
				{
					_data_size = data_size; 
				}
			}

			release_proc_info( proc_info ); 
		}

	}while( FALSE ); 

	if( _data_size > MAX_TRACE_DATA_SIZE )
	{
		_data_size = MAX_TRACE_DATA_SIZE; 
	}

	return _data_size; 
}

ULONG get_max_trace_data_size_ex( PVOID object, 
								 r3_action_notify *action, 
								 ULONG data_size )
{
	ULONG _data_size; 
	PROCESS_INFO *proc_info; 

	do 
	{
		ASSERT( NULL != action ); 

		if( STATUS_SUCCESS == check_data_flow_event( object, action ) )
		{
			ULONG buffer_size; 

			buffer_size = get_buffer_size( action ); 
			ASSERT( buffer_size > R3_NOTIFY_BUF_SIZE ); 
			
			_data_size = MAX_R3_NOTIFY_VARIABLE_SIZE_EX( action ) - action->action.action.size; 

			if( data_size < _data_size )
			{
				_data_size = data_size; 
			}

			break; 
		}

		do 
		{
			ASSERT( INVALID_PROCESS_ID != action->action.ctx.proc_id ); 

			proc_info = get_proc_info_by_proc_id( action->action.ctx.proc_id ); 

			if( proc_info == NULL )
			{ 
				if( data_size > trace_config.trace_data_size )
				{
					_data_size = trace_config.trace_data_size; 
				}
				else
				{
					_data_size = data_size; 
				}
			}
			else
			{
				if( proc_info->trace_data_size < 0 )
				{
					if( data_size > trace_config.trace_data_size )
					{
						_data_size = trace_config.trace_data_size; 
					}
					else
					{
						_data_size = data_size; 
					}
				}
				else
				{
					if( ( LONG )data_size > proc_info->trace_data_size )
					{
						_data_size = proc_info->trace_data_size; 
					}
					else
					{
						_data_size = data_size; 
					}
				}

				release_proc_info( proc_info ); 
			}
		}while( FALSE );

		if( _data_size > MAX_TRACE_DATA_SIZE )
		{
			_data_size = MAX_TRACE_DATA_SIZE; 
		}
	}while( FALSE ); 

	return _data_size; 
}