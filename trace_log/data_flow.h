#ifndef __DATA_FLOW_H__
#define __DATA_FLOW_H__
#include "trace_log_api.h"

extern DATA_FLOW_CONDITIONS data_flow_conditions; 

INLINE NTSTATUS config_data_flow_conditions( DATA_FLOW_CONDITIONS *conditions )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		data_flow_conditions.proc_id = NULL; 
		data_flow_conditions.thread_id = NULL; 
		data_flow_conditions.type = SYS_ACTION_NONE; 
		data_flow_conditions.object = NULL; 
		data_flow_conditions.cc_object_path_len = 0; 

		if( conditions->cc_object_path_len >= ARRAYSIZE( data_flow_conditions.object_path ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		data_flow_conditions.proc_id = conditions->proc_id; 
		data_flow_conditions.thread_id = conditions->thread_id; 
		data_flow_conditions.type = conditions->type; 
		
		ntstatus = ObReferenceObjectByHandle(
			conditions->object, 
			0,
			NULL,
			KernelMode,
			&data_flow_conditions.object,
			NULL ); 

		if( NT_SUCCESS( ntstatus ) )
		{
			ObDereferenceObject( data_flow_conditions.object ); 
		}

		data_flow_conditions.cc_object_path_len = conditions->cc_object_path_len; 

		memcpy( data_flow_conditions.object_path, conditions->object_path, ( conditions->cc_object_path_len + 1 ) << 1 ); 
	} while ( FALSE );

	return ntstatus; 
}

INLINE NTSTATUS _check_data_flow_event( PVOID object, r3_action_notify *action, DATA_FLOW_CONDITIONS *conditions )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		ASSERT( NULL != action ); 
		ASSERT( NULL != conditions ); 

		if( conditions->object != NULL 
			&& object != NULL )
		{
			if( conditions->object != object )
			{
				ntstatus = STATUS_INVALID_PARAMETER; 
				break; 
			}
		}

		if( conditions->proc_id != INVALID_PROCESS_ID )
		{
			if( conditions->type != action->action.ctx.proc_id )
			{
				ntstatus = STATUS_INVALID_PARAMETER; 
				break; 
			}
		}

		//if( *conditions->object_path != L'\0' )
		//{
		//	if( )
		//	{
		//		ntstatus = STATUS_INVALID_PARAMETER; 
		//		break; 
		//	}
		//}

		if( conditions->type != SYS_ACTION_NONE )
		{
			if( conditions->type != action->action.action.type )
			{
				ntstatus = STATUS_INVALID_PARAMETER; 
				break; 
			}
		}

		if( conditions->thread_id != INVALID_THREAD_ID )
		{
			if( conditions->thread_id != ( HANDLE )action->action.ctx.thread_id )
			{
				ntstatus = STATUS_INVALID_PARAMETER; 
				break; 
			}
		}

	}while( FALSE );

	return ntstatus; 
}

INLINE NTSTATUS check_data_flow_event( PVOID object, r3_action_notify *action )
{
	return _check_data_flow_event( object, action, &data_flow_conditions ); 
}

#endif //__DATA_FLOW_H__