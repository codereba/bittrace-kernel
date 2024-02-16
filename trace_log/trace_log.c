#include "trace_log_common.h"
#ifdef TEST_IN_RING3
#include "common_func.h"
#include "ring0_2_ring3.h"
#else
#include "common.h"
#endif //_TEST_IN_RING3
#include "trace_log_api.h"
#include "trace_log_help.h"
#include "infolist.h"
#include "trace_log.h"
#include "hash_table.h"
#include "rbtree.h"
#include "stdarg.h"
#include "mem_map_io.h"
#include "sys_event.h"
#include "sys_event_define.h"
#include "seven_fw_api.h"
#include "ndis_common.h"
#include "acl_common.h"
#include "Acl_IP.h"
#include "acl_domain.h"
#include "seven_fw_common.h"
#include "url_hash_table.h"
#include "dns_parse.h"
#include "http_parse.h"
#include "tcpip_parse.h"
#include "sevenfw_err_code.h"
#include "notify_event.h"
#include "function_sw.h"
#include "aio.h"
#include <fltKernel.h>
#include "r3_interface.h"
#include "cbuffer.h"
#include "r3_shared_vm.h"
#include "r3_shared_cbuffer.h"
#include "buf_array.h"
#include "r3_shared_buf_array.h"
#include "kern_callback.h"
#include "trace_common.h"
#include "wmi_io.h"
#ifdef SUPPORT_ACTION_TYPE
#include "action_type.h"
#endif //SUPPORT_ACTION_TYPE
#include "stack_trace.h"
#include "output_buffer_manage.h"
#include "ring3_2_ring0.h"
#include "volume_name_map.h"
#include "proc_info.h"
#include "data_flow.h"

#define MAX_WORK_TIME ( LONGLONG )( ( ( ( LONGLONG )24 * 3600 ) ) * 10000000 )

#define TRACE_LOG_FUNC_SW_COUNT 5
DEFINE_SW_ARR_BUF( trace_log_func_sw, TRACE_LOG_FUNC_SW_COUNT ); 

static const ULARGE_INTEGER driver_version = { ( ( 0 ) << 16 | 8906 ), 0 }; 

LARGE_INTEGER ring3_reply_wait_time = { 0 }; //{ DEF_RING3_REPLY_WAIT_TIME }; 

typedef struct _os_ver
{
	ULONG maj_ver; 
	ULONG min_ver; 
	ULONG build_num; 
} os_ver, *pos_ver; 

os_ver cur_os_ver = { 0 }; 

typedef struct _action_block_count
{
	ULONGLONG fw_block_count; 
	ULONGLONG defense_block_count; 
} action_block_count, *paction_block_count; 

typedef struct _action_management
{
	work_mode all_work_mode;
	action_block_count block_count; 
	ULONG log_mode; 
	KTIMER *work_timer; 
	KDPC *dpc; 
	KEVENT *event; 
} action_management, *paction_management; 

action_management action_manage = { 0 }; 

INT32 block_ping = FALSE; 

PDEVICE_OBJECT trace_log_mgr = NULL; 

typedef struct __ui_context
{
	PFILE_OBJECT file_obj_for_ui; 
	PEPROCESS ui_proc;
	ERESOURCE mapping_lock; 
} ui_context, *pui_context; 

ui_context ui_responsor = { 0 }; 

typedef struct _files_info
{
	LIST_ENTRY head; 
	ERESOURCE lock; 
	LONG file_count; 
} files_info, *pfiles_info; 

files_info all_open_files; 

typedef struct _file_context{
	//
	// Lock to rundown threads that are dispatching I/Os on a file handle 
	// while the cleanup for that handle is in progress.
	//
	LIST_ENTRY entry; 
	PFILE_OBJECT owner; 
	IO_REMOVE_LOCK file_rundown_lock;
} file_context, *pfile_context;

NTSTATUS _notify_action_aio( r3_action_notify *action, 
							ULONG buf_len, 
							PIRP irp ); 

NTSTATUS notify_action_aio( r3_action_notify *action, ULONG buf_len ); 

NTSTATUS query_trace_log_interface( PI_TRACE_LOG_TRACE trace_log_if ); 

NTSTATUS on_subscribe_driver_interface( PDEVICE_OBJECT dev_obj, PIRP irp, PIO_STACK_LOCATION irp_sp )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	SUBSCRIBE_DRIVER_INTERFACE_INFO *subscribe_info; 
	DRIVER_INTERFACE_SUBSCRIBE_OUTPUT_INFO *subscriber_info; 
	ULONG input_size; 
	ULONG output_size; 
	ULONG id; 

	do 
	{
		ASSERT( dev_obj != NULL ); 
		ASSERT( irp != NULL ); 
		ASSERT( irp_sp != NULL ); 

		irp->IoStatus.Information = 0; 

		input_size = irp_sp->Parameters.DeviceIoControl.InputBufferLength; 
		output_size = irp_sp->Parameters.DeviceIoControl.OutputBufferLength; 

		if( input_size != sizeof( SUBSCRIBE_DRIVER_INTERFACE_INFO ) 
			|| output_size != sizeof( DRIVER_INTERFACE_SUBSCRIBE_OUTPUT_INFO ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		subscribe_info = ( SUBSCRIBE_DRIVER_INTERFACE_INFO* )irp->AssociatedIrp.SystemBuffer; 

		if( NULL == subscribe_info->dev_obj )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		ntstatus = _subscribe_driver_interface( subscribe_info->dev_obj, &id ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		subscriber_info = ( ( DRIVER_INTERFACE_SUBSCRIBE_OUTPUT_INFO* )irp->AssociatedIrp.SystemBuffer ); 
		subscriber_info->id = id; 

		query_trace_log_interface( &subscriber_info->_interface ); 

		irp->IoStatus.Information = sizeof( DRIVER_INTERFACE_SUBSCRIBE_OUTPUT_INFO ); 

	}while( FALSE );

	irp->IoStatus.Status = ntstatus; 
	IoCompleteRequest( irp, IO_NO_INCREMENT ); 

	return ntstatus; 
}

NTSTATUS safe_notify_action_post( r3_action_notify *action_notify, 
										  NTSTATUS result, 
										  data_trace_context *trace_context )
{
	NTSTATUS ntstatus = STATUS_SUCCESS;
	r3_action_notify *action = NULL; 
	ASSERT( info != NULL ); 

	do 
	{
		do 
		{
			ntstatus = check_r3_action_notify_output_valid( action_notify ); 

			if( ntstatus != STATUS_SUCCESS )
			{
				break; 
			}

			ntstatus = notify_list_is_not_full(); 
			if( ntstatus != STATUS_SUCCESS )
			{
				break; 
			}

			action = allocate_action_notify(); 
			if( action == NULL )
			{
				ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
				break; 
			}

			memcpy( action, action_notify, action_notify->size ); 

			ntstatus = i_safe_notify_action_post( action, result, trace_context ); 
			if( ntstatus == STATUS_EVENT_NOTIFY_PENDING )
			{
				action = NULL; 
				ntstatus = STATUS_SUCCESS; 
				break; 
			}
		}while( FALSE ); 

		if( action != NULL )
		{
			deallocate_action_notify( action ); 
		}
	}while( FALSE );

	return ntstatus; 
}

NTSTATUS __collect_action_context( action_context *info, ULONG flags )
{
	return _collect_action_context_ex( info, flags ); 
}

NTSTATUS query_trace_log_interface( PI_TRACE_LOG_TRACE trace_log_if )
{
	ASSERT( trace_log_if != NULL ); 

	interlocked_exchange( ( ULONG_PTR* )&trace_log_if->collect_info, ( ULONG_PTR )collect_action_related_info ); 
	interlocked_exchange( ( ULONG_PTR* )&trace_log_if->notify_action_pre, ( ULONG_PTR )notify_action_pre_ex ); 
	interlocked_exchange( ( ULONG_PTR* )&trace_log_if->notify_action_post, ( ULONG_PTR )r3_notify_action_post_ex ); 

	interlocked_exchange( ( ULONG_PTR* )&trace_log_if->collect_context, ( ULONG_PTR )__collect_action_context ); 
	interlocked_exchange( ( ULONG_PTR* )&trace_log_if->safe_notify_action_post, ( ULONG_PTR )safe_notify_action_post ); 
	interlocked_exchange( ( ULONG_PTR* )&trace_log_if->filter_enabled, ( ULONG_PTR )filter_enabled ); 

	return STATUS_SUCCESS; 
}

NTSTATUS init_trace_log_file_check( files_info *info )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		ASSERT( info != NULL ); 

		InitializeListHead( &info->head ); 
		ntstatus = init_res_lock( &info->lock ); 
	}while( FALSE );

	return ntstatus; 
}

NTSTATUS add_trace_log_file( file_context *context )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		hold_w_res_lock( all_open_files.lock ); 

		InsertHeadList( &all_open_files.head, 
			&context->entry ); 

		all_open_files.file_count ++; 

		release_res_lock( all_open_files.lock ); 
	}while( FALSE );

	return ntstatus; 
}

NTSTATUS del_trace_log_file( file_context *context )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		hold_w_res_lock( all_open_files.lock ); 

		RemoveEntryList( &context->entry ); 

		all_open_files.file_count --; 

		release_res_lock( all_open_files.lock ); 
	}while( FALSE );

	return ntstatus; 
}

NTSTATUS find_trace_log_file( PFILE_OBJECT file_obj )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	LIST_ENTRY *entry; 
	file_context *context; 

	do 
	{
		hold_r_res_lock( all_open_files.lock ); 

		entry = all_open_files.head.Flink; 
		for( ; ; )
		{
			if( entry == &all_open_files.head )
			{
				ASSERT( FALSE ); 

				dbg_print( MSG_FATAL_ERROR, "one file 0x%0.8x have not opened but do some action\n", file_obj ); 
				ntstatus = STATUS_NOT_FOUND; 
				break; 
			}

			context = CONTAINING_RECORD( entry, file_context, entry ); 

			if( context->owner == file_obj )
			{
				break; 
			}

			entry = entry->Flink; 
		}
		release_res_lock( all_open_files.lock ); 
	}while( FALSE );

	return ntstatus; 

}

NTSTATUS uninit_files_info( files_info *info )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		ASSERT( TRUE == IsListEmpty( &info->head ) ); 
		ntstatus = uninit_res_lock( &info->lock ); 
	}while( FALSE );

	return ntstatus; 
}

NTSTATUS uninit_ui_responsor()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		if( ui_responsor.ui_proc != NULL 
			|| ui_responsor.file_obj_for_ui != NULL )
		{
			log_trace( ( MSG_FATAL_ERROR, "uninitialize ui responsor but ui process or file is not released.process:0x%0.8x,file 0x%0.8x\n", 
				ui_responsor.ui_proc, 
				ui_responsor.file_obj_for_ui ) );
		}

		ntstatus = uninit_res_lock( &ui_responsor.mapping_lock ); 

		if( ntstatus != STATUS_SUCCESS )
		{
			dbg_print( MSG_FATAL_ERROR, "delete ui responsor lock error 0x%0.8x\n", ntstatus ); 
		}
	}while( FALSE );

	return ntstatus; 
}

NTSTATUS init_ui_responsor()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		if( ui_responsor.ui_proc != NULL 
			|| ui_responsor.file_obj_for_ui != NULL )
		{
			log_trace( ( MSG_FATAL_ERROR, "initialize ui responsor but ui process or file is not released.process:0x%0.8x,file 0x%0.8x\n", 
				ui_responsor.ui_proc, 
				ui_responsor.file_obj_for_ui ) ); 

			KeBugCheck( STATUS_UNSUCCESSFUL ); 
		}

		ntstatus = init_res_lock( &ui_responsor.mapping_lock ); 

	}while( FALSE );

	return ntstatus; 
}

NTSTATUS DriverEntry( IN PDRIVER_OBJECT drv_obj, IN PUNICODE_STRING reg_path ); 
VOID trace_log_unload( PDRIVER_OBJECT drv_obj ); 

#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#pragma alloc_text( PAGE, trace_log_unload )
#endif //ALLOC_PRAGMA

#define MAX_LOG_ITEM_BYTE_COUNT_BIT 23
#define MAX_LOG_ITEM_BYTE_COUNT ( 1 << 23 )

#define MAX_EVENT_ITEM_COUNT 256
#define MAX_EVENT_ITEM_SIZE ( sizeof( sys_action_output ) + DEFAULT_OUTPUT_DATA_REGION_SIZE ) 

#define MAX_R3_NOTIFY_ITEM_COUNT 256
#define MAX_R3_NOTIFY_ITEM_SIZE R3_NOTIFY_BUF_SIZE

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
ULONG r3_buf_item_count[ MAX_R3_CBUFFER_TYPE ] = { 
	MAX_LOG_ITEM_BYTE_COUNT_BIT }; 

ULONG r3_array_buf_size[ MAX_R3_ARRAY_TYPE ] = { 
	MAX_EVENT_ITEM_COUNT * ( MAX_EVENT_ITEM_SIZE + sizeof( array_cell_head ) ), 
	MAX_R3_NOTIFY_ITEM_COUNT * ( MAX_R3_NOTIFY_ITEM_SIZE + sizeof( array_cell_head ) ) }; 

ULONG r3_array_buf_cell_size[ MAX_R3_ARRAY_TYPE ] = { 
	MAX_EVENT_ITEM_SIZE, 
	MAX_R3_NOTIFY_ITEM_SIZE }; 

r3_shared_buf_arr all_r3_arr[ MAX_R3_ARRAY_TYPE ] = { 0 }; 
r3_shared_cbuf all_r3_cbuf[ MAX_R3_CBUFFER_TYPE ] = { 0 }; 
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
INLINE NTSTATUS output_r3_cbuffer( R3_SHARED_CBUF_TYPE type, PVOID *buf_out, ULONG *buf_size_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		if( FALSE == is_valid_r3_cbuffer_type( type ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		*buf_out = all_r3_cbuf[ type ].r3_vm.r3_addr; 
		*buf_size_out = all_r3_cbuf[ type ].r3_vm.vm_size; 

	}while( FALSE );

	return ntstatus; 
}

INLINE NTSTATUS r3_buf_array_inited( R3_SHARED_ARRAY_TYPE type )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		if( FALSE == is_valid_r3_array_type( type ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER_1; 
			break; 
		}

		ntstatus = is_valid_r3_shared_vm( &all_r3_arr[ type ].r3_vm ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			ntstatus = STATUS_INVALID_PARAMETER_2; 
			break; 
		}

		ASSERT( all_r3_arr[ type ].r3_vm.vm_size != 0 ); 

		
#ifdef DBG
		if( all_r3_arr->arr.buf == NULL )
		{
			ASSERT( FALSE ); 
			ntstatus = STATUS_INVALID_PARAMETER_3; 
			break; 
		}
#endif //DBG

		if( STATUS_SUCCESS != is_valid_buf_array( &all_r3_arr[ type ].arr ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER_4; 
			break; 
		}
	}while( FALSE ); 

	return ntstatus; 
}

INLINE NTSTATUS r3_cbuffer_inited( R3_SHARED_CBUF_TYPE type )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		if( FALSE == is_valid_r3_cbuffer_type( type ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER_1; 
			break; 
		}

		ntstatus = is_valid_r3_shared_vm( &all_r3_cbuf[ type ].r3_vm ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			ntstatus = STATUS_INVALID_PARAMETER_2; 
			break; 
		}

		ASSERT( all_r3_cbuf[ type ].r3_vm.vm_size != 0 ); 

#ifdef DBG
		if( all_r3_cbuf[ type ].cbuf.cbuf == NULL )
		{
			ASSERT( FALSE ); 
			ntstatus = STATUS_INVALID_PARAMETER_3; 
			break; 
		}
#endif //DBG

		if( STATUS_SUCCESS != is_valid_cbuffer( all_r3_cbuf[ type ].cbuf.cbuf ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER_4; 
			break; 
		}

	}while( FALSE );

	return ntstatus; 
}

INLINE NTSTATUS all_r3_buf_is_inited()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	NTSTATUS _ntstatus; 
	ULONG i; 
	ULONG inited_count = 0; 

	do 
	{
		for( i = 0; i < ARRAY_SIZE( all_r3_cbuf ); i ++ )
		{
			_ntstatus = r3_cbuffer_inited( ( R3_SHARED_CBUF_TYPE )i ); 
			if( _ntstatus != STATUS_SUCCESS )
			{
				dbg_print( MSG_ERROR, "initialize ring3 shared buffer error 0x%0.8x\n", ntstatus ); 

				break; 
			}
			else
			{
				inited_count += 1; 
			}
		}

		if( inited_count != 0 && inited_count < ARRAY_SIZE( all_r3_cbuf ) )
		{
			ASSERT( _ntstatus != STATUS_SUCCESS ); 
			KeBugCheck( STATUS_DATA_ERROR ); 
			break; 
		}
		else if( inited_count == 0 )
		{
			ASSERT( _ntstatus != STATUS_SUCCESS ); 
			ntstatus = _ntstatus; 
			//break; 
		}

		for( i = 0; i < ARRAY_SIZE( all_r3_arr ); i ++ )
		{
			_ntstatus = r3_buf_array_inited( ( R3_SHARED_ARRAY_TYPE )i ); 
			if( _ntstatus != STATUS_SUCCESS )
			{
				dbg_print( MSG_ERROR, "initialize ring3 shared buffer error 0x%0.8x\n", ntstatus ); 

				break; 
			}
			else
			{
				inited_count += 1; 
			}
		}

		if( inited_count != 0 && inited_count < ARRAY_SIZE( all_r3_arr ) )
		{
			ASSERT( _ntstatus != STATUS_SUCCESS ); 
			KeBugCheck( STATUS_DATA_ERROR ); 
			break; 
		}
		else if( inited_count == 0 )
		{
			ASSERT( _ntstatus != STATUS_SUCCESS ); 
			ntstatus = _ntstatus; 
		}

	}while( FALSE );

	return ntstatus; 
}

INLINE NTSTATUS all_r3_buf_is_mapped()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	NTSTATUS _ntstatus; 
	ULONG i; 
	ULONG inited_count = 0; 

	do 
	{
		for( i = 0; i < ARRAY_SIZE( all_r3_cbuf ); i ++ )
		{
			_ntstatus = is_r3_shared_vm_mapped( &all_r3_cbuf[ i ].r3_vm ); 
			if( _ntstatus != STATUS_SUCCESS )
			{
				dbg_print( MSG_ERROR, "initialize ring3 shared buffer error 0x%0.8x\n", ntstatus ); 

				break; 
			}
			else
			{
				inited_count += 1; 
			}
		}

		if( inited_count != 0 && inited_count < ARRAY_SIZE( all_r3_cbuf ) )
		{
			ASSERT( _ntstatus != STATUS_SUCCESS ); 
			KeBugCheck( STATUS_DATA_ERROR ); 
			break; 
		}
		else if( inited_count == 0 )
		{
			ASSERT( _ntstatus != STATUS_SUCCESS ); 
			ntstatus = _ntstatus; 
			//break; 
		}

		for( i = 0; i < ARRAY_SIZE( all_r3_arr ); i ++ )
		{
			_ntstatus = is_r3_shared_vm_mapped( &all_r3_arr[ i ].r3_vm ); 
			if( _ntstatus != STATUS_SUCCESS )
			{
				dbg_print( MSG_ERROR, "initialize ring3 shared buffer error 0x%0.8x\n", ntstatus ); 

				break; 
			}
			else
			{
				inited_count += 1; 
			}
		}

		if( inited_count != 0 && inited_count < ARRAY_SIZE( all_r3_arr ) )
		{
			ASSERT( _ntstatus != STATUS_SUCCESS ); 
			KeBugCheck( STATUS_DATA_ERROR ); 
			break; 
		}
		else if( inited_count == 0 )
		{
			ASSERT( _ntstatus != STATUS_SUCCESS ); 
			ntstatus = _ntstatus; 
		}

	}while( FALSE );

	return ntstatus; 
}

INLINE NTSTATUS init_r3_cbuffers_r0()
{
	NTSTATUS ntstatus; 
	ULONG i; 

	do 
	{
		for( i = 0; i < ARRAY_SIZE( all_r3_cbuf ); i ++ )
		{
			ntstatus = init_ring3_share_cbuffer_r0( 1, r3_buf_item_count[ i ], &all_r3_cbuf[ i ] ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				dbg_print( MSG_ERROR, "initialize ring3 shared buffer error 0x%0.8x\n", ntstatus ); 

				i --; 

				for( ; ( INT32 )i >= 0; i -- )
				{
					ASSERT( ( INT32 )i >= 0 ); 

					ntstatus = uninit_ring3_share_cbuffer_r0( &all_r3_cbuf[ i ] ); 
					if( ntstatus != STATUS_SUCCESS )
					{
						dbg_print( MSG_ERROR, "uninitialize ring3 shared buffer error 0x%0.8x\n", ntstatus ); 
						//break; 
					}
				}

				break; 
			}
		}

	}while( FALSE );

	return ntstatus; 
}

//notice: call this function must be in driver entry or driver unload.

INLINE NTSTATUS uninit_r3_cbuffers_r0()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG i; 

	do 
	{
		for( i = 0; i < MAX_R3_CBUFFER_TYPE; i ++ )
		{
			ASSERT( ( INT32 )i >= 0 ); 

			if( ui_responsor.ui_proc != NULL )
			{
#ifdef BSOD_DEBUG
				KeBugCheck( STATUS_UNSUCCESSFUL ); 
#endif //BSOD_DEBUG

				ASSERT( FALSE ); 
			}

			ntstatus = uninit_ring3_share_cbuffer_r0( &all_r3_cbuf[ i ] ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				dbg_print( MSG_ERROR, "uninitialize ring3 shared buffer error 0x%0.8x\n", ntstatus ); 
				//break; 
			}
		}

	}while( FALSE );

	return ntstatus; 
}

INLINE NTSTATUS init_r3_arrays_r0()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	NTSTATUS _ntstatus; 
	BOOLEAN vms_inited = FALSE; 
	ULONG i; 

	do 
	{
		for( i = 0; i < ARRAY_SIZE( all_r3_arr ); i ++ )
		{
			ntstatus = create_r3_shared_vm_base( r3_array_buf_size[ i ], &all_r3_arr[ i ].r3_vm ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				ASSERT( all_r3_arr[ i ].r3_vm.r3_addr == NULL ); 
				ASSERT( all_r3_arr[ i ].r3_vm.r0_addr == NULL ); 
				ASSERT( all_r3_arr[ i ].r3_vm.mdl == NULL ); 

				dbg_print( MSG_ERROR, "initialize ring3 shared buffer error 0x%0.8x\n", ntstatus ); 

				i --; 

				for( ; ( INT32 )i >= 0; i -- )
				{
					ASSERT( ( INT32 )i >= 0 ); 

					_ntstatus = destroy_r3_shared_vm_base( &all_r3_arr[ i ].r3_vm ); 
					if( _ntstatus == STATUS_SUCCESS )
					{
						all_r3_arr[ i ].r3_vm.mdl = NULL; 
						all_r3_arr[ i ].r3_vm.r0_addr = NULL; 
						all_r3_arr[ i ].r3_vm.r3_addr = NULL; 
						all_r3_arr[ i ].r3_vm.vm_size = 0; 
					}
					else
					{
						if( _ntstatus != STATUS_UNSUCCESSFUL )
						{
							ASSERT( FALSE ); 
						}

						all_r3_arr[ i ].r3_vm.mdl = NULL; 
						all_r3_arr[ i ].r3_vm.r0_addr = NULL; 
						all_r3_arr[ i ].r3_vm.r3_addr = NULL; 
						all_r3_arr[ i ].r3_vm.vm_size = 0; 

						ASSERT( FALSE ); 
					}
				}

				
				break; 
			}

			ASSERT( all_r3_arr[ i ].r3_vm.mdl != NULL ); 
			ASSERT( all_r3_arr[ i ].r3_vm.r0_addr != NULL ); 
			ASSERT( all_r3_arr[ i ].r3_vm.r3_addr == NULL ); 
			ASSERT( all_r3_arr[ i ].r3_vm.vm_size != 0 ); 
		}

		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		vms_inited = TRUE; 

		for( i = 0; i < ARRAY_SIZE( all_r3_arr ); i ++ )
		{
			ntstatus = init_buf_array( &all_r3_arr[ i ].arr, 
				all_r3_arr[ i ].r3_vm.r0_addr, 
				all_r3_arr[ i ].r3_vm.vm_size, 
				r3_array_buf_cell_size[ i ] ); 

			if( ntstatus != STATUS_SUCCESS )
			{
				ASSERT( all_r3_arr[ i ].arr.buf == NULL ); 
				ASSERT( all_r3_arr[ i ].arr.buf_size == 0 ); 
				ASSERT( all_r3_arr[ i ].arr.cell_size == 0 ); 

				dbg_print( MSG_ERROR, "initialize ring3 shared buffer error 0x%0.8x\n", ntstatus ); 

				i --; 

				for( ; ( INT32 )i >= 0; i -- )
				{
					ASSERT( ( INT32 )i >= 0 ); 

					_ntstatus = uninit_buf_array( &all_r3_arr[ i ].arr ); 
					if( _ntstatus != STATUS_SUCCESS)
					{
						dbg_print( MSG_ERROR, "uninitialize buffer array error 0x%0.8\n", ntstatus ); 				
						ASSERT( FALSE ); 
					}
				}

				break; 
			}
		}

	}while( FALSE );

	if( ntstatus != STATUS_SUCCESS )
	{
		if( vms_inited == TRUE )
		{
			for( i = 0; i <  ARRAY_SIZE( all_r3_arr ); i ++ )
			{
				ntstatus = is_valid_r3_shared_vm( &all_r3_arr[ i ].r3_vm ); 

				if( ntstatus != STATUS_SUCCESS )
				{
					dbg_print( MSG_ERROR, "release the have not mapped vm\n" ); 
				}

				ntstatus = destroy_r3_shared_vm_base( &all_r3_arr[ i ].r3_vm ); 

				if( ntstatus == STATUS_SUCCESS )
				{
					all_r3_arr[ i ].r3_vm.mdl = NULL; 
					all_r3_arr[ i ].r3_vm.r0_addr = NULL; 
					all_r3_arr[ i ].r3_vm.r3_addr = NULL; 
					all_r3_arr[ i ].r3_vm.vm_size = 0; 
				}
				else
				{
					if( ntstatus != STATUS_UNSUCCESSFUL )
					{
						ASSERT( FALSE ); 
					}

					all_r3_arr[ i ].r3_vm.mdl = NULL; 
					all_r3_arr[ i ].r3_vm.r0_addr = NULL; 
					all_r3_arr[ i ].r3_vm.r3_addr = NULL; 
					all_r3_arr[ i ].r3_vm.vm_size = 0; 

					ASSERT( FALSE ); 
				}
			}
		}
	}
	return ntstatus; 
}

ULONG verify_driver = TRUE; 
INLINE NTSTATUS unmap_r3_arrays()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG i; 

	do 
	{
		if( ui_responsor.ui_proc == NULL )
		{
			ASSERT( FALSE && "release r3 buffer but dest process is null" ); 

			ntstatus = STATUS_INVALID_PARAMETER; 
			
			if( verify_driver == TRUE )
			{
				for( i = 0; i < ARRAYSIZE( all_r3_arr ); i ++ )
				{
					if( all_r3_arr[ i ].r3_vm.r3_addr != NULL ) 
					{
						KeBugCheck( STATUS_UNSUCCESSFUL ); 
					}
				}
			}

			break; 
		}

		{
			INT32 unmapped_vm_count = 0; 
			for( i = 0; i < ARRAYSIZE( all_r3_arr ); i ++ )
			{
				if( all_r3_arr[ i ].r3_vm.r3_addr != NULL ) 
				{
					ntstatus = unmap_r3_shared_vm_from_r3( ui_responsor.ui_proc, &all_r3_arr[ i ].r3_vm ); 
					if( ntstatus != STATUS_SUCCESS )
					{
						break; 
					}
				}
				else
				{
					unmapped_vm_count ++;
				}
			}

			ASSERT( unmapped_vm_count == 0 
				|| unmapped_vm_count == ARRAYSIZE( all_r3_arr ) ); 
		}
		
	} while ( FALSE );

	return ntstatus; 
}

INLINE NTSTATUS unmap_r3_cbuffers()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG i; 

	do 
	{
		if( ui_responsor.ui_proc == NULL )
		{
			ASSERT( FALSE && "release r3 buffer but dest process is null" ); 

			ntstatus = STATUS_INVALID_PARAMETER; 

			if( verify_driver == TRUE )
			{
				for( i = 0; i < ARRAYSIZE( all_r3_cbuf ); i ++ )
				{
					if( all_r3_cbuf[ i ].r3_vm.r3_addr != NULL )
					{
						KeBugCheck( STATUS_UNSUCCESSFUL ); 
					}
				}
			}

			break; 
		}

		{
			INT32 unmapped_vm_count = 0; 

			for( i = 0; i < ARRAYSIZE( all_r3_cbuf ); i ++ )
			{
				if( all_r3_cbuf[ i ].r3_vm.r3_addr != NULL ) 
				{
					ntstatus = unmap_r3_shared_vm_from_r3( ui_responsor.ui_proc, &all_r3_cbuf[ i ].r3_vm ); 
					if( ntstatus != STATUS_SUCCESS )
					{
						ASSERT( FALSE ); 
					}
				}
				else
				{
					unmapped_vm_count ++; 
					//ASSERT( FALSE ); 
				}
			}

			ASSERT( unmapped_vm_count == 0 
				|| unmapped_vm_count == ARRAYSIZE( all_r3_cbuf ) ); 
		}

	} while ( FALSE );

	return ntstatus; 
}

INLINE NTSTATUS map_r3_arrays()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 i; 

	do 
	{
		if( verify_driver == TRUE )
		{
			for( i = 0; i < ARRAYSIZE( all_r3_arr ); i ++ )
			{
				if( all_r3_arr[ i ].r3_vm.r3_addr != NULL ) 
				{
					ASSERT( FALSE && "must unmap buffer then map it again" ); 
				}
			}
		}

		if( ui_responsor.ui_proc == NULL )
		{
			ASSERT( FALSE && "map r3 buffer but dest process is null" ); 

			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		for( i = 0; i < ARRAYSIZE( all_r3_arr ); i ++ )
		{
			ntstatus = reinit_buf_array( &all_r3_arr[ i ].arr ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				ASSERT( FALSE && "reinitialize buffer array error" ); 
			}

			ASSERT( all_r3_arr[ i ].r3_vm.r3_addr == NULL ); 

			ntstatus = map_r3_shared_vm_to_r3( ui_responsor.ui_proc, &all_r3_arr[ i ].r3_vm ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				NTSTATUS _ntstatus; 

				i -- ; 

				for( ; i >= 0; i-- )
				{
					_ntstatus = unmap_r3_shared_vm_from_r3( ui_responsor.ui_proc, &all_r3_arr[ i ].r3_vm ); 
				}
				break; 
			}
		}

	} while ( FALSE );

	return ntstatus; 
}

INLINE NTSTATUS map_r3_cbuffers()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 i; 

	do 
	{
		if( verify_driver == TRUE )
		{
			for( i = 0; i < ARRAYSIZE( all_r3_cbuf ); i ++ )
			{
				if( all_r3_cbuf[ i ].r3_vm.r3_addr != NULL ) 
				{
					ASSERT( FALSE && "must unmap buffer then map it again" ); 
				}
			}
		}

		if( ui_responsor.ui_proc == NULL )
		{
			ASSERT( FALSE && "map r3 buffer but dest process is null" ); 

			ntstatus = STATUS_INVALID_PARAMETER; 

			break; 
		}

		for( i = 0; i < ARRAYSIZE( all_r3_cbuf ); i ++ )
		{
			ASSERT( all_r3_cbuf[ i ].r3_vm.r3_addr == NULL ); 

			ntstatus = map_r3_shared_vm_to_r3( ui_responsor.ui_proc, &all_r3_cbuf[ i ].r3_vm ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				NTSTATUS _ntstatus; 

				i -- ; 

				for( ; i >= 0; i-- )
				{
					_ntstatus = unmap_r3_shared_vm_from_r3( ui_responsor.ui_proc, &all_r3_cbuf[ i ].r3_vm ); 
				}
				break; 
			}
		}

	} while ( FALSE );

	return ntstatus; 
}

INLINE NTSTATUS uninit_r3_arrays_r0()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG i; 

	do 
	{
		for( i = 0; i <  ARRAY_SIZE( all_r3_arr ); i ++ )
		{
			ntstatus = is_valid_r3_shared_vm( &all_r3_arr[ i ].r3_vm ); 

			if( ntstatus != STATUS_SUCCESS )
			{
				dbg_print( MSG_ERROR, "release the have not mapped vm\n" ); 
			}

			ntstatus = uninit_buf_array( &all_r3_arr[ i ].arr ); 
			if( ntstatus != STATUS_SUCCESS)
			{
				dbg_print( MSG_ERROR, "uninitialize buffer array error 0x%0.8\n", ntstatus ); 				
				ASSERT( FALSE ); 
			}

#ifdef BSOD_DEBUG
			if( ui_responsor.ui_proc != NULL )
			{
				KeBugCheck( STATUS_UNSUCCESSFUL ); 
				ASSERT( FALSE ); 
			}
#endif //BSOD_DEBUG

			ntstatus = destroy_r3_shared_vm_base( &all_r3_arr[ i ].r3_vm ); 

			if( ntstatus == STATUS_SUCCESS )
			{
				all_r3_arr[ i ].r3_vm.mdl = NULL; 
				all_r3_arr[ i ].r3_vm.r0_addr = NULL; 
				all_r3_arr[ i ].r3_vm.r3_addr = NULL; 
				all_r3_arr[ i ].r3_vm.vm_size = 0; 
			}
			else
			{
				if( ntstatus != STATUS_UNSUCCESSFUL )
				{
					ASSERT( FALSE ); 
				}

				all_r3_arr[ i ].r3_vm.mdl = NULL; 
				all_r3_arr[ i ].r3_vm.r0_addr = NULL; 
				all_r3_arr[ i ].r3_vm.r3_addr = NULL; 
				all_r3_arr[ i ].r3_vm.vm_size = 0; 

				ASSERT( FALSE ); 
			}
		}

	}while( FALSE );

	return ntstatus; 
}

NTSTATUS init_r3_io_space_r0()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	BOOLEAN r3_cbufs_inited = FALSE; 
	BOOLEAN r3_arrays_inited = FALSE; 

	do 
	{
		ntstatus = init_r3_cbuffers_r0(); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		r3_cbufs_inited = TRUE; 

		ntstatus = init_r3_arrays_r0(); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		r3_arrays_inited = TRUE; 
	}while( FALSE );

	if( ntstatus != STATUS_SUCCESS )
	{
		if( r3_arrays_inited == TRUE )
		{
			uninit_r3_arrays_r0(); 
		}

		if( r3_cbufs_inited == TRUE )
		{
			uninit_r3_cbuffers_r0(); 
		}
	}
	return ntstatus; 
}

NTSTATUS uninit_r3_io_space_r0()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
#ifdef BSOD_DEBUG
		if( ui_responsor.ui_proc != NULL )
		{
			KeBugCheck( STATUS_UNSUCCESSFUL ); 
		}
#endif //BSOD_DEBUG

		if( verify_driver == TRUE )
		{
			ntstatus = all_r3_buf_is_inited(); 
			if( STATUS_SUCCESS != ntstatus )
			{
				ASSERT( FALSE ); 
			}
		}

		ntstatus = uninit_r3_arrays_r0(); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		ntstatus = uninit_r3_cbuffers_r0(); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

	}while( FALSE );

	return ntstatus; 
}

//notice:give these mapping and unmapping functions a lock to synchronize multiple threads do mapping or unmapping same time.
NTSTATUS unmap_r3_io_space()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		//__asm int 3; 

		ntstatus = unmap_r3_arrays(); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		ntstatus = unmap_r3_cbuffers(); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

	}while( FALSE );

	return ntstatus; 
}

NTSTATUS map_r3_io_space()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	BOOLEAN r3_cbufs_inited = FALSE; 
	BOOLEAN r3_arrays_inited = FALSE; 

	do 
	{
		ntstatus = map_r3_cbuffers(); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		r3_cbufs_inited = TRUE; 

		ntstatus = map_r3_arrays(); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		r3_arrays_inited = TRUE; 
	}while( FALSE );

	if( ntstatus != STATUS_SUCCESS )
	{
		if( r3_arrays_inited == TRUE )
		{
			unmap_r3_arrays(); 
		}

		if( r3_cbufs_inited == TRUE )
		{
			unmap_r3_cbuffers(); 
		}
	}
	return ntstatus; 
}
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

/*******************************************************
share virtual memory space to user space methods:
1.mapping one allocated big space (like circle buffer) 
to user process space.

2.mapping one user space of one process to the user space 
of other target process.( like the buffer in the irp, but 
that buffer is not allocated by self,so control it hardly.)

3.mapping more small memory space to user space of the 
target process but must mapping it to the fixed address.
( or fixed addresses ( saved by address array, user space 
use fixed address, but the physical address is not fixed).
*******************************************************/

INLINE NTSTATUS set_log_mode( ULONG mode )
{
	action_manage.log_mode = mode; 
	return STATUS_SUCCESS; 
}

INLINE NTSTATUS set_work_mode( ULONG mode )
{
	NTSTATUS ntstatus = STATUS_SUCCESS;

	log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

	action_manage.all_work_mode = mode; 

	ntstatus  = signal_notify_event( WORK_MODE_EVENT ); 

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 

	return ntstatus; 
}

BOOLEAN ring3_acl_debug = FALSE; 

#ifdef SUPPORT_MDL_REMAPPING
NTSTATUS release_action_info_notify( r3_action_notify *notify_info )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		ASSERT( notify_info != NULL ); 

		if( notify_info->data_buf.mdl != NULL && 
			notify_info->data_buf.r3_addr != NULL && 
			notify_info->data_buf.vm_size > 0 )
		{
			ntstatus = unmap_irp_io_buf( NULL, NULL, NULL, &notify_info->data_buf ); 
		}
		else
		{
			ASSERT( notify_info->data_buf.mdl == NULL ); 
			ASSERT( notify_info->data_buf.r3_addr == NULL ); 
			ASSERT( notify_info->data_buf.vm_size == 0 ); 

			ntstatus = STATUS_INVALID_PARAMETER; 
		}

	} while ( FALSE ); 

	return ntstatus; 
}
#else
#define release_action_info_notify( notify_info ) 
#endif //SUPPORT_MDL_REMAPPING

FORCEINLINE ULONG check_action_type_id( sys_action_type action_type )
{
	register ULONG type_id; 

	switch( action_type )
	{
	case EXEC_module_load:
	case SYS_load_mod:
	case SYS_unload_mod:
		type_id = MODULE_ACTIVITY_MESSAGE_ID; 
		break; 

	default:
		type_id = SYSTEM_ACTION_MESSAGE_ID; 
		break; 
	}

	return type_id; 
}


NTSTATUS convert_native_name_2_dos_name( LPCWSTR native_name, 
										ULONG cc_name_len, 
										LPWSTR name_output, 
										ULONG cc_buf_len, 
										ULONG *cc_ret_len ); 

typedef struct _trace_io_statistic
{
	ULONG success_count; 
	ULONG error_count; 
} trace_io_statistic, *ptrace_io_statistic; 

#ifdef _TRACE_IO_STATISTIC
trace_io_statistic trace_io_stat = { 0 }; 
#endif //_TRACE_IO_STATISTIC

ULONG filter_enabled()
{
	ULONG ret = 0; 

	do 
	{
		if( ring3_interface.client_port != NULL )
		{
			ret |= PRE_FILTER_ENABLED;
		}

#if EVENT_NOTIFY_FROM_WPP
		if( TRUE == bittrace_enabled() )
		{
			ret |= POST_FILTER_ENABLED;
		}
#else
		if( NULL != ui_responsor.file_obj_for_ui )
		{
			ret |= POST_FILTER_ENABLED;
		}
#endif //EVENT_NOTIFY_FROM_WPP

	} while ( FALSE ); 

	return ret; 
}

NTSTATUS prepare_action_notify_data( data_trace_context *data_context, 
									r3_action_notify *action_notify )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	NTSTATUS _ntstatus; 

	BYTE *data_buf; 
	ULONG max_data_size; 
	ULONG data_output_size = 0; 
	ULONG action_buffer_size; 

	log_trace( ( MSG_INFO, "enter %s \n", __FUNCTION__ ) ); 

	ASSERT( action_notify != NULL ); 

	do 
	{
		ASSERT( action_notify != NULL ); 
		ASSERT( data_context != NULL ); 

		action_buffer_size = get_buffer_size( action_notify ); 

		ASSERT( action_buffer_size >= R3_NOTIFY_BUF_SIZE ); 

		max_data_size = MAX_R3_NOTIFY_VARIABLE_SIZE( action_buffer_size ) - action_notify->action.action.size; 

#if BUG_ANALYZE
		{
			ULONG action_info_size; 
			sys_action_info *action_info; 
			action_info = &action_notify->action; 
			action_info_size = get_sys_action_output_size( action_info ); 

			if( action_info_size == 0 )
			{
				ASSERT( FALSE && "the length of the action record information is unknown" ); 
				ntstatus = STATUS_UNSUCCESSFUL; 
				break; 
			}

			log_trace( ( MSG_INFO, "size of the system action record is %u type is %u\n", 
				action_info_size, 
				action_info->action.type ) ); 
		}
#endif //BUG_ANALYZE

		data_buf = get_action_output_data_ptr( action_notify ); 

		do 
		{
			PVOID data; 

			ASSERT( action_notify->data_size == 0 ); 
			ASSERT( action_notify->real_data_size == 0 ); 
			ASSERT( action_notify->data_inited == FALSE ); 

			if( max_data_size == 0 )
			{
				log_trace( ( MSG_FATAL_ERROR, "why input data but the struct %u hold this information containing 0 data buffer.\n", action_notify->action.action.type ) ); 
				break; 
			}

			_ntstatus = get_action_data_from_context( data_context, &data, &data_output_size ); 

			if( _ntstatus != STATUS_SUCCESS )
			{
				break; 
			}
			else
			{
				if( data_output_size == 0 )
				{
					ASSERT( FALSE && "contain 0 size buffer" ); 
					action_notify->data_inited = TRUE; 	
					break; 
				}

				action_notify->real_data_size = data_output_size; 

				if( data_output_size > max_data_size )
				{
					data_output_size = max_data_size; 
				}

				adjust_trace_data_size( action_notify->action.ctx.proc_id, &data_output_size ); 

				ntstatus = safe_copy_data( data_buf, data, data_output_size ); 
				if( ntstatus != STATUS_SUCCESS )
				{
					break; 
				}

				action_notify->data_size = data_output_size; 
				action_notify->data_inited = TRUE; 

#define DATA_BUF_NULL_TERMINATING
#ifdef DATA_BUF_NULL_TERMINATE_DEBUG
				if( max_data_size - action_notify->data_size >= sizeof( ULONG ) )
				{
					*( ULONG* )( ( ( BYTE* )data_buf + max_data_size - sizeof( ULONG ) ) ) = SYS_ACTION_DATA_END_SIGN; 
				}
#endif //DATA_BUF_NULL_TERMINATE_DEBUG
			}

		}while( FALSE ); 

		//action_notify->size = ACTION_RECORD_OFFEST + action_notify->action.action.size + data_output_size; 
	}while( FALSE ); 

	return ntstatus; 
}

NTSTATUS r3_notify_action_post_init( r3_action_notify *action, 
								 data_trace_context *trace_context )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	NTSTATUS _ntstatus; 
	PVOID data; 
	ULONG data_size; 

	log_trace( ( MSG_INFO, "enter %s \n", __FUNCTION__ ) ); 

	ASSERT( action != NULL ); 

	do 
	{
		{
			BOOLEAN is_enabled; 

#if EVENT_NOTIFY_FROM_WPP
			is_enabled = bittrace_enabled(); 
#else
			is_enabled = TRUE;
#endif //EVENT_NOTIFY_FROM_WPP

			if( FALSE == is_enabled )
			{
				ntstatus = STATUS_NOT_FOUND; 
				break; 
			}
		}

		if( KeGetCurrentIrql() > APC_LEVEL ) 
		{
			ntstatus = STATUS_UNSUCCESSFUL; 
			break; 
		}

		ntstatus = check_r3_action_notify_output_valid( action ); 

		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		do
		{
			ULONG cc_ret_len; 

			if( action->action.ctx.proc_name_len > ARRAYSIZE( action->action.ctx.proc_name ) - 1 )
			{
				action->action.ctx.proc_name_len = 0; 
				action->action.ctx.proc_name[ 0 ] = L'\0'; 
				break; 
			}

			if( action->action.ctx.proc_name[ 0 ] != L'\\' )
			{
				ASSERT( action->action.ctx.proc_name[ 1 ] == L':' 
					|| action->action.ctx.proc_id < 10 ); 
				break; 
			}

			if( action->action.ctx.proc_name_len < MIN_NATIVE_NAME_LEN )
			{
				action->action.ctx.proc_name_len = 0; 
				action->action.ctx.proc_name[ 0 ] = L'\0'; 
				break; 
			}

			/************************************************************************
			if name converted, need change the name length.
			else name and name length must don't change anything.
			************************************************************************/

			{
				_ntstatus = convert_native_name_2_dos_name( action->action.ctx.proc_name, 
					action->action.ctx.proc_name_len, 
					action->action.ctx.proc_name, 
					ARRAYSIZE( action->action.ctx.proc_name ) - 1, 
					&cc_ret_len ); 

				if( _ntstatus != STATUS_SUCCESS )
				{
					log_trace( ( MSG_FATAL_ERROR, "convert the native name of the process to dos name error " ) );
				}
				else
				{
					action->action.ctx.proc_name[ cc_ret_len ] = L'\0'; 
					action->action.ctx.proc_name_len = cc_ret_len; 
				}
			}
		}while( FALSE );
		
		do
		{		
			if( action->data_inited != FALSE )
			{
				data = NULL; 
				data_size = 0; 
				break; 
			}

			if( NULL != trace_context )
			{
				ASSERT( action->data_size == 0 ); 
				_ntstatus = get_action_data_from_context( trace_context, &data, &data_size ); 

				if( _ntstatus != STATUS_SUCCESS )
				{
					ASSERT( data == NULL ); 
					ASSERT( data_size == 0 ); 

					ASSERT( action->data_size == 0 ); 
					ASSERT( action->real_data_size == 0 ); 

					data = NULL; 
					data_size = 0; 
					break; 
				}

				ASSERT( data != NULL ); 
				ASSERT( data_size != 0 ); 

				action->real_data_size = data_size; 

				if( data_size > MAX_R3_NOTIFY_VARIABLE_SIZE_EX( action ) - action->action.action.size )
				{
					ASSERT( FALSE ); 
					data_size = MAX_R3_NOTIFY_VARIABLE_SIZE_EX( action ) - action->action.action.size; 
				}

				adjust_trace_data_size( action->action.ctx.proc_id, &data_size ); 

				if( ExGetPreviousMode() != UserMode )
				{
					action->data_size = data_size; 
					action->size += data_size; 
					action->data_inited = TRUE; 

					break; 
				}

				if( ( ULONG_PTR )data > MmUserProbeAddress )
				{
					action->data_size = data_size; 
					action->size += data_size; 
					action->data_inited = TRUE; 

					break; 
				}

				{
					PVOID data_buf; 

					data_buf = get_action_output_data_ptr( action ); 

					try
					{
						memcpy( data_buf, data, data_size ); 
					}
					_except( EXCEPTION_EXECUTE_HANDLER )
					{
						ASSERT( action->data_inited == FALSE ); 
						ASSERT( action->data_size == 0 ); 
						ASSERT( action->real_data_size == 0 ); 

						dbg_print( MSG_FATAL_ERROR, "copy the data from ring 3 error 0x%0.8x\n", GetExceptionCode() ); 
						data = NULL; 
						data_size = 0; 
						break; 
					}

					action->data_size = data_size; 
					action->size += data_size; 
					action->data_inited = TRUE; 

					data = NULL; 
					data_size = 0; 

					break; 
				}
			}
			else
			{
				ASSERT( action->data_inited == FALSE ); 
				ASSERT( action->data_size == 0 ); 
				ASSERT( action->real_data_size == 0 ); 

				data = NULL; 
				data_size = 0; 
			}
		}while( FALSE );

		ASSERT(action->frame_count == 0 ); 
		ASSERT(action->frame_count <= ARRAYSIZE( action->stack_frame ) );

		_ntstatus = _capture_stack_back_trace( action->stack_frame, 
			ARRAYSIZE( action->stack_frame ), 
			INTERNAL_TRACE_FUNCTION_FRAME_COUNT, 
			&action->frame_count ); 

		if( _ntstatus != STATUS_SUCCESS )
		{
			log_trace( ( MSG_ERROR, "get the current action stack back trace error %u\n", _ntstatus ) ); 
		}
	}while( FALSE );

	if( STATUS_SUCCESS != ntstatus )
	{
		dbg_message_ex( MSG_IMPORTANT, "event is invalid: 0x%0.8x, type:%u, size:%u(real size:%u) data inited:%d, data size:%u, real data size:%u record size: %u\n", 
			ntstatus, 
			action->action.action.type, 
			action->size, 
			action->data_size + ACTION_RECORD_OFFEST + action->action.action.size, 
			action->data_inited, 
			action->real_data_size, 
			action->real_data_size, 
			action->action.action.size ); 
	}

	log_trace( ( MSG_INFO, "leave %s \n", __FUNCTION__ ) ); 

	return ntstatus; 
}

NTSTATUS r3_notify_action_post_ex( r3_action_notify *action, 
								  data_trace_context *trace_context )
{
	NTSTATUS ntstatus = STATUS_SUCCESS;

	do 
	{
		ntstatus = r3_notify_action_post_init( action, trace_context ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}


		/*****************************************************************
		notice:
		if add the event to list pending it.
		then must return STATUS_EVENT_NOTIFY_PENDING, must maintain the return status 
		don't change it any time when insert it to list.
		*****************************************************************/

		ntstatus = notify_action_aio( action, action->size );

		if( ntstatus != STATUS_SUCCESS )
		{
#ifdef _TRACE_IO_STATISTIC
			trace_io_stat.error_count += 1; 

			dbg_message_ex( MSG_ERROR, "logging event data error %u (success:%u error:%u all:%u)\n", 
				ntstatus, 
				trace_io_stat.success_count, 
				trace_io_stat.error_count, 
				trace_io_stat.success_count + trace_io_stat.error_count ); 
#endif //_TRACE_IO_STATISTIC
		}
		else
		{
#ifdef _TRACE_IO_STATISTIC
			trace_io_stat.success_count += 1; 
#endif //_TRACE_IO_STATISTIC
		}
	}while( FALSE ); 

	return ntstatus; 
}

NTSTATUS r3_notify_action_pre( r3_action_notify *action_notify, 
							  //data_trace_context *trace_context, 
							  action_response_type *response ) 

{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	NTSTATUS _ntstatus; 

	event_action_response action_resp = { 0 };
	ULONG action_response_size; 
	sys_action_desc *cur_action = NULL; 
	
	ASSERT( NULL != action_notify ); 

	if( PASSIVE_LEVEL < KeGetCurrentIrql() )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		goto _return; 
	}

	ntstatus = check_r3_action_notify_output_valid( action_notify ); 
	if( ntstatus != STATUS_SUCCESS )
	{
		goto _return; 
	}
	
	ntstatus = FltSendMessage( ring3_interface.filter,
		&ring3_interface.client_port, 
		action_notify,
		action_notify->size,  //R3_NOTIFY_BUF_SIZE, 
		&action_resp, 
		&action_response_size, 
		&ring3_reply_wait_time ); 

	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	if( ntstatus == STATUS_TIMEOUT )
	{
		goto _return; 
	}

_return:

	if( NULL != cur_action )
	{
		FREE_TAG_POOL( cur_action ); 
	}

	if( response != NULL )
	{
		*response = action_resp.action; 
	}

	log_trace( ( MSG_INFO, "leave %s \n", __FUNCTION__ ) ); 

	return ntstatus; 
}

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
NTSTATUS receive_ring3_response( ULONG logger_name, /*FLT_LEVEL flt_lvl, */
						  action_context *context, 
						  sys_action_desc *cur_action, 
						  PVOID data, 
						  ULONG data_len, 
						  action_response_type *action )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 flted; 
	PUNI_TRACE trace_logger; 
	PTRACE_LOGGER logger; 

	log_trace( ( MSG_INFO, "enter %s \n", __FUNCTION__ ) ); 

	ASSERT( context != NULL ); 
	ASSERT( cur_action != NULL ); 

	if( action != NULL )
	{
		*action = ACTION_ALLOW; 
	}

	if( cur_os_ver.maj_ver >= 6 )
	{
		ntstatus = _receive_ring3_response( cur_action, data, data_len, action, SMALLER_WAIT_TIME ); 
	}
	else
	{
		ntstatus = _receive_ring3_response( cur_action, data, data_len, action, 0 ); 
	}

	goto _return; 

_return:
	log_trace( ( MSG_INFO, "leave %s \n", __FUNCTION__ ) ); 

	return ntstatus; 
}
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

INLINE NTSTATUS url_filter( LPCSTR url, LPCSTR file_path )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	ASSERT( url != NULL ); 

	log_trace( ( MSG_INFO, "enter %s\n" __FUNCTION__ ) ); 
	log_trace( ( MSG_INFO, "check url %s, file path %s\n", url, file_path == NULL ? "NULL" : file_path ) ); 

	ntstatus = filter_url_addr( url, file_path ); 

//_return:
	log_trace( ( MSG_INFO, "leave %s \n", __FUNCTION__ ) ); 

	return ntstatus; 
}

NTSTATUS add_block_count( sys_action_type type )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	ASSERT( is_valid_action_type( type ) ); 

	log_trace( ( MSG_INFO, "enter %s \n", __FUNCTION__ ) ); 

	switch( type )
	{
#ifdef COMPATIBLE_OLD_ACTION_DEFINE
	case SOCKET_SEND:
	case SOCKET_RECV:
	case SOCKET_CONNECT:
	case LOCATE_URL:
#endif //COMPATIBLE_OLD_ACTION_DEFINE
	case NET_accept:
	case NET_send:
	case NET_recv:
	case NET_create:
	case NET_connect:
	case NET_listen:
		InterlockedIncrement( ( LONG* )&action_manage.block_count.fw_block_count ); 
		break; 
	default:
		InterlockedIncrement( ( LONG* )&action_manage.block_count.defense_block_count ); 
		break; 
	}

	signal_notify_event( BLOCK_COUNT_EVENT );
	log_trace( ( MSG_INFO, "leave %s \n", __FUNCTION__ ) ); 
	return ntstatus; 
}

NTSTATUS _notify_action_aio( r3_action_notify *action, 
							ULONG buf_len, 
							PIRP irp )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	PIO_STACK_LOCATION irp_sp; 
	r3_action_notify *action_out; 

	do 
	{
		ASSERT( action != NULL ); 
		ASSERT( buf_len > 0 ); 

		irp->IoStatus.Information = 0;

		if( irp->MdlAddress == NULL )
		{
			ASSERT( FALSE ); 
			ntstatus = STATUS_INVALID_PARAMETER_2; 
			break; 
		}

		irp_sp = IoGetCurrentIrpStackLocation( irp ); 

		if( irp_sp->Parameters.DeviceIoControl.OutputBufferLength < buf_len )
		{
			dbg_print( MSG_IMPORTANT, "%s buffer too small %u<%u\n", 
				irp_sp->Parameters.DeviceIoControl.OutputBufferLength, 
				buf_len ); 

			ntstatus = STATUS_BUFFER_TOO_SMALL;
			break; 
		}

		action_out = ( r3_action_notify* )MmGetSystemAddressForMdlSafe( irp->MdlAddress, 
			NormalPagePriority ); 

		if( action_out == NULL )
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			break; 
		}

		memcpy( action_out, action, buf_len ); 
		irp->IoStatus.Information = buf_len; 

	}while( FALSE ); 

	irp->IoStatus.Status = ntstatus; 

	IoCompleteRequest( irp, IO_NO_INCREMENT ); 
	return ntstatus; 
}

NTSTATUS notify_action_aio( r3_action_notify *action, ULONG buf_len )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	PIRP irp; 

	do 
	{
		ASSERT( action != NULL );
		ASSERT( buf_len > 0 );

		irp = IoCsqRemoveNextIrp( &io_queue.aio_safe_queue, NULL ); 

		if( NULL == irp )
		{
			log_trace( ( MSG_INFO, "a queued irp is not exist\n" ) ); 

			do 
			{
				ntstatus = notify_list_is_not_full(); 
				if( ntstatus != STATUS_SUCCESS )
				{
					break; 
				}
				
				ntstatus = add_action_notify_work( action, TRUE );
			}while( FALSE );
			break; // go back to waiting
		}

		ntstatus = _notify_action_aio( action, buf_len, irp ); 

	}while( FALSE ); 

	return ntstatus; 
}

BOOLEAN debug_notify_sys_action = FALSE;
NTSTATUS notify_action_pre_ex( r3_action_notify *action_notify, 
							  data_trace_context *trace_context, 
							  action_response_type *actoin_resp, 
							  ULONG flags )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	NTSTATUS _ntstatus; 
	action_response_type response = ACTION_ALLOW;
	sys_action_info *action_info;
	KIRQL cur_irql; 

	ASSERT( action_notify != NULL ); 

	log_trace( ( MSG_INFO, "enter %s \n", __FUNCTION__ ) );

	if( debug_notify_sys_action == TRUE )
	{
		goto _return; 
	}

	action_info = &action_notify->action; 

	if( FALSE == is_valid_action_type( action_info->action.type ) )
	{
		ntstatus = STATUS_INVALID_PARAMETER_1; 
		goto _return; 
	}

	if( action_manage.all_work_mode == WORK_FREE_MODE )
	{
		goto _return; 
	}
	else if( action_manage.all_work_mode == WORK_BLOCK_MODE )
	{
		if( action_can_be_blocked( action_info->action.type ) == TRUE )
		{
			response = ACTION_BLOCK; 

			goto _return; 
		}
	}

	switch( action_info->action.type )
	{
	case NET_icmp_send:
		if( action_info->action.do_net_icmp_send.type == ICMP_TYPE_REPLY )
		{
			if( block_ping == TRUE )
			{
				response = ACTION_BLOCK;
			}
		}

		goto _return; 
		break; 
	case NET_icmp_recv:
		if( action_info->action.do_net_icmp_recv.type == ICMP_TYPE_ECHO )
		{
			if( block_ping == TRUE )
			{
				response = ACTION_BLOCK;
			}
		}

		goto _return; 
		break; 
	}

	cur_irql = KeGetCurrentIrql(); 

	if( cur_irql >= DISPATCH_LEVEL )
	{
		goto _return; 
	}

	/**********************************************************************************************************
	check action policy in kernel mode.
	**********************************************************************************************************/

	do 
	{
		if( response != ACTION_LEARN )
		{
			break; 
		}

		if( ring3_interface.client_port == NULL )
		{
			break; 
		}

		//receive_ring3_response ->notify to ring3 from event.
		_ntstatus = r3_notify_action_pre( action_notify, &response ); 

		ASSERT( is_valid_response_type( response ) 
			&& response != ACTION_LEARN ); 

		if( !NT_SUCCESS( _ntstatus ) )
		{
			ASSERT( response == ACTION_ALLOW ); 
		}

		if( is_valid_response_type( response ) == FALSE || response == ACTION_LEARN )
		{
			ASSERT( FALSE && "invalid sys action response" ); 
			log_trace( ( MSG_ERROR, "!!!invalid sys action response %d\n", response ) ); 

			response = ACTION_ALLOW; 
		}

	}while( FALSE ); 

_return:
	if( actoin_resp != NULL )
	{
		*actoin_resp = response; 
	}

	if( response == ACTION_BLOCK )
	{
		if( action_notify != NULL )
		{
			add_block_count( action_notify->action.action.type ); 
		}
	}

	log_trace( ( MSG_INFO, "leave %s response is %ws\n", __FUNCTION__, get_action_resp_desc( *actoin_resp ) ) ); 

#ifdef DBG
	if( KeGetCurrentIrql() < DISPATCH_LEVEL )
	{
		DbgPrint( "response is %ws \n", get_action_resp_desc( *actoin_resp ) ); 
	}
#endif //DBG

	return ntstatus; 
}

/**************************************************
notice: logging the data for the system activity 
is by two step: 
1.filter action 
2.logging mapped data( notice this data is mapped 
by io manager ).

or can make a big enough for logging both information.

**************************************************/

VOID proc_create_callback( IN HANDLE parent_id, 
	IN HANDLE proc_id,
	IN BOOLEAN creating )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	action_response_type resp = ACTION_ALLOW; 
	r3_action_notify *proc_action = NULL; 
	ULONG path_len; 

	do 
	{
		if( creating == TRUE )
		{
			/************************************************************************************
			When a process is created, the process-notify routine runs in the context of the thread that created the new process. 
			When a process is deleted, the process-notify routine runs in the context of the last thread to exit from the process. 
			************************************************************************************/
			if( filter_enabled() == 0 )
			{
				break; 
			}

			proc_action = allocate_action_notify(); 

			if( proc_action == NULL )
			{
				ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
				break; 
			}

			ntstatus = collect_proc_action_context( parent_id, 
				&proc_action->action.ctx ); 

			if( ntstatus != STATUS_SUCCESS )
			{
				break; 
			}

			{
				PEPROCESS eproc = NULL; 

				do
				{
					ntstatus = PsLookupProcessByProcessId( ( HANDLE )proc_id, &eproc ); 
					if( ntstatus != STATUS_SUCCESS )
					{
						log_trace( ( MSG_ERROR, "%s:%u look up process error 0x%0.8x\n", __FUNCTION__, __LINE__, ntstatus ) ); 

						break; 
					}

					{
						ntstatus = reset_proc_name_record( eproc );
						ntstatus = get_proc_image_name_from_record( eproc, 
							proc_action->action.action.do_proc_exec.path_name,  
							MAX_NATIVE_NAME_SIZE, 
							&path_len, 
							NEED_RETRIEVE_PROC_NAME );
					}
				}while( FALSE ); 

				if( eproc != NULL )
				{
					ObDereferenceObject( eproc ); 
				}
			}

			if( ntstatus != STATUS_SUCCESS )
			{
				*proc_action->action.action.do_proc_exec.path_name = L'\0'; 
				proc_action->action.action.do_proc_exec.path_len = 0; 
				break; 
			}

			if( path_len >= MAX_NATIVE_NAME_SIZE )
			{
				proc_action->action.action.do_proc_exec.path_name[ MAX_NATIVE_NAME_SIZE - 1 ] = L'\0'; 
				path_len = MAX_NATIVE_NAME_SIZE - 1; 
			}
			else
			{
				if( proc_action->action.action.do_proc_exec.path_name[ path_len ] != L'\0' )
				{
					proc_action->action.action.do_proc_exec.path_name[ path_len ] = L'\0'; 
				}
			}

			proc_action->action.action.type = PROC_exec; 
			proc_action->action.action.do_proc_exec.target_pid = ( ULONG )proc_id; 
			proc_action->action.action.do_proc_exec.path_len = ( PATH_SIZE_T )path_len;

			proc_action->action.action.size = ACTION_RECORD_SIZE_BY_TYPE( proc_exec ) 
				+ ( ( proc_action->action.action.do_proc_exec.path_len + 1 ) << 1 ); 

			proc_action->size = ACTION_RECORD_OFFEST + proc_action->action.action.size; 

			proc_action->action.ctx.last_result = STATUS_SUCCESS; 

			ntstatus = r3_notify_action_post( proc_action ); 
			if( ntstatus == STATUS_EVENT_NOTIFY_PENDING )
			{
				proc_action = NULL; 
			}

			break; 
		}
		else
		{
			if( filter_enabled() == 0 )
			{
				ntstatus = STATUS_NO_SUCH_FILE; 
				break; 
			}

			do
			{
				ULONG path_len; 
				proc_action = allocate_action_notify(); 
				if( proc_action == NULL )
				{
					ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
					break; 
				}

				ntstatus = collect_proc_action_context( parent_id, 
					&proc_action->action.ctx ); 

				if( ntstatus != STATUS_SUCCESS )
				{
					break; 
				}

				proc_action->action.action.type = EXEC_destroy; 

				ntstatus = _get_proc_image_name_from_record( ( ULONG )proc_id, 
					proc_action->action.action.do_exec_destroy.path_name, 
					MAX_NATIVE_NAME_SIZE, 
					&path_len ); 

				if( path_len >= MAX_NATIVE_NAME_SIZE )
				{
					proc_action->action.action.do_exec_destroy.path_name[ MAX_NATIVE_NAME_SIZE - 1 ] = L'\0'; 
					path_len = MAX_NATIVE_NAME_SIZE - 1; 
				}
				else
				{
					if( proc_action->action.action.do_exec_destroy.path_name[ path_len ] != L'\0' )
					{
						proc_action->action.action.do_exec_destroy.path_name[ path_len ] = L'\0'; 
					}
				}

				proc_action->action.action.do_exec_destroy.path_len = ( PATH_SIZE_T )path_len;

				*( proc_action->action.action.do_exec_destroy.path_name 
					+ proc_action->action.action.do_exec_destroy.path_len 
					+ 1 ) = L'\0'; 

				proc_action->action.action.do_exec_destroy.cmd_len = 0; 

				proc_action->action.action.do_exec_destroy.pid = ( ULONG )proc_id; 
				proc_action->action.action.do_exec_destroy.parent_pid = ( ULONG )parent_id;

				proc_action->action.action.size = ACTION_RECORD_SIZE_BY_TYPE( exec_destroy ) 
					+ ( ( proc_action->action.action.do_exec_destroy.path_len + 2 ) << 1 ); 

				proc_action->size = proc_action->action.action.size + ACTION_RECORD_OFFEST; 
				proc_action->action.ctx.last_result = STATUS_SUCCESS; 

				ntstatus = r3_notify_action_post( proc_action ); 
				if( ntstatus == STATUS_EVENT_NOTIFY_PENDING )
				{
					proc_action = NULL; 
				}

				break; 
			}while( FALSE ); 

			ntstatus = remove_all_proc_info( proc_id ); 
			if( ntstatus != STATUS_SUCCESS )
			{
			}
		}
	}while( FALSE );

	if( proc_action != NULL )
	{
		deallocate_action_notify( proc_action ); 
	}

	return; 
}

NTSTATUS convert_ansi_to_unicode( CHAR *src_string, 
								 ULONG cc_src_string_len, 
								 WCHAR *dest_string, 
								 ULONG cc_dest_string_len, 
								 ULONG *cc_ret_len )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG i; 

	do 
	{
		ASSERT( src_string != NULL ); 
		ASSERT( cc_src_string_len > 0 ); 
		ASSERT( dest_string != NULL ); 
		ASSERT( cc_dest_string_len > 0 ); 

		if( cc_ret_len != NULL )
		{
			*cc_ret_len = 0; 
		}

		for( i = 0; i < cc_src_string_len; i ++ )
		{
			if( i >= cc_dest_string_len - 1 )
			{
				ntstatus = STATUS_BUFFER_OVERFLOW; 
				break; 
			}

			dest_string[ i ] = ( WCHAR )src_string[ i ]; 
		}

		dest_string[ i ] = L'\0'; 
		*cc_ret_len = i; 

	}while( FALSE );

	return ntstatus; 
}

NTSTATUS CALLBACK notify_dns_packet_info( CHAR* dns_name, 
									ULONG dns_name_len, 
									USHORT prot, 
									PVOID context, 
									PVOID *param_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	r3_action_notify *action = NULL;
	r3_action_notify *prev_action; 
	ULONG cc_path_len; 
	NTSTATUS io_status; 

	ASSERT( dns_name != NULL ); 
	ASSERT( dns_name_len > 0 ); 
	ASSERT( param_out != NULL ); 

	log_trace( ( MSG_INFO, "enter %s \n", __FUNCTION__ ) ); ; 

	do 
	{
		*param_out = NULL; 
		
		action = allocate_action_notify(); 
		if( NULL == action )
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			break; 
		}

		if( context != NULL )
		{
			prev_action = ( r3_action_notify* )context; 

			if( prev_action->action.action.type != NET_send )
			{
				ntstatus = STATUS_INVALID_PARAMETER_1; 
				break; 
			}

			if( prev_action->action.action.do_net_send.port != PORT_DOMAIN )
			{
				ntstatus = STATUS_INVALID_PARAMETER_2; 
				break; 
			}

			io_status = prev_action->action.ctx.last_result; 
		}
		else
		{
			io_status = STATUS_UNKNOWN; 
		}

		action->action.action.type = NET_dns; 
		switch( prot )
		{
		case UDP_PROTOCOL:
			action->action.action.do_net_dns.protocol = PROT_UDP; 
			break; 
		case TCP_PROTOCOL:
			action->action.action.do_net_dns.protocol = PROT_TCP; 
			break; 
		default:
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		ntstatus = convert_ansi_to_unicode( dns_name, 
			dns_name_len, 
			action->action.action.do_net_dns.path_name, 
			MAX_PATH, 
			&cc_path_len ); 

		if( ntstatus != STATUS_SUCCESS )
		{
			dbg_message_ex( MSG_FATAL_ERROR, "dns name too long: ws\n", action->action.action.do_net_dns.path_name ); 
		}

		action->action.action.do_net_dns.path_len = ( PATH_SIZE_T )cc_path_len; 

		action->action.action.size = ACTION_RECORD_SIZE_BY_TYPE( net_dns ) 
			+ ( ( action->action.action.do_net_dns.path_len + 1 ) << 1 ); 

		action->size = action->action.action.size + ACTION_RECORD_OFFEST;

		ntstatus = _collect_action_context_ex( &action->action.ctx, 0 ); 
		if( !NT_SUCCESS( ntstatus ) )
		{
			ASSERT( FALSE && "get action context failed \n" ); 
			break; 
		}

		{
			ntstatus = i_safe_notify_action_post( action, io_status, NULL ); 
			if( ntstatus == STATUS_EVENT_NOTIFY_PENDING ) 
			{
				action = NULL; 
			}
			else
			{
				if( ntstatus != STATUS_SUCCESS )
				{
					log_trace( ( MSG_FATAL_ERROR, "notify action post error 0x%0.8x\n", ntstatus ) ); 
				}
			}
		}

	}while( FALSE ); 

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 

	if( NULL != action )
	{
		deallocate_action_notify( action ); 
	}

	return ntstatus; 
}

NTSTATUS collect_action_related_info( relation_info_request_type type, action_info_request *request )
{
	NTSTATUS ntstatus = STATUS_SUCCESS;

	switch( type )
	{
	case LOOKUP_HOST_NAME:
		break; 

	case ANALYZE_DNS_PACK:
		ntstatus = analyze_dns_packet( request->dns_request.data, 
			request->dns_request.data_len, 
			request->dns_request.is_send, 
			notify_dns_packet_info, 
			request->dns_request.context ); 

		DBGPRINT( ( "add_domain_name_record return 0x%0.8x \n", ntstatus ) ); 

	default:
		break; 
	}

	return ntstatus; 
}

#define LOG_TRACE_TAG ( ULONG )'logt'

INLINE NTSTATUS init_flt_tip_event( HANDLE tip_event )
{
	NTSTATUS ntstatus; 
	KIRQL old_irql; 

	if( NULL == tip_event )
	{
		goto _return;
	}

	if( NULL != tip_event )
	{
		ObDereferenceObject( &tip_event );
		tip_event = NULL;
	}

	KdPrint( ( "Get msg tip event reference 0x%0.8x \n", tip_event ) );
	ntstatus = ObReferenceObjectByHandle( tip_event,
		0, 
		( POBJECT_TYPE ) NULL, 
		UserMode, 
		( PVOID )&tip_event, 
		( POBJECT_HANDLE_INFORMATION )NULL );

	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return;
	}

_return:
	return ntstatus; 
}

NTSTATUS default_irp_dispatch( PDEVICE_OBJECT dev_ob, PIRP irp )
{
	NTSTATUS ntstatus = STATUS_SUCCESS;; 

	irp->IoStatus.Information = 0; 
	irp->IoStatus.Status = ntstatus; 

	IoCompleteRequest( irp, IO_NO_INCREMENT );

	return ntstatus; 
}

CHAR *get_dev_io_ctrl_code( ULONG ioctl_code )
{
	CHAR *ioctl_code_desc; 
	switch( ioctl_code )
	{
	case IOCTL_GET_TRACE_MSG:
		ioctl_code_desc = "IOCTL_GET_TRACE_MSG"; 
		break; 
	case IOCTL_GET_TRACE_LOG:
		ioctl_code_desc = "IOCTL_GET_TRACE_LOG"; 
		break; 
	case IOCTL_ADD_PARAM_DEFINE: 
		ioctl_code_desc = "IOCTL_ADD_PARAM_DEFINE"; 
		break; 
	case IOCTL_ADD_RULE_DEFINE:
		ioctl_code_desc = "IOCTL_ADD_RULE_DEFINE"; 
		break; 
	case IOCTL_DEL_RULE_DEFINE: 
		ioctl_code_desc = "IOCTL_DEL_RULE_DEFINE"; 
		break; 
	case IOCTL_MODIFY_RULE_DEFINE:
		ioctl_code_desc = "IOCTL_MODIFY_RULE_DEFINE"; 
		break; 
	case IOCTL_ADD_APP_RULE_DEFINE:
		ioctl_code_desc = "IOCTL_ADD_APP_RULE_DEFINE"; 
		break; 
	case IOCTL_DEL_APP_RULE_DEFINE:
		ioctl_code_desc = "IOCTL_DEL_APP_RULE_DEFINE"; 
		break; 
	case IOCTL_ADD_APP_ACTION_TYPE_RULE:
		ioctl_code_desc = "IOCTL_ADD_APP_ACTION_TYPE_RULE"; 
		break; 
	case IOCTL_DEL_APP_ACTION_TYPE_RULE:
		break; 
	case IOCTL_ADD_ACTION_EVENT: 
		ioctl_code_desc = "IOCTL_DEL_APP_ACTION_TYPE_RULE"; 
		break; 
	case IOCTL_GET_ACTION_EVENT:
		ioctl_code_desc = "IOCTL_GET_ACTION_EVENT"; 
		break; 
	case IOCTL_RESPONSE_ACTION_EVENT:
		ioctl_code_desc = "IOCTL_RESPONSE_ACTION_EVENT"; 
		break; 
	case IOCTL_NOTIFY_DRIVER_INTERFACE: 
		ioctl_code_desc = "IOCTL_TRACE_LOG_SET_FLT_LOGGER"; 
		break; 
	case IOCTL_REMOVE_DRIVER_INTERFACE: 
		ioctl_code_desc = "IOCTL_TRACE_LOG_DEL_FLT_LOGGER"; 
		break; 
	case IOCTL_REGISTER_DRIVER_INTERFACE: 
		ioctl_code_desc = "IOCTL_TRACE_LOG_GET_FLT_LOGGER"; 
		break; 
	case IOCTL_DEREGISTER_DRIVER_INTERFACE:
		ioctl_code_desc = "IOCTL_TRACE_LOG_CHANGE_FLT_SETTING"; 
		break; 
	case IOCTL_SEVEN_FW_GET_VERSION:
		ioctl_code_desc = "IOCTL_SEVEN_FW_GET_VERSION"; 
		break; 
	case IOCTL_SEVEN_FW_SET_FILTER_IP:
		ioctl_code_desc = "IOCTL_SEVEN_FW_SET_FILTER_IP"; 
		break; 
	case IOCTL_SEVEN_FW_SET_WORK_MODE:
		ioctl_code_desc = "IOCTL_SEVEN_FW_SET_WORK_MODE"; 
		break; 
	case IOCTL_SEVEN_FW_GET_WORK_MODE:
		ioctl_code_desc = "IOCTL_SEVEN_FW_GET_WORK_MODE"; 
		break; 
	case IOCTL_SEVEN_FW_ADD_FILTER_NAME:
		ioctl_code_desc = "IOCTL_SEVEN_FW_ADD_FILTER_NAME"; 
		break; 
	case IOCTL_SEVEN_FW_DELETE_FILTER_NAME:
		ioctl_code_desc = "IOCTL_SEVEN_FW_DELETE_FILTER_NAME"; 
		break; 
	case IOCTL_SEVEN_FW_DELETE_ALL_FILTER_NAME:
		ioctl_code_desc = "IOCTL_SEVEN_FW_DELETE_ALL_FILTER_NAME"; 
		break; 
	case IOCTL_SEVEN_FW_FIND_FILTER_NAME_TEST:
		ioctl_code_desc = "IOCTL_SEVEN_FW_FIND_FILTER_NAME_TEST"; 
		break; 
	case IOCTL_SEVEN_FW_SET_HTTP_FILTER_NAME:
		ioctl_code_desc = "IOCTL_SEVEN_FW_SET_HTTP_FILTER_NAME"; 
		break; 
	case IOCTL_SEVEN_FW_UNSET_HTTP_FILTER_NAME:
		ioctl_code_desc = "IOCTL_SEVEN_FW_UNSET_HTTP_FILTER_NAME"; 
		break; 
	case IOCTL_SEVEN_FW_GET_HTTP_FILTER_NAMES:
		ioctl_code_desc = "IOCTL_SEVEN_FW_GET_HTTP_FILTER_NAMES"; 
		break; 
	case IOCTL_SEVEN_FW_SET_HTTP_FILTER_URL:
		ioctl_code_desc = "IOCTL_SEVEN_FW_SET_HTTP_FILTER_URL"; 
		break; 
	case IOCTL_SEVEN_FW_UNSET_HTTP_FILTER_URL:
		ioctl_code_desc = "IOCTL_SEVEN_FW_UNSET_HTTP_FILTER_URL"; 
		break; 
	case IOCTL_SEVEN_FW_SET_HTTP_FILTER_URLS:
		ioctl_code_desc = "IOCTL_SEVEN_FW_SET_HTTP_FILTER_URLS"; 
		break; 
	case IOCTL_SEVEN_FW_UNSET_HTTP_FILTER_URLS:
		ioctl_code_desc = "IOCTL_SEVEN_FW_UNSET_HTTP_FILTER_URLS"; 
		break; 
	case IOCTL_SEVEN_FW_GET_HTTP_FILTER_URLS:
		ioctl_code_desc = "IOCTL_SEVEN_FW_GET_HTTP_FILTER_URLS"; 
		break; 
	case IOCTL_NETWORK_BLOCK_ALL:
		ioctl_code_desc = "IOCTL_NETWORK_BLOCK_ALL"; 
		break; 
	case IOCTL_GET_BLOCK_COUNT:
		ioctl_code_desc = "IOCTL_GET_BLOCK_COUNT"; 
		break; 
	case IOCTL_START_TRACE_LOG_UI_INTERACT:
		ioctl_code_desc = "IOCTL_START_TRACE_LOG_UI_INTERACT"; 
		break; 
	case IOCTL_STOP_TRACE_LOG_UI_INTERACT:
		ioctl_code_desc = "IOCTL_STOP_TRACE_LOG_UI_INTERACT"; 
		break; 
	case IOCTL_BLOCK_PING:
		ioctl_code_desc = "IOCTL_BLOCK_PING"; 
		break; 
	case IOCTL_SET_LOG_MODE:
		ioctl_code_desc = "IOCTL_SET_LOG_MODE"; 
		break; 
	case IOCTL_GET_LOG_MODE:
		ioctl_code_desc = "IOCTL_GET_LOG_MODE"; 
		break; 
	case IOCTL_GET_USER_DIRECT_MEM: 
		ioctl_code_desc = "IOCTL_GET_USER_DIRECT_MEM"; 
		break; 
	default:
		ioctl_code_desc = "UNKNOWN_IOCTL_CODE"; 
		break; 
	}

	return ioctl_code_desc; 
}

NTSTATUS trace_log_internal_dev_ctrl( PDEVICE_OBJECT dev_obj, PIRP irp )
{
	NTSTATUS ntstatus = STATUS_SUCCESS;
	PIO_STACK_LOCATION irp_sp; 
	ULONG input_len; 
	ULONG output_len; 
	ULONG ret_len; 
	BOOLEAN irp_completed = FALSE; 

	irp_sp = IoGetCurrentIrpStackLocation( irp ); 

	ret_len = 0; 
	input_len = irp_sp->Parameters.DeviceIoControl.InputBufferLength; 
	output_len = irp_sp->Parameters.DeviceIoControl.OutputBufferLength; 

	DBGPRINT( ( "enter %s \n", __FUNCTION__ ) ); 
	DBGPRINT( ( "ioctl code is %s( 0x%0.8x \n", get_dev_io_ctrl_code( irp_sp->Parameters.DeviceIoControl.IoControlCode ), irp_sp->Parameters.DeviceIoControl.IoControlCode ) ); 

	switch( irp_sp->Parameters.DeviceIoControl.IoControlCode )
	{
	case IOCTL_NOTIFY_DRIVER_INTERFACE:
		{
			ret_len = 0; 
			ntstatus = STATUS_NOT_IMPLEMENTED; 
		}
		break; 
	case IOCTL_REMOVE_DRIVER_INTERFACE:
		{
			ret_len = 0; 
			ntstatus = STATUS_NOT_IMPLEMENTED; 
		}
		break; 

	case IOCTL_REGISTER_DRIVER_INTERFACE:
		{
			ntstatus = on_subscribe_driver_interface( dev_obj, irp, irp_sp ); 
			if( ntstatus != STATUS_SUCCESS )
			{

			}

			irp_completed = TRUE; 
		}
		break; 

	case IOCTL_DEREGISTER_DRIVER_INTERFACE:
		{
			ntstatus = on_unsubscribe_driver_interface( dev_obj, irp, irp_sp ); 
			if( ntstatus != STATUS_SUCCESS )
			{

			}

			irp_completed = TRUE; 
		}
		break; 
	case IOCTL_TRACE_LOG_SET_VOLUME_PATH_MAPPING: 
		{
			volume_name_map *path_map; 

			if( input_len < sizeof( volume_name_map ) )
			{
				ntstatus = STATUS_INVALID_PARAMETER; 
				break; 
			}

			path_map = ( volume_name_map* )irp->AssociatedIrp.SystemBuffer; 
			ntstatus = _input_volume_map_name( path_map ); 

			if( !NT_SUCCESS( ntstatus ) )
			{
				break; 
			}
		}
		break; 

	case IOCTL_TRACE_LOG_DEL_VOLUME_PATH_MAPPING: 
		{
			volume_name_map *path_map; 

			if( input_len < sizeof( volume_name_map ) )
			{
				ntstatus = STATUS_INVALID_PARAMETER; 
				break; 
			}

			path_map = ( volume_name_map* )irp->AssociatedIrp.SystemBuffer; 
			ntstatus = _remove_volume_map_name( path_map ); 

			if( !NT_SUCCESS( ntstatus ) )
			{
				break; 
			}
		}
		break; 
	default:
		break; 
	}

	if( FALSE == irp_completed )
	{
		irp->IoStatus.Information = ret_len; 
		irp->IoStatus.Status = ntstatus;

		IoCompleteRequest( irp, IO_NO_INCREMENT ); 
	}

//_return:
	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 
	return ntstatus; 
}

INLINE VOID trace_cur_time()
{
	LARGE_INTEGER cur_time; 
	KeQuerySystemTime( &cur_time ); 

	log_trace( ( MSG_INFO, "current time is %I64d\n", cur_time.QuadPart ) ); 
} 

#define SECOND_UNIT ( 1000 * 10000 )
VOID work_mode_timer( PKDPC dpc, PVOID eprcess, PVOID param1, PVOID param2 )
{
	log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

#ifdef DBG
	log_trace( ( MSG_INFO, "end work mode timer\n" ) ); 
	trace_cur_time(); 
#endif //DBG

	ASSERT( action_manage.event != NULL ); 

	{
		NTSTATUS ntstatus; 
		ntstatus = set_work_mode( WORK_ACL_MODE ); 
	}
	KeSetEvent( action_manage.event, 0, FALSE ); 

#ifdef DBG
	{
		INT32 i; 
		
		for( i = 0; i < 240; i ++ )
		{
			KeStallExecutionProcessor( 1000 ); 
		}
	}
#endif //DBG
	log_trace( ( MSG_INFO, "leave %s\n", __FUNCTION__ ) ); 
}

NTSTATUS set_work_timer( LARGE_INTEGER time )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	BOOLEAN timer_state; 
	BOOLEAN timer_canceled; 
	LARGE_INTEGER _work_time; 

	log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

#ifdef DBG
	log_trace( ( MSG_INFO, "start work mode timer\n" ) ); 
	trace_cur_time(); 
#endif //DBG

	ASSERT( action_manage.work_timer != NULL ); 
	ASSERT( action_manage.dpc != NULL ); 
	ASSERT( action_manage.event != NULL ); 

#ifdef DBG
	timer_state = KeReadStateTimer( action_manage.work_timer ); 
	
	log_trace( ( MSG_INFO, "current work mode timer signal state is %d\n", timer_state ) ); 
	
	{
		ULONG event_state; 
		event_state = KeReadStateEvent( action_manage.event ); 
		log_trace( ( MSG_INFO, "current event state %d\n", event_state ) ); 
	}
#endif //DBG

	timer_canceled = KeCancelTimer( action_manage.work_timer ); 
	if( timer_canceled == FALSE )
	{
		ntstatus = KeWaitForSingleObject( action_manage.event, 
			Executive, 
			KernelMode, 
			FALSE, 
			NULL ); 

		if( ntstatus != STATUS_SUCCESS )
		{
			log_trace( ( MSG_ERROR, "wait the work mode synchronize event failed 0x%0.8x\n", ntstatus ) ); 
			ASSERT( FALSE ); 
			//goto _return; 
		}
	}
#ifdef DBG
	else
	{
		ULONG event_state; 
		event_state = KeReadStateEvent( action_manage.event ); 
		ASSERT( event_state == 0 ); 
	}
#endif //DBG

	_work_time.QuadPart = -time.QuadPart; 

	KeClearEvent( action_manage.event ); 
	KeSetTimer( action_manage.work_timer, 
		_work_time, 
		action_manage.dpc ); 

//_return:
	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 
	return ntstatus; 
}

HANDLE get_cur_proc_handle( PKTHREAD cur_thread )
{
	NTSTATUS ntstatus; 
	HANDLE proc_handle = NULL; 
	PEPROCESS eproc; 

	do 
	{
		if( cur_thread == NULL )
		{
			eproc = PsGetCurrentProcess(); 
			ASSERT( eproc != NULL ); 
		}
		else
		{
			eproc = IoThreadToProcess( cur_thread ); 
		}

		ASSERT( eproc != NULL ); 

		ntstatus = ObOpenObjectByPointer( 
			eproc,
			OBJ_KERNEL_HANDLE, 
			NULL,
			0, 
			*PsProcessType,
			KernelMode,
			&proc_handle ); 

		if( ntstatus != STATUS_SUCCESS )
		{
			ASSERT( proc_handle == NULL ); 
			break; 
		}

	} while ( FALSE ); 

	return proc_handle; 
}

NTSTATUS check_active_proc_vm_md5( HANDLE proc_id )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
	}while( FALSE );

	return ntstatus; 
}


NTSTATUS trace_log_dev_ctrl( PDEVICE_OBJECT dev_obj, PIRP irp )
{
	NTSTATUS ntstatus = STATUS_SUCCESS;
	PIO_STACK_LOCATION irp_sp; 
	ULONG input_len; 
	ULONG output_len; 
	ULONG ret_len; 
	BOOLEAN irp_completed = FALSE; 
	file_context *context; 

	irp_sp = IoGetCurrentIrpStackLocation( irp ); 

	ASSERT( irp_sp->FileObject != NULL ); 

	ret_len = 0; 
	input_len = irp_sp->Parameters.DeviceIoControl.InputBufferLength; 
	output_len = irp_sp->Parameters.DeviceIoControl.OutputBufferLength; 


	DBGPRINT( ( "enter %s \n", __FUNCTION__ ) ); 
	DBGPRINT( ( "ioctl code is %s( 0x%0.8x )\n", get_dev_io_ctrl_code( irp_sp->Parameters.DeviceIoControl.IoControlCode ), irp_sp->Parameters.DeviceIoControl.IoControlCode ) ); 

	context = ( file_context* )irp_sp->FileObject->FsContext; 
	
	//notice: lock is only need to protecting the asynchronously io.so can advance it.
	ntstatus = IoAcquireRemoveLock( &context->file_rundown_lock, irp ); 

	if( !NT_SUCCESS( ntstatus ) ) 
	{
		goto _return; 
	}

	switch( irp_sp->Parameters.DeviceIoControl.IoControlCode )
	{
		case IOCTL_GET_TRACE_LOG:
			{
#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
				PULONG logger_name; 
				sys_log_output *log_output;
				ASSERT( METHOD_OUT_DIRECT == METHOD_FROM_CTL_CODE( IOCTL_GET_TRACE_LOG ) ); 

				KdPrint( ( "Output buffer length is %d, system log output buffer size is %d \n", output_len, sizeof( sys_log_output ) ) );
				if( input_len < sizeof( ULONG ) )
				{
					ret_len = 0; 
					ntstatus = STATUS_INVALID_PARAMETER; 
					break; 
				}

				if( output_len < sizeof( sys_log_output ) + sizeof( sys_log_unit ) )
				{
					ret_len = sizeof( sys_log_output ) + sizeof( sys_log_unit );
					ntstatus = STATUS_BUFFER_TOO_SMALL;
					break;
				}

				logger_name = ( PULONG )irp->AssociatedIrp.SystemBuffer; 

				if( irp->MdlAddress == NULL )
				{
					ntstatus = STATUS_UNSUCCESSFUL; 
					break; 
				}

				log_output = ( sys_log_output* )MmGetSystemAddressForMdlSafe( irp->MdlAddress, NormalPagePriority ); 
				if( log_output == NULL )
				{
					ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
					break; 
				}
				ntstatus = output_trace_logs( *logger_name, log_output, output_len ); 
				ret_len = log_output->size * sizeof( sys_log_unit ) + sizeof( sys_log_output ); 
#else
				ntstatus = STATUS_NOT_SUPPORTED; 
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0
			}
			break; 
	case IOCTL_ASYNC_GET_ACTION_EVENT:

		if( output_len < sizeof( r3_action_notify ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		{
			NTSTATUS _ntstatus; 
			r3_action_notify *pending_event; 
			BOOLEAN inited = TRUE; 

			_ntstatus = get_action_pending_notify( &pending_event, &inited ); 

			if( _ntstatus != STATUS_SUCCESS )
			{
				ASSERT( pending_event == NULL ); 
				ASSERT( inited == FALSE ); 

				ntstatus = aio_insert_irp_safe( &io_queue.aio_safe_queue, irp, NULL ); 
				if( ntstatus != STATUS_SUCCESS )
				{
					log_trace( ( MSG_FATAL_ERROR, "insert the irp to the aio queue error 0x%0.8x\n", ntstatus ) ); 
				}
				else
				{
					ntstatus = STATUS_PENDING; 
				}

				break; 
			}

			do 
			{
				ASSERT( NULL != pending_event ); 

				if( inited == FALSE )
				{
					ntstatus = r3_notify_action_post_init( pending_event, NULL ); 
					if( ntstatus != STATUS_SUCCESS )
					{
						dbg_message_ex( MSG_IMPORTANT, "initialize the pending notify error 0x%0.8x\n", ntstatus ); 
						break; 
					}
				}

				ntstatus = _notify_action_aio( pending_event, 
					pending_event->size, 
					irp ); 

				irp_completed = TRUE; 
			}while( FALSE );

			deallocate_action_notify( pending_event ); 
		}
		break; 
	
	case IOCTL_GET_ACTION_EVENT:
#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0

		if( output_len < sizeof( sys_action_output_map ) )
		{
			ret_len = sizeof( sys_action_output_map ); 
			ntstatus = STATUS_BUFFER_TOO_SMALL; 
			
			break; 
		}
		else
		{
			sys_action_output_map *action_output;

			if( irp->MdlAddress == NULL )
			{
				ntstatus = STATUS_UNSUCCESSFUL; 
				break; 
			}

			action_output = ( sys_action_output_map* )MmGetSystemAddressForMdlSafe( irp->MdlAddress, 
				NormalPagePriority ); 

			if( action_output == NULL )
			{
				ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
				break; 
			}
			
			ret_len = output_len; 
			ntstatus = get_next_sys_event( action_output, &ret_len ); 
			break; 
		}
#else
		ntstatus = STATUS_NOT_SUPPORTED; 
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0
		break; 
	case IOCTL_RESPONSE_ACTION_EVENT:
		//__asm int 3; 
#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
		if( input_len < sizeof( event_action_response ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
		}
		else
		{
			event_action_response* sys_event_respon; 
			sys_event_respon = ( event_action_response* )irp->AssociatedIrp.SystemBuffer;
			ntstatus = response_action_event( sys_event_respon ); 
		}
#else
		ntstatus = STATUS_NOT_IMPLEMENTED; 
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

		break; 
	case IOCTL_ADD_PARAM_DEFINE:
		break; 
	case IOCTL_ADD_RULE_DEFINE: 
		{
			access_rule_desc *rule_input; 
			
			if( input_len < sizeof( access_rule_desc ) )
			{
				ntstatus = STATUS_BUFFER_TOO_SMALL; 
				break; 
			}

			rule_input = ( access_rule_desc* )irp->AssociatedIrp.SystemBuffer; 

			ntstatus = init_access_desc_param_ptr( rule_input->type, &rule_input->desc ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				break; 
			}

			ntstatus = add_action_rule( rule_input, MODIFY_RULE ); 
		}
		break; 
	case IOCTL_DEL_RULE_DEFINE:
		{
			access_rule_desc *rule_input; 

			if( input_len < sizeof( access_rule_desc ) )
			{
				ntstatus = STATUS_BUFFER_TOO_SMALL; 
				break; 
			}

			rule_input = ( access_rule_desc* )irp->AssociatedIrp.SystemBuffer; 

			ntstatus = init_access_desc_param_ptr( rule_input->type, &rule_input->desc ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				break; 
			}

			ntstatus = _del_action_rule( rule_input ); 
		}
		break; 

	case IOCTL_MODIFY_RULE_DEFINE:
		{
			access_rule_modify_info *rule_modify_info; 

			if( input_len < sizeof( access_rule_modify_info ) )
			{
				ntstatus = STATUS_BUFFER_TOO_SMALL; 
				break; 
			}

			rule_modify_info = ( access_rule_modify_info* )irp->AssociatedIrp.SystemBuffer; 

			ntstatus = init_access_desc_param_ptr( rule_modify_info->dest_rule.type, &rule_modify_info->dest_rule.desc ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				break; 
			}

			ntstatus = init_access_desc_param_ptr( rule_modify_info->rule_setting.type, &rule_modify_info->rule_setting.desc ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				break; 
			}

			ntstatus = modify_action_rule( &rule_modify_info->dest_rule, 
				&rule_modify_info->rule_setting ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				break; 
			}
		}
		break; 

#ifdef USE_SECOND_ACL
	case IOCTL_SEVEN_FW_GET_HTTP_FILTER_URLS:
		{
			if ( output_len > sizeof( FILTER_NAMES_OUTPUT ) + sizeof( CHAR ) )
			{
				INT32 ret; 
				ULONG output_length; 

				output_length = output_len; 
				ret = get_all_http_filter_urls( ( PFILTER_NAMES_OUTPUT )irp->AssociatedIrp.SystemBuffer, &output_length ); 

				if( ret < 0 )
				{
					ntstatus = STATUS_UNSUCCESSFUL; 
				}
				else
				{
					ret_len = output_length; 
					ntstatus = STATUS_SUCCESS; 
				}
			}
			else
			{
				ntstatus = STATUS_INVALID_PARAMETER; 
			}
		}
		break; 
	case IOCTL_SEVEN_FW_SET_HTTP_FILTER_URL: 
		if ( input_len >= sizeof( FILTER_URL_INPUT ) )
		{
			// Copy the information in the system buffer.

			PFILTER_URL_INPUT http_filter_name; 
			PULONG add_ret; 

			http_filter_name = ( PFILTER_URL_INPUT )irp->AssociatedIrp.SystemBuffer; 
			add_ret = ( PULONG )irp->AssociatedIrp.SystemBuffer; 

			if( FALSE == MmIsAddressValid( http_filter_name ) || 
				FALSE == MmIsAddressValid( http_filter_name + 1 ) || 
				FALSE == MmIsAddressValid( ( ( CHAR* )( http_filter_name + 1 ) ) + http_filter_name->length ) )
			{
				DBGPRINT( ( "url info buffer is invalid \n" ) ); 
				ntstatus = STATUS_INVALID_PARAMETER; 
			}
			else
			{
				if( http_filter_name->length > input_len - sizeof( FILTER_URL_INPUT ) )
				{
					DBGPRINT( ( "input filter name length is greater than the input buffer length \n" ) ); 
					ntstatus = STATUS_INVALID_PARAMETER; 
				}
				else
				{
					ntstatus = set_http_filter_url( http_filter_name, ADD_FILTER_TEXT ); 
					if( !NT_SUCCESS( ntstatus ) )
					{
						if( ntstatus == STATUS_LIST_ITEM_ALREADY_EXIST )
						{
							DBGPRINT( ( "STATUS_LIST_ITEM_ALREADY_EXIST\n" ) ); 
							*add_ret = 0; 
							ret_len = sizeof( ULONG ); 
							ntstatus = STATUS_SUCCESS; 
						}
						else
						{
							*add_ret = 0; 
							ret_len = sizeof( ULONG ); 
							DBGPRINT( ( "set_http_filter_name failed \n" ) ); 
						}
					}
					else
					{
						DBGPRINT( ( "set_http_filter_name success\n" ) ); 
						*add_ret = ADDED_NEW_FILTER; 
						ret_len = sizeof( ULONG ); 
					}
				}
			}
			// Everything went ok.
		}
		else
		{
			DBGPRINT( ( "url info input size is invalid \n" ) ); 
			ntstatus = STATUS_INVALID_PARAMETER; 
		}
		break; 
	case IOCTL_SEVEN_FW_UNSET_HTTP_FILTER_URL: 
		if ( input_len >= sizeof( FILTER_URL_INPUT ) )
		{
			PFILTER_URL_INPUT http_filter_url; 

			http_filter_url = ( PFILTER_URL_INPUT )irp->AssociatedIrp.SystemBuffer; 

			if( FALSE == MmIsAddressValid( http_filter_url ) || 
				FALSE == MmIsAddressValid( http_filter_url + 1 ) || 
				FALSE == MmIsAddressValid( ( ( CHAR* )( http_filter_url + 1) ) + http_filter_url->length ) )
			{
				DBGPRINT( ( "url info buffer is invalid \n" ) ); 
				ntstatus = STATUS_INVALID_PARAMETER; 
			}
			else
			{
				if( http_filter_url->length > input_len - sizeof( FILTER_URL_INPUT ) )
				{
					DBGPRINT( ( "input filter name length is greater than the input buffer length \n" ) ); 
					ntstatus = STATUS_INVALID_PARAMETER; 
				}
				else
				{
					INT32 ret; 
					ret = set_http_filter_url( http_filter_url, DEL_FILTER_TEXT ); 
					if( ret < 0 )
					{
						DBGPRINT( ( "set_http_filter_name failed \n" ) ); 
						ntstatus = STATUS_UNSUCCESSFUL; 
					}
					else
					{
						DBGPRINT( ( "set_http_filter_name success\n" ) ); 
						ntstatus = STATUS_SUCCESS; 
					}

				}
			}
			// Everything went ok.
		}
		else
		{
			DBGPRINT( ( "url info input size is invalid \n" ) ); 
			ntstatus = STATUS_INVALID_PARAMETER; 
		}
		break; 

	case IOCTL_SEVEN_FW_SET_HTTP_FILTER_URLS: 
		if( input_len > sizeof( FILTER_URLS_INPUT ) )
		{
			PFILTER_URLS_INPUT urls_input; 

			urls_input = ( PFILTER_URLS_INPUT )irp->AssociatedIrp.SystemBuffer; 

			if( FALSE == MmIsAddressValid( urls_input ) || 
				FALSE == MmIsAddressValid( urls_input->urls ) || 
				FALSE == MmIsAddressValid( ( ( CHAR* )urls_input ) + urls_input->size - 1 ) )
			{
				DBGPRINT( ( "urls info buffer is invalid \n" ) ); 
				ntstatus = STATUS_INVALID_PARAMETER; 
			}
			else
			{
				if( urls_input->size > input_len )
				{
					DBGPRINT( ( "input urls length is greater than the input buffer length \n" ) ); 
					ntstatus = STATUS_INVALID_PARAMETER; 
				}
				else
				{
					ntstatus = set_http_filter_urls( urls_input, input_len, ADD_FILTER_TEXT ); 
					if( !NT_SUCCESS( ntstatus ) )
					{
						DBGPRINT( ( "set_http_filter_urls failed 0x%0.8x\n", ntstatus ) ); 
					}
					else
					{
						DBGPRINT( ( "set_http_filter_urls success\n" ) ); 
					}
				}
			}
			// Everything went ok.
		}
		else
		{
			DBGPRINT( ( "urls info input size is invalid \n" ) ); 
			ntstatus = STATUS_INVALID_PARAMETER; 
		}
		break; 

	case IOCTL_SEVEN_FW_SET_FILTER_IP:
		break; 

#endif //USE_SECOND_ACL

	case IOCTL_ADD_ACTION_EVENT:
		break;  
		
	case IOCTL_ADD_APP_ACTION_TYPE_RULE:
		{
			access_rule_desc *rule_input; 

			if( input_len < sizeof( access_rule_desc ) )
			{
				ntstatus = STATUS_BUFFER_TOO_SMALL; 
				break; 
			}

			rule_input = ( access_rule_desc* )irp->AssociatedIrp.SystemBuffer; 

			ntstatus = init_access_desc_param_ptr( rule_input->type, &rule_input->desc ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				break; 
			}

			ntstatus = add_app_action_type_rule( rule_input ); 
		}
		break; 

	case IOCTL_DEL_APP_ACTION_TYPE_RULE:
		break; 

	case IOCTL_ADD_APP_RULE_DEFINE: 
		{
			access_rule_desc *rule_input; 

			if( input_len < sizeof( access_rule_desc ) )
			{
				ntstatus = STATUS_BUFFER_TOO_SMALL; 
				break; 
			}

			rule_input = ( access_rule_desc* )irp->AssociatedIrp.SystemBuffer; 

			ntstatus = init_access_desc_param_ptr( rule_input->type, &rule_input->desc ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				break; 
			}

			ntstatus = add_app_rule_define( rule_input ); 
		}
		break; 

	case IOCTL_DEL_APP_RULE_DEFINE:
		break; 

	case IOCTL_NETWORK_BLOCK_ALL: 

		ntstatus = set_work_mode( WORK_BLOCK_MODE ); 

		log_trace( ( MSG_INFO, "set the work mode to %d \n", action_manage.all_work_mode ) ); 
		break; 

	case IOCTL_GET_BLOCK_COUNT: 
		log_trace( ( MSG_INFO, "IOCTL_GET_BLOCK_COUNT\n" ) ); 

		if( output_len != sizeof( ULONGLONG ) * 2 )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}
		else
		{
			ULONGLONG *block_count; 

			block_count = ( ULONGLONG* )irp->AssociatedIrp.SystemBuffer; 
		
			*block_count = action_manage.block_count.fw_block_count; 
			*( block_count + 1 ) = action_manage.block_count.defense_block_count; 
			ret_len = sizeof( ULONGLONG ) * 2; 

			log_trace( ( MSG_INFO, "output the block count : firewall %I64u, defense %I64u \n", 
				*block_count, 
				*( block_count + 1 ) ) ); 
		}
		break; 

	case IOCTL_SEVEN_FW_SET_WORK_MODE: 
		log_trace( ( MSG_INFO, "IOCTL_SEVEN_FW_SET_WORK_MODE\n" ) ); 

		if( input_len != sizeof( ULONG ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}
		else
		{
			ULONG *work_mode_set; 

			work_mode_set = ( ULONG* )irp->AssociatedIrp.SystemBuffer; 

			if( is_valid_work_mode( *work_mode_set ) == FALSE )
			{
				ntstatus = STATUS_INVALID_PARAMETER; 
				log_trace( ( MSG_INFO, "set work mode to a invalid value %d\n", *work_mode_set ) ); 
				break; 
			}

			ntstatus = set_work_mode( *work_mode_set ); 

			log_trace( ( MSG_INFO, "set work mode to %ws \n", get_work_mode_desc( *work_mode_set ) ) ); 
		}
		break; 
	case IOCTL_SEVEN_FW_GET_WORK_MODE:
		log_trace( ( MSG_INFO, "IOCTL_SEVEN_FW_GET_WORK_MODE\n" ) ); 

		if( output_len != sizeof( ULONG ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}
		else
		{
			ULONG *work_mode_out; 

			work_mode_out = ( ULONG* )irp->AssociatedIrp.SystemBuffer; 

			ASSERT( is_valid_work_mode( action_manage.all_work_mode ) ); 

			*work_mode_out = action_manage.all_work_mode; 
			ret_len = sizeof( ULONG ); 

			log_trace( ( MSG_INFO, "output the work mode %ws\n", 
				get_work_mode_desc( *work_mode_out ) ) ); 
		}
		break;
	case IOCTL_SET_LOG_MODE: 
		log_trace( ( MSG_INFO, "IOCTL_SET_LOG_MODE\n" ) ); 

		if( input_len != sizeof( ULONG ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}
		else
		{
			ULONG *log_mode_set; 

			log_mode_set = ( ULONG* )irp->AssociatedIrp.SystemBuffer; 

			ntstatus = set_log_mode( *log_mode_set ); 

			log_trace( ( MSG_INFO, "set work mode to log mode 0x%0.8x\n", *log_mode_set ) ); 
		}
		break; 
	case IOCTL_GET_LOG_MODE:
		log_trace( ( MSG_INFO, "IOCTL_GET_LOG_MODE\n" ) ); 

		if( output_len != sizeof( ULONG ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}
		else
		{
			ULONG *log_mode_out; 

			log_mode_out = ( ULONG* )irp->AssociatedIrp.SystemBuffer; 

			*log_mode_out = action_manage.log_mode; 
			ret_len = sizeof( ULONG ); 

			log_trace( ( MSG_INFO, "output the work mode 0x%0.8x\n", 
				*log_mode_out ) ); 
		}
		break; 
	case IOCTL_SEVEN_FW_SET_NOTIFY_EVENT:
		log_trace( ( MSG_INFO, "IOCTL_SEVEN_FW_SET_NOTIFY_EVENT\n" ) ); 

		if( input_len < sizeof( event_to_notify ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}
		else
		{
			event_to_notify *event_input; 
			event_input = ( event_to_notify* )irp->AssociatedIrp.SystemBuffer; 

			ntstatus = set_notify_event( event_input, irp->RequestorMode, irp_sp->FileObject );
		}
		break;
	case IOCTL_SEVEN_FW_SET_NOTIFY_EVENTS:
		log_trace( ( MSG_INFO, "IOCTL_SEVEN_FW_SET_NOTIFY_EVENTS\n" ) ); 

		if( input_len < sizeof( notify_events_set ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}
		else
		{
			notify_events_set *event_set; 
			event_set = ( notify_events_set* )irp->AssociatedIrp.SystemBuffer; 
			if( event_set->event_num * sizeof( event_to_notify ) + FIELD_OFFSET( notify_events_set, events ) > input_len )
			{
				ntstatus = STATUS_INVALID_PARAMETER; 
				break; 
			}

			ntstatus = set_notify_events( event_set, input_len, irp->RequestorMode, irp_sp->FileObject );
		}
		break; 
	case IOCTL_START_TRACE_LOG_UI_INTERACT:
		{
			if( UserMode != ExGetPreviousMode() )
			{
				ntstatus = STATUS_UNSUCCESSFUL; 
				break; 
			}

			if( irp_sp->DeviceObject != trace_log_mgr )
			{
				ntstatus = STATUS_UNSUCCESSFUL; 
				break; 
			}

			if( FALSE == MmIsAddressValid( irp_sp->FileObject ) )
			{
				ntstatus = STATUS_UNSUCCESSFUL; 
				break; 
			}

			if( irp_sp->FileObject->DeviceObject != trace_log_mgr )
			{
				ntstatus = STATUS_UNSUCCESSFUL; 
				break; 
			}

			ntstatus = find_trace_log_file( irp_sp->FileObject ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				break; 
			}

			hold_w_res_lock( ui_responsor.mapping_lock ); 

			if( ui_responsor.file_obj_for_ui == NULL )
			{
				ui_responsor.file_obj_for_ui = irp_sp->FileObject; 
				ui_responsor.ui_proc = PsGetCurrentProcess(); 
				ASSERT( ui_responsor.ui_proc != NULL );
			}
			else
			{
				ntstatus = STATUS_ALREADY_REGISTERED; 
			}
			release_res_lock( ui_responsor.mapping_lock );
		}
		break; 
	case IOCTL_STOP_TRACE_LOG_UI_INTERACT:
		{
			BOOLEAN lock_held = FALSE; 

			do 
			{
				hold_w_res_lock( ui_responsor.mapping_lock ); 

				lock_held = TRUE; 

				if( irp_sp->FileObject != ui_responsor.file_obj_for_ui )
				{
					ntstatus = STATUS_INVALID_PARAMETER; 
					break; 
				}

				ui_responsor.file_obj_for_ui = NULL; 

				if( NULL != ui_responsor.ui_proc )
				{
#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
					ntstatus = unmap_r3_io_space(); 
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0
					ui_responsor.ui_proc = NULL; 
				}
				else
				{
					ASSERT( FALSE && "releasing the ui responsor proc handle that's null\n"); 
				}

				release_res_lock( ui_responsor.mapping_lock ); 

				lock_held = FALSE; 

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
				// move it to unlocked code.
				ntstatus = release_pending_sys_action(); 
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

			}while( FALSE );

			if( lock_held == TRUE )
			{
				release_res_lock( ui_responsor.mapping_lock ); 
			}
		}
		break; 
	case IOCTL_BLOCK_PING:
		log_trace( ( MSG_INFO, "IOCTL_BLOCK_PING\n" ) ); 

		if( input_len < sizeof( INT32 ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}
		else
		{
			INT32 *block; 
			block = ( INT32* )irp->AssociatedIrp.SystemBuffer; 

			if( *block == FALSE )
			{
				block_ping = FALSE; 
			}
			else
			{
				block_ping = TRUE; 
			}
		}
		break; 
	case IOCTL_RESET_LEARNED_RULE: 
		{
			clear_response_records(); 
			clear_app_response_records(); 
		}
		break; 
	case IOCTL_GET_USER_DIRECT_MEM:
		{
			
		}
		break; 
	case IOCTL_SET_WAIT_RING3_REPLY_TIME:
		{
			LARGE_INTEGER *wait_time_input; 
			LARGE_INTEGER old_wait_time;

			if( sizeof( LARGE_INTEGER ) > input_len )
			{
				ntstatus = STATUS_INVALID_PARAMETER; 
				break; 
			}

			wait_time_input = ( LARGE_INTEGER* )irp->AssociatedIrp.SystemBuffer; 
			if( wait_time_input->QuadPart > 0 )
			{
				wait_time_input->QuadPart = -wait_time_input->QuadPart; 
			}

			if( wait_time_input->QuadPart < MAX_RING3_REPLY_WAIT_TIME )
			{
				ntstatus = STATUS_INVALID_PARAMETER_1; 
				break; 
			}

			old_wait_time.QuadPart = ring3_reply_wait_time.QuadPart; 

			ring3_reply_wait_time.QuadPart = wait_time_input->QuadPart; 

			if( ring3_reply_wait_time.QuadPart < MAX_RING3_REPLY_WAIT_TIME )
			{
				ring3_reply_wait_time.QuadPart = MAX_RING3_REPLY_WAIT_TIME; 
			}

			if( output_len >= sizeof( LARGE_INTEGER ) )
			{
				( ( LARGE_INTEGER* )irp->AssociatedIrp.SystemBuffer )->QuadPart = old_wait_time.QuadPart; 
				ret_len = sizeof( LARGE_INTEGER ); 
			}

			ntstatus = STATUS_SUCCESS;
		}
		break; 
	case IOCTL_DRIVER_WORK_STATE: 
		{
			sw_ctrl *ctrl; 
			sw_state old_state; 

			if( sizeof( sw_ctrl ) > input_len )
			{
				ntstatus = STATUS_INVALID_PARAMETER; 
				break; 
			}

			ctrl = ( sw_ctrl* )irp->AssociatedIrp.SystemBuffer; 
			ntstatus = set_sw_state( trace_log_func_sw, ctrl->id, ( sw_state )ctrl->state, &old_state ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				break; 
			}

			log_trace( ( MSG_INFO, "set switch %u to %u\n", ctrl->id, ctrl->state ) );

			if( output_len >= sizeof( sw_ctrl ) )
			{
				ctrl->state = old_state; 
				ret_len = sizeof( sw_ctrl ); 
			}
			ntstatus = STATUS_SUCCESS;
		}
		break; 
	case IOCTL_INIT_RING3_R3_VM:
		{
#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
			BOOLEAN lock_held = FALSE; 

			do 
			{
				if( output_len < sizeof( all_shared_vm_out ) )
				{
					ntstatus = STATUS_BUFFER_TOO_SMALL; 
					break; 
				}

				hold_w_res_lock( ui_responsor.mapping_lock ); 
				lock_held = TRUE; 

				if( ui_responsor.ui_proc != PsGetCurrentProcess())
				{
					ntstatus = STATUS_INVALID_PARAMETER; 
					break; 
				}

				if( STATUS_SUCCESS != all_r3_buf_is_mapped() )
				{
					ntstatus = map_r3_io_space(); 
					if( ntstatus != STATUS_SUCCESS )
					{
						break; 
					}
				}

				memset( irp->AssociatedIrp.SystemBuffer, 0, sizeof( all_shared_vm_out ) ); 

				( ( all_shared_vm_out* )irp->AssociatedIrp.SystemBuffer )->all_shared_vm[ 0 ].vm_size = all_r3_cbuf[ SYS_LOG_BUF ].r3_vm.vm_size; 
				( ( all_shared_vm_out* )irp->AssociatedIrp.SystemBuffer )->all_shared_vm[ 0 ].r3_addr = all_r3_cbuf[ SYS_LOG_BUF ].r3_vm.r3_addr; 
				( ( all_shared_vm_out* )irp->AssociatedIrp.SystemBuffer )->all_shared_vm[ 1 ].vm_size = all_r3_arr[ SYS_ACTION_BUF_ARRAY ].r3_vm.vm_size; 
				( ( all_shared_vm_out* )irp->AssociatedIrp.SystemBuffer )->all_shared_vm[ 1 ].r3_addr = all_r3_arr[ SYS_ACTION_BUF_ARRAY ].r3_vm.r3_addr; 
				( ( all_shared_vm_out* )irp->AssociatedIrp.SystemBuffer )->all_shared_vm[ 2 ].vm_size = all_r3_arr[ R3_NOTIFY_BUF_ARRAY ].r3_vm.vm_size; 
				( ( all_shared_vm_out* )irp->AssociatedIrp.SystemBuffer )->all_shared_vm[ 2 ].r3_addr = all_r3_arr[ R3_NOTIFY_BUF_ARRAY ].r3_vm.r3_addr; 

				ret_len = sizeof( all_shared_vm_out ); 
			}while( FALSE );

			if( lock_held == TRUE )
			{
				release_res_lock( ui_responsor.mapping_lock ); 
			}
#else
			ntstatus = STATUS_NOT_IMPLEMENTED;
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0
		}
		break; 
	case IOCTL_UNINIT_RING3_VM:
		{
#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0

			do 
			{
				hold_w_res_lock( ui_responsor.mapping_lock ); 

				if( irp_sp->FileObject != ui_responsor.file_obj_for_ui )
				{
					ntstatus = STATUS_INVALID_PARAMETER; 
					break; 
				}

				if( NULL != ui_responsor.ui_proc )
				{

					ntstatus = unmap_r3_io_space(); 
					ASSERT( STATUS_SUCCESS == ntstatus );
				}
				else
				{
					ASSERT( FALSE && "releasing the ui responsor proc handle that's null\n"); 
				}
			}while( FALSE );

			release_res_lock( ui_responsor.mapping_lock ); 
#else
			ntstatus = STATUS_NOT_IMPLEMENTED; 
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0
		}
		break; 
	case IOCTL_GET_EVENTMON_DRIVER_VERSION:
		{
			ULARGE_INTEGER *version; 

			do 
			{
				if( output_len < sizeof( driver_version ) )
				{
					ntstatus = STATUS_BUFFER_TOO_SMALL; 
					break; 
				}

				version = ( ULARGE_INTEGER* )irp->AssociatedIrp.SystemBuffer; 
				*version = driver_version; 

				ret_len = sizeof( driver_version ); 
			
			}while( FALSE ); 
		}
		break; 
	case IOCTL_EVENT_TRACE_CONFIG: 
		{
			do 
			{
				if( input_len != sizeof( event_trace_config ) )
				{
					ntstatus = STATUS_BUFFER_TOO_SMALL; 
					break; 
				}

				ntstatus = config_trace_data_size( ( event_trace_config* )irp->AssociatedIrp.SystemBuffer ); 

			}while( FALSE );
		}
		break; 
	case IOCTL_EVENT_DATA_FLOW_TRACE_CONFIG: 
		{
			do 
			{
				if( input_len != sizeof( DATA_FLOW_CONDITIONS ) )
				{
					ntstatus = STATUS_BUFFER_TOO_SMALL; 
					break; 
				}

				ntstatus = config_data_flow_conditions( ( DATA_FLOW_CONDITIONS* )irp->AssociatedIrp.SystemBuffer ); 

			}while( FALSE );
		}
		break; 
	default:
		ntstatus = STATUS_NOT_IMPLEMENTED; 
		break; 
	}

	IoReleaseRemoveLock( &context->file_rundown_lock, irp );  

_return:

	if( ntstatus != STATUS_PENDING 
		&& irp_completed == FALSE )
	{
		irp->IoStatus.Information = ret_len; 
		irp->IoStatus.Status = ntstatus;

		IoCompleteRequest( irp, IO_NO_INCREMENT ); 
	}

	return ntstatus; 
}

NTSTATUS uninit_fw_rules()
{
	NTSTATUS ntstatus; 

	UninitAllAclList();

	ntstatus = release_http_filter_list();
	if( !NT_SUCCESS( ntstatus ) )
	{
		DBGPRINT( ( "init_http_filter_list\n" ) ); 
		ASSERT( FALSE ); 
	}

	return ntstatus; 
}

NTSTATUS init_manage_context()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

	action_manage.all_work_mode = WORK_ACL_MODE; 

	memset( &action_manage.block_count, 0, sizeof( action_manage.block_count ) ); 

	action_manage.work_timer = NULL; 
	action_manage.dpc = NULL; 
	action_manage.event = NULL; 

	action_manage.work_timer = ( KTIMER* )ALLOC_TAG_POOL( sizeof( KTIMER ) ); 
	if( action_manage.work_timer == NULL )
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		goto _return; 
	}

	KeInitializeTimer( action_manage.work_timer ); 

	action_manage.dpc = ( KDPC* )ALLOC_TAG_POOL( sizeof( KDPC ) ); 
	if( action_manage.dpc == NULL )
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		goto _return; 
	}

	KeInitializeDpc( action_manage.dpc, work_mode_timer, NULL ); 

	action_manage.event = ( KEVENT* )ALLOC_TAG_POOL( sizeof( KEVENT ) ); 
	if( action_manage.event == NULL )
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		goto _return; 
	}

	KeInitializeEvent( action_manage.event, NotificationEvent, TRUE ); 

_return: 
	if( !NT_SUCCESS( ntstatus ) )
	{
		if( action_manage.work_timer != NULL )
		{
			FREE_TAG_POOL( action_manage.work_timer ); 
		}

		if( action_manage.dpc != NULL )
		{
			FREE_TAG_POOL( action_manage.dpc ); 
		}

		if( action_manage.event != NULL )
		{
			FREE_TAG_POOL( action_manage.event ); 
		}
	}

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 
	return ntstatus; 
}

VOID uninit_manage_context()
{
	BOOLEAN timer_canceled; 
	ASSERT( action_manage.work_timer != NULL ); 
	ASSERT( action_manage.dpc != NULL ); 
	ASSERT( action_manage.event != NULL ); 

	timer_canceled = KeCancelTimer( action_manage.work_timer ); 
	if( timer_canceled == FALSE )
	{
		NTSTATUS ntstatus; 
		ntstatus = KeWaitForSingleObject( action_manage.event, 
			Executive, 
			KernelMode, 
			FALSE, 
			NULL ); 

		if( ntstatus != STATUS_SUCCESS )
		{
			log_trace( ( MSG_ERROR, "wait the work mode synchronize event failed 0x%0.8x\n", ntstatus ) ); 
			ASSERT( FALSE ); 
		}
	}
#ifdef DBG
	else
	{
		ULONG event_state; 
		event_state = KeReadStateEvent( action_manage.event ); 
		ASSERT( event_state == 0 ); 
	}
#endif //DBG

	FREE_TAG_POOL( action_manage.work_timer ); 
	FREE_TAG_POOL( action_manage.dpc ); 
	FREE_TAG_POOL( action_manage.event ); 
}

#ifdef INTEGRATE_DRIVERS_FUNCTION
VOID tracelog_uninit( PDRIVER_OBJECT drv_obj )
#else
VOID trace_log_unload( PDRIVER_OBJECT drv_obj )
#endif //INTEGRATE_DRIVERS_FUNCTION
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

#ifndef INTEGRATE_DRIVERS_FUNCTION
	uninit_action_notify_buffer_manage(); 

	uninit_proc_info_manage(); 

	stop_event_notify_worker(); 

#endif //INTEGRATE_DRIVERS_FUNCTION

	uninit_all_callback(); 

#ifdef _R3_INTERFACE
	ASSERT( ring3_interface.filter != NULL ); 
	unreg_r3_interface(); 
#endif //_R3_INTERFACE

	{
		UNICODE_STRING trace_log_dos_name; 

		RtlInitUnicodeString( &trace_log_dos_name, TRACE_LOG_DEV_DOS_NAME ); 

		IoDeleteSymbolicLink( &trace_log_dos_name ); 

		ASSERT( trace_log_mgr != NULL ); 
		IoDeleteDevice( trace_log_mgr );
	}

	ntstatus = uninit_driver_interface(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		log_trace( ( MSG_ERROR, "release the driver interface error\n" ) ); 
	}

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
	if( cur_os_ver.maj_ver >= 6 )
	{
		release_sys_events_list( HAVE_PENDING_EVENT ); 
	}
	else
	{
		release_sys_events_list( 0 ); 
	}
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

#if _SUPPORT_RING0_POLICY
	ntstatus = uninit_action_manage(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		log_trace( ( MSG_ERROR, "release the action management context failed\n" ) ); 
	}
#endif //_SUPPORT_RING0_POLICY
	
#ifdef _DNS_NAME_PARSING
	ntstatus = uninit_fw_rules(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		log_trace( ( MSG_ERROR, "release network filter context failed\n" ) ); 
	}
#endif //_DNS_NAME_PARSING

	release_all_events();

#ifdef DBG
	if( KeGetCurrentIrql() > PASSIVE_LEVEL )
	{
		KeBugCheck( STATUS_FAIL_CHECK ); 
	}
#endif //DBG

	uninit_trace_context( drv_obj ); 

	uninit_trace_log_aio_queue(); 

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
	uninit_r3_io_space_r0(); 
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

	uninit_ui_responsor(); 

	uninit_files_info( &all_open_files ); 
}

NTSTATUS init_fw_rules()
{
	NTSTATUS ntstatus; 
	BOOLEAN acl_list_inited = FALSE; 
	BOOLEAN http_filter_inited = FALSE; 

	ntstatus = InitAllAclList();
	if( !NT_SUCCESS( ntstatus ) )
	{
		DBGPRINT( ( "InitAllAclList \n" ) );
		goto _return; 
	}

	acl_list_inited = TRUE; 

	ntstatus = init_http_filter_list();
	if( !NT_SUCCESS( ntstatus ) )
	{
		DBGPRINT( ( "init_http_filter_list\n" ) ); 
		goto _return; 
	}

	http_filter_inited = TRUE; 

_return:

	if( ntstatus != STATUS_SUCCESS )
	{
		if( http_filter_inited == TRUE )
		{
			release_http_filter_list(); 
		}

		if( acl_list_inited == TRUE )
		{
			UninitAllAclList(); 
		}
	}

	return ntstatus; 
}

NTSTATUS is_safe_rundown_file( file_context *context )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		ASSERT( context != NULL ); 

		if( context == NULL )
		{
			ntstatus = STATUS_INVALID_PARAMETER_1; 
			break; 
		}

	}while( FALSE );

	return ntstatus; 
}

NTSTATUS aio_read( __in PDEVICE_OBJECT DeviceObject, 
				  __in PIRP irp )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	PIO_STACK_LOCATION  irp_sp;
	LARGE_INTEGER       currentTime;
	file_context *context;
	PVOID               read_buffer;
	BOOLEAN irp_completed = TRUE; 

	PAGED_CODE();

	log_trace( ( MSG_INFO, "enter %s :0x%p\n", __FUNCTION__, irp ) );

	do 
	{
		irp_sp = IoGetCurrentIrpStackLocation( irp );
		ASSERT( irp_sp->FileObject != NULL );

		context = irp_sp->FileObject->FsContext; 
		ntstatus = is_safe_rundown_file( context ); 

		if( ntstatus != STATUS_SUCCESS )
		{
			ntstatus = STATUS_INVALID_DEVICE_REQUEST; 
			break; 
		}

		ntstatus = IoAcquireRemoveLock( &context->file_rundown_lock, irp ); 

		if( !NT_SUCCESS( ntstatus ) )
		{
			break; 
		}
		
		if( irp_sp->Parameters.Read.Length < R3_NOTIFY_BUF_SIZE - DEFAULT_OUTPUT_DATA_REGION_SIZE )
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			IoReleaseRemoveLock( &context->file_rundown_lock, irp );
			break; 
		}

		{
			NTSTATUS _ntstatus; 
			r3_action_notify *pending_event; 
			BOOLEAN inited = TRUE; 

			_ntstatus = get_action_pending_notify( &pending_event, &inited ); 

			if( _ntstatus != STATUS_SUCCESS )
			{
				ASSERT( pending_event == NULL ); 
				ASSERT( inited == FALSE ); 

				ntstatus = aio_insert_irp_safe( &io_queue.aio_safe_queue, irp, NULL ); 
				if( ntstatus != STATUS_SUCCESS )
				{
					//__asm int 3; 

					log_trace( ( MSG_FATAL_ERROR, "insert the irp to the aio queue error 0x%0.8x\n", ntstatus ) ); 
				}
				else
				{
					ntstatus = STATUS_PENDING; 
				}

				break; 
			}

			do 
			{
				ASSERT( NULL != pending_event ); 

				if( inited == FALSE )
				{
					ntstatus = r3_notify_action_post_init( pending_event, NULL ); 
					if( ntstatus != STATUS_SUCCESS )
					{
						dbg_message_ex( MSG_IMPORTANT, "initialize the pending notify erro 0x%0.8x\n", ntstatus ); 
						break; 
					}
				}

				ntstatus = _notify_action_aio( pending_event, 
					pending_event->size, 
					irp ); 

				irp_completed = TRUE; 
			}while( FALSE );

			deallocate_action_notify( pending_event ); 
		}
	}while( FALSE ); 

	if( ntstatus != STATUS_PENDING 
		&& irp_completed == FALSE )
	{
		irp->IoStatus.Information = 0; 
		irp->IoStatus.Status = ntstatus; 
		IoCompleteRequest( irp, IO_NO_INCREMENT ); 
	}

	return ntstatus;
}

NTSTATUS tracelog_cleanup( PDEVICE_OBJECT dev_obj, PIRP irp )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	NTSTATUS _ntstatus; 
	PIO_STACK_LOCATION irp_sp;
	file_context *context; 
	BOOLEAN lock_held = FALSE; 

	log_trace( ( MSG_INFO, "enter %s \n" , __FUNCTION__ ) ); 

	irp_sp = IoGetCurrentIrpStackLocation( irp ); 

	log_trace( ( MSG_INFO, "file object is 0x%0.8x \n", irp_sp->FileObject ) ); 

#define IRP_CLEANUP_FLAGS ( IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API )
	ASSERT( IRP_CLEANUP_FLAGS == ( irp->Flags & IRP_CLEANUP_FLAGS ) ); 

	do 
	{
		hold_w_res_lock( ui_responsor.mapping_lock ); 
		lock_held = TRUE; 

		if( irp_sp->FileObject != ui_responsor.file_obj_for_ui )
		{
			break; 
		}

		ui_responsor.file_obj_for_ui = NULL; 

		if( NULL != ui_responsor.ui_proc )
		{
#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
			_ntstatus = unmap_r3_io_space(); 
			ASSERT( STATUS_SUCCESS == _ntstatus ); 
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0
			ui_responsor.ui_proc = NULL; 
		}
		else
		{
			ASSERT( FALSE && "releasing the ui responsor proc handle that's null\n"); 
		}

		release_res_lock( ui_responsor.mapping_lock ); 
		lock_held = FALSE; 

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
		release_pending_sys_action(); 
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

	}while( FALSE );

	if( lock_held == TRUE )
	{
		release_res_lock( ui_responsor.mapping_lock ); 
	}

	context = irp_sp->FileObject->FsContext; 
	ASSERT( context != NULL ); 

	_ntstatus = IoAcquireRemoveLock( &context->file_rundown_lock, irp );
	ASSERT( NT_SUCCESS( _ntstatus ) );

	//
	// Wait for all the threads that are currently dispatching to exit and 
	// prevent any threads dispatching I/O on the same handle beyond this point.
	//
	IoReleaseRemoveLockAndWait( &context->file_rundown_lock, 
		irp ); 

	_ntstatus = process_aio_queue( irp_sp->FileObject ); 
	if( _ntstatus != STATUS_SUCCESS )
	{
		log_trace( ( MSG_ERROR, "process pending aio requests error 0x%0.8x file 0x%0.8x\n", _ntstatus, irp_sp->FileObject ) ); 
	}

	ASSERT( all_open_files.file_count >= 1 ); 

	if( all_open_files.file_count <= 1 )
	{
		//__asm int 3; 

		_ntstatus = process_aio_queue( NULL ); 
		if( _ntstatus != STATUS_SUCCESS )
		{
			log_trace( ( MSG_ERROR, "process pending aio requests error 0x%0.8x\n", _ntstatus ) ); 
		}
	}

	release_notify_event_by_file_obj( irp_sp->FileObject ); 

	irp->IoStatus.Status = ntstatus; 
	irp->IoStatus.Information = 0; 

	IoCompleteRequest( irp, IO_NO_INCREMENT ); 

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n" , __FUNCTION__, ntstatus ) ); 

	return ntstatus; 
}

//notice must initialize file rundown lock for aio.

NTSTATUS check_legal_trace_process( HANDLE proc_id )
{
	return STATUS_SUCCESS; 
}

NTSTATUS tracelog_create_close(
    PDEVICE_OBJECT dev_obj,
    PIRP irp )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	PIO_STACK_LOCATION irp_sp;
    file_context *context;

    UNREFERENCED_PARAMETER( dev_obj );

    PAGED_CODE();

	log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 
    irp_sp = IoGetCurrentIrpStackLocation( irp );

    ASSERT( irp_sp->FileObject != NULL ); 

	switch( irp_sp->MajorFunction )
	{
	case IRP_MJ_CREATE:
		log_trace( ( MSG_INFO, "IRP_MJ_CREATE\n" ) ); ;

		//
		// Make sure nobody is using the FsContext scratch area.
		//
		if( irp_sp->FileObject->FsContext != NULL )
		{
			ASSERT( FALSE && "who already used the context of the file object\n" ); 

			ntstatus = STATUS_UNSUCCESSFUL; 
			goto _return; 
		}

		context = ( file_context* )ALLOC_TAG_POOL( 
			sizeof( file_context ) ); 

		if( NULL == context ) 
		{
			ntstatus =  STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		IoInitializeRemoveLock( &context->file_rundown_lock, LOG_TRACE_TAG, 0, 0 );

		InitializeListHead( &context->entry ); 

		context->owner = irp_sp->FileObject; 

		//
		// Store the context in the FileObject's scratch area.
		//
		irp_sp->FileObject->FsContext = ( PVOID )context;

		add_trace_log_file( context ); 

		ntstatus = check_legal_trace_process( PsGetCurrentProcessId() ); 

		hold_w_res_lock( ui_responsor.mapping_lock ); 

		if( ntstatus == STATUS_SUCCESS 
			&& ui_responsor.file_obj_for_ui == NULL )
		{
			ui_responsor.file_obj_for_ui = irp_sp->FileObject; 
			ui_responsor.ui_proc = PsGetCurrentProcess(); 
			ASSERT( ui_responsor.ui_proc != NULL );
		}
		else
		{
			ntstatus = STATUS_ALREADY_REGISTERED; 
		}

		release_res_lock( ui_responsor.mapping_lock ); 

		ntstatus = STATUS_SUCCESS; 
		break;

	case IRP_MJ_CLOSE:
		log_trace( ( MSG_INFO, "IRP_MJ_CLOSE\n" ) ); 

		context = irp_sp->FileObject->FsContext;

		del_trace_log_file( context ); 

		FREE_TAG_POOL( context );

		ntstatus = STATUS_SUCCESS;
		break;

	default:
		ASSERT(FALSE);  // should never hit this
		ntstatus = STATUS_NOT_IMPLEMENTED;
		break;
	}

_return:
    irp->IoStatus.Status = ntstatus;
    irp->IoStatus.Information = 0;
    IoCompleteRequest( irp, IO_NO_INCREMENT );

    return ntstatus;
}

#ifdef _R3_INTERFACE
PDRIVER_OBJECT trace_log_drv_obj = NULL; 
#endif //_R3_INTERFACE

#ifdef INTEGRATE_DRIVERS_FUNCTION
VOID eventmon_unload( PDRIVER_OBJECT drv_obj ); 
NTSTATUS r3_eventmon_unload( __in FLT_FILTER_UNLOAD_FLAGS Flags )
#else
NTSTATUS r3_trace_log_unload( __in FLT_FILTER_UNLOAD_FLAGS Flags )
#endif //INTEGRATE_DRIVERS_FUNCTION
{

    PAGED_CODE();

    UNREFERENCED_PARAMETER( Flags );

    log_trace( ( MSG_INFO,
                ( "unloading ring3 interface \n" ) ) ); 

    //
    //  If the CDO is still referenced and the unload is not mandatry
    //  then fail the unload
    //
    
#ifdef SAFE_RING3_MAPPING_UNLOAD
    _hold_r_res_lock( &ring3_interface.res_lock );

    if( FlagOn( ring3_interface.flags, GLOBAL_DATA_F_CDO_OPEN_REF) 
		&& !FlagOn( Flags, FLTFL_FILTER_UNLOAD_MANDATORY ) )
	{
        log_trace( ( MSG_INFO, ( "Fail unloading driver since the unload is optional is open\n" ) ) );
        _release_res_lock( &ring3_interface.res_lock ); 
        return STATUS_FLT_DO_NOT_DETACH;
    }
	_release_res_lock( &ring3_interface.res_lock ); 
#endif //SAFE_RING3_MAPPING_UNLOAD

	ASSERT( trace_log_drv_obj != NULL ); 

#ifdef INTEGRATE_DRIVERS_FUNCTION
	eventmon_unload( trace_log_drv_obj ); 
#else
	trace_log_unload( trace_log_drv_obj ); 
#endif //INTEGRATE_DRIVERS_FUNCTION

    return STATUS_SUCCESS;
}

NTSTATUS tracelog_io_obj( IN PDEVICE_OBJECT dev_obj )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		ASSERT( dev_obj != NULL ); 

		if( trace_log_mgr == dev_obj )
		{
			break; 
		}

		ntstatus = STATUS_NOT_FOUND; 
	}while( FALSE );

	return ntstatus; 
}

#ifdef INTEGRATE_DRIVERS_FUNCTION
#include "driver_integrated.h"

NTSTATUS tracelog_init( IN PDRIVER_OBJECT drv_obj, IN PUNICODE_STRING reg_path )
#else
NTSTATUS DriverEntry( IN PDRIVER_OBJECT drv_obj, IN PUNICODE_STRING reg_path )
#endif //INTEGRATE_DRIVERS_FUNCTION
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 ret; 

#if _DNS_NAME_PARSING
	BOOLEAN fw_rule_inited = FALSE; 
#endif //_DNS_NAME_PARSING

	BOOLEAN driver_interface_inited = FALSE; 

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
	BOOLEAN event_list_inited = FALSE; 
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

#if _SUPPORT_RING0_POLICY
	BOOLEAN action_manage_inited = FALSE; 
#endif //_SUPPORT_RING0_POLICY

	BOOLEAN aio_queue_inited = FALSE; 
	BOOLEAN trace_log_dev_sym_inited = FALSE; 
	BOOLEAN npaged_look_aside_inited = FALSE; 

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
	BOOLEAN r3_io_space_inited = FALSE; 
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

	BOOLEAN callback_inited = FALSE; 
	BOOLEAN ui_responsor_inited = FALSE; 
	BOOLEAN opened_file_check_inited = FALSE; 
	BOOLEAN trace_provider_inited = FALSE; 

	BOOLEAN event_notify_worker_started = FALSE; 

#ifndef INTEGRATE_DRIVERS_FUNCTION
	BOOLEAN proc_info_manage_inited = FALSE; 
	BOOLEAN notify_buffer_manage_inited = FALSE; 
#endif //INTEGRATE_DRIVERS_FUNCTION

#ifdef _R3_INTERFACE
	BOOLEAN r3_interface_reg = FALSE; 
#endif //_R3_INTERFACE

	UNICODE_STRING trace_log_dev_name; 
	UNICODE_STRING trace_log_dos_name; 
	INT32 i;

	PsGetVersion( &cur_os_ver.maj_ver, 
		&cur_os_ver.min_ver, 
		&cur_os_ver.build_num, 
		NULL );

	ntstatus = init_trace_log_file_check( &all_open_files ); 
	if( ntstatus != STATUS_SUCCESS )
	{
		goto _return; 
	}
	opened_file_check_inited = TRUE; 

	ntstatus = init_ui_responsor(); 
	if( ntstatus != STATUS_SUCCESS )
	{
		goto _return; 
	}

	ui_responsor_inited = TRUE; 

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0 
	ntstatus = init_r3_io_space_r0(); 

	if( ntstatus != STATUS_SUCCESS )
	{
		goto _return; 
	}

	r3_io_space_inited = TRUE; 
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

	ntstatus = init_sw_arr( &trace_log_func_sw, TRACE_LOG_FUNC_SW_COUNT, 0, trace_log_func_sw_buf ); 

	if( ntstatus != STATUS_SUCCESS )
	{
		goto _return; 
	}

	ntstatus = init_trace_log_aio_queue( NULL ); 
	if( ntstatus != STATUS_SUCCESS )
	{
		goto _return; 
	}

	aio_queue_inited = TRUE;

	ntstatus = get_proc_name_off_from_eproc(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		ASSERT( FALSE && "can't get the eprocess name offset" ); ; 
		goto _return; 
	}

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
	if( cur_os_ver.maj_ver >= 6 )
	{
		ntstatus = init_sys_events_list( HAVE_PENDING_EVENT ); 
	}
	else
	{
		ntstatus = init_sys_events_list( 0 ); 
	}

	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}
	event_list_inited = TRUE; 
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

#if _SUPPORT_RING0_POLICY
	ntstatus = init_action_manage(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}
	action_manage_inited = TRUE; 
#endif //_SUPPORT_RING0_POLICY 

#ifndef INTEGRATE_DRIVERS_FUNCTION
	ntstatus = init_proc_info_manage(); 
	if( ntstatus != STATUS_SUCCESS )
	{
		goto _return; 
	}

	proc_info_manage_inited = TRUE; 

	ntstatus = init_action_notify_buffer_manage(); 
	if( ntstatus != STATUS_SUCCESS )
	{
		goto _return; 
	}

	notify_buffer_manage_inited = TRUE; 

	ntstatus = start_event_notify_worker(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	event_notify_worker_started = TRUE; 

#endif //INTEGRATE_DRIVERS_FUNCTION

	RtlInitUnicodeString( &trace_log_dev_name, TRACE_LOG_DEV_NAME ); 
	RtlInitUnicodeString( &trace_log_dos_name, TRACE_LOG_DEV_DOS_NAME ); 

	ntstatus = IoCreateDevice( drv_obj, 
		0, 
		&trace_log_dev_name, 
		FILE_DEVICE_UNKNOWN, 
		0, 
		FALSE, 
		&trace_log_mgr ); 

	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	trace_log_mgr->Flags |= DO_DIRECT_IO; 

	ntstatus = init_trace_context( drv_obj, reg_path, trace_log_mgr ); 
	if( ntstatus != STATUS_SUCCESS )
	{
		goto _return; 
	}

	trace_provider_inited = TRUE;

	ntstatus = IoCreateSymbolicLink( &trace_log_dos_name, 
		&trace_log_dev_name ); 

	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	trace_log_dev_sym_inited = TRUE; 

#ifndef INTEGRATE_DRIVERS_FUNCTION
	for( i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i ++ )
	{
		drv_obj->MajorFunction[ i ] = default_irp_dispatch; 
	}

	drv_obj->MajorFunction[ IRP_MJ_READ ] = aio_read;

	drv_obj->MajorFunction[ IRP_MJ_CREATE ] = tracelog_create_close; 

	drv_obj->MajorFunction[ IRP_MJ_CLOSE ] = tracelog_create_close; 

	drv_obj->MajorFunction[ IRP_MJ_CLEANUP ] = tracelog_cleanup; 

	drv_obj->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = trace_log_dev_ctrl; 

	drv_obj->MajorFunction[ IRP_MJ_INTERNAL_DEVICE_CONTROL ] = trace_log_internal_dev_ctrl; 

#else
	for( i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i ++ )
	{
		integrated_context[ TRACELOG_DRIVER_INDEX ].major_func[ i ] = default_irp_dispatch; 
	}

	integrated_context[ TRACELOG_DRIVER_INDEX ].major_func[ IRP_MJ_CREATE ] = tracelog_create_close; 

	integrated_context[ TRACELOG_DRIVER_INDEX ].major_func[ IRP_MJ_CLOSE ] = tracelog_create_close; 

	integrated_context[ TRACELOG_DRIVER_INDEX ].major_func[ IRP_MJ_CLEANUP ] = tracelog_cleanup; 

	integrated_context[ TRACELOG_DRIVER_INDEX ].major_func[ IRP_MJ_DEVICE_CONTROL ] = trace_log_dev_ctrl; 

	integrated_context[ TRACELOG_DRIVER_INDEX ].major_func[ IRP_MJ_INTERNAL_DEVICE_CONTROL ] = trace_log_internal_dev_ctrl; 

	integrated_context[ TRACELOG_DRIVER_INDEX ].is_drv_io_obj = tracelog_io_obj;
#endif //INTEGRATE_DRIVERS_FUNCTION

#ifdef _R3_INTERFACE
	trace_log_drv_obj = drv_obj; 

#ifdef INTEGRATE_DRIVERS_FUNCTION
#ifdef SUPPORT_DRIVER_UNLOAD
	ntstatus = register_r3_interface( drv_obj, reg_path, r3_eventmon_unload ); 
#else
	ntstatus = register_r3_interface( drv_obj, reg_path, NULL ); 
#endif //SUPPORT_DRIVER_UNLOAD
#else
	ntstatus = register_r3_interface( drv_obj, reg_path, r3_trace_log_unload ); 
#endif //INTEGRATE_DRIVERS_FUNCTION

	if( ntstatus != STATUS_SUCCESS )
	{
		goto _return; 
	}

	r3_interface_reg = TRUE; 
#else
#ifdef INTEGRATE_DRIVERS_FUNCTION
	drv_obj->DriverUnload = NULL; 
#else
	drv_obj->DriverUnload = trace_log_unload; 
#endif //INTEGRATE_DRIVERS_FUNCTION
#endif //_R3_INTERFACE
	
	memset( all_notify_events, 0, sizeof( all_notify_events ) ); 

	init_sp_lock( events_lock ); 

	ntstatus = init_driver_interface( TRACE_LOG_INTERFACE_NAME ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	driver_interface_inited = TRUE; 

	ntstatus = init_all_callback(); 
	if( ntstatus != STATUS_SUCCESS )
	{
		goto _return; 
	}

	callback_inited = TRUE; 

_return:

	if( !NT_SUCCESS( ntstatus ) )
	{
		NTSTATUS _ntstatus;

		if( driver_interface_inited == TRUE )
		{
			_ntstatus = uninit_driver_interface(); 

			if( !NT_SUCCESS( _ntstatus ) )
			{
				log_trace( ( MSG_ERROR, "*** release driver interface error ***\n") ); 
			}
		}

#ifndef INTEGRATE_DRIVERS_FUNCTION
		if( TRUE == event_notify_worker_started )
		{
			stop_event_notify_worker(); 
		}

		if( notify_buffer_manage_inited == TRUE )
		{
			uninit_action_notify_buffer_manage(); 
		}

		if( TRUE == proc_info_manage_inited )
		{
			uninit_proc_info_manage(); 
		}

#endif //INTEGRATE_DRIVERS_FUNCTION

		if( opened_file_check_inited == TRUE )
		{
			uninit_files_info( &all_open_files ); 
		}

		if( ui_responsor_inited == TRUE )
		{
			uninit_ui_responsor(); 
		}

#ifdef _R3_INTERFACE
		if( r3_interface_reg == TRUE )
		{
			unreg_r3_interface(); 
		}
#endif //_R3_INTERFACE

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
		if( r3_io_space_inited == TRUE )
		{
			uninit_r3_io_space_r0(); 
		}
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

#if SUPPORT_VA_REGION_MAPPING_R3_TO_R0
		if( event_list_inited == TRUE )
		{
			if( cur_os_ver.maj_ver >= 6 )
			{
				release_sys_events_list( HAVE_PENDING_EVENT ); 
			}
			else
			{
				release_sys_events_list( 0 ); 
			}
		}
#endif //SUPPORT_VA_REGION_MAPPING_R3_TO_R0

#if _SUPPORT_RING0_POLICY
		if( action_manage_inited == TRUE )
		{
			_ntstatus = uninit_action_manage(); 
			if( !NT_SUCCESS( _ntstatus ) )
			{
				log_trace( ( MSG_ERROR, "*** release action manage failed ***\n") ); 
			}
		}
#endif //_SUPPORT_RING0_POLICY

#if _DNS_NAME_PARSING
		if( fw_rule_inited == TRUE )
		{
			_ntstatus = uninit_fw_rules(); 
			if( !NT_SUCCESS( _ntstatus ) )
			{
				log_trace( ( MSG_ERROR, "*** release firewall rules failed ***\n") ); 
			}
		}
#endif //_DNS_NAME_PARSING

		if( TRUE == trace_provider_inited )
		{
			uninit_trace_context( drv_obj ); 
		}

		if( TRUE == callback_inited )
		{
			uninit_all_callback(); 
		}

		if( aio_queue_inited == TRUE )
		{
			uninit_trace_log_aio_queue(); 
		}

		if( trace_log_dev_sym_inited != FALSE )
		{
			IoDeleteSymbolicLink( &trace_log_dos_name ); 
		}

		if( trace_log_mgr != NULL )
		{
			IoDeleteDevice( trace_log_mgr ); 
		}
	}

	return ntstatus; 
}