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
#else
#include "common.h"
#endif //TEST_IN_RING3

#include "acl_define.h"
#include "action_type_parse.h"
#include "action_check.h"
#include "action_setup.h"

ULONG get_param_data_type_len( param_info *param )
{
	ULONG data_type_len; 

	switch( param->type )
	{
	case INT8_TYPE:
		data_type_len = sizeof( CHAR ); 
		break; 
	case INT16_TYPE: 
		data_type_len = sizeof( SHORT ); 
		break; 
	case INT32_TYPE: 
		data_type_len = sizeof( INT32 );  
		break; 
	case INT64_TYPE:
		data_type_len = sizeof( LONGLONG ); 
		break; 
	case UINT8_TYPE:
		data_type_len = sizeof( BYTE ); 
		break; 
	case UINT16_TYPE:
		data_type_len = sizeof( USHORT ); 
		break; 
	case UINT32_TYPE: 
		data_type_len = sizeof( UINT32 ); 
		break; 
	case UINT64_TYPE: 
		data_type_len = sizeof( ULONGLONG ); 
		break; 
	case PTR_TYPE:
		data_type_len = sizeof( PVOID ); 
		break; 
	case STRING_PARAM:
		if( param->data.string_val == NULL )
		{
			data_type_len = 0; 
			break; 
		}

		data_type_len = strlen( param->data.string_val ) + sizeof( CHAR ); 
		break; 
	case WSTRING_TYPE:
		if( param->data.wstring_val == NULL )
		{
			data_type_len = 0; 
			break; 
		}

		data_type_len = ( ( wcslen( param->data.wstring_val ) + 1 ) << 1 ); 
		break; 
	case ANSI_STRING_TYPE:
		if( param->data.ansi_val.Buffer == NULL )
		{
			ASSERT( FALSE ); 
			data_type_len = 0; 
			break; 
		}

		data_type_len = param->data.ansi_val.Length + sizeof( CHAR ); 

		break; 
	case UNICODE_STRING_TYPE:
		if( param->data.unicode_val.Buffer == NULL )
		{
			ASSERT( FALSE ); 
			data_type_len = 0; 
			break; 
		}

		data_type_len = param->data.unicode_val.Length + sizeof( WCHAR ); 

		break; 
	case DATA_BLOB_TYPE:
		data_type_len = 0; 
		break; 
	default:
		data_type_len = 0;  
		break;
	}

	return data_type_len; 
}

NTSTATUS copy_param_data( BYTE *data_buf, 
						 ULONG buf_len, 
						 param_info *param, 
						 ULONG *param_data_len )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		ASSERT( data_buf != NULL ); 
		ASSERT( param_data_len != NULL ); 

		ASSERT( buf_len > 0 ); 
		ASSERT( buf_len >= get_param_data_type_len( param ) ); 

		*param_data_len = 0; 
		switch( param->type )
		{
		case INT8_TYPE:
			*( INT8* )data_buf = param->data.int8_val; 
			*param_data_len = sizeof( param->data.int8_val ); 
			break; 
		case INT16_TYPE: 
			*( SHORT* )data_buf = param->data.int16_val; 
			*param_data_len = sizeof( param->data.int16_val ); 
			break; 
		case INT32_TYPE: 
			*( INT32* )data_buf = param->data.int32_val; 
			*param_data_len = sizeof( param->data.int32_val ); 
			break; 
		case INT64_TYPE:
			*( INT64* )data_buf = param->data.int64_val; 
			*param_data_len = sizeof( param->data.int64_val ); 
			break; 
		case UINT8_TYPE:
			*( UINT8* )data_buf = param->data.uint8_val; 
			*param_data_len = sizeof( param->data.uint8_val ); 
			break; 
		case UINT16_TYPE:
			*( UINT16* )data_buf = param->data.uint16_val; 
			*param_data_len = sizeof( param->data.uint16_val ); 
			break; 
		case UINT32_TYPE: 
			*( UINT32* )data_buf = param->data.uint32_val; 
			*param_data_len = sizeof( param->data.uint32_val ); 
			break; 
		case UINT64_TYPE: 
			*( ULONGLONG* )data_buf = param->data.uint64_val; 
			*param_data_len = sizeof( param->data.uint64_val ); 
			break; 
		case PTR_TYPE:
			*( PVOID* )data_buf = ( PVOID )( ULONG_PTR )param->data.ptr_val; 
			*param_data_len = sizeof( param->data.ptr_val ); 
			break; 
		case STRING_PARAM:
			if( param->data.string_val == NULL )
			{
				ASSERT( FALSE ); 
				ntstatus = STATUS_INVALID_PARAMETER_2; 
				break; 
			}

			*param_data_len = sizeof( param->data.string_val ) + sizeof( CHAR ); 

			memcpy( data_buf, param->data.string_val, *param_data_len ); 
			break; 
		case WSTRING_TYPE:
			if( param->data.wstring_val == NULL )
			{
				ASSERT( FALSE ); 
				ntstatus = STATUS_INVALID_PARAMETER_2; 
				break; 
			}

			*param_data_len = ( wcslen( param->data.wstring_val ) << 1 ) + sizeof( WCHAR ); 
			memcpy( data_buf, param->data.wstring_val, *param_data_len ); 
			break; 
		case ANSI_STRING_TYPE:
			if( param->data.ansi_val.Buffer == NULL )
			{
				ASSERT( FALSE ); 
				ntstatus = STATUS_INVALID_PARAMETER_3; 
				break; 
			}

			memcpy( data_buf, param->data.ansi_val.Buffer, param->data.ansi_val.Length ); 

			*( CHAR* )( data_buf + param->data.ansi_val.Length ) = '\0'; 
			*param_data_len = param->data.ansi_val.Length + sizeof( CHAR ); 

			break; 

		case UNICODE_STRING_TYPE:

			if( param->data.unicode_val.Buffer == NULL )
			{
				ASSERT( FALSE ); 
				ntstatus = STATUS_INVALID_PARAMETER_3; 
				break; 
			}

			memcpy( data_buf, param->data.unicode_val.Buffer, param->data.unicode_val.Length ); 

			*( WCHAR* )( data_buf + param->data.unicode_val.Length ) = L'\0'; 
			*param_data_len = param->data.unicode_val.Length + sizeof( WCHAR ); 

			break; 

		case DATA_BLOB_TYPE:
			ntstatus = STATUS_NOT_SUPPORTED; 
			break; 
		default:
			ntstatus = STATUS_NOT_IMPLEMENTED; 
			break;
		}

	}while( FALSE );

	return ntstatus; 
}

NTSTATUS construct_param_struct_data( param_info all_params[ ], 
						   ULONG param_count, 
						   PVOID struct_data_buf, 
						   ULONG buf_len,  
						   ULONG *struct_data_len )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	BYTE *param_data_buf = NULL; 
	ULONG data_copied_len; 
	ULONG struct_data_buf_len; 
	ULONG param_data_len; 
	ULONG i; 

	do 
	{
		ASSERT( struct_data_len != 0 );

		*struct_data_len = 0;

		if( all_params == NULL )
		{
			ntstatus = STATUS_INVALID_PARAMETER_1;
			break;
		}

		if( param_count == 0 )
		{
			ntstatus = STATUS_INVALID_PARAMETER_2;
			break;
		}

		struct_data_buf_len = 0;
		
		for( i = 0; i < param_count; i ++ )
		{
			param_data_len = get_param_data_type_len( &all_params[ i ] );
			if( param_data_len == 0 )
			{
				ntstatus = STATUS_INVALID_PARAMETER_3;
				break; 
			}

			struct_data_buf_len += param_data_len;
		}

		if( struct_data_len != NULL )
		{
			*struct_data_len = struct_data_buf_len;
		}

		if( buf_len < struct_data_buf_len )
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			break; 
		}

		param_data_buf = ( BYTE* )struct_data_buf;
		
		if( param_data_buf == NULL )
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			break; 
		}

		data_copied_len = 0; 
		for( i = 0; i < param_count; i ++ )
		{
			ntstatus = copy_param_data( param_data_buf + data_copied_len, 
				buf_len - data_copied_len, 
				&all_params[ i ], 
				&param_data_len ); 

			if( ntstatus !=	STATUS_SUCCESS )
			{
				break; 
			}

			data_copied_len += param_data_len; 
		}

		ASSERT( data_copied_len == struct_data_buf_len ); 
	}while( FALSE ); 

	return ntstatus; 
}

NTSTATUS test_action_data_setup()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	param_info all_params[ MAX_PARAMS_COUNT ]; 
	sys_action_info *action = NULL; 
	ULONG ret_len; 

	do 
	{
		action = ( sys_action_info* )alloc_sys_action_info( ACTION_RECORD_SIZE_BY_TYPE( exec_create ) + ( ( MAX_PATH + MAX_PATH ) << 1 ) ); 
		if( action == NULL )
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			break; 
		}

#define TEST_PROC_ID 0
#define TEST_PARENT_PROC_ID 10
#define TEST_IMAGE_BASE 0x80000001

		all_params[ 0 ].type = UINT32_TYPE; 
		all_params[ 0 ].data.uint32_val = TEST_PROC_ID; 

		all_params[ 1 ].type = UINT32_TYPE; 
		all_params[ 1 ].data.uint32_val = TEST_PARENT_PROC_ID; 

		all_params[ 2 ].type = PTR_TYPE; 
		all_params[ 2 ].data.ptr_val = ( ULONGLONG )( PVOID )( ULONG_PTR )( ULONG )0x80003210; 

#define TEST_EXEC_CREATE_PATH L"test_proc"
#define TEST_EXEC_CREATE_CMD L"test_cmd"

		all_params[ 3 ].type = UINT16_TYPE; 
		all_params[ 3 ].data.uint32_val = CONST_STR_LEN( TEST_EXEC_CREATE_PATH ); 

		all_params[ 4 ].type = UINT16_TYPE; 
		all_params[ 4 ].data.uint32_val = CONST_STR_LEN( TEST_EXEC_CREATE_CMD ); 

		all_params[ 5 ].type = WSTRING_TYPE; 
		all_params[ 5 ].data.wstring_val = TEST_EXEC_CREATE_PATH; 

		all_params[ 6 ].type = WSTRING_TYPE; 
		all_params[ 6 ].data.wstring_val = TEST_EXEC_CREATE_CMD; 

		//ntstatus = collect_action_context( action&->ctx ); 
		//if( ntstatus != STATUS_SUCCESS )
		//{
		//	break; 
		//}

		action->action.type = EXEC_create; 

		ntstatus = construct_param_struct_data( all_params, 
			7, 
			( BYTE* )&action->action.do_exec_create, 
			sizeof( exec_create ) + ( ( MAX_PATH + MAX_PATH ) << 1 ), 
			&ret_len ); 

		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		if( action->action.do_exec_create.pid != all_params[ 0 ].data.uint32_val )
		{
			ASSERT( FALSE ); 
		}

		if( action->action.do_exec_create.parent_pid != all_params[ 1 ].data.uint32_val )
		{
			ASSERT( FALSE ); 
		}

		if( action->action.do_exec_create.image_base != all_params[ 2 ].data.ptr_val )
		{
			ASSERT( FALSE ); 
		}

		if( action->action.do_exec_create.path_len != all_params[ 3 ].data.uint16_val )
		{
			ASSERT( FALSE ); 
		}

		if( action->action.do_exec_create.cmd_len != all_params[ 4 ].data.uint16_val )
		{
			ASSERT( FALSE ); 
		}

		if( wcscmp( action->action.do_exec_create.path_name, 
			all_params[ 5 ].data.wstring_val ) != 0 )
		{
			ASSERT( FALSE ); 
		}

		if( wcscmp( action->action.do_exec_create.path_name 
			+ all_params[ 3 ].data.uint16_val + 1, 
			all_params[ 6 ].data.wstring_val ) != 0 )
		{
			ASSERT( FALSE ); 
		}

	}while( FALSE );

	if( action != NULL )
	{
		FREE_TAG_POOL( action ); 
	}

	return ntstatus; 
}

NTSTATUS analyze_action_meaning( sys_action_info *action, sys_action_type *action_mean )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		if( action_mean == NULL )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		*action_mean = BA_other; 
	}while( FALSE ); 

	return ntstatus; 
}