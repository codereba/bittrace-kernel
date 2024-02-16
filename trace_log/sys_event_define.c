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
//#define WIN32_NO_STATUS
#include "ring0_2_ring3.h"
#else
#include "common.h"
#endif //TEST_IN_RING3

#include "rbtree.h"
#include "hash_table.h"
#include "acl_define.h"
#include "trace_log_api.h"
#include "sys_event_define.h"
#include "socket_rule.h"
#include <ntstrsafe.h>

#define MAX_ACTION_RULE_NUM 4900

typedef struct _response_record_item
{
	LIST_ENTRY entry; 
	action_response_type response; 
	data_trace_option trace_option; 
	WCHAR app_name[1]; 
} response_record_item, *presponse_record_item; 

ULONG param_define_size[] = 
{
	URL_DEFINE_TABLE_SIZE, 
	IP_DEFINE_TABLE_SIZE, 
	PORT_DEFINE_TABLE_SIZE, 
	FILE_DEFINE_TABLE_SIZE, 
	REG_DEFINE_TABLE_SIZE, 
	COM_DEFINE_TABLE_SIZE, 
	APP_DEFINE_TABLE_SIZE, 
	COMMON_DEFINE_TABLE_SIZE, 
}; 

ULONG class_param_define_size[] = 
{
	CLASS_IP_DEFINE_TABLE_SIZE, 
	CLASS_URL_DEFINE_TABLE_SIZE, 
	CLASS_PORT_DEFINE_TABLE_SIZE, 
	CLASS_FILE_DEFINE_TABLE_SIZE, 
	CLASS_REG_DEFINE_TABLE_SIZE, 
	CLASS_COM_DEFINE_TABLE_SIZE, 
	CLASS_APP_DEFINE_TABLE_SIZE, 
	CLASS_COMMON_DEFINE_TABLE_SIZE 
}; 

ULONG action_rule_define_size[] = 
{
	IP_PORT_RULE_DEFINE_TABLE_SIZE, 
	URL_RULE_DEFINE_TABLE_SIZE, 
	FILE_RULE_DEFINE_TABLE_SIZE, 
	REG_RULE_DEFINE_TABLE_SIZE, 
	COM_RULE_DEFINE_TABLE_SIZE, 
	COMMON_RULE_TABLE_SIZE
}; 

#define IP_PORT_RESPONSE_TABLE_SIZE 1
#define URL_REPONSE_TABLE_SIZE 512 
#define FILE_RESPONSE_TABLE_SIZE 256
#define REG_RESPONSE_TABLE_SIZE 256
#define COM_RESPONSE_TABLE_SIZE 256
#define COMMON_RESPONSE_TABLE_SIZE 128

#define APP_RECORD_TABLE_NUM 1
#define APP_RECORD_TABLE_SIZE 512 

ULONG app_response_size[] = 
{
	APP_RECORD_TABLE_SIZE
}; 

ULONG action_response_size[] = 
{
	IP_PORT_RESPONSE_TABLE_SIZE, 
	URL_REPONSE_TABLE_SIZE, 
	FILE_RESPONSE_TABLE_SIZE, 
	REG_RESPONSE_TABLE_SIZE, 
	COM_RESPONSE_TABLE_SIZE, 
	COMMON_RESPONSE_TABLE_SIZE
}; 

//LPCTSTR action_descs[] = { }; 

common_hash_table all_param_define[ MAX_PARAM_DEFINE_TYPE ] = { 0 }; 
common_hash_table all_class_param_define[ MAX_PARAM_DEFINE_TYPE ] = { 0 }; 
common_hash_table all_action_rule[ MAX_ACTION_RULE_TYPE ] = { 0 }; 
common_hash_table all_action_response[ MAX_ACTION_RULE_TYPE ] = { 0 }; 
common_hash_table all_app_response[ APP_RECORD_TABLE_NUM ] = { 0 }; 

ERESOURCE *all_param_define_lock = NULL; 
ERESOURCE *all_action_rule_lock = NULL; 
ERESOURCE *all_response_lock = NULL; 
ERESOURCE *all_app_response_lock = NULL; 

INLINE ULONG correct_socket_ip( ULONG socket_ip, INT32 is_begin ) 
{
	return ( ( socket_ip == 0 ) ? ( ( is_begin == TRUE ) ? 0 : ( ULONG )( -1 ) ) : socket_ip ); 
}

INLINE ULONG correct_socket_port( ULONG socket_port, INT32 is_begin ) 
{
	return ( ( socket_port == 0 ) ? ( ( is_begin == TRUE ) ? 0 : ( ULONG )0xffff ) : socket_port ); 
}

ULONG calc_param_need_size( param_define_type type )
{
	ULONG alloc_size = 0; 

	switch( type )
	{
	case URL_DEFINE:
		alloc_size = FIELD_OFFSET( param_define_item, param ) 
			+ FIELD_OFFSET( param_all_desc, common ) 
			+ sizeof( url_param_define ); 
		break; 
	case FILE_DEFINE:
		alloc_size = FIELD_OFFSET( param_define_item, param ) 
			+ FIELD_OFFSET( param_all_desc, common ) 
			+ sizeof( file_param_define ); 
		break; 
	case APP_DEFINE:
		alloc_size = FIELD_OFFSET( param_define_item, param ) 
			+ FIELD_OFFSET( param_all_desc, common ) 
			+ sizeof( app_param_define ); 
		break; 
	case COM_DEFINE:
		alloc_size = FIELD_OFFSET( param_define_item, param ) 
			+ FIELD_OFFSET( param_all_desc, common ) 
			+ sizeof( com_param_define ); 

		break; 
	case REG_DEFINE:
		alloc_size = FIELD_OFFSET( param_define_item, param ) 
			+ FIELD_OFFSET( param_all_desc, common ) 
			+ sizeof( reg_param_define ); 
		break; 
	case COMMON_DEFINE:
		alloc_size = FIELD_OFFSET( param_define_item, param ) 
			+ FIELD_OFFSET( param_all_desc, common ) 
			+ sizeof( common_param_define ); 
		break; 
	case IP_DEFINE: 
		alloc_size = FIELD_OFFSET( param_define_item, param ) 
			+ FIELD_OFFSET( param_all_desc, common ) 
			+ sizeof( ip_param_define ); 
		break; 
	case PORT_DEFINE: 
		alloc_size = FIELD_OFFSET( param_define_item, param ) 
			+ FIELD_OFFSET( param_all_desc, common ) 
			+ sizeof( port_param_define ); 
		break; 
	default:
		ASSERT( FALSE && "invalid param define type \n" ); 
		break; 
	}

	return alloc_size; 
}

NTSTATUS alloc_param_define( param_define_type type, param_define *param_input, INT32 flag, param_define_item **param_alloc )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	NTSTATUS _ntstatus; 
	ULONG need_size; 
	param_define_item *new_define = NULL; 
	ULONG name_len; 
	ULONG buf_len; 

	ASSERT( is_valid_param_define_type( type ) == TRUE ); 
	ASSERT( param_input != NULL ); 
	ASSERT( param_alloc != NULL ); 

	*param_alloc = NULL; 

	ntstatus = check_param_define_valid( ( param_define* )&param_input->common, !!( flag & CLASS_PARAM ), type, 0 ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		//if( ntstatus == STATUS_PARAM_NO_MEANING )
		//{
		//	ntstatus = STATUS_SUCCESS; 
		//}
		ASSERT( ntstatus == STATUS_PARAM_NO_MEANING ); 

		goto _return; 
	}

	if( flag & CLASS_PARAM )
	{
		need_size = FIELD_OFFSET( param_define_item, param ) 
			+ FIELD_OFFSET( param_all_desc, common ) 
			+ sizeof( class_param_define ); 

		new_define = ( param_define_item* )ALLOC_TAG_POOL( need_size ); 
		if( new_define == NULL )
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			goto _return; 
		}

		new_define->param.type = type; 
		new_define->param.is_cls = TRUE; 
		new_define->param.size = sizeof( class_param_define ); 

		wcsncpy( new_define->param.cls.class_name, param_input->cls.class_name, _MAX_CLASS_NAME_LEN ); 
		if( new_define->param.cls.class_name[ _MAX_CLASS_NAME_LEN - 1 ] != L'\0' )
		{
			ASSERT( FALSE ); 
			ntstatus = STATUS_INVALID_PARAMETER; 
			goto _return; 
		}

		unicode_str_to_upper( new_define->param.cls.class_name ); 
	}
	else if( is_name_param_define_type( type ) == TRUE )
	{
		need_size = calc_param_need_size( type ); 
		if( need_size <= FIELD_OFFSET( param_define_item, param ) 
			+ FIELD_OFFSET( param_all_desc, common ) )
		{
			ASSERT( FALSE ); 
			ntstatus = STATUS_INVALID_PARAMETER; 
			goto _return; 
		} 

		new_define = ( param_define_item* )ALLOC_TAG_POOL( need_size ); 
		if( new_define == NULL )
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			goto _return; 
		}

		new_define->param.type = type; 
		new_define->param.is_cls = FALSE; 
		new_define->param.size = ( USHORT )need_size - ( FIELD_OFFSET( param_define_item, param ) 
			+ FIELD_OFFSET( param_all_desc, common ) ); 

		buf_len = get_name_param_len_wchar_unit( type ); 
		if( buf_len == 0 )
		{
			ASSERT( FALSE && "parameter length logic error" ); 

			ntstatus = STATUS_INVALID_PARAMETER; 
			goto _return; 
		}

		name_len = wcsnlen( param_input->common.name, buf_len ); 
		if( name_len == buf_len )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			goto _return; 
		}

		_ntstatus = RtlStringCchCopyW( new_define->param.common.name, 
			ARRAYSIZE( new_define->param.common.name ), 
			param_input->common.name ); 

		if( _ntstatus != STATUS_SUCCESS )
		{

		}

		if( is_path_name_param_define_type( type ) == TRUE )
		{
			if( new_define->param.file.file_path[ name_len - 1 ] == L'\\' )
			{
				new_define->param.file.file_path[ name_len - 1 ] = L'\0'; 
			}
		}

		unicode_str_to_upper( new_define->param.common.name ); 

		if( type == URL_DEFINE )
		{
			ntstatus = parse_url_param( &new_define->param ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				goto _return; 
			}
		}
	}
	else if( type == IP_DEFINE )
	{
		need_size = FIELD_OFFSET( param_define_item, param ) 
			+ FIELD_OFFSET( param_all_desc, common ) 
			+ sizeof( ip_param_define ); 

		new_define = ( param_define_item* )ALLOC_TAG_POOL( need_size ); 
		if( new_define == NULL )
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			goto _return; 
		}

		new_define->param.type = type; 
		new_define->param.is_cls = FALSE; 
		new_define->param.size = sizeof( ip_param_define ); 

		new_define->param.ip.ip_begin = correct_socket_ip( param_input->ip.ip_begin, TRUE ); 
		new_define->param.ip.ip_end = correct_socket_ip( param_input->ip.ip_end, FALSE ); 
	}
	else if( type == PORT_DEFINE )
	{
		need_size = FIELD_OFFSET( param_define_item, param ) 
			+ FIELD_OFFSET( param_all_desc, common ) 
			+ sizeof( port_param_define ); 

		new_define = ( param_define_item* )ALLOC_TAG_POOL( need_size ); 
		if( new_define == NULL )
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			goto _return; 
		}

		new_define->param.type = type; 
		new_define->param.is_cls = FALSE; 
		new_define->param.size = sizeof( port_param_define ); 

		new_define->param.port.type = param_input->port.type; 
		new_define->param.port.port_begin = correct_socket_port( param_input->port.port_begin, TRUE ); 
		new_define->param.port.port_end = correct_socket_port( param_input->port.port_end, FALSE ); 
	}
	else 
	{
		ASSERT( "invalid param define type" && FALSE ); 
	}


	InitializeListHead( &new_define->define_list ); 
	InitializeListHead( &new_define->entry ); 

	new_define->ref_count = 0; 

	*param_alloc = new_define;

_return:
	if( !NT_SUCCESS( ntstatus ) )
	{
		ASSERT( *param_alloc == NULL ); 
		if( new_define != NULL )
		{
			FREE_TAG_POOL( new_define ); 
		}
	}

	return ntstatus; 
}

NTSTATUS _alloc_param_define( param_all_desc *param_input, INT32 flag, param_define_item **param_alloc )
{
	ASSERT( param_input != NULL ); 
	return alloc_param_define( param_input->type, 
		( param_define* )&param_input->common, 
		param_input->is_cls == TRUE ? CLASS_PARAM : COMMON_PARAM, 
		param_alloc ); 
}

INT32 compare_define_name_no_case( LPCWSTR define_name, LPCWSTR name_compare )
{
	INT32 ret; 

	while( *( name_compare ) != L'\0' && *( define_name ) != L'\0' )
	{
		ASSERT( *define_name < 'a' || *define_name > 'z' ); 

		if( *name_compare >= 'a' && *name_compare <= 'z' )
		{
			if( *define_name != *name_compare + 'A' - 'a' )
			{
				break; 
			}
		}
		else
		{
			if( *define_name != *name_compare )
			{
				break; 
			}
		}

		name_compare ++; 
		define_name ++; 
	}

	if( *name_compare != L'\0' || *define_name != L'\0' )
	{
		ret = *name_compare - *define_name; 
	}
	else 
	{
		ret = 0; 
	}

	return ret; 
}

INT32 compare_define_name_no_case_len_by_dest( LPCWSTR define_name, LPCWSTR name_compare, ULONG len )
{
	INT32 ret; 

	while( *( name_compare ++ )!= L'\0' && *( define_name ++ ) != L'\0' && len -- > 0 )
	{
		if( *name_compare >= 'a' && *name_compare <= 'z' )
		{
			if( *define_name != *name_compare + 'A' - 'a' )
			{
				break; 
			}
		}
		else
		{
			if( *define_name != *name_compare )
			{
				break; 
			}
		}
	}

	if( *define_name != L'\0' )
	{
		ret = *name_compare - *define_name; 
	}
	else if( *name_compare != L'\0' )
	{
		if( len > 0 )
		{
			ret = *name_compare - *define_name; 
		}
		else 
		{
			ret = 0; 
		}
	}
	else
	{
		ret = 0; 
	}

	return ret; 
}

INT32 compare_define_path_no_case( LPCWSTR define_name, LPCWSTR name_compare )
{
	INT32 ret; 

	while( *( name_compare )!= L'\0' || *( define_name ) != L'\0' )
	{
		ASSERT( *define_name >= 'A' && *define_name <= 'Z' ); 

		if( *name_compare >= 'a' && *name_compare <= 'z' )
		{
			if( *define_name != *name_compare + 'A' - 'a' )
			{
				break; 
			}
		}
		else
		{
			if( *define_name != *name_compare )
			{
				break; 
			}
		}

		name_compare ++; 
		define_name ++; 
	}

	if( *define_name != L'\0' )
	{
		ret = *name_compare - *define_name; 
	}
	else 
	{
		ret = 0; 
	}

	return ret; 
}

INT32 compare_define_name_no_case_len( LPCWSTR define_name, LPCWSTR name_compare, ULONG len )
{
	INT32 ret; 

	while( *( name_compare ++ )!= L'\0' && *( define_name ++ ) != L'\0' && len -- > 0 )
	{
		if( *name_compare >= 'a' && *name_compare <= 'z' )
		{
			if( *define_name != *name_compare + 'A' - 'a' )
			{
				break; 
			}
		}
		else
		{
			if( *define_name != *name_compare )
			{
				break; 
			}
		}
	}

	if( *name_compare != L'\0' || *define_name != L'\0' )
	{
		ASSERT( len > 0 ); 

		ret = *name_compare - *define_name; 
	}
	else 
	{
		ret = 0; 
	}

	return ret; 
}

ULONG CALLBACK calc_class_name_hash_code( PVOID param, ULONG table_size )
{
	return unicode_str_hash( ( LPCWSTR )param, table_size ); 
}

INT32 CALLBACK compare_class_define( PVOID param, PLIST_ENTRY entry, PVOID param_iteration )
{
	INT32 ret = FALSE; 
	LPCWSTR class_name; 
	param_define_item *param_item; 

	ASSERT( entry != NULL ); 
	ASSERT( param != NULL ); 
	ASSERT( MmIsAddressValid( entry ) == TRUE ); 

	class_name = ( LPCWSTR )param; 
	param_item = CONTAINING_RECORD( entry, param_define_item, entry ); 
	
#ifdef DBG
	{
		if( param_item->param.cls.class_name[ _MAX_CLASS_NAME_LEN - 1 ] != L'\0' )
		{
			param_item->param.cls.class_name[ _MAX_CLASS_NAME_LEN - 1 ] = L'\0'; 
		}

		DBGPRINT( ( "compare name %ws with %ws \n", 
			class_name, 
			param_item->param.cls.class_name ) ); 
	}
#endif

	ASSERT( is_valid_param_define_type( param_item->param.type ) );  ; 

	if( compare_define_name_no_case_len( param_item->param.cls.class_name, class_name, _MAX_CLASS_NAME_LEN ) == 0 ) 
	{
		ret = TRUE; 
		goto _return; 
	}

_return:
	return ret; 
}

NTSTATUS find_in_hash_table_lock_free( PVOID param, init_iteration_callback init_iteration_func, uninit_iteration_callback uninit_iteration_func, iterate_name_callback iteration_func, calc_hash_code_callback hash_code_func, compare_hash_table_item_callback compare_func, common_hash_table *table, PLIST_ENTRY *item_found )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG hash_code;  
	PLIST_ENTRY table_row; 
	PVOID param_next; 
	PVOID iterate_context = NULL; 

	PLIST_ENTRY list_entry; 
	PLIST_ENTRY list_entry_next; 

	ASSERT( table != NULL ); 
	ASSERT( param != NULL ); 
	ASSERT( hash_code_func != NULL ); 
	ASSERT( compare_func != NULL ); 

	DBGPRINT( ( "enter %s \n", __FUNCTION__ ) ); 

	if( item_found != NULL )
	{
		*item_found = NULL; 
	}

	if( init_iteration_func != NULL )
	{
		ASSERT( iteration_func != NULL ); 
		ASSERT( uninit_iteration_func != NULL ); 

		ntstatus = init_iteration_func( param, &hash_code, table->size, &param_next, &iterate_context ); 
		if( !NT_SUCCESS( ntstatus ) )
		{
			goto _return; 
		}


#ifdef DBG
		if( hash_code == INVALID_HASH_CODE )
		{
			ASSERT( FALSE && "generate invalid hash code" ); 
			ntstatus = STATUS_INVALID_PARAMETER; 
			goto _return; 
		}
#endif //DBG

		ASSERT( iterate_context != NULL ); 
		ASSERT( param_next != NULL ); 

		for( ; ; )
		{
			ASSERT( hash_code < table->size ); 

			if( NULL == table->hash_table )
			{
				ASSERT( FALSE ); 
				ntstatus = STATUS_UNSUCCESSFUL; 
				goto _return; 
			}

			table_row = &table->hash_table[ hash_code ]; 

			list_entry = table_row->Flink; 
			for( ; ; )
			{
				if( list_entry == table_row )
				{
					ntstatus = STATUS_NOT_FOUND; 
					break; 
				}

				list_entry_next = list_entry->Flink; 

				if( compare_func( param, list_entry, param_next ) == TRUE )
				{
					if( item_found != NULL )
					{
						*item_found = list_entry; 
					}

					goto _return; 
				}

				list_entry = list_entry_next; 
			}

			if( iteration_func == NULL )
			{
				break; 
			}

			ntstatus = iteration_func( iterate_context, &hash_code, table->size, &param_next ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				goto _return; 
			}

#ifdef DBG
			if( hash_code == INVALID_HASH_CODE )
			{
				ASSERT( FALSE && "generate invalid hash code" ); 
				ntstatus = STATUS_INVALID_PARAMETER; 
				goto _return; 
			}
#endif //DBG

			ASSERT( param_next != NULL ); 
			ASSERT( hash_code != INVALID_HASH_CODE ); 
		}
	}
	else
	{
		hash_code = hash_code_func( param, table->size ); 
#ifdef DBG
		if( hash_code == INVALID_HASH_CODE )
		{
			ASSERT( FALSE && "generate invalid hash code" ); 
			ntstatus = STATUS_INVALID_PARAMETER; 
			goto _return; 
		}
#endif //DBG
		ASSERT( hash_code < table->size ); 

		if( NULL == table->hash_table )
		{
			ASSERT( FALSE ); 
			ntstatus = STATUS_UNSUCCESSFUL; 
			goto _return; 
		}

		table_row = &table->hash_table[ hash_code ]; 

		list_entry = table_row->Flink; 
		for( ; ; )
		{
			if( list_entry == table_row )
			{
				ntstatus = STATUS_NOT_FOUND; 
				break; 
			}

			list_entry_next = list_entry->Flink; 

			if( compare_func( param, list_entry, NULL ) == TRUE )
			{
				if( item_found != NULL )
				{
					*item_found = list_entry; 
				}

				goto _return; 
			}

			list_entry = list_entry_next; 
		}
	}

_return:

	if( iterate_context != NULL )
	{
		ASSERT( uninit_iteration_func != NULL ); 
		uninit_iteration_func( iterate_context ); 
	}

	return ntstatus; 
}

NTSTATUS find_in_hash_table( PVOID param, init_iteration_callback init_iteration_func, uninit_iteration_callback uninit_iteration_func, iterate_name_callback iteration_func, calc_hash_code_callback hash_code_func, compare_hash_table_item_callback compare_func, common_hash_table *table, PLIST_ENTRY *item_found )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	ASSERT( table != NULL ); 

	hold_hash_table_lock( table ); 

	ntstatus = find_in_hash_table_lock_free( param, init_iteration_func, uninit_iteration_func, iteration_func, hash_code_func, compare_func, table, item_found ); 

	release_hash_table_lock( table ); 
	
	return ntstatus; 
}

INLINE common_hash_table *get_param_define_table( param_define_type type )
{
	common_hash_table *table; 
	ASSERT( is_valid_param_define_type( type ) ); 
	
	table = &all_param_define[ type ]; 
	return table; 
}

INLINE common_hash_table *get_class_param_define_table( param_define_type type )
{
	common_hash_table *table; 
	ASSERT( is_valid_param_define_type( type ) );

	table = &all_class_param_define[ type ]; 

	return table; 
}

NTSTATUS add_param_define_to_class( param_define_item *param_input, LPCWSTR class_name )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	param_define_type type; 
	common_hash_table *table; 
	PLIST_ENTRY item_found; 
	param_define_item *param_found; 

	type = param_input->param.type; 

	ASSERT( is_valid_param_define_type( type ) ); 

	table = get_class_param_define_table( type ); 

	hold_hash_table_lock( table ); 

	ntstatus = find_in_hash_table_lock_free( ( PVOID )class_name, NULL, NULL, NULL, calc_class_name_hash_code, compare_class_define, table, &item_found ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	ASSERT( item_found != NULL ); 

	param_found = ( param_define_item* )CONTAINING_RECORD( item_found, param_define_item, entry ); 

	InsertHeadList( &param_found->define_list, &param_input->define_list ); 

_return:
	release_hash_table_lock( table ); 
	return ntstatus; 
}

NTSTATUS add_param_define( param_define_item *param_input, ULONG flag, LPCWSTR class_name )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG hash_code; 
	common_hash_table *table; 

	ASSERT( param_input != NULL ); 
	ASSERT( is_valid_param_define_type( param_input->param.type ) ); 

	if( ( flag & CLASS_PARAM ) != 0 && param_input->param.is_cls == FALSE )
	{
		ASSERT( FALSE ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	ntstatus = check_param_desc_valid( &param_input->param ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		ASSERT( FALSE ); 
		if( ntstatus != STATUS_PARAM_NO_MEANING )
		{
			goto _return; 
		}

		ASSERT( FALSE ); 
		ntstatus = STATUS_SUCCESS; 
		goto _return; 
	}

	if( param_input->param.is_cls == TRUE )
	{
		param_input->param.is_cls = TRUE; 

		table = get_class_param_define_table( param_input->param.type ); 
		hash_code = calc_class_name_hash_code( ( PVOID )param_input->param.cls.class_name, table->size ); 
	}
	else 
	{
		table = get_param_define_table( param_input->param.type ); 
		if( param_input->param.type == COM_DEFINE )
		{
			hash_code = calc_com_name_hash_code( ( PVOID )param_input->param.com.com_name, table->size ); 
		}
		else if( param_input->param.type == FILE_DEFINE )
		{
			hash_code = calc_file_name_hash_code( ( PVOID )param_input->param.file.file_path, table->size ); 
		}
		else if( param_input->param.type == REG_DEFINE )
		{
			hash_code = calc_reg_name_hash_code( ( PVOID )param_input->param.reg.reg_path, table->size ); 
		}
		else if( param_input->param.type == APP_DEFINE )
		{
			hash_code = calc_app_name_hash_code( ( PVOID )param_input->param.app.app_name, table->size ); 
		}
		else if( param_input->param.type == IP_DEFINE )
		{
			hash_code = _calc_ip_hash_code( ( PVOID )&param_input->param.ip, table->size ); 
		}
		else if( param_input->param.type == PORT_DEFINE )
		{
			hash_code = calc_port_hash_code( ( PVOID )&param_input->param.port, table->size ); 
		}
		else if( param_input->param.type == URL_DEFINE )
		{
			ASSERT( param_input->param.url.domain_name_len > 0 ); 

			hash_code = calc_url_name_hash_code( ( PVOID )( param_input->param.url.url + param_input->param.url.domain_name_off ), table->size ); 
		}
		else if( param_input->param.type == COMMON_DEFINE )
		{
			hash_code = calc_name_hash_code( ( PVOID )param_input->param.common.name, table->size ); 
		}
		else
		{
			ASSERT( "param define type is invalid" && FALSE ); 
		}

		if( class_name != NULL )
		{
			add_param_define_to_class( param_input, class_name ); 
		}
	}

	insert_to_hash_table( table, hash_code, &param_input->entry ); 
	ASSERT( param_input->ref_count == 0 ); 
	param_input->ref_count ++; 

_return:
	return ntstatus; 
}

ULONG CALLBACK calc_name_hash_code( PVOID param, ULONG table_size )
{
	return unicode_str_hash( ( LPCWSTR )param, table_size ); 
}

ULONG CALLBACK _calc_ip_hash_code( PVOID param, ULONG table_size )
{
	ip_param_define *ip_define; 

	ip_define = ( ip_param_define* )param; 

	return long_hash( ( ULONG )ip_define->ip_begin, table_size ); 
}

ULONG CALLBACK calc_port_hash_code( PVOID param, ULONG table_size )
{
	port_param_define *port_define; 

	port_define = ( port_param_define* )param; 

	return long_hash( port_define->port_begin, table_size ); 
}

INT32 CALLBACK compare_app_name( PVOID param, PLIST_ENTRY item, PVOID param_iteration )
{
	INT32 ret = TRUE; 
	INT32 _ret; 
	param_define_item *param_item; 
	
	ASSERT( param != NULL ); 
	ASSERT( item != NULL ); 

	param_item = ( param_define_item* )CONTAINING_RECORD( item, param_define_item, entry ); 

	ASSERT( param_item->param.type == APP_DEFINE ); 

	_ret = compare_define_name_no_case( param_item->param.app.app_name, ( LPCWSTR )param ); 
	if( _ret != 0 )
	{
		ret = FALSE; 
	}

	return ret; 
}

INT32 CALLBACK compare_com_name( PVOID param, PLIST_ENTRY item, PVOID param_iteration )
{
	INT32 ret = TRUE; 
	INT32 _ret; 
	param_define_item *param_item; 

	ASSERT( param != NULL ); 
	ASSERT( item != NULL ); 

	param_item = ( param_define_item* )CONTAINING_RECORD( item, param_define_item, entry ); 

	ASSERT( param_item->param.type == COM_DEFINE ); 

	_ret = compare_define_name_no_case( param_item->param.com.com_name, ( LPCWSTR )param ); 
	if( _ret != 0 )
	{
		ret = FALSE; 
	}

	return ret; 
}

INT32 CALLBACK compare_common_name( PVOID param, PLIST_ENTRY item, PVOID param_iteration )
{
	INT32 ret = TRUE; 
	INT32 _ret; 
	param_define_item *param_item; 

	ASSERT( param != NULL ); 
	ASSERT( item != NULL ); 

	param_item = ( param_define_item* )CONTAINING_RECORD( item, param_define_item, entry ); 

	ASSERT( param_item->param.type == COMMON_DEFINE ); 

	_ret = compare_define_name_no_case( param_item->param.common.name, ( LPCWSTR )param ); 
	if( _ret != 0 )
	{
		ret = FALSE; 
	}

	return ret; 
}

INT32 CALLBACK compare_file_name( PVOID param, PLIST_ENTRY item, PVOID param_iteration )
{
	INT32 ret = TRUE; 
	INT32 _ret;

	param_define_item *param_item; 

	ASSERT( param != NULL );
	ASSERT( item != NULL ); 

	param_item = ( param_define_item* )CONTAINING_RECORD( item, param_define_item, entry ); 

	ASSERT( param_item->param.type == FILE_DEFINE ); 

	_ret = compare_define_name_no_case( param_item->param.file.file_path, ( LPCWSTR )param ); 
	if( _ret != 0 )
	{

		ret = FALSE; 
	}

	return ret; 
}

INT32 CALLBACK compare_reg_name( PVOID param, PLIST_ENTRY item, PVOID param_iteration )
{
	INT32 ret = TRUE; 
	INT32 _ret; 
	param_define_item *param_item; 

	ASSERT( param != NULL ); 
	ASSERT( item != NULL ); 
	param_item = ( param_define_item* )CONTAINING_RECORD( item, param_define_item, entry ); 

	ASSERT( param_item->param.type == REG_DEFINE ); 

	_ret = compare_define_name_no_case( param_item->param.reg.reg_path, ( LPCWSTR )param ); 
	if( _ret != 0 )
	{
		ret = FALSE;
		goto _return; 
	}

_return:
	return ret; 
}

INT32 CALLBACK compare_url_name( PVOID param, PLIST_ENTRY item, PVOID param_iteration )
{
	INT32 ret = TRUE; 
	INT32 _ret; 
	param_define_item *param_item; 

	ASSERT( item != NULL ); 
	param_item = ( param_define_item* )CONTAINING_RECORD( item, param_define_item, entry ); 

	_ret = compare_url_define( ( LPCWSTR )param, param_item->param.url.url );
	if( _ret != 0 )
	{
		ret = FALSE; 
		goto _return; 
	}

_return:
	return ret; 
}

ULONG CALLBACK calc_url_name_hash_code( PVOID param, ULONG table_size )
{
	ULONG hash_code = INVALID_HASH_CODE; 
	LPCWSTR domain_name; 
	ULONG domain_name_len; 

	if( !NT_SUCCESS( get_domain_name_in_url( ( LPCWSTR )param, &domain_name, &domain_name_len ) ) )
	{
		//DBG_BP(); 
		ASSERT( FALSE ); 
		goto _return; 
	}

	hash_code = unicode_fix_len_str_hash( domain_name, domain_name_len, table_size ); 

_return:
	return hash_code; 
}

INT32 CALLBACK compare_ip_define( PVOID param, PLIST_ENTRY item, PVOID param_iteration )
{
	INT32 ret = FALSE; 
	ip_param_define *ip_define; 
	param_define_item *param_item; 

	ASSERT( param != NULL ); 
	ASSERT( item != NULL ); 

	ip_define = ( ip_param_define* )param; 
	param_item = CONTAINING_RECORD( item, param_define_item, entry ); 

	ASSERT( param_item->param.type == IP_DEFINE ); 

	if( ip_define->ip_begin == param_item->param.ip.ip_begin 
		&& ip_define->ip_end == param_item->param.ip.ip_end )
	{
		ret = TRUE; 
		goto _return; 
	}

_return:
	return ret; 
}

INT32 CALLBACK compare_port_define( PVOID param, PLIST_ENTRY item, PVOID param_iteration )
{
	INT32 ret = FALSE; 
	port_param_define *port_define; 
	param_define_item *param_item; 

	ASSERT( param != NULL ); 
	ASSERT( item != NULL ); 

	port_define = ( port_param_define* )param; 
	param_item = CONTAINING_RECORD( item, param_define_item, entry ); 

	ASSERT( param_item->param.type == PORT_DEFINE ); 

	if( port_define->port_begin == param_item->param.port.port_begin 
		&& port_define->port_end == param_item->param.port.port_end )
	{
		ret = TRUE; 
		goto _return; 
	}

_return:
	return ret; 
}

VOID get_param_define_callback_and_param( param_all_desc *param_input, param_define_type type, PVOID *param, calc_hash_code_callback *hash_code_func, compare_hash_table_item_callback *compare_item_func )
{
	ASSERT( param_input != NULL );
	ASSERT( param != NULL ); 
	ASSERT( compare_item_func != NULL ); 
	ASSERT( hash_code_func != NULL ); 

	ASSERT( is_valid_param_define_type( type ) ); 
	switch( type ) 
	{
	case APP_DEFINE:
		{
			*param = ( PVOID )param_input->app.app_name; 
			*hash_code_func = calc_app_name_hash_code; 
			*compare_item_func = compare_app_name; 
		}
		break; 
	case COM_DEFINE:
		{
			*param = ( PVOID )param_input->com.com_name; 
			*hash_code_func = calc_com_name_hash_code; 
			*compare_item_func = compare_com_name; 
		}
		break; 
	case FILE_DEFINE:
		{
			*param = ( PVOID )param_input->file.file_path; 
			*hash_code_func = calc_file_name_hash_code; 
			*compare_item_func = compare_file_name; 
		}
		break; 
	case REG_DEFINE:
		{
			*param = ( PVOID )param_input->reg.reg_path; 
			*hash_code_func = calc_reg_name_hash_code; 
			*compare_item_func = compare_reg_name; 
		}
		break; 
	case IP_DEFINE:
		{
			*param = ( PVOID )&param_input->ip; 
			*hash_code_func = _calc_ip_hash_code; 
			*compare_item_func = compare_ip_define; 
		}
		break; 
	case PORT_DEFINE: 
		{
			*param = ( PVOID )&param_input->port; 
			*hash_code_func = calc_port_hash_code; 
			*compare_item_func = compare_port_define; 
		}
		break; 
	case URL_DEFINE:
		{
			*param = ( PVOID )param_input->url.url; 
			*hash_code_func = calc_url_name_hash_code; 
			*compare_item_func = compare_url_name; 
		}
		break; 
	case COMMON_DEFINE: 
		{
			*param = ( PVOID )param_input->common.name; 
			*hash_code_func = calc_name_hash_code; 
			*compare_item_func = compare_common_name; 
		}
		break; 
	default: 
		{

			ASSERT( "invalid param define type" && FALSE ); 
		}
	}
}

NTSTATUS get_param_define( param_define_type type, param_all_desc *param_input, param_define_item **item_found )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	common_hash_table *table; 
	PLIST_ENTRY list_found;
	calc_hash_code_callback hash_code_func; 
	compare_hash_table_item_callback compare_item_func; 
	//init_iteration_callback init_iterator_func; 
	//uninit_iteration_callback uninit_iterator_func; 
	//iterate_name_callback iterate_func; 
	PVOID param; 

	ASSERT( item_found != NULL ); 

	ntstatus = check_param_desc_valid( param_input ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		if( ntstatus == STATUS_PARAM_NO_MEANING )
		{
#ifdef DBG
			if( TRUE == is_must_meaningful_param( type ) )
			{
				ASSERT( FALSE && "why create the no meaning value for the must have meaning parameter" ); 
			}
#endif //DBG

			ntstatus = STATUS_SUCCESS; 
		}
		goto _return; 
	}

	//if( ntstatus == STATUS_PARAM_NO_MEANING )
	//{
	//	goto _return; 
	//}

	table = get_param_define_table( type ); 
	get_param_define_callback_and_param( param_input, type, &param, &hash_code_func, &compare_item_func ); 

	ntstatus = find_in_hash_table( param, NULL, NULL, NULL, hash_code_func, compare_item_func, table, &list_found ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return;
	}

	ASSERT( list_found != NULL ); 

	*item_found = ( param_define_item* )CONTAINING_RECORD( list_found, param_define_item, entry ); 
_return:
	return ntstatus; 
}

NTSTATUS get_class_param_define( param_define_type type, param_all_desc *param_input, param_define_item **item_found )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	common_hash_table *table; 
	calc_hash_code_callback hash_code_func; 
	compare_hash_table_item_callback compare_item_func; 
	PLIST_ENTRY list_found; 
	PVOID param; 

	ASSERT( param_input->is_cls == TRUE ); 

	ntstatus = check_param_desc_valid( param_input ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		if( ntstatus != STATUS_PARAM_NO_MEANING )
		{
			goto _return; 
		}

		ntstatus = STATUS_SUCCESS; 
	}

	//if( ntstatus == STATUS_PARAM_NO_MEANING )
	//{
	//	goto _return; 
	//}

	hash_code_func = calc_class_name_hash_code; 
	compare_item_func = compare_class_define; 
	param = ( PVOID )param_input->cls.class_name; 
	table = get_class_param_define_table( type ); 

	ntstatus = find_in_hash_table( param, NULL, NULL, NULL, hash_code_func, compare_item_func, table, &list_found ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return;
	}

	ASSERT( list_found != NULL ); 


	*item_found = ( param_define_item* )CONTAINING_RECORD( list_found, param_define_item, entry ); 

_return:
	return ntstatus; 
}

NTSTATUS get_rule_define( param_define_type type, 
						 access_rule_desc *rule_input, 
						 ULONG param_index, 
						 INT32 alloc_new, 
						 param_define_item **param )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	param_all_desc *param_desc; 
	//BOOLEAN is_cls;  

	ASSERT( is_valid_param_define_type( type ) ); 
	ASSERT( param_index < MAX_RULE_PARAM_NUM ); 
	ASSERT( param != NULL ); 

	*param = NULL; 

	ntstatus = get_rule_param_from_index( rule_input->type, &rule_input->desc, &param_desc, param_index ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	if( param_desc->type != type )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		log_trace( ( MSG_INFO, "the param of the rule %ws, respected type is %ws, but real type is %ws \n", 
			get_rule_type_desc( rule_input->type ), 
			get_param_type_desc( type ), 
			get_param_type_desc( param_desc->type ) ) ); 

		ASSERT( FALSE ); 
		goto _return; 
	}

	if( param_desc->is_cls == TRUE )
	{

		ntstatus = get_class_param_define( type, param_desc, param ); 
		if( !NT_SUCCESS( ntstatus ) )
		{
			if( alloc_new == TRUE )
			{
				ntstatus = add_class_param_define( type, ( param_other_desc* )&param_desc->cls, param ); 
				if( !NT_SUCCESS( ntstatus ) )
				{
					ASSERT( *param == NULL ); 
				}
				else
				{
					ASSERT( *param != NULL ); 
				}
			}
		}
	}
	else
	{
		ntstatus = get_param_define( type, param_desc, param ); 

		if( !NT_SUCCESS( ntstatus ) )
		{
			if( ntstatus == STATUS_NOT_FOUND )
			{
				if( alloc_new == TRUE )
				{
					ntstatus = add_common_param_define( type, ( param_define* )&param_desc->common, NULL, param ); 
				}

				if( !NT_SUCCESS( ntstatus ) )
				{
					ASSERT( *param == NULL ); 
				}

#ifdef DBG
				if( check_param_desc_valid( param_desc ) == STATUS_PARAM_NO_MEANING )
				{
					ASSERT( *param == NULL ); 
				}
#endif //DBG
			}
			goto _return; 
		}
	}

_return:
	return ntstatus; 
}

NTSTATUS pre_get_defines_of_rule( access_rule_desc *rule_input )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	if( rule_input->type == URL_RULE_TYPE )
	{
	}
	else if( rule_input->type == FILE_RULE_TYPE )
	{
	}
	else if( rule_input->type == COM_RULE_TYPE )
	{
	}
	else if( rule_input->type == REG_RULE_TYPE )
	{
	}
	else if( rule_input->type == SOCKET_RULE_TYPE )
	{
		if( rule_input->desc.socket.src_ip.ip.ip_begin == 0 
				&& rule_input->desc.socket.src_ip.ip.ip_end == 0 
				&& rule_input->desc.socket.src_port.port.port_begin == 0 
				&& rule_input->desc.socket.src_port.port.port_end == 0 
				&& rule_input->desc.socket.dest_ip.ip.ip_begin == 0 
				&& rule_input->desc.socket.dest_ip.ip.ip_end == 0 
				&& rule_input->desc.socket.dest_port.port.port_begin == 0 
				&& rule_input->desc.socket.dest_port.port.port_end == 0 )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			goto _return; 
		}
	}
	else if( rule_input->type == COMMON_RULE_TYPE )
	{
	}
	else 
	{
		ASSERT( "invalid action rule type" && FALSE ); 
	}

_return:
	return ntstatus; 
}

NTSTATUS _get_defines_of_rule( action_rule_define *rule, access_rule_desc *rule_input, INT32 auto_add )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	access_rule_type type; 

	ASSERT( rule_input != NULL ); 

	log_trace( ( MSG_INFO, "enter %s rule type is %ws\n", __FUNCTION__, get_rule_type_desc( rule_input->type ) ) ); 

	type = rule_input->type; 

	ntstatus = check_access_rule_input_valid( rule_input, FALSE ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		ASSERT( FALSE ); 
		goto _return; 
	}

	ntstatus = get_rule_define( APP_DEFINE, rule_input, 0, auto_add, &rule->common.app ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		ASSERT( ntstatus != STATUS_PARAM_NO_MEANING ); 
		goto _return; 
	}

#ifdef DBG
	//ASSERT( rule->socket.dest_ip != NULL ); 
	if( check_param_desc_valid( ( param_all_desc* )&rule_input->desc.common.app ) == STATUS_PARAM_NO_MEANING )
	{
		ASSERT( rule_input->desc.common.app.app.app_name[ 0 ] == L'\0' ); 
		ASSERT( rule->common.app == NULL ); 
	}
	else
	{
		ASSERT( rule->common.app != NULL ); 
	}
#endif //DBG

	switch( type )
	{
	case URL_RULE_TYPE:
		{
			ntstatus = get_rule_define( URL_DEFINE, rule_input, 1, auto_add, &rule->url.url ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				goto _return; 
			}
			ASSERT( rule->url.url != NULL ); 
		}
		break; 
	case FILE_RULE_TYPE:
		{
			ntstatus = get_rule_define( FILE_DEFINE, rule_input, 1, auto_add, &rule->file.file_path ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				goto _return; 
			}

			ASSERT( rule->file.file_path != NULL ); 
		}
		break; 
	case COM_RULE_TYPE:
		{
			ntstatus = get_rule_define( COM_DEFINE, rule_input, 1, auto_add, &rule->com.com_name ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				goto _return; 
			}
			ASSERT( rule->com.com_name != NULL ); 
		}
		break; 
	case REG_RULE_TYPE:
		{

			ntstatus = get_rule_define( REG_DEFINE, rule_input, 1, auto_add, &rule->reg.reg_path ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				goto _return; 
			}
			ASSERT( rule->reg.reg_path != NULL ); 
		}
		break; 
	case SOCKET_RULE_TYPE:
		{
			ntstatus = get_rule_define( IP_DEFINE, rule_input, 1, auto_add, &rule->socket.src_ip ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				ASSERT( ntstatus != STATUS_PARAM_NO_MEANING ); 
				goto _return; 
			}

#ifdef DBG
			if( check_param_desc_valid( ( param_all_desc* )&rule_input->desc.socket.src_ip ) == STATUS_PARAM_NO_MEANING )
			{
				ASSERT( rule_input->desc.socket.src_ip.ip.ip_begin == 0 
					&& rule_input->desc.socket.src_ip.ip.ip_end == 0 ); 
				ASSERT( rule->socket.src_ip == NULL ); 
			}
			else
			{
				ASSERT( rule->socket.src_ip != NULL ); 
			}
#endif //DBG

			ntstatus = get_rule_define( PORT_DEFINE, rule_input, 2, auto_add, &rule->socket.src_port ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				ASSERT( ntstatus != STATUS_PARAM_NO_MEANING ); 
				goto _return; 			
			}

#ifdef DBG
			//ASSERT( rule->socket.src_port != NULL ); 
			if( check_param_desc_valid( ( param_all_desc* )&rule_input->desc.socket.src_port ) == STATUS_PARAM_NO_MEANING )
			{
				ASSERT( rule_input->desc.socket.src_port.port.port_begin == 0 
					&& rule_input->desc.socket.src_port.port.port_end == 0 ); 
				ASSERT( rule->socket.src_port == NULL ); 
			}
			else
			{
				ASSERT( rule->socket.src_port != NULL ); 
			}
#endif //DBG

			ntstatus = get_rule_define( IP_DEFINE, rule_input, 3, auto_add, &rule->socket.dest_ip ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				ASSERT( ntstatus != STATUS_PARAM_NO_MEANING ); 
				goto _return; 

			}

#ifdef DBG
			//ASSERT( rule->socket.dest_ip != NULL ); 
			if( check_param_desc_valid( ( param_all_desc* )&rule_input->desc.socket.dest_ip ) == STATUS_PARAM_NO_MEANING )
			{
				ASSERT( rule_input->desc.socket.dest_ip.ip.ip_begin == 0 
					&& rule_input->desc.socket.dest_ip.ip.ip_end == 0 ); 
				ASSERT( rule->socket.dest_ip == NULL ); 
			}
			else
			{
				ASSERT( rule->socket.dest_ip != NULL ); 
			}
#endif //DBG

			ntstatus = get_rule_define( PORT_DEFINE, rule_input, 4, auto_add, &rule->socket.dest_port ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				ASSERT( ntstatus != STATUS_PARAM_NO_MEANING ); 
				goto _return; 

			}
			//ASSERT( rule->socket.dest_port != NULL ); 
			//if( ntstatus == STATUS_PARAM_NO_MEANING )
			//{
			//	ASSERT( rule_input->desc.socket.dest_port.port.port_begin == 0 
			//		&& rule_input->desc.socket.dest_port.port.port_end == 0 ); 
			//	ASSERT( rule->socket.dest_port == NULL ); 
			//}
			//else
			//{
			//	ASSERT( rule->socket.dest_port != NULL ); 
			//}
		}
		break; 
	case COMMON_RULE_TYPE:
		{
			ntstatus = get_rule_define( rule_input->desc.common.app.type, rule_input, 0, auto_add, &rule->common.app ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				ASSERT( ntstatus != STATUS_PARAM_NO_MEANING ); 
				goto _return; 
			}

			//if( ntstatus == STATUS_PARAM_NO_MEANING )
			//{
			//	ASSERT( rule_input->desc.common.app.app.app_name[ 0 ] == L'\0' ); 
			//	ASSERT( rule->common.app == NULL ); 
			//}
			//else
			//{
			//	ASSERT( rule->common.app != NULL ); 
			//}

			ntstatus = get_rule_define( rule_input->desc.common.param0.type, rule_input, 1, auto_add, &rule->common.param0 ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				ASSERT( ntstatus != STATUS_PARAM_NO_MEANING ); 
				goto _return; 
			}

			//ASSERT( rule->common.param0 != NULL ); 
			//if( ntstatus == STATUS_PARAM_NO_MEANING )
			//{
			//	ASSERT( rule_input->desc.common.param0.common.name[ 0 ] == L'\0' ); 
			//	ASSERT( rule->common.param0 == NULL ); 
			//}
			//else
			//{
			//	ASSERT( rule->common.param0 != NULL ); 
			//}


			//ntstatus = get_rule_define( rule_input->desc.common.param1.type, rule_input, 2, auto_add, &rule->common.param1 ); 
			//if( !NT_SUCCESS( ntstatus ) )
			//{
			//	goto _return; 
			//}
			////ASSERT( rule->common.param1 != NULL ); 
			//if( ntstatus == STATUS_SUCCESS_NOT_NEED_CONTINUE )
			//{
			//	ASSERT( rule_input->desc.common.param1.common.name[ 0 ] == L'\0' ); 
			//	ASSERT( rule->common.param1 == NULL ); 
			//}
			//else
			//{
			//	ASSERT( rule->common.param1 != NULL ); 
			//}

			//ntstatus = get_rule_define( rule_input->desc.common.param2.type, rule_input, 3, auto_add, &rule->common.param2 ); 
			//if( !NT_SUCCESS( ntstatus ) )
			//{
			//	goto _return; 
			//}
			////ASSERT( rule->common.param2 != NULL ); 
			//if( ntstatus == STATUS_SUCCESS_NOT_NEED_CONTINUE )
			//{
			//	ASSERT( rule_input->desc.common.param2.common.name[ 0 ] == L'\0' ); 
			//	ASSERT( rule->common.param2 == NULL ); 
			//}
			//else
			//{
			//	ASSERT( rule->common.param2 != NULL ); 
			//}

			//ntstatus = get_rule_define( rule_input->desc.common.param3.type, rule_input, 4, auto_add, &rule->common.param3 ); 
			//if( !NT_SUCCESS( ntstatus ) )
			//{
			//	goto _return; 
			//}
			////ASSERT( rule->common.param3 != NULL ); 
			//if( ntstatus == STATUS_SUCCESS_NOT_NEED_CONTINUE )
			//{
			//	ASSERT( rule_input->desc.common.param3.common.name[ 0 ] == L'\0' ); 
			//	ASSERT( rule->common.param3 == NULL ); 
			//}
			//else
			//{
			//	ASSERT( rule->common.param3 != NULL ); 
			//}
		}
		break; 
	default: 
		{
			ASSERT( "invalid action rule type" && FALSE ); 
			ntstatus = STATUS_INVALID_PARAMETER; 
		}
	}

_return:

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 

	return ntstatus; 
}

common_hash_table *get_action_rule_table( access_rule_type type )
{
	common_hash_table *table; 

	ASSERT( is_valid_access_rule_type( type ) ); 

	table = &all_action_rule[ type ]; 

	return table; 
}

common_hash_table *get_response_record_table( access_rule_type type )
{
	common_hash_table *table; 

	ASSERT( is_valid_access_rule_type( type ) ); 

	table = &all_action_response[ type ]; 

	return table; 
}

#define NAME_PARAM_INDEX 1
INLINE ULONG calc_name_rule_hash_code( PVOID param, ULONG table_size )
{
	ULONG hash_code; 
	action_desc *desc; 
	ASSERT( param != NULL ); 

	desc = ( action_desc* )param; 
	hash_code = unicode_str_hash( desc->common.param0.common.name, table_size ); 

	return hash_code; 
}

ULONG CALLBACK calc_url_rule_hash_code( PVOID param, ULONG table_size )
{
	ULONG hash_code; // = 0; 
	action_desc *desc; 

	ASSERT( param != NULL ); 

	desc = ( action_desc* )param; 

	hash_code = calc_url_name_hash_code( desc->url.url.url.url, table_size ); 

	goto _return; 
_return:
	return hash_code; 
}

ULONG CALLBACK calc_socket_rule_hash_code( PVOID param, ULONG table_size )
{
	ULONG hash_code; 
	action_desc *desc; 
	ASSERT( param != NULL ); 

	desc = ( action_desc* )param; 

	hash_code = long_hash( ( ULONG )desc->socket.dest_ip.ip.ip_begin, table_size ); 

	return hash_code; 
}

ULONG CALLBACK calc_file_rule_hash_code( PVOID param, ULONG table_size )
{
	return calc_name_rule_hash_code( param, table_size ); 
}

ULONG CALLBACK calc_reg_rule_hash_code( PVOID param, ULONG table_size )
{
	return calc_name_rule_hash_code( param, table_size ); 
}

ULONG CALLBACK calc_com_rule_hash_code( PVOID param, ULONG table_size )
{
	return calc_name_rule_hash_code( param, table_size ); 
}

ULONG CALLBACK calc_common_rule_hash_code( PVOID param, ULONG table_size )
{
	return calc_name_rule_hash_code( param, table_size ); 
}

NTSTATUS _add_action_rule( access_rule_desc *rule_input, action_rule_item *rule_add )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG hash_code; 
	common_hash_table *table; 

	ASSERT( rule_add != NULL ); 
	ASSERT( is_valid_access_rule_type( rule_add->rule.type ) ); 
	ASSERT( is_rbtree_link_rule( rule_add->rule.type ) == FALSE ); 

	table = get_action_rule_table( rule_add->rule.type ); 

	switch( rule_input->type )
	{
	case URL_RULE_TYPE: 
		hash_code = calc_url_rule_hash_code( &rule_input->desc, table->size ); 
		if( hash_code == INVALID_HASH_CODE )
		{
			ASSERT( FALSE && "generate invalid hash code" ); 
			ntstatus = STATUS_INVALID_PARAMETER; 
			goto _return; 
		}
		ASSERT( hash_code < table->size ); 

		break; 
	case SOCKET_RULE_TYPE: 
		hash_code = calc_socket_rule_hash_code( &rule_input->desc, table->size ); 
		break; 
	case FILE_RULE_TYPE: 
		hash_code = calc_file_rule_hash_code( &rule_input->desc, table->size ); 
		break; 
	case REG_RULE_TYPE: 
		hash_code = calc_reg_rule_hash_code( &rule_input->desc, table->size ); 
		break; 
	case COM_RULE_TYPE: 
		hash_code = calc_com_rule_hash_code( &rule_input->desc, table->size ); 
		break; 
	case COMMON_RULE_TYPE: 
		hash_code = calc_common_rule_hash_code( &rule_input->desc, table->size ); 
		break; 
	}

	insert_to_hash_table( table, hash_code, &rule_add->entry ); 
	
	ASSERT( rule_add->ref_count == 0 ); 
	rule_add->ref_count ++; 

_return:
	return ntstatus; 
} 

NTSTATUS _add_action_rule_lock_free( access_rule_desc *rule_input, action_rule_item *rule_add )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG hash_code; 
	common_hash_table *table; 

	ASSERT( rule_add != NULL ); 
	ASSERT( is_valid_access_rule_type( rule_add->rule.type ) ); 
	ASSERT( is_rbtree_link_rule( rule_add->rule.type ) == FALSE ); 

	table = get_action_rule_table( rule_add->rule.type ); 

	switch( rule_input->type )
	{
	case URL_RULE_TYPE: 
		hash_code = calc_url_rule_hash_code( &rule_input->desc, table->size ); 
		if( hash_code == INVALID_HASH_CODE )
		{
			ASSERT( FALSE && "generate invalid hash code" ); 
			ntstatus = STATUS_INVALID_PARAMETER; 
			goto _return; 
		}
		ASSERT( hash_code < table->size ); 

		break; 
	case SOCKET_RULE_TYPE: 
		hash_code = calc_socket_rule_hash_code( &rule_input->desc, table->size ); 
		break; 
	case FILE_RULE_TYPE: 
		hash_code = calc_file_rule_hash_code( &rule_input->desc, table->size ); 
		break; 
	case REG_RULE_TYPE: 
		hash_code = calc_reg_rule_hash_code( &rule_input->desc, table->size ); 
		break; 
	case COM_RULE_TYPE: 
		hash_code = calc_com_rule_hash_code( &rule_input->desc, table->size ); 
		break; 
	case COMMON_RULE_TYPE: 
		hash_code = calc_common_rule_hash_code( &rule_input->desc, table->size ); 
		break; 
	}

	insert_to_hash_table_lock_free( table, hash_code, &rule_add->entry ); 

	ASSERT( rule_add->ref_count == 0 ); 
	rule_add->ref_count ++; 

_return:
	return ntstatus; 
} 

NTSTATUS pre_process_record_rule( access_rule_desc *rule_input, sys_action_type action_type )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		if( action_type == NET_connect 
			|| action_type == NET_send )
		{
			rule_input->desc.socket.src_port.port.port_begin = 0; 
			rule_input->desc.socket.src_port.port.port_end = 0xffff; 

			//rule_input->desc.socket.src_ip.ip.ip_begin = 0; 
			//rule_input->desc.socket.src_ip.ip.ip_end = 0; 
		}
		else if( action_type == NET_accept 
			|| action_type == NET_recv )
		{
			rule_input->desc.socket.dest_port.port.port_begin = 0; 
			rule_input->desc.socket.dest_port.port.port_end = 0xffff; 
		}
	} while ( FALSE );

	return ntstatus; 
}

NTSTATUS pre_process_record_action( sys_action_desc *action )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		if( action->type == NET_connect 
			|| action->type == NET_send )
		{
			action->desc.socket.src_port.port.port_begin = 0; 
			action->desc.socket.src_port.port.port_end = 0; 

			//rule_input->desc.socket.src_ip.ip.ip_begin = 0; 
			//rule_input->desc.socket.src_ip.ip.ip_end = 0; 
		}
		else if( action->type == NET_accept 
			|| action->type == NET_recv )
		{
			action->desc.socket.dest_port.port.port_begin = 0; 
			action->desc.socket.dest_port.port.port_end = 0; 
		}
	} while ( FALSE );

	return ntstatus; 
}

NTSTATUS input_action_rule_from_desc( sys_action_desc *sys_action, ULONG flags )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	access_rule_desc *rule_input = NULL; 

	log_trace( ( MSG_INFO, "enter %s \n", __FUNCTION__ ) ); 

	rule_input = ( access_rule_desc* )ALLOC_TAG_POOL( sizeof( access_rule_desc ) ); 
	if( rule_input == NULL )
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		goto _return; 
	}

	rule_input->resp = sys_action->resp; 
	rule_input->type = acl_type( sys_action->type ); 

	ntstatus = init_access_rule( rule_input->type, rule_input ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	ntstatus = copy_params( rule_input->type, &sys_action->desc, &rule_input->desc ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	ntstatus = pre_process_record_rule( rule_input, sys_action->type ); 
	
	if( ntstatus != STATUS_SUCCESS )
	{
		goto _return; 
	}

	//ntstatus = correct_params_of_rule( rule_input ); 
	//if( !NT_SUCCESS( ntstatus ) )
	//{
	//	
	//}

	ntstatus = add_action_rule( rule_input, flags );

_return:

	if( rule_input != NULL )
	{
		FREE_TAG_POOL( rule_input );  
	}

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 
	return ntstatus; 
}

INT32 compare_name_define( LPCWSTR define_name, LPCWSTR check_name )
{
	INT32 ret = FALSE; 
	INT32 _ret; 

	if( define_name[ 0 ] == L'\0' 
		|| check_name[ 0 ] == L'\0' )
	{
		ret = TRUE; 
		goto _return; 
	}

	_ret = compare_define_name_no_case( define_name, check_name ); 
	if( _ret == 0 )
	{
		ret = TRUE; 
		goto _return; 
	}

_return:
	return ret;
}

INT32 compare_url_define( LPCWSTR url_param, LPCWSTR url )
{
	INT32 ret = FALSE; 
	INT32 _ret; 
	LPCWSTR _domain_name; 
	ULONG _domain_name_len; 

	if( url[ 0 ] == L'\0' 
		|| url_param[ 0 ] == L'\0' )
	{
		ret = TRUE; 
		goto _return; 
	}

	if( !NT_SUCCESS( get_domain_name_in_url( url, &_domain_name, &_domain_name_len ) ) )
	{
		ASSERT( FALSE ); 
		goto _return; 
	}

	_ret = compare_define_name_no_case_len_by_dest( url_param, _domain_name, _domain_name_len ); 
	if( _ret == 0 )
	{
		ret = TRUE; 
		goto _return; 
	}

_return:
	return ret;
}

INT32 compare_whole_path_define_name_no_case( LPCWSTR define_name, LPCWSTR name_compare )
{
	INT32 ret; 

	while( *( name_compare )!= L'\0' || *( define_name ) != L'\0' )
	{
		ASSERT( *define_name < 'a' || *define_name > 'z' ); 

		if( *name_compare >= 'a' && *name_compare <= 'z' )
		{
			if( *define_name != *name_compare + 'A' - 'a' )
			{
				break; 
			}
		}
		else
		{
			if( *define_name != *name_compare )
			{
				break; 
			}
		}

		name_compare ++; 
		define_name ++; 
	}

	if( *define_name == L'\0' )
	{
		if( *name_compare == L'\\' 
			|| *name_compare == L'/' )
		{
			name_compare ++; 
		}
	}

	if( *name_compare != L'\0' || *define_name != L'\0' )
	{
		ret = *name_compare - *define_name; 
	}
	else 
	{
		ret = 0; 
	}

	return ret; 
}

INT32 compare_while_path_define( LPCWSTR define_name, LPCWSTR check_name )
{
	INT32 ret = FALSE; 
	INT32 _ret; 

	if( define_name[ 0 ] == L'\0' 
		|| check_name[ 0 ] == L'\0' )
	{
		ret = TRUE; 
		goto _return; 
	}

	_ret = compare_whole_path_define_name_no_case( define_name, check_name ); 
	if( _ret == 0 )
	{
		ret = TRUE; 
		goto _return; 
	}

_return:
	return ret;
}

INT32 compare_path_define( LPWSTR define_name, LPWSTR check_name )
{
	INT32 ret = TRUE; 
	INT32 _ret; 

	if( define_name[ 0 ] != L'\0' )
	{
		_ret = compare_define_path_no_case( define_name, check_name ); 
		if( _ret != 0 )
		{
			ret = FALSE; 
			goto _return; 
		}
	}

_return:
	return ret;
}

INT32 CALLBACK compare_reg_rule( PVOID param, PLIST_ENTRY list_item, PVOID param_iteration )
{
	INT32 ret = TRUE; 
	action_desc *params; 
	action_rule_item *rule_item; 

	ASSERT( param != NULL ); 
	ASSERT( list_item != NULL ); 

	log_trace( ( MSG_INFO, "enter %s \n", __FUNCTION__ ) ); 
	rule_item = CONTAINING_RECORD( list_item, action_rule_item, entry ); 

	params = ( action_desc* )param; 

	ASSERT( rule_item->rule.rule.reg.reg_path != NULL ); 

	if( rule_item->rule.rule.reg.app != NULL )
	{
		log_trace( ( MSG_INFO, "record app name is %ws cur action app name is %ws \n", rule_item->rule.rule.reg.app->param.app.app_name, params->reg.app.app.app_name ) ); 

		ret = compare_name_define( rule_item->rule.rule.reg.app->param.app.app_name, 
			params->reg.app.app.app_name ); 

		if( ret == FALSE )
		{
			goto _return; 
		}
	}

	if( rule_item->rule.rule.reg.reg_path->param.reg.reg_path[ 0 ] == L'\0' 
		|| params->reg.reg_path.reg.reg_path[ 0 ] == L'\0' )
	{
		ASSERT( FALSE ); 
		log_trace( ( MSG_INFO, "*** check reg rule, but the reg path is null! ( rule 0x%0.8x ( %ws ), check 0x%0.8x ( %ws ) ) *** \n", 
			rule_item->rule.rule.reg.reg_path->param.reg.reg_path, 
			rule_item->rule.rule.reg.reg_path->param.reg.reg_path, 
			params->reg.reg_path.reg.reg_path, 
			params->reg.reg_path.reg.reg_path ) ); 
		goto _return; 
	}
	else
	{
		//ULONG name_len; 
		log_trace( ( MSG_INFO, "record registry path is %ws compare with %ws, iteration name is %ws\n", rule_item->rule.rule.reg.reg_path->param.reg.reg_path, 
			params->reg.reg_path.reg.reg_path, 
			( LPWSTR )param_iteration ) ); 

		//name_len = wcsnlen( params->reg.reg_path.reg.reg_path, _MAX_REG_PATH_LEN ); 
		//ASSERT( name_len < _MAX_REG_PATH_LEN ); 

		//if( params->reg.reg_path.reg.reg_path[ name_len - 1 ] == L'\\' 
		//	|| params->reg.reg_path.reg.reg_path[ name_len - 1 ] == L'/' )
		//{
		//	params->reg.reg_path.reg.reg_path[ name_len - 1 ] = L'\0';  
		//}

		if( param_iteration != NULL )
		{
			ret = compare_name_define( rule_item->rule.rule.reg.reg_path->param.reg.reg_path, ( LPWSTR )param_iteration ); 

		}
		else
		{
			ret = compare_name_define( rule_item->rule.rule.reg.reg_path->param.reg.reg_path, params->reg.reg_path.reg.reg_path ); 
		}

		if( ret == FALSE )
		{
			goto _return; 
		}
	}

_return: 
	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ret ) ); 
	return ret; 
}

INT32 CALLBACK compare_com_rule( PVOID param, PLIST_ENTRY list_item, PVOID param_iteration )
{
	INT32 ret = TRUE; 
	action_desc *params; 
	action_rule_item *rule_item; 

	ASSERT( param != NULL ); 
	ASSERT( list_item != NULL ); 

	rule_item = ( action_rule_item* )CONTAINING_RECORD( list_item, action_rule_item, entry ); 

	params = ( action_desc* )param; 

	ASSERT( rule_item->rule.rule.com.com_name != NULL ); 

	if( rule_item->rule.rule.com.app != NULL )
	{
		ret = compare_name_define( rule_item->rule.rule.com.app->param.app.app_name, 
			params->com.app.app.app_name ); 
		if( ret == FALSE )
		{
			goto _return; 
		}
	}

	if( rule_item->rule.rule.com.com_name->param.com.com_name[ 0 ] == L'\0' 
		|| params->com.com.app.app_name[ 0 ] == L'\0' )
	{
		log_trace( ( MSG_INFO, "*** check reg rule, but the reg path is null! ( rule 0x%0.8x ( %ws ), check 0x%0.8x ( %ws ) ) *** \n", 
			rule_item->rule.rule.com.com_name->param.com.com_name, 
			rule_item->rule.rule.com.com_name->param.com.com_name, 
			params->com.com.app.app_name, 
			params->com.com.app.app_name ) ); 
		goto _return; 
	}
	else
	{
		ret = compare_name_define( rule_item->rule.rule.com.com_name->param.com.com_name, params->com.com.app.app_name ); 
		if( ret == FALSE  )
		{
			goto _return; 
		}
	}

_return:
	return ret; 
}

INT32 CALLBACK compare_file_rule( PVOID param, PLIST_ENTRY list_item, PVOID param_iteration )
{
	INT32 ret = TRUE; 
	action_desc *params; 
	action_rule_item *rule_item; 

	log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

	ASSERT( param != NULL ); 
	ASSERT( list_item != NULL ); 

	rule_item = ( action_rule_item* )CONTAINING_RECORD( list_item, action_rule_item, entry ); 

	params = ( action_desc* )param; 

	ASSERT( rule_item->rule.rule.file.file_path != NULL ); 

	if( rule_item->rule.rule.file.app != NULL )
	{
		log_trace( ( MSG_INFO, "record file name is %ws action file name is %ws \n", rule_item->rule.rule.app.app->param.app.app_name, params->file.app.app.app_name ) ); 

		ret = compare_name_define( rule_item->rule.rule.file.app->param.app.app_name, 
			params->file.app.app.app_name ); 
		if( ret == FALSE )
		{
			goto _return; 
		}
	}

	if( rule_item->rule.rule.file.file_path->param.file.file_path[ 0 ] == L'\0' 
		|| params->file.file_path.file.file_path[ 0 ] == L'\0' )
	{
		ASSERT( FALSE ); 
		log_trace( ( MSG_INFO, "*** check reg rule, but the reg path is null! ( rule 0x%0.8x ( %ws ), check 0x%0.8x ( %ws ) ) *** \n", 
			rule_item->rule.rule.file.file_path->param.file.file_path, 
			rule_item->rule.rule.file.file_path->param.file.file_path, 
			params->file.file_path.file.file_path, 
			params->file.file_path.file.file_path ) ); 
		goto _return; 
	}
	else
	{
		log_trace( ( MSG_INFO, "record file name is %ws action file name is %ws \n", rule_item->rule.rule.file.file_path->param.file.file_path, 
			params->file.file_path.file.file_path ) ); 

		if( param_iteration != NULL )
		{
			ret = compare_name_define( rule_item->rule.rule.file.file_path->param.file.file_path, ( LPWSTR )param_iteration ); 

		}
		else
		{
			ret = compare_name_define( rule_item->rule.rule.file.file_path->param.file.file_path, params->file.file_path.file.file_path ); 
		}
	}

	//ASSERT( params->type == rule_item->rule.type ); 

_return:
	log_trace( ( MSG_INFO, "enter %s 0x%0.8x\n", __FUNCTION__, ret ) ); 
	return ret; 
}

INT32 _compare_socket_info( action_rule_define *socket_define, action_desc *socket )
{
	INT32 ret = FALSE; 
	//INT32 _is_greater = FALSE; 

	ASSERT( socket != NULL 
		&& socket_define != NULL ); 

	//ASSERT( is_greater != NULL ); 

#define INVALID_IP 0 

	if( socket_define->socket.dest_ip != NULL )
	{
		//if( socket->socket.dest_ip.ip.ip_begin > socket_define->socket.dest_ip->param.ip.ip_begin )
		//{
		//	_is_greater = TRUE;
		//}
		//else
		//{
		//	_is_greater = FALSE; 
		//}

		ret = compare_value_region_define( ( ULONG )socket->socket.dest_ip.ip.ip_begin, 
			( ULONG )socket->socket.dest_ip.ip.ip_end, 
			( ULONG )socket_define->socket.dest_ip->param.ip.ip_begin, 
			( ULONG )socket_define->socket.dest_ip->param.ip.ip_end ); 

		if( ret == FALSE )
		{
			goto _return; 
		}
	}
	//else
	//{
	//	if( socket->socket.dest_ip.ip.ip_begin > 0 )
	//	{
	//		_is_greater = TRUE;
	//	}
	//	else
	//	{
	//		_is_greater = FALSE; 
	//	}
	//}

	if( socket_define->socket.src_ip != NULL )
	{
		ret = compare_value_region_define( ( ULONG )socket->socket.src_ip.ip.ip_begin, 
			( ULONG )socket->socket.src_ip.ip.ip_end, 
			( ULONG )socket_define->socket.src_ip->param.ip.ip_begin, 
			( ULONG )socket_define->socket.src_ip->param.ip.ip_end ); 
		if(  ret == FALSE  )
		{
			goto _return; 
		}
	}

	if( socket_define->socket.src_port != NULL )
	{
		ret = compare_value_region_define( socket->socket.src_port.port.port_begin, 
			socket->socket.src_port.port.port_end, 
			socket_define->socket.src_port->param.port.port_begin, 
			socket_define->socket.src_port->param.port.port_end ); 
		if( ret == FALSE )
		{
			goto _return; 
		}
	}

	if( socket_define->socket.dest_port != NULL )
	{
		ret = compare_value_region_define( socket->socket.dest_port.port.port_begin, 
			socket->socket.dest_port.port.port_end, 
			socket_define->socket.dest_port->param.port.port_begin, 
			socket_define->socket.dest_port->param.port.port_end ); 
		if( ret == FALSE )
		{
			goto _return; 
		}
	}

	ret = TRUE; 

_return:
	return ret; 
}

INT32 CALLBACK compare_socket_rule( PVOID param, PLIST_ENTRY list_item, PVOID param_iteration )
{
	INT32 ret = TRUE; 
	action_desc *params; 
	action_rule_item *rule_item; 

	ASSERT( param != NULL ); 
	ASSERT( list_item != NULL ); 

	rule_item = CONTAINING_RECORD( list_item, action_rule_item, entry ); 

	params = ( action_desc* )param; 

	ASSERT( rule_item->rule.rule.socket.dest_ip != NULL 
		|| rule_item->rule.rule.socket.dest_port != NULL 
		|| rule_item->rule.rule.socket.src_ip != NULL 
		|| rule_item->rule.rule.socket.src_port != NULL ); 

	if( rule_item->rule.rule.socket.app != NULL )
	{
		ret = compare_name_define( rule_item->rule.rule.socket.app->param.app.app_name, 
			params->socket.app.app.app_name ); 

		if( ret == FALSE )
		{
			goto _return; 
		}
	}

	ret = _compare_socket_info( &rule_item->rule.rule, params ); 

_return:
	return ret; 
}

INT32 CALLBACK compare_common_rule( PVOID param, PLIST_ENTRY list_item, PVOID param_iteration )
{
	INT32 ret = TRUE; 
	action_desc *params; 
	action_rule_item *rule_item; 

	ASSERT( param != NULL ); 
	ASSERT( list_item != NULL ); 

	rule_item = CONTAINING_RECORD( list_item, action_rule_item, entry ); 

	params = ( action_desc* )param; 

	ASSERT( rule_item->rule.rule.common.app != NULL 
		|| rule_item->rule.rule.common.param0 != NULL 
		|| rule_item->rule.rule.common.param1 != NULL 
		|| rule_item->rule.rule.common.param2 != NULL 
		|| rule_item->rule.rule.common.param3 != NULL ); 

	if( rule_item->rule.rule.common.action_type != params->common.action_type )
	{
		ret = FALSE; 
		goto _return; 
	}

	if( rule_item->rule.rule.common.app != NULL )
	{
		ret = compare_name_define( rule_item->rule.rule.reg.app->param.app.app_name, 
			params->reg.app.app.app_name ); 
		if( ret == FALSE )
		{
			goto _return; 
		}
	}

	if( rule_item->rule.rule.common.param0 != NULL )
	{
		ret = compare_name_define( rule_item->rule.rule.common.param0->param.common.name, 
			params->common.param0.common.name ); 
		if( ret == FALSE )
		{
			goto _return; 
		}
	}

_return:
	return ret; 
}

INT32 CALLBACK compare_url_rule( PVOID param, PLIST_ENTRY list_item, PVOID param_iteration )
{
	INT32 ret = TRUE; 
	action_desc *params; 
	action_rule_item *rule_item; 

	ASSERT( param != NULL ); 
	ASSERT( list_item != NULL ); 

	rule_item = CONTAINING_RECORD( list_item, action_rule_item, entry ); 

	params = ( action_desc* )param; 

	if( params == NULL )
	{
		DBG_BP(); 
	}

	if( rule_item == NULL || rule_item->rule.rule.url.url == NULL )
	{
		DBG_BP(); 
	}

	if( rule_item->rule.rule.socket.app!= NULL )
	{
		ret = compare_name_define( rule_item->rule.rule.url.app->param.app.app_name, 
			params->url.app.app.app_name ); 
		if( ret == FALSE )
		{
			goto _return; 
		}
	}

	ASSERT( rule_item->rule.rule.url.url != NULL ); 

	if( rule_item->rule.rule.url.url->param.url.url[ 0 ] == L'\0' 
		|| params->url.url.url.url[ 0 ] == L'\0' )
	{
		log_trace( ( MSG_INFO, "*** check reg rule, but the reg path is null! ( rule 0x%0.8x ( %ws ), check 0x%0.8x ( %ws ) ) *** \n", 
			rule_item->rule.rule.url.url->param.url.url, 
			rule_item->rule.rule.url.url->param.url.url, 
			params->url.url.url.url, 
			params->url.url.url.url ) ); 
		goto _return; 
	}
	else
	{
		ret = compare_url_define( rule_item->rule.rule.url.url->param.url.url, params->url.url.url.url ); 
		if( ret == FALSE )
		{
			goto _return; 
		}
	}

_return:
	return ret; 
}

NTSTATUS CALLBACK no_interate( PVOID param, PVOID *param_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ASSERT( param != NULL ); 
	ASSERT( param_out != NULL ); 

	*param_out = NULL; 

	return ntstatus; 
}

NTSTATUS CALLBACK init_name_iteration( PVOID param, PULONG hash_code, ULONG tbl_size, PVOID *param_out, PVOID *context )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	LPWSTR name; 
	ULONG _hash_code; 
	action_desc *desc; 
	ULONG name_len; 
	fs_style_interator *fs_style_path_iter = NULL; 

	ASSERT( context != NULL ); 
	ASSERT( tbl_size > 0 ); 
	ASSERT( hash_code != NULL ); 

	if( param_out == NULL )
	{
		ASSERT( FALSE ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}; 

	if( param == NULL )
	{
		ASSERT( FALSE ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	*param_out = NULL; 
	*context = NULL; 
	*hash_code = INVALID_HASH_CODE; 

	//if( ( buf_len % 2 ) != 0 )
	//{
	//	ASSERT( FALSE ); 
	//	log_trace( ( MSG_WARNING, "buffer length is not wide char size aligned\n" ) ); 
	//}

	desc = ( action_desc* )param; 

	name = ( LPWSTR )desc->common.param0.common.name; 

	//if( name[ buf_len / sizeof( WCHAR ) ] != L'\0' )
	//{
	//	name[ buf_len / sizeof( WCHAR ) ] = L'\0'; 
	//}

	name_len = wcslen( name ); 

	fs_style_path_iter = ( fs_style_interator* )ALLOC_TAG_POOL( sizeof( fs_style_interator ) ); 
	if( fs_style_path_iter == NULL )
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		goto _return; 
	}

	fs_style_path_iter->index = name_len; 
	fs_style_path_iter->length = name_len + 1; 
	fs_style_path_iter->org_path = NULL; 
	fs_style_path_iter->iterator = NULL; 

	fs_style_path_iter->org_path = ( LPWSTR )ALLOC_TAG_POOL( ( ( name_len + 1 )* sizeof( WCHAR ) ) * 2 ) ; 
	
	if( fs_style_path_iter->org_path == NULL )
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		goto _return; 
	}

	fs_style_path_iter->iterator = ( LPWSTR )fs_style_path_iter->org_path + name_len + 1; 

	memcpy( ( PVOID )fs_style_path_iter->org_path, name, ( name_len + 1 ) * sizeof( WCHAR ) ); 
	memcpy( fs_style_path_iter->iterator, name, ( name_len + 1 ) * sizeof( WCHAR ) ); 

	unicode_str_to_upper( fs_style_path_iter->iterator ); 

	if( fs_style_path_iter->org_path[ name_len - 1 ] == PATH_DELIM )
	{
		( ( LPWSTR )fs_style_path_iter->org_path )[ name_len - 1 ] = L'\0'; 
	}

	if( fs_style_path_iter->iterator[ name_len - 1 ] == PATH_DELIM )
	{
		fs_style_path_iter->iterator[ name_len - 1 ] = L'\0'; 
	}

	_hash_code = unicode_str_hash( fs_style_path_iter->iterator, tbl_size ); 
	*param_out = fs_style_path_iter->iterator; 
	*context = ( PVOID )fs_style_path_iter; 
	*hash_code = _hash_code; 

_return:
	return ntstatus; 
}

NTSTATUS CALLBACK uninit_name_iteration( PVOID context )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	fs_style_interator *fs_style_path_iter; 

	ASSERT( context != NULL ); 

	fs_style_path_iter = ( fs_style_interator* )context; 
	if( fs_style_path_iter->org_path != NULL )
	{
		FREE_TAG_POOL( ( PVOID )fs_style_path_iter->org_path ); 
	}
	else
	{
		ASSERT( FALSE && "uninitialize a not initialized fs tyle name iterator" ); 
	}

	FREE_TAG_POOL( fs_style_path_iter ); 

	return ntstatus; 
}

NTSTATUS CALLBACK iterate_fs_style_path( PVOID param, PULONG hash_code, ULONG tbl_size, PVOID *param_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	fs_style_interator *reg_path_iter; 
	ULONG _hash_code; 

	//ASSERT( param != NULL ); 
	ASSERT( param_out != NULL ); 
	ASSERT( hash_code != NULL ); 
	ASSERT( tbl_size > 0 ); 

	if( param == NULL )
	{
		ASSERT( FALSE ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	*param_out = NULL; 
	*hash_code = 0; 

	reg_path_iter = ( fs_style_interator* )param; 

	if( reg_path_iter->index <= 1 )
	{
		ASSERT( reg_path_iter->index >= 1 ); 

		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

#ifdef DBG
	if( reg_path_iter->index == reg_path_iter->length - 1 )
	{
		ASSERT( reg_path_iter->iterator[ reg_path_iter->index - 1 ] != PATH_DELIM ); 
	}
	else
	{
		ASSERT( reg_path_iter->iterator[ reg_path_iter->index - 1 ] == L'\0' ); 
	}
#endif //DBG

	for( ; ; )
	{
		if( reg_path_iter->iterator[ reg_path_iter->index - 1 ] == PATH_DELIM )
		{
			reg_path_iter->iterator[ reg_path_iter->index - 1 ] = L'\0'; 
			break; 
		}

		if( reg_path_iter->index == 2 )
		{
			ntstatus = STATUS_UNSUCCESSFUL; 
			goto _return; 
		}

		reg_path_iter->index --; 
	}

	*param_out = reg_path_iter->iterator; 
	_hash_code = unicode_str_hash( reg_path_iter->iterator, tbl_size ); 
	*hash_code = _hash_code; 

_return:
	return ntstatus; 
}


#define DOMAIN_NAME_DELIM_UNICODE L'.'
#define DOMAIN_NAME_DELIM '.'

NTSTATUS CALLBACK init_url_iteration( PVOID param, PULONG hash_code, ULONG tbl_size, PVOID *param_out, PVOID *context )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	LPWSTR name; 
	ULONG _hash_code; 
	action_desc *desc; 
	ULONG name_len; 
	fs_style_interator *fs_style_path_iter = NULL; 

	ASSERT( context != NULL ); 
	ASSERT( tbl_size > 0 ); 
	ASSERT( hash_code != NULL ); 

	if( param_out == NULL )
	{
		ASSERT( FALSE ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}; 

	if( param == NULL )
	{
		ASSERT( FALSE ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	*param_out = NULL; 
	*context = NULL; 
	*hash_code = INVALID_HASH_CODE; 

	//if( ( buf_len % 2 ) != 0 )
	//{
	//	ASSERT( FALSE ); 
	//	log_trace( ( MSG_WARNING, "buffer length is not wide char size aligned\n" ) ); 
	//}

	desc = ( action_desc* )param; 

	ntstatus = parse_url_param( ( param_all_desc* )&desc->url.url ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	name = ( LPWSTR )desc->url.url.url.url + desc->url.url.url.domain_name_off; 

	//if( name[ buf_len / sizeof( WCHAR ) ] != L'\0' )
	//{
	//	name[ buf_len / sizeof( WCHAR ) ] = L'\0'; 
	//}

	name_len = desc->url.url.url.domain_name_len; 

	fs_style_path_iter = ( fs_style_interator* )ALLOC_TAG_POOL( sizeof( fs_style_interator ) ); 
	if( fs_style_path_iter == NULL )
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		goto _return; 
	}

	fs_style_path_iter->index = 0; 
	fs_style_path_iter->length = name_len + 1; 
	fs_style_path_iter->org_path = NULL; 
	fs_style_path_iter->iterator = NULL; 

	fs_style_path_iter->org_path = ( LPWSTR )ALLOC_TAG_POOL( ( ( name_len + 1 )* sizeof( WCHAR ) ) * 2 ) ; 

	if( fs_style_path_iter->org_path == NULL )
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		goto _return; 
	}

	fs_style_path_iter->iterator = ( LPWSTR )fs_style_path_iter->org_path + name_len + 1; 

	memcpy( ( PVOID )fs_style_path_iter->org_path, name, ( name_len + 1 ) * sizeof( WCHAR ) ); 
	memcpy( fs_style_path_iter->iterator, name, ( name_len + 1 ) * sizeof( WCHAR ) ); 

	( ( LPWSTR )fs_style_path_iter->org_path )[ name_len ] = L'\0'; 
	fs_style_path_iter->iterator[ name_len ] = L'\0'; 

	unicode_str_to_upper( fs_style_path_iter->iterator ); 

	if( fs_style_path_iter->org_path[ name_len - 1 ] == DOMAIN_NAME_DELIM_UNICODE )
	{
		( ( LPWSTR )fs_style_path_iter->org_path )[ name_len - 1 ] = L'\0'; 
	}

	if( fs_style_path_iter->iterator[ name_len - 1 ] == DOMAIN_NAME_DELIM_UNICODE )
	{
		fs_style_path_iter->iterator[ name_len - 1 ] = L'\0'; 
	}

	if( fs_style_path_iter->iterator[ 0 ] == DOMAIN_NAME_DELIM_UNICODE )
	{
		fs_style_path_iter->index = 1; 
	}

	_hash_code = unicode_str_hash( fs_style_path_iter->iterator + fs_style_path_iter->index, tbl_size ); 
	*param_out = fs_style_path_iter->iterator + fs_style_path_iter->index; 
	*context = ( PVOID )fs_style_path_iter; 
	*hash_code = _hash_code; 

_return:
	if( !NT_SUCCESS( ntstatus ) )
	{
		if( fs_style_path_iter != NULL )
		{
			if( fs_style_path_iter->org_path != NULL )
			{
				FREE_TAG_POOL( ( PVOID )fs_style_path_iter->org_path ); 
			}

			FREE_TAG_POOL( fs_style_path_iter ); 
		}
	}
	return ntstatus; 
}

NTSTATUS CALLBACK uninit_url_iteration( PVOID context )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	fs_style_interator *fs_style_path_iter; 

	ASSERT( context != NULL ); 

	fs_style_path_iter = ( fs_style_interator* )context; 
	if( fs_style_path_iter->org_path != NULL )
	{
		FREE_TAG_POOL( ( PVOID )fs_style_path_iter->org_path ); 
	}
	else
	{
		ASSERT( FALSE && "uninitialize a not initialized fs tyle name iterator" ); 
	}

	FREE_TAG_POOL( fs_style_path_iter ); 

	return ntstatus; 
}

NTSTATUS CALLBACK interate_url_path( PVOID param, PULONG hash_code, ULONG tbl_size, PVOID *param_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	fs_style_interator *url_iter; 
	ULONG _hash_code; 

	//ASSERT( param != NULL ); 
	ASSERT( param_out != NULL ); 
	ASSERT( hash_code != NULL ); 
	ASSERT( tbl_size > 0 ); 

	if( param == NULL )
	{
		ASSERT( FALSE ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	*param_out = NULL; 
	*hash_code = 0; 

	url_iter = ( fs_style_interator* )param; 

	if( url_iter->index >= url_iter->length - 1 )
	{
		ASSERT( ( LONG )url_iter->index >= 0 ); 

		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

#ifdef DBG
	if( url_iter->index == url_iter->length - 1 )
	{
		ASSERT( url_iter->iterator[ url_iter->index - 1 ] != DOMAIN_NAME_DELIM_UNICODE ); 
	}
	else if( url_iter->index != 0 )
	{
		ASSERT( url_iter->iterator[ url_iter->index ] == DOMAIN_NAME_DELIM_UNICODE ); 
	}
#endif //DBG

	for( ; ; )
	{
		if( url_iter->iterator[ url_iter->index ] == DOMAIN_NAME_DELIM_UNICODE )
		{
			url_iter->index ++; 
			break; 
		}
		else if( url_iter->iterator[ url_iter->index ] == L'\0' )
		{
			ntstatus = STATUS_UNSUCCESSFUL; 
			goto _return; 
		}
		else if( url_iter->index == url_iter->length - 1 )
		{
			ntstatus = STATUS_UNSUCCESSFUL; 
			goto _return; 
		}

		url_iter->index ++; 
	}

	*param_out = url_iter->iterator + url_iter->index; 
	_hash_code = unicode_str_hash( url_iter->iterator + url_iter->index, tbl_size ); 
	*hash_code = _hash_code; 

_return:
	return ntstatus; 
}

INLINE VOID get_action_rule_func( access_rule_type rule_type, 
						  init_iteration_callback *init_iteration_func, 
						  uninit_iteration_callback *uninit_iteration_func, 
						  iterate_name_callback *iteration_func, 
						  calc_hash_code_callback *hash_code_func, 
						  compare_hash_table_item_callback *compare_func )
{
	switch( rule_type )
	{
	case URL_RULE_TYPE: 
		*init_iteration_func = init_url_iteration; 
		*uninit_iteration_func = uninit_url_iteration; 
		*iteration_func = interate_url_path; 
		*hash_code_func = calc_url_rule_hash_code; 
		*compare_func = compare_url_rule; 
		break; 
	case SOCKET_RULE_TYPE: 
		*init_iteration_func = NULL; 
		*uninit_iteration_func = NULL; 
		*iteration_func = NULL; 
		*hash_code_func = calc_socket_rule_hash_code; 
		*compare_func = compare_socket_rule; 
		break; 
	case FILE_RULE_TYPE:
		*init_iteration_func = init_name_iteration; 
		*uninit_iteration_func = uninit_name_iteration; 
		*iteration_func = iterate_fs_style_path; 
		*hash_code_func = calc_file_rule_hash_code; 
		*compare_func = compare_file_rule; 
		break; 
	case REG_RULE_TYPE: 
		*init_iteration_func = init_name_iteration; 
		*uninit_iteration_func = uninit_name_iteration; 
		*iteration_func = iterate_fs_style_path; 
		*hash_code_func = calc_reg_rule_hash_code; 
		*compare_func = compare_reg_rule; 
		break; 
	case COM_RULE_TYPE: 
		*init_iteration_func = NULL; 
		*uninit_iteration_func = NULL; 
		*iteration_func = NULL; 
		*hash_code_func = calc_com_rule_hash_code; 
		*compare_func = compare_com_rule; 
		break; 
	case COMMON_RULE_TYPE: 
		*init_iteration_func = NULL; 
		*uninit_iteration_func = NULL; 
		*iteration_func = NULL; 
		*hash_code_func = calc_common_rule_hash_code; 
		*compare_func = compare_common_rule; 
		break; 
	default:
		ASSERT( FALSE ); 
		break; 
	}
}

INLINE VOID get_action_rule_func_and_param( access_rule_type rule_type, 
									sys_action_desc *cur_action, 
									init_iteration_callback *init_iteration_func, 
									uninit_iteration_callback *uninit_iteration_func, 
									iterate_name_callback *iteration_func, 
									calc_hash_code_callback *hash_code_func, 
									compare_hash_table_item_callback *compare_func, 
									PVOID *param )
{
	*param = ( PVOID )&cur_action->desc; 
	get_action_rule_func( rule_type, init_iteration_func, uninit_iteration_func, iteration_func, hash_code_func, compare_func ); 
}

VOID _get_action_rule_func_and_param( access_rule_type rule_type, 
											access_rule_desc *rule_input, 
											init_iteration_callback *init_iteration_func, 
											uninit_iteration_callback *uninit_iteration_func, 
											iterate_name_callback *iterate_func, 
											calc_hash_code_callback *hash_code_func, 
											compare_hash_table_item_callback *compare_func, 
											PVOID *param )
{
	*param = ( PVOID )&rule_input->desc; 
	get_action_rule_func( rule_type, init_iteration_func, uninit_iteration_func, iterate_func, hash_code_func, compare_func ); 
}

NTSTATUS find_action_rule( access_rule_type type, 
						  sys_action_desc *cur_action, 
						  data_trace_option *trace_option )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	common_hash_table *table; 
	PLIST_ENTRY item_found; 
	action_rule_item *rule_found; 
	PVOID param; 
	init_iteration_callback init_iteration_func; 
	uninit_iteration_callback uninit_iteration_func; 
	iterate_name_callback iterate_func; 
	calc_hash_code_callback hash_code_func; 
	compare_hash_table_item_callback compare_func; 

	ASSERT( is_valid_access_rule_type( type ) == TRUE ); 
	ASSERT( is_rbtree_link_rule( type ) == FALSE ); 
	ASSERT( cur_action != NULL ); 

	log_trace( ( MSG_INFO, "enter %s \n", __FUNCTION__ ) ); 

	cur_action->resp = ACTION_ALLOW; 

	table = get_action_rule_table( type ); 
	
	get_action_rule_func_and_param( type, 
		cur_action, 
		&init_iteration_func, 
		&uninit_iteration_func, 
		&iterate_func, 
		&hash_code_func, 
		&compare_func, 
		&param ); 

	log_trace( ( MSG_INFO, "init iteration fucntion is 0x%0.8x, uninit iteration fuction is 0x%0.8x iteration function is 0x%0.8x hash function is 0x%0.8x, compare function is 0x%0.8x parameter is 0x%0.8x hash table is 0x%0.8x\n", init_iteration_func, uninit_iteration_func, iterate_func, hash_code_func, compare_func, param, table ) ); 

	hold_hash_table_lock( table ); 
	ntstatus = find_in_hash_table_lock_free( ( PVOID )&cur_action->desc, init_iteration_func, uninit_iteration_func, iterate_func, hash_code_func, compare_func, table, &item_found ); 

	if( !NT_SUCCESS( ntstatus ) )
	{
		log_trace( ( MSG_ERROR, "!!!find this action rule failed\n" ) ); 
		goto _return; 
	}

	ASSERT( item_found != NULL ); 
	rule_found = ( action_rule_item* )CONTAINING_RECORD( item_found, action_rule_item, entry ); 

	if( NULL != trace_option )
	{
		*trace_option = rule_found->rule.trace_option; 
	}

	cur_action->resp = rule_found->rule.action; 

_return: 
	release_hash_table_lock( table ); 

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 

	return ntstatus; 
}

INLINE VOID remove_cls_define_list( PLIST_ENTRY param_list )
{
	PLIST_ENTRY list_entry; 
	ASSERT( param_list != NULL ); 

	for( ; ; )
	{
		list_entry = param_list->Flink; 
		if( list_entry == param_list )
		{
			break; 
		}

		RemoveEntryList( list_entry ); 
		InitializeListHead( list_entry ); 
	}

	InitializeListHead( param_list ); 
}

NTSTATUS del_param_define( param_all_desc *param_input )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	common_hash_table *table; 
	param_define_item *param_found; 
	PLIST_ENTRY param_list; 
	calc_hash_code_callback hash_code_func; 
	compare_hash_table_item_callback compare_func; 
	PVOID param; 

	ASSERT( param_input != NULL ); 
	ASSERT( param_input->is_cls == FALSE ); 

	table = get_param_define_table( param_input->type ); 
	get_param_define_callback_and_param( param_input, param_input->type, &param, &hash_code_func, &compare_func ); 

	hold_hash_table_lock( table ); 
	ntstatus = find_in_hash_table_lock_free( param, 
		NULL, 
		NULL, 
		NULL, 
		hash_code_func, 
		compare_func, 
		table, 
		&param_list ); 

	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	ASSERT( param_list != NULL ); 
	param_found = ( param_define_item* )CONTAINING_RECORD( param_list, param_define_item, entry ); 

	ASSERT( param_found->param.is_cls == FALSE ); 

	RemoveEntryList( &param_found->entry ); 

	FREE_TAG_POOL( param_found ); 

_return:
	release_hash_table_lock( table ); 
	return ntstatus; 
}

NTSTATUS del_class_param_define( param_all_desc *param )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	common_hash_table *table; 
	param_define_item *param_found; 
	PLIST_ENTRY param_list; 

	ASSERT( param != NULL ); 
	ASSERT( param->is_cls == TRUE ); 

	table = get_class_param_define_table( param->type ); 

	hold_hash_table_lock( table ); 
	ntstatus = find_in_hash_table_lock_free( param->cls.class_name, 
		NULL, 
		NULL, 
		NULL, 
		calc_class_name_hash_code, 
		compare_class_define, 
		table, 
		&param_list ); 

	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	ASSERT( param_list != NULL ); 

	param_found = ( param_define_item* )CONTAINING_RECORD( param_list, param_define_item, entry ); 

	RemoveEntryList( &param_found->entry ); 

	remove_cls_define_list( &param_found->define_list ); 

	FREE_TAG_POOL( param_found ); 

_return:
	release_hash_table_lock( table ); 
	return ntstatus; 
}

NTSTATUS init_action_rule_lock()
{
	NTSTATUS ntstatus; 
	ntstatus = init_resource_locks( MAX_ACTION_RULE_TYPE, &all_action_rule_lock ); 
	return ntstatus; 
}

NTSTATUS init_response_record_lock()
{
	NTSTATUS ntstatus; 
	ntstatus = init_resource_locks( MAX_ACTION_RULE_TYPE, &all_response_lock ); 
	return ntstatus; 
}

NTSTATUS init_app_record_lock()
{
	NTSTATUS ntstatus; 
	ntstatus = init_resource_locks( APP_RECORD_TABLE_NUM, &all_app_response_lock ); 
	return ntstatus; 
}

NTSTATUS init_param_define_lock()
{
	NTSTATUS ntstatus; 
	ntstatus = init_resource_locks( MAX_PARAM_DEFINE_TYPE, &all_param_define_lock ); ;
	return ntstatus; 
}

NTSTATUS uninit_action_rule_lock()
{
	NTSTATUS ntstatus; 
	ntstatus = uninit_resource_locks( MAX_ACTION_RULE_TYPE, all_action_rule_lock ); 
	all_action_rule_lock = NULL; ;
	return ntstatus; 
}

NTSTATUS uninit_response_record_lock()
{
	NTSTATUS ntstatus; 
	ntstatus = uninit_resource_locks( MAX_ACTION_RULE_TYPE, all_response_lock ); 
	all_response_lock = NULL; ;
	return ntstatus; 
}

NTSTATUS uninit_app_record_lock()
{
	NTSTATUS ntstatus; 
	ntstatus = uninit_resource_locks( APP_RECORD_TABLE_NUM, all_app_response_lock ); 
	all_app_response_lock = NULL; ;
	return ntstatus; 
}

NTSTATUS uninit_param_define_lock()
{
	NTSTATUS ntstatus; 
	ntstatus = uninit_resource_locks( MAX_PARAM_DEFINE_TYPE, all_param_define_lock ); 
	all_param_define_lock = NULL; 
	return ntstatus; 
}

NTSTATUS init_param_defines()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 lock_inited = FALSE; 
	INT32 i = 0; 

	ntstatus = init_param_define_lock(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	lock_inited = TRUE; 

	for( i = 0; i < ARRAY_SIZE( all_param_define ); i ++ )
	{
		if( is_fw_param_define_type( i ) == TRUE )
		{
			ntstatus = init_common_hash_table_spin_lock( &all_param_define[ i ], 
				param_define_size[ i ] ); 
		}
		else
		{
			ntstatus = init_common_hash_table( &all_param_define[ i ], 
				param_define_size[ i ], 
				&all_param_define_lock[ i ], 
				hold_w_resource_lock, 
				hold_r_resource_lock, 
				release_resource_lock ); 
		}
		if( !NT_SUCCESS( ntstatus ) )
		{
			goto _return;
		}
	}

_return:
	if( !NT_SUCCESS( ntstatus ) )
	{
		for( ; i > 0; i -- )
		{
			if( is_fw_param_define_type( i - 1 ) == TRUE )
			{
				release_common_hash_table_spin_lock( &all_param_define[ i - 1 ], release_hash_element_place_holder ); 
			}
			else
			{
				release_common_hash_table( &all_param_define[ i - 1 ], release_hash_element_place_holder ); 
			}
		}

		if( lock_inited == TRUE )
		{
			uninit_param_define_lock(); 
		}
	}

	return ntstatus; 
}

NTSTATUS init_class_param_defines()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 i = 0; 

	ASSERT( all_param_define_lock != NULL );
	for( i = 0; i < ARRAY_SIZE( all_class_param_define ); i ++ )
	{
		if( is_fw_param_define_type( i ) == TRUE )
		{
			ntstatus = init_common_hash_table_spin_lock( &all_class_param_define[ i ], 
				class_param_define_size[ i ] ); 
		}
		else
		{
			ntstatus = init_common_hash_table( &all_class_param_define[ i ], 
				class_param_define_size[ i ], 
				&all_param_define_lock[ i ], 
				hold_w_resource_lock, 
				hold_r_resource_lock, 
				release_resource_lock ); 
		}

		if( !NT_SUCCESS( ntstatus ) )
		{
			goto _return;
		}
	}

_return:
	if( !NT_SUCCESS( ntstatus ) )
	{
		for( ; i > 0; i -- )
		{
			if( is_fw_param_define_type( i - 1 ) == TRUE )
			{
				release_common_hash_table_spin_lock( &all_class_param_define[ i - 1 ], release_hash_element_place_holder ); 
			}
			else
			{
				release_common_hash_table( &all_class_param_define[ i - 1 ], release_hash_element_place_holder ); 
			}
		}
	}

	return ntstatus; 
}

NTSTATUS init_action_rule_defines()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 i = 0; 
	INT32 lock_inited = FALSE; 

	ntstatus = init_action_rule_lock(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	lock_inited = TRUE; 

	for( i = 0; i < ARRAY_SIZE( all_action_rule ); i ++ )
	{
		if( is_fw_rule_type( i ) == TRUE )
		{
			ntstatus = init_common_hash_table_spin_lock( &all_action_rule[ i ], 
				action_rule_define_size[ i ] ); 

		}
		else
		{
			ntstatus = init_common_hash_table( &all_action_rule[ i ], 
				action_rule_define_size[ i ], 
				&all_param_define_lock[ i ], 
				hold_w_resource_lock, 
				hold_r_resource_lock, 
				release_resource_lock ); 
		}

		if( !NT_SUCCESS( ntstatus ) )
		{
			goto _return;
		}
	}

_return:
	if( !NT_SUCCESS( ntstatus ) )
	{
		for( ; i > 0; i -- )
		{
			if( is_fw_rule_type( i - 1 ) == TRUE )
			{
				release_common_hash_table_spin_lock( &all_action_rule[ i - 1 ], release_hash_element_place_holder ); 
			}
			else
			{
				release_common_hash_table( &all_action_rule[ i - 1 ], release_hash_element_place_holder ); 
			}
		}

		if( lock_inited == TRUE )
		{
			uninit_action_rule_lock(); 
		}
	}

	return ntstatus; 
}

NTSTATUS init_response_records()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 i = 0; 
	INT32 lock_inited = FALSE; 

	ntstatus = init_response_record_lock(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	lock_inited = TRUE; 

	for( i = 0; i < ARRAY_SIZE( all_action_response ); i ++ )
	{
		if( is_fw_rule_type( i ) == TRUE )
		{
			ntstatus = init_common_hash_table_spin_lock( &all_action_response[ i ], 
				action_response_size[ i ] ); 
		}
		else
		{
			ntstatus = init_common_hash_table( &all_action_response[ i ], 
				action_response_size[ i ], 
				&all_response_lock[ i ], 
				hold_w_resource_lock, 
				hold_r_resource_lock, 
				release_resource_lock ); 
		}

		if( !NT_SUCCESS( ntstatus ) )
		{
			goto _return;
		}
	}

_return:
	if( !NT_SUCCESS( ntstatus ) )
	{
		for( ; i > 0; i -- )
		{
			if( is_fw_rule_type( i - 1 ) == TRUE )
			{
				release_common_hash_table_spin_lock( &all_action_response[ i - 1 ], release_hash_element_place_holder ); 
			}
			else
			{
				release_common_hash_table( &all_action_response[ i - 1 ], release_hash_element_place_holder ); 
			}
		}
		if( lock_inited == TRUE )
		{
			uninit_response_record_lock(); 
		}
	}

	return ntstatus; 
}

NTSTATUS init_app_records()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 i = 0; 

#ifdef HAVE_APP_RECORD_LOCK
	INT32 lock_inited = FALSE; 

	ntstatus = init_app_record_lock(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	lock_inited = TRUE; 
#endif //HAVE_APP_RECORD_LOCK

	for( i = 0; i < ARRAY_SIZE( all_app_response ); i ++ )
	{
		ntstatus = init_common_hash_table_spin_lock( &all_app_response[ i ], 
			app_response_size[ i ] ); 

		//ntstatus = init_common_hash_table( &all_action_response[ i ], 
		//	action_response_size[ i ], 
		//	&all_response_lock[ i ], 
		//	hold_w_resource_lock, 
		//	hold_r_resource_lock, 
		//	release_resource_lock ); 

		if( !NT_SUCCESS( ntstatus ) )
		{
			goto _return;
		}
	}

_return:
	if( !NT_SUCCESS( ntstatus ) )
	{
		for( ; i > 0; i -- )
		{
			release_common_hash_table_spin_lock( &all_app_response[ i - 1 ], release_hash_element_place_holder ); 
			//release_common_hash_table( &all_action_response[ i - 1 ], release_hash_element_place_holder ); 
		}

#ifdef HAVE_APP_RECORD_LOCK
		if( lock_inited == TRUE )
		{
			uninit_app_record_lock(); 
		}
#endif //HAVE_APP_RECORD_LOCK
	}

	return ntstatus; 
}

NTSTATUS CALLBACK release_param_define( PLIST_ENTRY element )
{
	param_define_item *param_item; 

	param_item = ( param_define_item* )CONTAINING_RECORD( element, param_define_item, entry ); 

	ASSERT( param_item->param.is_cls == FALSE ); 
	ASSERT( is_valid_param_define_type( param_item->param.type ) ); 
	RemoveEntryList( &param_item->define_list ); 
	RemoveEntryList( &param_item->entry ); 

	FREE_TAG_POOL( param_item ); 

	return STATUS_SUCCESS; 
}

NTSTATUS uninit_param_defines()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 i; 

	ASSERT( all_param_define_lock != NULL ); 
	for( i = 0; i < ARRAY_SIZE( all_param_define ); i ++ )
	{
		if( is_fw_param_define_type( i ) == TRUE )
		{
			release_common_hash_table_spin_lock( &all_param_define[ i ], release_param_define ); 
		}
		else
		{
			release_common_hash_table( &all_param_define[ i ], release_param_define ); 
		}
	}

	uninit_param_define_lock(); 

//_return:
	return ntstatus; 
}

NTSTATUS CALLBACK release_class_param_define( PLIST_ENTRY element )
{
	param_define_item *param_item; 

	param_item = ( param_define_item* )CONTAINING_RECORD( element, param_define_item, entry ); 

	ASSERT( param_item->param.is_cls == TRUE ); 
	ASSERT( is_valid_param_define_type( param_item->param.type ) ); 
	remove_cls_define_list( &param_item->define_list ); 
	RemoveEntryList( &param_item->entry ); 

	FREE_TAG_POOL( param_item ); 

	return STATUS_SUCCESS; 
}

NTSTATUS uninit_class_param_defines()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 i; 

	ASSERT( all_param_define_lock != NULL ); 
	for( i = 0; i < ARRAY_SIZE( all_class_param_define ); i ++ )
	{
		if( is_fw_param_define_type( i ) == TRUE )
		{
			release_common_hash_table_spin_lock( &all_class_param_define[ i ], release_class_param_define ); 
		}
		else
		{
			release_common_hash_table( &all_class_param_define[ i ], release_class_param_define ); 
		}
	}

//_return:
	return ntstatus; 
}

NTSTATUS CALLBACK release_action_rule_define( PLIST_ENTRY element )
{
	action_rule_item *param_item; 

	param_item = ( action_rule_item* )CONTAINING_RECORD( element, action_rule_item, entry ); 

	ASSERT( is_valid_access_rule_type( param_item->rule.type ) ); 
	RemoveEntryList( &param_item->entry ); 

	FREE_TAG_POOL( param_item );

	return STATUS_SUCCESS; 
}

NTSTATUS CALLBACK release_action_response_record( PLIST_ENTRY element )
{
	response_record_item *resp_record; 

	resp_record = ( response_record_item* )CONTAINING_RECORD( element, response_record_item, entry ); 

	ASSERT( is_valid_response_type( resp_record->response ) ); 
	RemoveEntryList( element /*&resp_record->entry*/ ); 

	FREE_TAG_POOL( resp_record );

	return STATUS_SUCCESS; 
}

NTSTATUS uninit_action_rule_defines()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 i; 

#ifdef TEST_IN_RING3
//#ifdef _DEBUG
//	TCHAR module_name[ MAX_PATH ]; 
//	GetModuleFileName( NULL, module_name, MAX_PATH ); 
//	
//	log_trace( ( MSG_INFO, "current exe file is %ws \n", module_name ) ); 
//	MessageBox( NULL, module_name, NULL, 0 ); 
//	DBG_BP(); 
//#endif //_DEBUG

#else 
	ASSERT( all_action_rule_lock != NULL ); 
#endif //TEST_IN_RING3


	for( i = 0; i < ARRAY_SIZE( all_action_rule ); i ++ )
	{
		if( is_fw_rule_type( i ) == TRUE )
		{
			release_common_hash_table_spin_lock( &all_action_rule[ i ], release_action_rule_define ); 
		}
		else
		{
			release_common_hash_table( &all_action_rule[ i ], release_action_rule_define ); 
		}
	}

	uninit_action_rule_lock(); 
//_return:
	return ntstatus; 
}

NTSTATUS uninit_response_records()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 i; 

	ASSERT( all_response_lock != NULL ); 

	for( i = 0; i < ARRAY_SIZE( all_action_response ); i ++ )
	{
		if( is_fw_rule_type( i ) == TRUE )
		{
			release_common_hash_table_spin_lock( &all_action_response[ i ], release_action_response_record ); 
		}
		else
		{
			release_common_hash_table( &all_action_response[ i ], release_action_response_record ); 
		}
	}

	uninit_response_record_lock(); 
	//_return:
	return ntstatus; 
}

NTSTATUS uninit_app_response_records()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 i; 

#ifdef HAVE_APP_RECORD_LOCK
	ASSERT( all_app_response_lock != NULL ); 
#endif //HAVE_APP_RECORD_LOCK

	for( i = 0; i < ARRAY_SIZE( all_app_response ); i ++ )
	{
		release_common_hash_table_spin_lock( &all_app_response[ i ], release_action_response_record ); 
		//release_common_hash_table( &all_app_response[ i ], release_action_response_record ); 
	}

#ifdef HAVE_APP_RECORD_LOCK
	uninit_response_record_lock(); 
#endif //HAVE_APP_RECORD_LOCK

	//_return:
	return ntstatus; 
}

VOID clear_response_records()
{
	INT32 i; 

	ASSERT( all_response_lock != NULL ); 

	for( i = 0; i < ARRAY_SIZE( all_action_response ); i ++ )
	{
		clear_common_hash_table( &all_action_response[ i ], release_action_response_record ); 
	}
}

VOID clear_app_response_records()
{
	INT32 i; 

#ifdef HAVE_APP_RECORD_LOCK
	ASSERT( all_app_response_lock != NULL ); 
#endif //HAVE_APP_RECORD_LOCK

	for( i = 0; i < ARRAY_SIZE( all_app_response ); i ++ )
	{
		clear_common_hash_table( &all_app_response[ i ], release_action_response_record ); 
	}
}

NTSTATUS init_action_manage()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 param_defines_inited = FALSE; 
	INT32 class_param_inited = FALSE; 
	INT32 action_rule_inited = FALSE; 
	INT32 response_inited = FALSE; 
	INT32 app_response_inited = FALSE; 

	ntstatus = init_param_defines(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}
	param_defines_inited = TRUE; 

	ntstatus = init_class_param_defines(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}
	class_param_inited = TRUE; 

	ntstatus = init_action_rule_defines(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}
	action_rule_inited = TRUE; 

	ntstatus = init_response_records(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}
	response_inited = TRUE; 

	ntstatus = init_app_records(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	app_response_inited = TRUE; 

	ntstatus = init_socket_rule_rbt(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

_return:
	if( !NT_SUCCESS( ntstatus ) )
	{
		if( app_response_inited == TRUE )
		{
			uninit_app_response_records(); 
		}

		if( response_inited == TRUE )
		{
			uninit_response_records(); 
		}

		if( action_rule_inited == TRUE )
		{
			uninit_action_rule_defines(); 
		}

		if( class_param_inited == TRUE )
		{
			uninit_class_param_defines(); 
		}

		if( param_defines_inited == TRUE )
		{
			uninit_param_defines(); 
		}
	}

	return ntstatus; 
}

NTSTATUS uninit_action_manage()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	ntstatus = uninit_action_rule_defines(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		ASSERT( FALSE ); 
	}

	ntstatus = uninit_app_response_records(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		ASSERT( FALSE ); 
	}

	ntstatus = uninit_response_records(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		ASSERT( FALSE ); 
	}

	ntstatus = uninit_class_param_defines(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		ASSERT( FALSE ); 
	}

	ntstatus = uninit_param_defines(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		ASSERT( FALSE ); 
	}

	ntstatus = release_socket_rule_rbt(); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		ASSERT( FALSE ); 
	}

	//_return:
	return ntstatus; 
}

NTSTATUS del_action_rule( sys_action_desc *cur_action )
{
	NTSTATUS ntstatus = STATUS_SUCCESS;  
	common_hash_table *table; 
	PLIST_ENTRY item_found; 
	action_rule_item *rule_found; 
	PVOID param; 
	access_rule_type rule_type; 
	init_iteration_callback init_iteration_func; 
	uninit_iteration_callback uninit_iteration_func; 
	iterate_name_callback iterate_func; 
	calc_hash_code_callback hash_code_func; 
	compare_hash_table_item_callback compare_func; 

	if( is_valid_access_rule_type( cur_action->type ) == FALSE )
	{
		ASSERT( FALSE ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}; 

	rule_type = acl_type( cur_action->type ); 

	if( is_rbtree_link_rule( rule_type ) == TRUE )
	{
		ASSERT( FALSE ); 
		//hold_rbt_lock( &socket_rule_rbt ); 
		//rule_found = rb_search_socket_rule_lock_free( cur_action->desc ); 

		//if( rule_found != NULL )
		//{
		//	rb_remove_socket_rule_lock_free( &rule_found->rb_node ); 

		//	FREE_TAG_POOL( rule_found ); 
		//}

		//release_rbt_lock( &socket_rule_rbt ); 

	}
	else
	{
		do 
		{
			table = get_action_rule_table( rule_type ); 

			get_action_rule_func_and_param( rule_type, cur_action, &init_iteration_func, &uninit_iteration_func, &iterate_func, &hash_code_func, &compare_func, &param ); 

			hold_hash_table_lock( table ); 
			ntstatus = find_in_hash_table_lock_free( ( PVOID )&cur_action->desc, init_iteration_func, uninit_iteration_func, iterate_func, hash_code_func, compare_func, table, &item_found ); 

			if( !NT_SUCCESS( ntstatus ) )
			{
				break; 
			}

			ASSERT( item_found != NULL ); 

			rule_found = ( action_rule_item* )CONTAINING_RECORD( item_found, action_rule_item, entry ); 

			RemoveEntryList( item_found ); 
			FREE_TAG_POOL( rule_found ); 
		} while ( FALSE );

		release_hash_table_lock( table ); 
	}
_return:
	return ntstatus; 
}

NTSTATUS _del_action_rule( access_rule_desc *rule_input )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	common_hash_table *table; 
	action_rule_item *rule_found; 
	PLIST_ENTRY item_found; 
	PVOID param; 
	access_rule_type rule_type; 
	init_iteration_callback init_iteration_func; 
	uninit_iteration_callback uninit_iteration_func; 
	iterate_name_callback iterate_func; 
	calc_hash_code_callback hash_code_func; 
	compare_hash_table_item_callback compare_func; 

	ntstatus = check_access_rule_input_valid( rule_input, FALSE ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		//ASSERT( FALSE ); 
		goto _return; 
	}

	rule_type = rule_input->type; 

	if( is_rbtree_link_rule( rule_type ) == TRUE )
	{
		do 
		{
			hold_rbt_lock( &socket_rule_rbt ); 
			ntstatus = rb_search_socket_rule_lock_free( &socket_rule_rbt, rule_input, &rule_found ); 

			if( !NT_SUCCESS( ntstatus ) )
			{
				break; 
			}

			rb_remove_socket_rule_lock_free( &rule_found->rb_node ); 

			FREE_TAG_POOL( rule_found ); 

		} while ( FALSE );

		release_rbt_lock( &socket_rule_rbt ); 

	}
	else
	{
		do 
		{
			table = get_action_rule_table( rule_type ); 

			_get_action_rule_func_and_param( rule_type, rule_input, &init_iteration_func, &uninit_iteration_func, &iterate_func, &hash_code_func, &compare_func, &param ); 

			hold_hash_table_lock( table ); 
			ntstatus = find_in_hash_table_lock_free( param, NULL, NULL, NULL, hash_code_func, compare_func, table, &item_found ); 

			if( !NT_SUCCESS( ntstatus ) )
			{
				break; 
			}

			ASSERT( item_found != NULL ); 

			rule_found = ( action_rule_item* )CONTAINING_RECORD( item_found, action_rule_item, entry ); 

			ASSERT( rule_found->ref_count > 0 ); 
			RemoveEntryList( item_found ); 
			FREE_TAG_POOL( rule_found ); 

			table->count --; 
		} while( FALSE );

		release_hash_table_lock( table ); 
	}

_return:
	return ntstatus; 
}

NTSTATUS modify_action_rule( access_rule_desc *dest_rule, 
							access_rule_desc *rule_setting )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	common_hash_table *table; 
	PLIST_ENTRY item_found; 
	PVOID param; 
	access_rule_type rule_type; 
	action_rule_item *rule_item_modified; 
	INT32 lock_hold = FALSE; 
	init_iteration_callback init_iteration_func; 
	uninit_iteration_callback uninit_iteration_func; 
	iterate_name_callback iterate_func; 
	calc_hash_code_callback hash_code_func; 
	compare_hash_table_item_callback compare_func; 

	ASSERT( dest_rule != NULL ); 
	ASSERT( rule_setting != NULL ); 

	ntstatus = check_access_rule_input_valid( dest_rule, FALSE ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		ASSERT( FALSE ); 
		goto _return; 
	}

	ntstatus = check_access_rule_input_valid( rule_setting, FALSE ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		ASSERT( FALSE ); 
		goto _return; 
	}

	if( rule_setting->type != dest_rule->type )
	{
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	rule_type = dest_rule->type; 

	if( is_rbtree_link_rule( rule_type ) == TRUE )
	{
		rb_node *node; 

		hold_rbt_lock( &socket_rule_rbt ); 

		lock_hold = TRUE; 
		do 
		{
			ntstatus = rb_search_socket_rule_lock_free( &socket_rule_rbt, dest_rule, &rule_item_modified ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				break; 
			}

			if( rule_item_modified != NULL )
			{
				rb_remove_socket_rule_lock_free( &rule_item_modified->rb_node ); 

				FREE_TAG_POOL( rule_item_modified ); 
			}

			release_rbt_lock( &socket_rule_rbt ); 

			lock_hold = FALSE; 

			ntstatus = rb_insert_socket_rule( rule_setting, &node ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				break; 
			}

			//ntstatus = alloc_access_rule( rule_setting, &rule_item_modified ); 
			//if( !NT_SUCCESS( ntstatus ) )
			//{
			//	break; 
			//}

			//ASSERT( rule_setting != NULL ); 

			//rb_link_node( &rule_item_modified->rb_node, parent, p );

			//ASSERT( rule_item_modified->ref_count == 0 ); 
			//rule_item_modified->ref_count ++; 

		} while ( FALSE );

		if( lock_hold == TRUE )
		{
			release_rbt_lock( &socket_rule_rbt ); 
		}
	}
	else
	{
		do 
		{
			table = get_action_rule_table( rule_type ); 

			_get_action_rule_func_and_param( rule_type, dest_rule, &init_iteration_func, &uninit_iteration_func, &iterate_func, &hash_code_func, &compare_func, &param ); 

			hold_hash_table_lock( table ); 
			lock_hold = TRUE; 

			ntstatus = find_in_hash_table_lock_free( param, init_iteration_func, uninit_iteration_func, iterate_func, hash_code_func, compare_func, table, &item_found ); 

			if( !NT_SUCCESS( ntstatus ) )
			{
				break; 
			}

			ASSERT( item_found != NULL ); 

			rule_item_modified = ( action_rule_item* )CONTAINING_RECORD( item_found, action_rule_item, entry ); 

			ASSERT( rule_item_modified->ref_count > 0 ); 
			RemoveEntryList( item_found ); 
			FREE_TAG_POOL( rule_item_modified ); 

			ntstatus = alloc_access_rule( rule_setting, &rule_item_modified ); 
			if( !NT_SUCCESS( ntstatus ) )
			{
				break; 
			}

			ASSERT( rule_setting != NULL ); 

			ntstatus = _add_action_rule_lock_free( rule_setting, rule_item_modified ); 
		} while ( FALSE );

		if( lock_hold == TRUE )
		{
			release_hash_table_lock( table ); 
		}
	}
_return:
	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 

	return ntstatus; 
}

ULONG CALLBACK calc_response_record_hash( PVOID param, ULONG table_size )
{
	return unicode_str_hash( ( LPCWSTR )param, table_size ); 
}

INT32 CALLBACK compare_response_record( PVOID param, PLIST_ENTRY item, PVOID param_iteration )
{
	INT32 ret = TRUE; 
	INT32 _ret; 
	response_record_item *response_record; 

	ASSERT( param != NULL ); 
	ASSERT( item != NULL ); 

	response_record = ( response_record_item* )item; 

	_ret = compare_define_name_no_case( response_record->app_name, ( LPWSTR )param ); 

	if( _ret != 0 )
	{
		ret = FALSE; 
	}

	return ret; 
}

NTSTATUS remove_oldest_access_rule( common_hash_table *table )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	return ntstatus; 
}

NTSTATUS add_action_rule( access_rule_desc *rule_input, ULONG flags )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	action_rule_item *rule_alloc; 
	PLIST_ENTRY item_found; 
	PVOID param; 
	common_hash_table *table; 
	//INT32 lock_held = FALSE; 
	init_iteration_callback init_iteration_func; 
	uninit_iteration_callback uninit_iteration_func; 
	iterate_name_callback iterate_func; 
	calc_hash_code_callback hash_code_func; 
	compare_hash_table_item_callback compare_func; 

	log_trace( ( MSG_INFO, "enter %s \n", __FUNCTION__ ) ); 

	ASSERT( rule_input != NULL ); 


	ntstatus = check_access_rule_input_valid( rule_input, FALSE ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		//ASSERT( FALSE ); 
		goto _return; 
	}

	if( is_rbtree_link_rule( rule_input->type ) == TRUE )
	{
		rb_node *node_out; 
		ntstatus = rb_insert_socket_rule( rule_input, &node_out ); 
		if( !NT_SUCCESS( ntstatus ) )
		{
			goto _return; 
		}
	}
	else
	{

		table = get_action_rule_table( rule_input->type ); 

		_get_action_rule_func_and_param( rule_input->type, 
			rule_input, 
			&init_iteration_func, 
			&uninit_iteration_func, 
			&iterate_func, 
			&hash_code_func, 
			&compare_func, 
			&param ); 

		log_trace( ( MSG_INFO, "init iteration function is 0x%0.8x, uninit iteration fuction is 0x%0.8x iteration function is 0x%0.8x hash function is 0x%0.8x, compare function is 0x%0.8x parameter is 0x%0.8x hash table is 0x%0.8x\n", init_iteration_func, uninit_iteration_func, iterate_func, hash_code_func, compare_func, param, table ) ); 

		hold_hash_table_lock( table ); 
		//lock_held = TRUE; 

		ntstatus = find_in_hash_table_lock_free( param, NULL, NULL, NULL, hash_code_func, compare_func, table, &item_found ); 
		if( NT_SUCCESS( ntstatus ) /*|| ( !NT_SUCCESS( ntstatus ) && ntstatus != STATUS_NOT_FOUND )*/ )
		{
			ASSERT( item_found != NULL ); 
			rule_alloc = ( action_rule_item* )CONTAINING_RECORD( item_found, action_rule_item, entry ); 
			if( flags == MODIFY_RULE )
			{
				if( rule_alloc->rule.action != rule_input->resp )
				{
					rule_alloc->rule.action = rule_input->resp; 
				}
			}

			release_hash_table_lock( table ); 
			//lock_held = FALSE; 
			goto _return; 
		}

		release_hash_table_lock( table ); 
		//lock_held = FALSE; 

		if( table->count > MAX_ACTION_RULE_NUM )
		{
			//remove_oldest_access_rule( table ); 
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			DbgPrint( "*** access rule table is overflow ***\n" ); 
			goto _return; 
		}

		ntstatus = alloc_access_rule( rule_input, &rule_alloc ); 
		if( !NT_SUCCESS( ntstatus ) )
		{
			goto _return; 
		}

		ASSERT( rule_alloc != NULL ); 

		ntstatus = _add_action_rule( rule_input, rule_alloc ); 
	}


_return: 
	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 

	return ntstatus; 
}

NTSTATUS add_action_response_record( access_rule_type rule_type, action_response_type resp, LPWSTR app_name, ULONG name_len )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	response_record_item *response_record = NULL; 
	common_hash_table *table; 
	ULONG hash_code; 
	PLIST_ENTRY item_found; 
	
	if( is_valid_access_rule_type( rule_type ) == FALSE )
	{
		ASSERT( FALSE ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return;
	}

	if( is_valid_response_type( resp ) == FALSE )
	{
		ASSERT( FALSE ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	if( app_name == NULL )
	{
		ASSERT( FALSE ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	if( app_name[ name_len - 1 ] != L'\0' )
	{
		app_name[ name_len - 1 ] = L'\0'; 
	}

	table = get_response_record_table( rule_type ); 

	ntstatus = find_in_hash_table( app_name, NULL, NULL, NULL, 
		calc_response_record_hash, 
		compare_response_record, 
		table, 
		&item_found ); 

	if( NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	response_record = ( response_record_item* )ALLOC_TAG_POOL( sizeof( response_record_item ) + name_len * sizeof( WCHAR ) ); 

	if( response_record == NULL )
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		goto _return; 
	}

	response_record->trace_option.trace_mode = 0; 
	response_record->trace_option.tracing_size = 0; 

	response_record->response = resp; 
	wcsncpy( response_record->app_name, app_name, name_len ); 
	//if( response_record->app_name[ name_len - 1 ] != L'\0' )
	//{
	//	response_record->app_name[ name_len ] = L'\0'; 
	//}

	unicode_str_to_upper( response_record->app_name ); 

	hash_code = unicode_str_hash( response_record->app_name, table->size ); 
	ASSERT( hash_code < table->size ); 

	insert_to_hash_table( table, hash_code, &response_record->entry ); 
	ntstatus = STATUS_SUCCESS; 

_return:
	if( !NT_SUCCESS( ntstatus ) )
	{
		if( response_record != NULL )
		{
			FREE_TAG_POOL( response_record ); 
		}
	}
	return ntstatus; 
}

NTSTATUS add_app_response_record( action_response_type resp, LPWSTR app_name, ULONG name_len )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	response_record_item *response_record = NULL; 
	common_hash_table *table; 
	ULONG hash_code; 
	PLIST_ENTRY item_found; 

	if( is_valid_response_type( resp ) == FALSE )
	{
		ASSERT( FALSE ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	if( app_name == NULL )
	{
		ASSERT( FALSE ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	if( name_len == 0 )
	{
		ASSERT( FALSE ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	if( app_name[ name_len - 1 ] != L'\0' )
	{
		app_name[ name_len - 1 ] = L'\0'; 
	}

	table = &all_app_response[ 0 ]; 

	ntstatus = find_in_hash_table( app_name, NULL, NULL, NULL, 
		calc_response_record_hash, 
		compare_response_record, 
		table, 
		&item_found ); 

	if( NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	response_record = ( response_record_item* )ALLOC_TAG_POOL( sizeof( response_record_item ) + name_len * sizeof( WCHAR ) ); 

	if( response_record == NULL )
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		goto _return; 
	}

	response_record->trace_option.trace_mode = 0; 
	response_record->trace_option.tracing_size = 0; 

	response_record->response = resp; 
	wcsncpy( response_record->app_name, app_name, name_len ); 
	//if( response_record->app_name[ name_len - 1 ] != L'\0' )
	//{
	//	response_record->app_name[ name_len ] = L'\0'; 
	//}

	unicode_str_to_upper( response_record->app_name ); 

	hash_code = unicode_str_hash( response_record->app_name, table->size ); 
	ASSERT( hash_code < table->size ); 

	insert_to_hash_table( table, hash_code, &response_record->entry ); 
	ntstatus = STATUS_SUCCESS; 

_return:
	if( !NT_SUCCESS( ntstatus ) )
	{
		if( response_record != NULL )
		{
			FREE_TAG_POOL( response_record ); 
		}
	}
	return ntstatus; 
}

NTSTATUS _add_action_response_record( sys_action_type type, action_response_type resp, LPWSTR app_name, ULONG name_len )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	access_rule_type rule_type; 

	ASSERT( is_valid_action_type( type ) == TRUE ); 
	ASSERT( is_valid_response_type( resp ) == TRUE ); 
	ASSERT( app_name != NULL ); 

	//if( app_name[ name_len - 1 ] != L'\0' )
	//{
	//	app_name[ name_len - 1 ] = L'\0'; 
	//}

	rule_type = acl_type( type ); 

	ntstatus = add_action_response_record( rule_type, resp, app_name, name_len ); 

//_return:
	return ntstatus; 
}

NTSTATUS find_response_record( sys_action_type type, LPWSTR app_name, ULONG name_len, data_trace_option *trace_option, action_response_type *resp )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	common_hash_table *table; 
	access_rule_type rule_type; 
	response_record_item *response_record; 
	//ULONG hash_code; 
	PLIST_ENTRY item_found; 
	INT32 lock_held = FALSE; 

	ASSERT( resp != NULL ); 

	*resp = ACTION_ALLOW; 

	if( app_name[ name_len - 1 ] != L'\0' )
	{
		app_name[ name_len - 1 ] = L'\0'; 
	}

	rule_type = acl_type( type ); 

	table = get_response_record_table( rule_type ); 

	hold_hash_table_lock( table ); 

	lock_held = TRUE; 

	ntstatus = find_in_hash_table_lock_free( app_name, NULL, NULL, NULL, 
		calc_response_record_hash, 
		compare_response_record, 
		table, 
		&item_found ); 

	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	ASSERT( item_found != NULL ); 

	response_record = ( response_record_item* )CONTAINING_RECORD( item_found, response_record_item, entry ); 
	
	if( trace_option != NULL )
	{
		*trace_option = response_record->trace_option; 
	}

	*resp = response_record->response; 

_return:
	if( lock_held == TRUE )
	{
		release_hash_table_lock( table ); 
	}
	return ntstatus; 
}

LPCWSTR all_sys_proc[] = {
	L"WINLOGON.EXE", 
		L"SYSTEM", 
		L"CSRSS.EXE", 
		L"SERVICES.EXE", 
		L"WININIT.EXE", 
		L"LSASS.EXE", 
		//L"SVCHOST.EXE", 
		L"SMSS.EXE", 
		L"LSM.EXE", 
		//L"EXPLORER.EXE", 
		L"SEVENFW.EXE", 
		L"SEVENFWUPDATE.E"	
}; 

NTSTATUS check_system_key_proc( LPCWSTR proc_name )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 i; 
	for( i = 0; i < ARRAY_SIZE( all_sys_proc ); i ++ )
	{
		if( compare_define_name_no_case( all_sys_proc[ i ], proc_name ) == 0 )
		{
			goto _return; 
		}
	}

	ntstatus = STATUS_NOT_FOUND; 

_return:
	return ntstatus; 
}

NTSTATUS find_app_response_record( LPWSTR app_name, ULONG name_len, data_trace_option *trace_option, action_response_type *resp )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	common_hash_table *table; 
	access_rule_type rule_type; 
	response_record_item *response_record; 
	//ULONG hash_code; 
	PLIST_ENTRY item_found; 
	INT32 lock_held = FALSE; 

	ASSERT( resp != NULL ); 

	*resp = ACTION_ALLOW; 

	if( app_name[ name_len - 1 ] != L'\0' )
	{
		app_name[ name_len - 1 ] = L'\0'; 
	}

	table = &all_app_response[ 0 ]; 

	hold_hash_table_lock( table ); 

	lock_held = TRUE; 

	ntstatus = find_in_hash_table_lock_free( app_name, NULL, NULL, NULL, 
		calc_response_record_hash, 
		compare_response_record, 
		table, 
		&item_found ); 

	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	ASSERT( item_found != NULL ); 

	response_record = ( response_record_item* )CONTAINING_RECORD( item_found, response_record_item, entry ); 
	*resp = response_record->response; 

	if( trace_option != NULL )
	{
		*trace_option = response_record->trace_option; 
	}

_return:
	if( lock_held == TRUE )
	{
		release_hash_table_lock( table ); 
	}
	return ntstatus; 
}

NTSTATUS check_sys_acl( sys_action_desc *cur_action, data_trace_option *trace_option, action_response_type *response )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	access_rule_type rule_type; 

	//ASSERT( need_log != NULL ); 
	ASSERT( cur_action != NULL ); 

	log_trace( ( MSG_INFO, "enter %s, action is %ws\n", __FUNCTION__, get_action_desc( cur_action->type ) ) ); ; 

	if( response != NULL )
	{
		*response = ACTION_ALLOW; 
	}

	ntstatus = check_sys_action_input_valid( cur_action ); 
	if( !NT_SUCCESS( ntstatus ) ) 
	{
		ASSERT( FALSE ); 
		goto _return; 
	}

	ntstatus = find_app_response_record( cur_action->desc.common.app.app.app_name, 
		wcslen( cur_action->desc.common.app.app.app_name ) + 1, 
		trace_option, 
		&cur_action->resp ); 

	if( NT_SUCCESS( ntstatus ) )
	{
		ASSERT( cur_action->resp  == ACTION_ALLOW 
			|| cur_action->resp  == ACTION_BLOCK ); 

		goto _return; 
	}
	
	ntstatus = find_response_record( cur_action->type, 
		cur_action->desc.common.app.app.app_name, 
		wcslen( cur_action->desc.common.app.app.app_name ) + 1, 
		trace_option, 
		&cur_action->resp ); 

	if( NT_SUCCESS( ntstatus ) )
	{
		ASSERT( cur_action->resp  == ACTION_ALLOW 
			|| cur_action->resp  == ACTION_BLOCK ); 

		goto _return; 
	}

	rule_type = acl_type( cur_action->type ); 

	ntstatus = find_action_rule( rule_type, cur_action, trace_option ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

#ifdef CHECK_TRACE_OPTION
	if( trace_option != NULL )
	{
		log_trace( ( MSG_INFO, "trace mode is 0x%0.8x, trace data size is %u\n", trace_option->trace_mode, trace_option->tracing_size ) ); 
	}
#endif //CHECK_TRACE_OPTION
	
_return: 

	if( response != NULL )
	{
		*response = cur_action->resp; 
	}

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 

	return ntstatus; 
}

NTSTATUS alloc_access_rule( access_rule_desc *rule_input, action_rule_item **rule_alloc )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	action_rule_item *rule_add = NULL; 
	//ULONG rule_size; 
	access_rule_type type; 

	ASSERT( rule_alloc != NULL ); 
	ASSERT( is_valid_access_rule_type( rule_input->type ) ); 

	log_trace( ( MSG_INFO, "enter %s \n", __FUNCTION__ ) ); 

	*rule_alloc = NULL; 
	type = rule_input->type; 

	rule_add = ( action_rule_item* )ALLOC_TAG_POOL( sizeof( action_rule_item ) ); 
	if( rule_add == NULL )
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		goto _return; 
	}

	memset( rule_add, 0, sizeof( action_rule_item ) ); 
	
	rule_add->ref_count = 0; 
	rule_add->rule.type = type; 
	rule_add->rule.action = rule_input->resp; 

	if( type == COMMON_RULE_TYPE )
	{
		rule_add->rule.rule.common.action_type = rule_input->desc.common.action_type; 
	}

	ntstatus = get_defines_of_rule( &rule_add->rule.rule, rule_input ); 
	if( !NT_SUCCESS( ntstatus ) ) 
	{
		log_trace( ( MSG_ERROR, "get rule defines failed 0x%0.8x\n", ntstatus ) ); 
		goto _return; 
	}

	if( is_rbtree_link_rule( rule_add->rule.type ) == TRUE )
	{
		rule_add->rb_node.rb_left = NULL; 
		rule_add->rb_node.rb_right = NULL; 
		rule_add->rb_node.rb_parent_color = 0; 
	}
	else
	{
		InitializeListHead( &rule_add->entry ); 
	}

_return: 
	if( !NT_SUCCESS( ntstatus ) )
	{
		if( rule_add != NULL )
		{
			FREE_TAG_POOL( rule_add ); 
		}
	}
	else
	{
		*rule_alloc = rule_add; 
	}

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 
	return ntstatus; 
}

INT32 compare_define_domain_name_no_case( LPCWSTR define_name, LPCSTR name_compare )
{
	INT32 ret; 

	while( *( name_compare ) != L'\0' && *( define_name ) != L'\0' )
	{
		ASSERT( *define_name < 'a' || *define_name > 'z' ); 

		if( *name_compare >= 'a' && *name_compare <= 'z' )
		{
			if( *define_name != *name_compare + 'A' - 'a' )
			{
				break; 
			}
		}
		else
		{
			if( *define_name != *name_compare )
			{
				break; 
			}
		}

		name_compare ++; 
		define_name ++; 
	}

	if( *name_compare != '\0' || *define_name != L'\0' )
	{
		ret = *name_compare - *define_name; 
	}
	else 
	{
		ret = 0; 
	}

	return ret; 
}

INT32 CALLBACK domain_name_compare( PVOID param, PLIST_ENTRY list_item, PVOID param_iteration )
{
	INT32 ret = TRUE; 
	INT32 _ret; 
	action_rule_item *rule_item; 
	LPCSTR domain_name; 

	ASSERT( param != NULL ); 
	ASSERT( list_item != NULL ); 

	log_trace( ( MSG_INFO, "enter %s \n", __FUNCTION__ ) ); 
	rule_item = CONTAINING_RECORD( list_item, action_rule_item, entry ); 

	ASSERT( rule_item->rule.rule.url.url != NULL ); 

	domain_name = ( LPCSTR )param; 

#if 0
	if( rule_item->rule.rule.url.url != NULL )
	{
		log_trace( ( MSG_INFO, "record app name is %ws cur action app name is %ws \n", rule_item->rule.rule.reg.app->param.app.app_name, L"" ) ); 

		ret = compare_name_define( rule_item->rule.rule.reg.app->param.app.app_name, 
			L"" ); 

		if( ret == FALSE )
		{
			goto _return; 
		}
	}
#endif 

	if( rule_item->rule.rule.reg.reg_path->param.url.url[ 0 ] == L'\0' 
		|| domain_name[ 0 ] == L'\0' )
	{
		ASSERT( FALSE ); 
		log_trace( ( MSG_INFO, "*** check reg rule, but the reg path is null! ( rule 0x%0.8x ( %ws ), check 0x%0.8x ( %ws ) ) *** \n", 
			rule_item->rule.rule.reg.reg_path->param.reg.reg_path, 
			rule_item->rule.rule.reg.reg_path->param.reg.reg_path, 
			domain_name, 
			domain_name ) ); 
		goto _return; 
	}
	else
	{
		//ULONG name_len;  

		//name_len = wcsnlen( params->reg.reg_path.reg.reg_path, _MAX_REG_PATH_LEN ); 
		//ASSERT( name_len < _MAX_REG_PATH_LEN ); 

		//if( params->reg.reg_path.reg.reg_path[ name_len - 1 ] == L'\\' 
		//	|| params->reg.reg_path.reg.reg_path[ name_len - 1 ] == L'/' )
		//{
		//	params->reg.reg_path.reg.reg_path[ name_len - 1 ] = L'\0';  
		//}

		if( param_iteration != NULL )
		{
			log_trace( ( MSG_INFO, "record url is %ws compare with %s \n", rule_item->rule.rule.url.url->param.url.url, 
				( LPWSTR )param_iteration ) );

			_ret = compare_define_domain_name_no_case( rule_item->rule.rule.url.url->param.url.url, ( LPSTR )param_iteration ); 

		}
		else
		{
			_ret = compare_define_domain_name_no_case( rule_item->rule.rule.url.url->param.url.url, domain_name ); 
		}

		if( _ret != 0 )
		{
			ret = FALSE; 
		}
		else
		{
			ret = TRUE; 
		}
	}

_return: 
	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ret ) ); 
	return ret; 
}

NTSTATUS CALLBACK domain_name_iteration_init( PVOID param, PULONG hash_code, ULONG tbl_size, PVOID *param_out, PVOID *context )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	//LPWSTR name; 
	ULONG _hash_code; 
	LPCSTR domain_name; 
	ULONG name_len; 
	path_char_interator *fs_style_path_iter = NULL; 

	ASSERT( context != NULL ); 
	ASSERT( tbl_size > 0 ); 
	ASSERT( hash_code != NULL ); 

	if( param_out == NULL )
	{
		ASSERT( FALSE ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}; 

	if( param == NULL )
	{
		ASSERT( FALSE ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	*param_out = NULL; 
	*context = NULL; 
	*hash_code = INVALID_HASH_CODE; 

	//if( ( buf_len % 2 ) != 0 )
	//{
	//	ASSERT( FALSE ); 
	//	log_trace( ( MSG_WARNING, "buffer length is not wide char size aligned\n" ) ); 
	//}

	domain_name = ( LPCSTR )param; 

	//if( name[ buf_len / sizeof( WCHAR ) ] != L'\0' )
	//{
	//	name[ buf_len / sizeof( WCHAR ) ] = L'\0'; 
	//}

	name_len = strlen( domain_name ); 

	fs_style_path_iter = ( path_char_interator* )ALLOC_TAG_POOL( sizeof( path_char_interator ) ); 
	if( fs_style_path_iter == NULL )
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		goto _return; 
	}

	fs_style_path_iter->index = 0; 
	fs_style_path_iter->length = name_len + 1; 
	fs_style_path_iter->org_path = NULL; 
	fs_style_path_iter->iterator = NULL; 

	fs_style_path_iter->org_path = ( LPSTR )ALLOC_TAG_POOL( ( ( name_len + 1 ) * sizeof( CHAR ) ) * 2 ) ; 

	if( fs_style_path_iter->org_path == NULL )
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		goto _return; 
	}

	fs_style_path_iter->iterator = ( LPSTR )fs_style_path_iter->org_path + name_len + 1; 

	memcpy( ( PVOID )fs_style_path_iter->org_path, domain_name, ( name_len + 1 ) * sizeof( CHAR ) ); 
	memcpy( fs_style_path_iter->iterator, domain_name, ( name_len + 1 ) * sizeof( CHAR ) ); 

	ansi_str_to_upper( fs_style_path_iter->iterator ); 

	if( fs_style_path_iter->org_path[ name_len - 1 ] == DOMAIN_NAME_DELIM )
	{
		( ( LPSTR )fs_style_path_iter->org_path )[ name_len - 1 ] = '\0'; 
	}

	if( fs_style_path_iter->iterator[ name_len - 1 ] == DOMAIN_NAME_DELIM )
	{
		fs_style_path_iter->iterator[ name_len - 1 ] = '\0'; 
	}

	if( fs_style_path_iter->iterator[ 0 ] == DOMAIN_NAME_DELIM )
	{
		fs_style_path_iter->index = 1; 
	}

	_hash_code = ansi_str_hash( fs_style_path_iter->iterator + fs_style_path_iter->index, tbl_size ); 
	*param_out = fs_style_path_iter->iterator + fs_style_path_iter->index; 
	*context = ( PVOID )fs_style_path_iter; 
	*hash_code = _hash_code; 

_return:
	return ntstatus; 
}

ULONG CALLBACK hash_domain_name( PVOID param, ULONG table_size )
{
	ULONG hash_code; 

	hash_code = ansi_str_hash( ( LPCSTR )param, table_size ); 

	return hash_code; 
}

NTSTATUS CALLBACK domain_name_iteration_uninit( PVOID context )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	path_char_interator *fs_style_path_iter; 

	ASSERT( context != NULL ); 

	fs_style_path_iter = ( path_char_interator* )context; 
	if( fs_style_path_iter->org_path != NULL )
	{
		FREE_TAG_POOL( ( PVOID )fs_style_path_iter->org_path ); 
	}
	else
	{
		ASSERT( FALSE && "uninitialize a not initialized fs tyle name iterator" ); 
	}

	FREE_TAG_POOL( fs_style_path_iter ); 

	return ntstatus; 
}

ULONG CALLBACK hash_socket_action( PVOID param, ULONG table_size )
{
	sys_action_record *socket_action; 
	ULONG hash_code = INVALID_HASH_CODE; 

	//socket_action = ( sys_action_record* )param; 

	//hash_code = long_hash( socket_action->socket_info.dest_ip, table_size ); 

	return hash_code; 
}

INT32 CALLBACK socket_info_compare( PVOID param, PLIST_ENTRY list_item, PVOID param_iteration )
{
	INT32 ret = TRUE; 
	INT32 _ret; 
	action_rule_item *rule_item; 
	LPCSTR domain_name; 

	ASSERT( param != NULL ); 
	ASSERT( list_item != NULL ); 
	ASSERT( param_iteration == NULL ); 

	log_trace( ( MSG_INFO, "enter %s \n", __FUNCTION__ ) ); 
	rule_item = CONTAINING_RECORD( list_item, action_rule_item, entry ); 

	ASSERT( rule_item->rule.rule.url.url != NULL ); 

	domain_name = ( LPCSTR )param; 

#if 0
	if( rule_item->rule.rule.url.url != NULL )
	{
		log_trace( ( MSG_INFO, "record app name is %ws cur action app name is %ws \n", rule_item->rule.rule.reg.app->param.app.app_name, L"" ) ); 

		ret = compare_name_define( rule_item->rule.rule.reg.app->param.app.app_name, 
			L"" ); 

		if( ret == FALSE )
		{
			goto _return; 
		}
	}
#endif 

	if( rule_item->rule.rule.reg.reg_path->param.url.url[ 0 ] == L'\0' 
		|| domain_name[ 0 ] == L'\0' )
	{
		ASSERT( FALSE ); 
		log_trace( ( MSG_INFO, "*** check reg rule, but the reg path is null! ( rule 0x%0.8x ( %ws ), check 0x%0.8x ( %ws ) ) *** \n", 
			rule_item->rule.rule.reg.reg_path->param.reg.reg_path, 
			rule_item->rule.rule.reg.reg_path->param.reg.reg_path, 
			domain_name, 
			domain_name ) ); 
		goto _return; 
	}
	else
	{
		//ULONG name_len;  

		//name_len = wcsnlen( params->reg.reg_path.reg.reg_path, _MAX_REG_PATH_LEN ); 
		//ASSERT( name_len < _MAX_REG_PATH_LEN ); 

		//if( params->reg.reg_path.reg.reg_path[ name_len - 1 ] == L'\\' 
		//	|| params->reg.reg_path.reg.reg_path[ name_len - 1 ] == L'/' )
		//{
		//	params->reg.reg_path.reg.reg_path[ name_len - 1 ] = L'\0';  
		//}

		if( param_iteration != NULL )
		{
			log_trace( ( MSG_INFO, "record url is %ws compare with %s \n", rule_item->rule.rule.url.url->param.url.url, 
				( LPWSTR )param_iteration ) );

			_ret = compare_define_domain_name_no_case( rule_item->rule.rule.url.url->param.url.url, ( LPSTR )param_iteration ); 

		}
		else
		{
			_ret = compare_define_domain_name_no_case( rule_item->rule.rule.url.url->param.url.url, domain_name ); 
		}

		if( _ret != 0 )
		{
			ret = FALSE; 
		}
		else
		{
			ret = TRUE; 
		}
	}

_return: 
	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ret ) ); 
	return ret; 
}

NTSTATUS CALLBACK domain_name_iteration( PVOID param, PULONG hash_code, ULONG tbl_size, PVOID *param_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	path_char_interator *url_path_iter; 
	ULONG _hash_code; 

	//ASSERT( param != NULL ); 
	ASSERT( param_out != NULL ); 
	ASSERT( hash_code != NULL ); 
	ASSERT( tbl_size > 0 ); 

	if( param == NULL )
	{
		ASSERT( FALSE ); 
		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

	*param_out = NULL; 
	*hash_code = 0; 

	url_path_iter = ( path_char_interator* )param; 

	if( url_path_iter->index >= url_path_iter->length - 1 )
	{
		ASSERT( ( LONG )url_path_iter->index >= 0 ); 

		ntstatus = STATUS_INVALID_PARAMETER; 
		goto _return; 
	}

#ifdef DBG
	if( url_path_iter->index == url_path_iter->length - 1 )
	{
		ASSERT( url_path_iter->iterator[ url_path_iter->index - 1 ] != DOMAIN_NAME_DELIM ); 
	}
	else if( url_path_iter->index != 0 )
	{
		ASSERT( url_path_iter->iterator[ url_path_iter->index - 1 ] == DOMAIN_NAME_DELIM ); 
	}
#endif //DBG

	for( ; ; )
	{
		if( url_path_iter->iterator[ url_path_iter->index ] == DOMAIN_NAME_DELIM )
		{
			url_path_iter->index ++; 
			break; 
		}
		else if( url_path_iter->iterator[ url_path_iter->index ] == L'\0' )
		{
			ntstatus = STATUS_UNSUCCESSFUL; 
			goto _return; 
		}
		else if( url_path_iter->index == url_path_iter->length - 1 )
		{
			ntstatus = STATUS_UNSUCCESSFUL; 
			goto _return; 
		}

		url_path_iter->index ++; 
	}

	*param_out = url_path_iter->iterator + url_path_iter->index; 
	_hash_code = ansi_str_hash( url_path_iter->iterator + url_path_iter->index, tbl_size ); 
	*hash_code = _hash_code; 

_return:
	return ntstatus; 
}

NTSTATUS CALLBACK check_domain_rule( CHAR* dns_name, 
									ULONG dns_name_len, 
									USHORT prot, 
									PVOID *param_out )
{

	NTSTATUS ntstatus = STATUS_SUCCESS; 
	//access_rule_type rule_type; 
	common_hash_table *table; 
	PLIST_ENTRY item_found; 
	action_rule_item *rule_item; 

	ASSERT( dns_name != NULL ); 
	ASSERT( dns_name_len > 0 ); 
	ASSERT( param_out != NULL ); 

	//ASSERT( cur_action != NULL ); 

	log_trace( ( MSG_INFO, "enter %s \n", __FUNCTION__ ) ); ; 

	*param_out = NULL; 

	//ntstatus = check_sys_action_input_valid( cur_action ); 
	//if( !NT_SUCCESS( ntstatus ) ) 
	//{
	//	ASSERT( FALSE ); 
	//	goto _return; 
	//}

	table = get_action_rule_table( URL_RULE_TYPE ); 

	hold_hash_table_lock( table ); 

	ntstatus = find_in_hash_table_lock_free( ( PVOID )dns_name, 
		domain_name_iteration_init, 
		domain_name_iteration_uninit, 
		domain_name_iteration, 
		hash_domain_name, 
		domain_name_compare, 
		table, 
		&item_found ); 

	if( !NT_SUCCESS( ntstatus ) )
	{
		log_trace( ( MSG_ERROR, "!!!find this action rule failed\n" ) ); 
		goto _return; 
	}

	ASSERT( item_found != NULL ); 
	rule_item = ( action_rule_item* )CONTAINING_RECORD( item_found, action_rule_item, entry ); 

	if( rule_item->rule.action != ACTION_BLOCK )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		goto _return; 
	}

	ASSERT( rule_item->ref_count > 0 ); 

	log_trace( ( MSG_INFO, "add the rule record item reference count new is %d \n", 
		rule_item->ref_count ) ); 

	rule_item->ref_count ++; 

	*param_out = ( PVOID )rule_item; 

_return: 
	release_hash_table_lock( table ); 

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 

	return ntstatus; 
}

NTSTATUS check_socket_acl_direct( LPWSTR app_name, sys_action_record *action_record, data_trace_option *trace_option, action_response_type *response )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	access_rule_type rule_type; 
	PLIST_ENTRY item_found; 
	action_rule_item *rule_item; 
	//INT32 lock_held = FALSE; 
	//data_trace_option _trace_option; 
	action_response_type _response; 

	log_trace( ( MSG_INFO, "enter %s \n", __FUNCTION__ ) ); 

	ASSERT( response != NULL ); 
	ASSERT( action_record != NULL ); 

	//if( ( action_record->socket_info.src_port == 0 
	//	&& action_record->socket_info.dest_port == 0 ) 
	//	|| ( action_record->socket_info.src_ip == 0 
	//	&& action_record->socket_info.dest_ip == 0 ) 
	//	|| is_valid_prot_type( action_record->socket_info.prot ) == FALSE 
	//	|| is_socket_action( action_record->type ) == FALSE )
	//{
	//	ASSERT( FALSE && "input invalid socket action \n" ); 
	//	ntstatus = STATUS_INVALID_PARAMETER; 
	//	goto _return; 
	//}

	*response = ACTION_ALLOW; 
	//ASSERT( cur_action != NULL ); 

	//ntstatus = check_sys_action_input_valid( cur_action ); 
	//if( !NT_SUCCESS( ntstatus ) ) 
	//{
	//	ASSERT( FALSE ); 
	//	goto _return; 
	//}

	//hold_rbt_lock( &socket_rule_rbt ); 

	//lock_held = TRUE; 

	//ntstatus = rb_check_socket_action( &socket_rule_rbt, 
	//	app_name, 
	//	&action_record->socket_info, 
	//	trace_option, 
	//	&_response ); 

	//if( !NT_SUCCESS( ntstatus ) )
	//{
	//	log_trace( ( MSG_ERROR, "!!!find this action rule failed\n" ) ); 
	//	if( ntstatus == STATUS_NOT_FOUND )
	//	{
	//		*response = ACTION_LEARN; 
	//	}
	//	goto _return; 
	//}

	//ASSERT( _response == ACTION_ALLOW || _response == ACTION_BLOCK ); 

	//*response = _response; 

//_return: 
	//if( lock_held == TRUE )
	//{
	//	release_rbt_lock( &socket_rule_rbt ); 
	//}

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) );

	return ntstatus; 
}

