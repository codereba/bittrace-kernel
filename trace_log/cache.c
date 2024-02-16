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
#include <stdio.h>
#include <dontuse.h>
#include <suppress.h>
#include "cache.h"
#include <driverspecs.h>
#include "wild_card.h"

BOOLEAN order_priority = TRUE; 
BOOLEAN calc_lowest_priority = FALSE; 

LRESULT init_cache_hash_table( hash_table_cache *table, PERESOURCE lock, ULONG size, ULONG item_count, calc_hash_code_callback hash_func, ULONG flags )
{
	LRESULT ret = ERROR_SUCCESS; 
	INT32 i; 

	do 
	{
		ASSERT( table != NULL ); 

		if( lock == NULL )
		{
			ret = ERROR_INVALID_PARAMETER; 
			break; 
		}

		if( size == 0 )
		{
			ret = ERROR_INVALID_PARAMETER; 
			break; 
		}

		if( hash_func == NULL )
		{
			ret = ERROR_INVALID_PARAMETER; 
			break; 
		}

		if( item_count == 0 )
		{
			ret = ERROR_INVALID_PARAMETER; 
			break; 
		}

		table->lock = lock; 

		table->table = ( LIST_ENTRY* )allocate_mem( size * sizeof( LIST_ENTRY ) ); 
		if( table->table == NULL )
		{
			ret = ERROR_NOT_ENOUGH_MEMORY; 
			break; 
		}

		for( i = 0; ( ULONG )i < size; i ++ )
		{
			InitializeListHead( &table->table[ i ] ); 
		}

		table->calc_hash = hash_func; 

		table->item_count = 0; 
		table->find_count = 0; 
		table->flags = flags; 
		table->size = size; 
		table->max_item_count = item_count; 

	}while( FALSE );

	return ret; 
}

LRESULT uninit_cache_hash_table( hash_table_cache *table, uninit_cache_data_callback *uninit_func )
{
	LRESULT ret = ERROR_SUCCESS; 
	INT32 i; 
	LIST_ENTRY *entry; 
	LIST_ENTRY *next_entry; 
	cache_data *data; 

	do 
	{
		ASSERT( table != NULL ); 
		ASSERT( table->lock != NULL ); 

		ret = write_lock_cache_table( table ); 
		if( ret != ERROR_SUCCESS )
		{
			break; 
		}

		ASSERT( NULL != table->table ); 

		for( i = 0; ( ULONG )i < table->size; i ++ )
		{
			entry = table->table[ i ].Flink; 
			for( ; ; )
			{
				if( entry == &table->table[ i ] )
				{
					break; 
				}

				next_entry = entry->Flink; 

				RemoveEntryList( entry ); 

				data = CONTAINING_RECORD( entry, cache_data, cache_entry ); 
				data->begin_find_time = 0; 
				InitializeListHead( &data->cache_entry ); 

				if( uninit_func != NULL )
				{
					NTSTATUS _ntstatus;
					_ntstatus = ( *uninit_func )( data ); 
					if( _ntstatus != STATUS_SUCCESS )
					{
						dbg_print( MSG_ERROR, "uninitialize the cached data error 0x%0.8x\n", _ntstatus ); 
					}
				}
				
				data->hit_count = 0; 
				
				entry = next_entry; 
			}
		}

		ret = unlock_cache_table( table ); 
		if( ret != ERROR_SUCCESS )
		{
			break; 
		}

		free_mem( table->table ); 

		table->calc_hash = NULL; 

		table->item_count = 0; 
		table->find_count = 0; 
		table->flags = 0; 
		table->max_item_count = 0; 

	}while( FALSE );

	return ret; 
}

LRESULT init_cache_list( data_cache *cache_list, PERESOURCE lock, ULONG size, ULONG flags )
{
	LRESULT ret = ERROR_SUCCESS; 

	ASSERT( cache_list != NULL ); 

#ifdef _DRIVER
	cache_list->lock = lock; 
#else
#ifdef VISTA
	cache_list->lock = CreateMutexEx( NULL, NULL, 0, MUTEX_ALL_ACCESS ); 
#else
	cache_list->lock = CreateMutex( NULL, FALSE, NULL ); 
#endif //VISTA
#endif //_DRIVER

	if( NULL == cache_list->lock )
	{
		ret = ERROR_ERRORS_ENCOUNTERED;
		goto _return; 
	}

	InitializeListHead( &cache_list->cache_list ); 
	cache_list->item_count = 0; 
	cache_list->find_count = 0; 
	cache_list->flags = flags; 
	cache_list->max_item_count = size; 

_return:
	return ret; 
}

ULONG CALLBACK calc_file_name_hash( cache_data *cache, PVOID param, PVOID param2, ULONG table_size )
{
	ULONG hash_code; 
	LPCWSTR file_name; 
	ULONG name_len; 
	
	file_name = ( LPCWSTR )param; 
	name_len = ( ULONG )param2; 

	ASSERT( param != NULL ); 
	ASSERT( name_len > 0 ); 

	hash_code = calc_str_hash_code( file_name, name_len, table_size ); 
	ASSERT( hash_code < table_size ); 

	return hash_code; 
}

ULONG CALLBACK calc_file_id_hash( cache_data *cache, PVOID param1, PVOID param2, ULONG tbl_size )
{
	ULONG hash_code = INVALID_HASH_CODE; 

	do 
	{
		if( cache == NULL )
		{
			LPCWSTR name; 
			ULONG name_len; 

			if( param1 == NULL || param2 == NULL )
			{
				break; 
			}

			name = ( LPCWSTR )param1; 
			name_len = ( ULONG )( PVOID )param2; 
			hash_code = calc_str_hash_code( name, name_len, tbl_size ); 
		}
		else
		{
			FILE_ID_LINK *file_id;

			file_id = CONTAINING_RECORD( cache, FILE_ID_LINK, cache ); 
#ifdef DBG
			{

				hash_code = calc_str_hash_code( file_id->file_id.file_name, file_id->file_id.name_len, tbl_size ); 
				ASSERT( hash_code < tbl_size ); 

				if( hash_code != file_id->file_id.hash_code )
				{
					dbg_print( MSG_INFO, "the file id save hash code is not correctly (%u:%u)\n", hash_code, file_id->file_id.hash_code ); 
				}
			}
#else
			hash_code = file_id->file_id.hash_code; 
#endif //DBG
		}

		ASSERT( hash_code < tbl_size ); 
	}while( FALSE );

	return hash_code; 
}

LRESULT hash_add_cache_data_dbg( hash_table_cache *table, cache_data *data, ULONG search_count, calc_hash_code_callback hash_code_func, check_cache_data_callback check_valid/*PVOID data, ULONG data_len */)
{
	LRESULT ret = ERROR_SUCCESS; 
	ULONG hash_code; 
	LIST_ENTRY *list_head; 
	LIST_ENTRY *entry; 
	cache_data *cache_found; 

	ASSERT( table != NULL ); 
	ASSERT( data != NULL ); 
	ASSERT( table->lock != NULL ); 
	ASSERT( hash_code_func != NULL ); 

	do 
	{
		dbg_print( 0, "insert new data %p\n", data ); 
		data->hit_count = 0;

		hash_code = hash_code_func( data, NULL, NULL, table->size ); 

		ASSERT( hash_code < table->size ); 

		list_head = &table->table[ hash_code ]; 


		ret = read_lock_cache_table( table ); 
		if( ret != ERROR_SUCCESS )
		{
			break; 
		}

		entry = list_head->Flink; 

		for( ; ; )
		{
			if( entry == list_head )
			{
				cache_found = NULL; 
				break; 
			}

			cache_found = CONTAINING_RECORD( entry, cache_data, cache_entry ); 

			if( cache_found == data )
			{
				break; 
			}

			entry = entry->Flink; 
		}

		ret = unlock_cache_table( table ); 
		if( ret != ERROR_SUCCESS )
		{
			break; 
		}

		if( cache_found == NULL )
		{
			if( table->item_count >= table->max_item_count )
			{
				ret = hash_remove_rarest_hit_data( table, hash_code, search_count ); 
				if( ret != ERROR_SUCCESS )
				{
					dbg_print( MSG_INFO, "remove the rarest hitted cache data error 0x%0.8x\n", ret ); 
				}
			}

			ret = write_lock_cache_table( table ); 
			if( ret != ERROR_SUCCESS )
			{
				break; 
			}

			ASSERT( TRUE == IsListEmpty( &data->cache_entry ) ); 

			if( check_valid != NULL )
			{
				ret = check_valid( data ); 
				if( ret != ERROR_SUCCESS )
				{
					__asm int 3; 
				}
			}

			data->begin_find_time = table->find_count; 
			InsertTailList( list_head, &data->cache_entry ); 
			table->item_count ++; 

			ret = unlock_cache_table( table ); 
			if( ret != ERROR_SUCCESS )
			{
				break; 
			}
		}
	}while( FALSE ); 

	return ret; 
}

LRESULT hash_add_cache_data( hash_table_cache *table, cache_data *data, ULONG search_count, calc_hash_code_callback hash_code_func/*PVOID data, ULONG data_len */)
{
	LRESULT ret = ERROR_SUCCESS; 
	ULONG hash_code; 
	LIST_ENTRY *list_head; 
	LIST_ENTRY *entry; 
	cache_data *cache_found; 

	ASSERT( table != NULL ); 
	ASSERT( data != NULL ); 
	ASSERT( table->lock != NULL ); 
	ASSERT( hash_code_func != NULL ); 

	do 
	{
		dbg_print( 0, "insert new data %p\n", data ); 
		data->hit_count = 0;

		hash_code = hash_code_func( data, NULL, NULL, table->size );
		ASSERT( hash_code < table->size ); 

		list_head = &table->table[ hash_code ]; 


		ret = read_lock_cache_table( table ); 
		if( ret != ERROR_SUCCESS )
		{
			break; 
		}

		entry = list_head->Flink; 

		for( ; ; )
		{
			if( entry == list_head )
			{
				cache_found = NULL; 
				break; 
			}

			cache_found = CONTAINING_RECORD( entry, cache_data, cache_entry ); 

			if( cache_found == data )
			{
				break; 
			}

			entry = entry->Flink; 
		}

		ret = unlock_cache_table( table ); 
		if( ret != ERROR_SUCCESS )
		{
			break; 
		}

		if( cache_found == NULL )
		{
			if( table->item_count >= table->max_item_count )
			{
				ret = hash_remove_rarest_hit_data( table, hash_code, search_count ); 
				if( ret != ERROR_SUCCESS )
				{
					dbg_print( MSG_INFO, "remove the rarest hitted cache data error 0x%0.8x\n", ret ); 
				}
			}

			ret = write_lock_cache_table( table ); 
			if( ret != ERROR_SUCCESS )
			{
				break; 
			}

			ASSERT( TRUE == IsListEmpty( &data->cache_entry ) );

			data->begin_find_time = table->find_count; 
			InsertTailList( list_head, &data->cache_entry ); 
			table->item_count ++; 

			ret = unlock_cache_table( table ); 
			if( ret != ERROR_SUCCESS )
			{
				break; 
			}
		}
	}while( FALSE ); 

	return ret; 
}

LRESULT hash_find_rarest_cache_data_lock_free( hash_table_cache *table, ULONG hash_code, cache_data **data_out, ULONG count )
{
	LRESULT ret = ERROR_SUCCESS; 
	PLIST_ENTRY entry; 
	PLIST_ENTRY list_head; 
	cache_data *data; 
	LONG min_unhit_count = -1; 
	ULONG lower_item_count; 
	ULONG find_count; 
	cache_data *rarest_hit_data = NULL; 
	INT32 i; 

	ASSERT( table !=  NULL ); 
	ASSERT( data_out != NULL ); 

	*data_out = NULL; 

	do 
	{
		if( count == 0 )
		{
			ret = ERROR_INVALID_PARAMETER;
			break; 
		}

		find_count = 0; 
		lower_item_count = 0; 

		if( hash_code == INVALID_HASH_CODE )
		{
			for( i = 0; ( ULONG )i < table->size; i ++ )
			{
				list_head  = &table->table[ i ]; 

				entry = list_head->Flink; 
				for( ; ; )
				{
					if( entry == list_head )
					{
						break; 
					}

					data = CONTAINING_RECORD( entry, cache_data, cache_entry ); 

					ASSERT( table->find_count > 0 ); 
					ASSERT( data->hit_count >= 0 ); 
					ASSERT( data->hit_count <= table->find_count ); 

					if( ( table->find_count - data->begin_find_time ) - data->hit_count > min_unhit_count )
					{
						lower_item_count ++; 
						if( lower_item_count >= 3 )
						{
							dbg_print( MSG_ERROR, "the cache list is not sort by priority correctly lower item found time %u\n", lower_item_count ); 
						}

						min_unhit_count = ( table->find_count - data->begin_find_time ) - data->hit_count; 
						rarest_hit_data = data;
					}

					entry = entry->Flink; 

					find_count ++; 

					if( find_count == count )
					{
						break; 
					}
				}
			}
		}
		else
		{
			ASSERT( hash_code < table->size ); 

			list_head  = &table->table[ hash_code ]; 

			entry = list_head->Flink; 
			
			if( TRUE == calc_lowest_priority )
			{
				for( ; ; )
				{
					if( entry == list_head )
					{
						break; 
					}
					data = CONTAINING_RECORD( entry, cache_data, cache_entry ); 

					ASSERT( table->find_count > 0 ); 
					ASSERT( data->hit_count >= 0 ); 
					ASSERT( data->hit_count <= table->find_count ); 

					if( ( table->find_count - data->begin_find_time ) - data->hit_count > min_unhit_count )
					{
						ASSERT( FALSE ); 
						lower_item_count ++; 
						if( lower_item_count >= 3 )
						{
							dbg_print( MSG_ERROR, "the cache list is not sort by priority correctly lower item found time %u\n", lower_item_count ); 

						}
						min_unhit_count = ( table->find_count - data->begin_find_time ) - data->hit_count; 
						rarest_hit_data = data; 
					}

					entry = entry->Flink; 

					find_count ++; 
					if( find_count == count )
					{
						break; 
					}
				}
			}
			else
			{
				if( entry == list_head )
				{
					rarest_hit_data = NULL; 
					break; 
				}

				data = CONTAINING_RECORD( entry, cache_data, cache_entry ); 

				ASSERT( table->find_count > 0 ); 
				ASSERT( data->hit_count >= 0 ); 
				ASSERT( data->hit_count <= table->find_count ); 

				min_unhit_count = ( table->find_count - data->begin_find_time ) - data->hit_count; 
				rarest_hit_data = data; 
				break; 
			}
		}
#ifdef _DEBUG
		if( 0 < table->item_count ) 
		{
			ASSERT( NULL != rarest_hit_data ); 
		}
#endif //_DEBUG

	} while ( FALSE ); 

	*data_out = rarest_hit_data; 
	return ret; 
}

LRESULT hash_remove_rarest_hit_data( hash_table_cache *table, ULONG hash_code, ULONG search_size )
{
	LRESULT ret = ERROR_SUCCESS; 
	cache_data *data_found; 
	BOOLEAN lock_held = FALSE; 

	ASSERT( NULL != table ); 

	do 
	{

#ifdef DBG
		if( search_size == 0 )
		{
			ASSERT( FALSE ); 
			ret = ERROR_INVALID_PARAMETER; 
			break; 
		}
#endif //DBG

		ret = write_lock_cache_table( table ); 
		if( ret != ERROR_SUCCESS )
		{
			break; 
		}

		lock_held = TRUE; 

		ret = hash_find_rarest_cache_data_lock_free( table, hash_code, &data_found, search_size ); 

		if( ret != ERROR_SUCCESS )
		{
			break; 
		}

		if( data_found == NULL )
		{
			ret = ERROR_NOT_FOUND; 
			break; 
		}

		dbg_print( MSG_INFO, "find the rarest hit cache data 0x%0.8x its hit count is %u \n", data_found, data_found->hit_count/*, data_found->data */); 
		RemoveEntryList( &data_found->cache_entry );
		init_cache_data( data_found ); 

	}while( FALSE ); 

	if( TRUE == lock_held )
	{
		ret = unlock_cache_table( table );
	}

	return ret; 
}

LRESULT add_cache_data( data_cache *cache_list, cache_data *data, ULONG search_count/*PVOID data, ULONG data_len */)
{
	LRESULT ret = ERROR_SUCCESS; 
	LIST_ENTRY *list_head; 
	LIST_ENTRY *cache_entry; 
	cache_data *cache;

	ASSERT( cache_list != NULL ); 
	ASSERT( data != NULL ); 

	do 
	{
		list_head = &cache_list->cache_list; 
		
		data->hit_count = 0; 

		cache_entry = list_head->Blink; 

		for( ; ; )
		{
			if( cache_entry == list_head )
			{
				cache = NULL; 
				break; 
			}

			cache = CONTAINING_RECORD( cache_entry, cache_data, cache_entry ); 

			if( cache == data )
			{
				break; 
			}

			cache_entry = cache_entry->Flink; 
		}

		if( cache != NULL )
		{
			ret = ERROR_ALREADY_EXISTS; 
			break; 
		}

		if( cache_list->item_count > cache_list->max_item_count )
		{
			ret = remove_rarest_hit_data( cache_list, search_count ); 
			if( ret != ERROR_SUCCESS )
			{
				dbg_print( MSG_INFO, "remove the rarest hitted cache data error 0x%0.8x\n", ret ); 
			}
		}

		ret = write_lock_cache_list( cache_list ); 
		if( ret != ERROR_SUCCESS )
		{
			break; 
		}

		data->begin_find_time = cache_list->find_count; 
		InsertTailList( &cache_list->cache_list, &data->cache_entry ); 
		cache_list->item_count ++; 

		ret = unlock_cache_list( cache_list ); 
		if( ret != ERROR_SUCCESS )
		{
			break; 
		}
	}while( FALSE );

	return ret; 
}

LRESULT find_cache_lock_free( data_cache *cache_list, PVOID param1, PVOID param2, cache_data **data_out, ULONG *search_time )
{
	LRESULT ret = ERROR_SUCCESS; 
	PLIST_ENTRY entry; 
	cache_data *data; 
	ULONG next_item_offset; 
	ULONG find_time; 

#ifdef _REALIZE_CACHE_LIST
	do 
	{
		ASSERT( cache_list != NULL ); 
		ASSERT( data_out != NULL ); 
		ASSERT( found_time != NULL ); 

		do 
		{
			*search_time = 0; 

			if( cache_list->flags & CACHE_LIFO_FIND_MODE )
			{
				next_item_offset = FIELD_OFFSET( LIST_ENTRY, Blink ); 
			}
			else
			{
				next_item_offset = FIELD_OFFSET( LIST_ENTRY, Flink ); 
			}

			cache_list->find_count ++; 
			
			find_time = 0; 
			entry = *( ( LIST_ENTRY** )( ( BYTE* )&cache_list->cache_list + next_item_offset ) ); 
			for( ; ; )
			{
				if( entry == &cache_list->cache_list )
				{
					ret = ERROR_NOT_FOUND; 
					data = NULL; 
					break; 
				}

				data = CONTAINING_RECORD( entry, cache_data, cache_entry ); 
				ret = _compare_file_id( data, param1, param2 ); 
				if( ret == ERROR_SUCCESS )
					//if( data->data == data_find )
				{
					data->hit_count ++; 
					break; 
				}

				entry = *( ( LIST_ENTRY** )( ( BYTE* )entry + next_item_offset ) ); 
				find_time ++; 
			}

			//unlock_cache_list( cache_list ); 

		}while( FALSE ); 

		*data_out = data; 
		*search_time = find_time; 
	} while ( FALSE ); 

#endif //REALIZE_CACHE_LIST

	return ret; 
}

LRESULT find_cache( data_cache *cache_list, PVOID param1, PVOID param2, cache_data **data_out, ULONG *found_time )
{
	LRESULT ret = ERROR_SUCCESS; 
	PLIST_ENTRY entry; 
	cache_data *data; 
	ULONG next_item_offset; 
	ULONG find_time; 

#ifdef REALIZE_CACHE_LIST
	ASSERT( cache_list != NULL ); 
	ASSERT( data_out != NULL ); 
	ASSERT( found_time != NULL ); 

	do 
	{
		*found_time = 0; 

		if( cache_list->flags & CACHE_LIFO_FIND_MODE )
		{
			next_item_offset = FIELD_OFFSET( LIST_ENTRY, Blink ); 
		}
		else
		{
			next_item_offset = FIELD_OFFSET( LIST_ENTRY, Flink ); 
		}

		read_lock_cache_list( cache_list ); 

		cache_list->find_count ++; 

		find_time = 0; 
		entry = *( ( LIST_ENTRY** )( ( BYTE* )&cache_list->cache_list + next_item_offset ) ); 
		for( ; ; )
		{
			if( entry == &cache_list->cache_list )
			{
				ret = ERROR_NOT_FOUND; 
				data = NULL; 
				break; 
			}

			data = CONTAINING_RECORD( entry, cache_data, cache_entry ); 
			ret = _compare_file_id( data, param1, param2 ); 
			if( ret == ERROR_SUCCESS )
			//if( data->data == data_find )
			{
				data->hit_count ++; 
				break; 
			}

			entry = *( ( LIST_ENTRY** )( ( BYTE* )entry + next_item_offset ) ); 
			find_time ++; 
		}

		if( data != NULL )
		{
			LRESULT _ret; 

			unlock_cache_list( cache_list ); 
			write_lock_cache_list( cache_list ); 

			_ret = order_cache_data_by_priority( cache_list, data ); 
			if( _ret != ERROR_SUCCESS )
			{
				dbg_print( MSG_ERROR, "order cache data by priority error 0x%0.8x\n", _ret ); 
			}
		}

		unlock_cache_list( cache_list ); 
		
	}while( FALSE ); 

	*data_out = data; 
	*found_time = find_time; 

#endif //REALIZE_CACHE_LIST

	return ret; 
}

LRESULT _compare_file_id( cache_data *data, PVOID param1, PVOID param2 )
{
	LRESULT ret = ERROR_SUCCESS; 
	INT32 _ret; 
	FILE_ID_LINK *file_id; 
	LPCWSTR dest_file; 
	ULONG name_len; 

	do 
	{
		ASSERT( param1 != NULL );

		dest_file = ( LPCWSTR )param1; 
		name_len = ( ULONG )param2;

		file_id = CONTAINING_RECORD( data, FILE_ID_LINK, cache ); 

		_ret = compare_str( file_id->file_id.file_name, file_id->file_id.name_len, dest_file, name_len ); 
		if( _ret != 0 )
		{
			ret = ERROR_NOT_FOUND; 
			break; 
		}
	} while ( FALSE ); 

	return ret; 
}

LRESULT hash_find_cache( hash_table_cache *table, 
	PVOID param1, 
	PVOID param2, 
	ULONG ref_obj_off, 
	calc_hash_code_callback calc_hash_code_func, 
	compare_hash_item_callback compare_hash_func, 
	cache_data **data_out, 
	ULONG *found_time )
{
	LRESULT ret = ERROR_SUCCESS; 
	LIST_ENTRY *list_head; 
	PLIST_ENTRY entry; 
	cache_data *data; 
	ULONG next_item_offset; 
	ULONG find_time; 
	ULONG hash_code; 
	LRESULT _ret; 
	ref_obj *_obj; 

	ASSERT( table != NULL ); 
	ASSERT( param1 != NULL ); 
	ASSERT( param2 != NULL ); 
	ASSERT( data_out != NULL ); 
	ASSERT( calc_hash_code_func != NULL ); 
	ASSERT( compare_hash_func != NULL ); 

	do 
	{
		read_lock_cache_table( table ); 
		ret = hash_find_cache_lock_free( table, param1, param2, calc_hash_code_func, compare_hash_func, &data, &find_time, &hash_code ); 
		if( ret == ERROR_SUCCESS )
		{
			ASSERT( data != NULL ); 
			_obj = ( ref_obj* )( ( BYTE* )data - ref_obj_off ); 
			reference_obj( _obj ); 
		}

		unlock_cache_table( table ); 

		if( ret != ERROR_SUCCESS )
		{
			ASSERT( data == NULL ); 
		}
		else
		{
			ASSERT( data != NULL ); 
			ASSERT( hash_code < table->size ); 

			if( TRUE == order_priority )
			{
				write_lock_cache_table( table ); 

				_ret = hash_order_cache_data_by_priority( table, data, hash_code ); 
				if( _ret != ERROR_SUCCESS )
				{
					dbg_print( MSG_ERROR, "order cache data by priority error 0x%0.8x\n", _ret ); 
				}

				unlock_cache_table( table ); 
			}
		}
	}while( FALSE ); 

	*data_out = data; 

	if( found_time != NULL )
	{
		*found_time = find_time; 
	}

	return ret; 
}

LRESULT hash_find_cache_lock_free( hash_table_cache *table, PVOID param1, PVOID param2, 
	calc_hash_code_callback calc_hash_func, 
	compare_hash_item_callback compare_func, 
	cache_data **data_out, 
	ULONG *found_time, 
	ULONG *hash_code_out )
{
	LRESULT ret = ERROR_SUCCESS; 
	LIST_ENTRY *list_head; 
	PLIST_ENTRY entry; 
	cache_data *data; 
	ULONG next_item_offset; 
	ULONG find_time; 
	ULONG hash_code; 
	LRESULT _ret; 

	ASSERT( table != NULL ); 
	ASSERT( param1 != NULL ); 
	ASSERT( param2 != NULL ); 
	ASSERT( data_out != NULL ); 
	ASSERT( calc_hash_func != NULL ); 

	do 
	{
		*found_time = 0; 

		if( table->flags & CACHE_LIFO_FIND_MODE )
		{
			next_item_offset = FIELD_OFFSET( LIST_ENTRY, Blink ); 
		}
		else
		{
			next_item_offset = FIELD_OFFSET( LIST_ENTRY, Flink ); 
		}

		table->find_count ++; 

		find_time = 0; 

		hash_code = calc_hash_func( NULL, param1, param2, table->size ); 
		if( hash_code == INVALID_HASH_CODE )
		{
			ret = ERROR_ERRORS_ENCOUNTERED; 
			break; 
		}

		ASSERT( hash_code < table->size ); 
		ASSERT( hash_code < table->size ); 

		list_head = &table->table[ hash_code ]; 

		entry = *( ( LIST_ENTRY** )( ( BYTE* )list_head + next_item_offset ) ); 
		for( ; ; )
		{
			if( entry == list_head )
			{
				ret = ERROR_NOT_FOUND; 
				data = NULL; 
				break; 
			}

			data = CONTAINING_RECORD( entry, cache_data, cache_entry ); 

			_ret = compare_func( data, param1, param2 ); 
			if( _ret == 0 )
			{
				data->hit_count ++;
				break; 
			}

			entry = *( ( LIST_ENTRY** )( ( BYTE* )entry + next_item_offset ) ); 
			find_time ++; 
		}
	}while( FALSE ); 

	if( hash_code_out != NULL )
	{
		*hash_code_out = hash_code; 
	}

	*data_out = data; 

	if( found_time != NULL )
	{
		*found_time = find_time; 
	}

	return ret; 
}

LRESULT find_rarest_cache_data_lock_free( data_cache *cache_list, cache_data **data_out, ULONG count )
{
	LRESULT ret = ERROR_SUCCESS; 
	PLIST_ENTRY entry; 
	cache_data *data; 
	LONG min_unhit_count = -1; 
	ULONG lower_item_count; 
	ULONG find_count; 
	cache_data *rarest_hit_data = NULL; 

	ASSERT( cache_list !=  NULL ); 
	ASSERT( data_out != NULL ); 

	*data_out = NULL; 

	do 
	{
		find_count = 0; 
		lower_item_count = 0; 
		entry = cache_list->cache_list.Flink; 
		for( ; ; )
		{
			if( entry == &cache_list->cache_list )
			{
				break; 
			}

			if( find_count == count )
			{
				break; 
			}

			data = CONTAINING_RECORD( entry, cache_data, cache_entry ); 

			ASSERT( cache_list->find_count > 0 ); 
			ASSERT( data->hit_count >= 0 ); 
			ASSERT( data->hit_count <= cache_list->find_count ); 

			if( ( cache_list->find_count - data->begin_find_time ) - data->hit_count > min_unhit_count )
			{
				ASSERT( FALSE ); 
				lower_item_count ++; 
				if( lower_item_count >= 3 )
				{
					dbg_print( MSG_ERROR, "the cache list is not sort by priority correctly lower item found time %u\n", lower_item_count ); 

				}
				min_unhit_count = ( cache_list->find_count - data->begin_find_time ) - data->hit_count; 
				rarest_hit_data = data; 
			}

			entry = entry->Flink; 

			find_count ++; 
		}
	} while ( FALSE ); 

#ifdef _DEBUG
	if( FALSE == IsListEmpty( &cache_list->cache_list )) 
	{
		ASSERT( NULL != rarest_hit_data ); 
	}
#endif //_DEBUG

	*data_out = rarest_hit_data; 
	return ret; 
}

LRESULT remove_rarest_hit_data( data_cache *cache_list, ULONG search_size )
{
	LRESULT ret = ERROR_SUCCESS; 
	cache_data *data_found; 
	BOOLEAN lock_held = FALSE; 

	ASSERT( NULL != cache_list ); 

	do 
	{
		ret = write_lock_cache_list( cache_list ); 
		if( ret != ERROR_SUCCESS )
		{
			break; 
		}

		lock_held = TRUE; 
		ret = find_rarest_cache_data_lock_free( cache_list, &data_found, search_size ); 

		if( ret != ERROR_SUCCESS )
		{
			break; 
		}

		if( data_found == NULL )
		{
			ret = ERROR_NOT_FOUND; 
			break; 
		}

		RemoveEntryList( &data_found->cache_entry ); 
		init_cache_data( data_found ); 

	}while( FALSE );

	if( TRUE == lock_held )
	{
		ret = unlock_cache_list( cache_list );
	}
	return ret; 
}

LRESULT dump_cache_list( data_cache *cache_list )
{
	LRESULT ret = ERROR_SUCCESS; 
	cache_data *data; 
	LIST_ENTRY *entry; 
	ULONG item_count; 

	ASSERT( cache_list != NULL ); 
	do 
	{
		item_count = 0; 
		entry = cache_list->cache_list.Blink; 
		for( ; ; )
		{
			if( entry == &cache_list->cache_list )
			{
				break; 
			}

			data = CONTAINING_RECORD( entry, cache_data, cache_entry ); 
			dump_cache_data( data ); 

			entry = entry->Blink; 
			item_count ++; 
		}
	}while( FALSE );
	
	dbg_print( MSG_INFO, "all cached data count is %u\n", item_count ); 
	return ret; 
}

LRESULT dump_hash_cache_table( hash_table_cache *table, ULONG dump_count )
{
	LRESULT ret = ERROR_SUCCESS; 
	cache_data *data; 
	LIST_ENTRY *entry; 
	LIST_ENTRY *list_head; 
	ULONG item_count; 
	INT32 i; 

	ASSERT( table != NULL ); 
	do 
	{
		item_count = 0; 
		for( i = 0; ( ULONG )i < table->size; i ++ )
		{
			list_head  = &table->table[ i ]; 

			entry = list_head->Flink; 
			for( ; ; )
			{
				if( entry == list_head )
				{
					break; 
				}

				data = CONTAINING_RECORD( entry, cache_data, cache_entry ); 

				ASSERT( table->find_count > 0 ); 
				ASSERT( data->hit_count >= 0 ); 
				ASSERT( data->hit_count <= table->find_count ); 

				dump_cache_data( data ); 

				entry = entry->Flink; 

				item_count ++; 

				if( item_count == dump_count )
				{
					break; 
				}
			}
		}
	}while( FALSE );

	dbg_print( MSG_INFO, "all cached data count is %u dump count is %u\n", item_count, dump_count ); 
	return ret; 
}

VOID thread_order_cache( PVOID context )
{
	return; 
}