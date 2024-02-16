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

#ifdef DRIVER
#include "common.h"
#include <ntstrsafe.h>
#else
#include "common_func.h"
#endif //DRIVER

#ifndef DRIVER
#define allocate_mem( size ) malloc( size )
#define free_mem( buf ) free( buf )
#endif //DRIVER

#include "btree_node.h"
#include "b_tree.h"
#include "path_tree.h"

#if defined(ASSERT) 
#undef ASSERT
#endif //ASSERT

#define INVALID_CONF_LEVLEL 0xffff
#define INVALID_INTE_LEVEL 0xffff 
#define INVALID_CLASS 0xffffffff

#if defined(_DEBUG)
#include <assert.h>

#define ASSERT(x) if( ( x ) == FALSE ) __asm int 3; 
//#define ASSERT(x) __assume(x)
#else
#define ASSERT(x) 
#endif

#ifndef DRIVER

typedef enum _msg_op{
	OPERATE_EXEC      = 0x0001,
	OPERATE_WRITE     = 0x0002,
	OPERATE_READ      = 0x0004,
	OPERATE_APPEND    = 0x0008,
	OPERATE_DELETE    = 0x0010,
	/*wdh modify*/
	OPERATE_MEASURE   = 0x0020,
	OPERATE_MOUNT     = 0x0040,
} msg_op, *pmsg_op; 

#define OPERATE_MASK ( OPERATE_EXEC | OPERATE_WRITE | OPERATE_READ | OPERATE_APPEND | OPERATE_DELETE | OPERATE_MEASURE | OPERATE_MOUNT ) 

#define is_valid_operation( op ) ( ( op & ( ~OPERATE_MASK ) ) == 0 )

#define InitializeListHead32(ListHead) (\
	(ListHead)->Flink = (ListHead)->Blink = PtrToUlong((ListHead)))

#if !defined(MIDL_PASS) && !defined(SORTPP_PASS)

#define RTL_STATIC_LIST_HEAD(x) LIST_ENTRY x = { &x, &x }

FORCEINLINE
	VOID
	InitializeListHead(
	__out PLIST_ENTRY ListHead
	)
{
	ListHead->Flink = ListHead->Blink = ListHead;
}

__checkReturn
	BOOLEAN
	FORCEINLINE
	IsListEmpty(
	__in const LIST_ENTRY * ListHead
	)
{
	return (BOOLEAN)(ListHead->Flink == ListHead);
}

FORCEINLINE
	BOOLEAN
	RemoveEntryList(
	__in PLIST_ENTRY Entry
	)
{
	PLIST_ENTRY Blink;
	PLIST_ENTRY Flink;

	Flink = Entry->Flink;
	Blink = Entry->Blink;
	Blink->Flink = Flink;
	Flink->Blink = Blink;
	return (BOOLEAN)(Flink == Blink);
}

FORCEINLINE
	PLIST_ENTRY
	RemoveHeadList(
	__inout PLIST_ENTRY ListHead
	)
{
	PLIST_ENTRY Flink;
	PLIST_ENTRY Entry;

	Entry = ListHead->Flink;
	Flink = Entry->Flink;
	ListHead->Flink = Flink;
	Flink->Blink = ListHead;
	return Entry;
}



FORCEINLINE
	PLIST_ENTRY
	RemoveTailList(
	__inout PLIST_ENTRY ListHead
	)
{
	PLIST_ENTRY Blink;
	PLIST_ENTRY Entry;

	Entry = ListHead->Blink;
	Blink = Entry->Blink;
	ListHead->Blink = Blink;
	Blink->Flink = ListHead;
	return Entry;
}


FORCEINLINE
	VOID
	InsertTailList(
	__inout PLIST_ENTRY ListHead,
	__inout __drv_aliasesMem PLIST_ENTRY Entry
	)
{
	PLIST_ENTRY Blink;

	Blink = ListHead->Blink;
	Entry->Flink = ListHead;
	Entry->Blink = Blink;
	Blink->Flink = Entry;
	ListHead->Blink = Entry;
}


FORCEINLINE
	VOID
	InsertHeadList(
	__inout PLIST_ENTRY ListHead,
	__inout __drv_aliasesMem PLIST_ENTRY Entry
	)
{
	PLIST_ENTRY Flink;

	Flink = ListHead->Flink;
	Entry->Flink = Flink;
	Entry->Blink = ListHead;
	Flink->Blink = Entry;
	ListHead->Flink = Entry;
}

FORCEINLINE
	VOID
	AppendTailList(
	__inout PLIST_ENTRY ListHead,
	__inout PLIST_ENTRY ListToAppend
	)
{
	PLIST_ENTRY ListEnd = ListHead->Blink;

	ListHead->Blink->Flink = ListToAppend;
	ListHead->Blink = ListToAppend->Blink;
	ListToAppend->Blink->Flink = ListHead;
	ListToAppend->Blink = ListEnd;
}

FORCEINLINE
	PSINGLE_LIST_ENTRY
	PopEntryList(
	__inout PSINGLE_LIST_ENTRY ListHead
	)
{
	PSINGLE_LIST_ENTRY FirstEntry;
	FirstEntry = ListHead->Next;
	if (FirstEntry != NULL) {
		ListHead->Next = FirstEntry->Next;
	}

	return FirstEntry;
}


FORCEINLINE
	VOID
	PushEntryList(
	__inout PSINGLE_LIST_ENTRY ListHead,
	__inout __drv_aliasesMem PSINGLE_LIST_ENTRY Entry
	)
{
	Entry->Next = ListHead->Next;
	ListHead->Next = Entry;
}

#define release_sp_lock( lock )
#define hold_sp_lock( lock ) 
#define KeInitializeSpinLock( lock ) 
typedef unsigned char KIRQL; 

#endif //(MIDL_PASS)
#endif //DRIVER

NTSTATUS init_path_tree( path_tree *tree, ULONG tree_order )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		ASSERT( tree != NULL ); 
		ntstatus = init_btree( tree, tree_order ); 

	}while( FALSE );

	return ntstatus; 
}

typedef struct _data_stack
{
	LIST_ENTRY entry; 
	PVOID element; 
} data_stack, *pdata_stack; 

typedef struct _stack_container
{
	KSPIN_LOCK lock; 
	LIST_ENTRY elements; 
} stack_container, *pstack_container; 

NTSTATUS init_stack( stack_container *stack )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		ASSERT( stack != NULL ); 
		
		InitializeListHead( &stack->elements ); 
		KeInitializeSpinLock( &stack->lock ); 

	}while( FALSE );

	return ntstatus; 
}
NTSTATUS push_stack( stack_container *stack, PVOID element )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	data_stack *data = NULL; 
	KIRQL old_irql; 

	ASSERT( stack != NULL ); 
	ASSERT( element != NULL ); 

	do 
	{
		data = ( data_stack* )allocate_mem( sizeof( data_stack ) ); 
		if( data == NULL )
		{
			break; 
		}

		InitializeListHead( &data->entry ); 
		data->element = element; 

		hold_sp_lock( stack->lock, old_irql ); 
		InsertHeadList( &stack->elements, &data->entry ); 
		release_sp_lock( stack->lock, old_irql ); 
	}while( FALSE );

	if( ntstatus != STATUS_SUCCESS )
	{
		free_mem( data ); 
	}

	return ntstatus; 
}

NTSTATUS pop_stack( stack_container *stack, PVOID *element_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	KIRQL old_irql; 
	LIST_ENTRY *entry; 
	data_stack *_stack = NULL; 

	do
	{
		ASSERT( element_out != NULL ); 
		*element_out = NULL; 

		hold_sp_lock( stack->lock, old_irql ); 

		entry = RemoveTailList( &stack->elements ); 

		if( entry == &stack->elements )
		{
			release_sp_lock( stack->lock, old_irql ); 
			ntstatus = STATUS_NO_MORE_ENTRIES; 
			break; 
		}

		_stack = CONTAINING_RECORD( entry, data_stack, entry ); 

		release_sp_lock( stack->lock, old_irql ); 

		*element_out = _stack->element; 

		free_mem( _stack ); 
	
	}while( FALSE ); 

	return ntstatus; 
}

NTSTATUS _release_path_tree_node( path_tree_node *node, btree_node **root_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		ASSERT( node != NULL ); 
		//ASSERT( node->root != NULL ); 

		dbg_print( MSG_INFO, "enter %s\n", __FUNCTION__ ); 

		dump_path_comp_node( node ); 

		ASSERT( PATH_TREE_NODE_MAGIC_NUM == node->magic_num ); 
#ifdef DBG
		{
			ULONG *end_magic_num; 

			ASSERT( node->dir_len <= MAX_NATIVE_NAME_SIZE ); 
			end_magic_num = ( ULONG * )( ( BYTE* )node + ( node->dir_len << 1 ) + sizeof( *node ) ); 
			ASSERT( PATH_TREE_NODE_MAGIC_NUM == *end_magic_num ); 
		}
#endif //DBG

		*root_out = node->root; 

		free( node ); 

	} while ( FALSE );

	dbg_print( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, 0 ); 
	return STATUS_SUCCESS; 
}

NTSTATUS uninit_path_sub_tree( path_tree *tree, btree_node *tree_root )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	stack_container stack; 
	stack_container tree_stack; 
	PVOID element; 
	btree_node *node; 
	btree_node *_node; 
	btree_node *sub_tree; 
	btree_node *_sub_tree; 
	INT32 i; 

	do 
	{
		ASSERT( tree_root != NULL ); 

		init_stack( &stack ); 
		init_stack( &tree_stack ); 

		hold_tree_w_lock( tree ); 

		if( tree_root != NULL )
		{
			//_node = tree_root; 

			push_stack( &tree_stack, tree_root ); 

			for( ; ; )
			{
				ntstatus = pop_stack( &tree_stack, &element ); 
				if( ntstatus == STATUS_NO_MORE_ENTRIES )
				{
					break; 
				}

				ASSERT( element != NULL ); 
				_sub_tree = ( btree_node* )element; 

				ASSERT( _sub_tree != NULL ); 

				push_stack( &stack, _sub_tree ); 

				for( ; ; )
				{
					ntstatus = pop_stack( &stack, &element ); 
					if( ntstatus == STATUS_NO_MORE_ENTRIES )
					{
						break; 
					}

					ASSERT( element != NULL ); 

					node = ( btree_node* )element; 
					if( node->is_leaf == TRUE )
					{
						for( i = 0; ( ULONG )i < node->num_keys; i ++ )
						{
							ASSERT( node->pointers[ i ] != NULL ); 
							_release_path_tree_node( node->pointers[ i ], &sub_tree ); 

							if( sub_tree != NULL )
							{
								push_stack( &tree_stack, sub_tree ); 
							}
							//else
							//{

							//}
						}

						free_tree_node( node ); 
					}
					else
					{
						for( i = 0; ( ULONG )i < node->num_keys + 1; i ++ )
						{
							ASSERT( node->pointers[ i ] != NULL ); 
							push_stack( &stack, node->pointers[ i ] ); 
						}

						free_tree_node( node ); 
					}
				}
			}
		}

		release_tree_lock( tree ); 

		ASSERT( TRUE == IsListEmpty( &stack.elements ) ); 
		ASSERT( TRUE == IsListEmpty( &tree_stack.elements ) ); 

		uninit_btree_lock( tree ); 
	}while( FALSE );

	return ntstatus; 
}

NTSTATUS uninit_path_tree( path_tree *tree )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	stack_container stack; 
	stack_container tree_stack; 
	PVOID element; 
	btree_node *node; 
	btree_node *_node; 
	btree_node *sub_tree; 
	btree_node *_sub_tree; 
	INT32 i; 
	
	do 
	{
		ASSERT( tree != NULL ); 

		init_stack( &stack ); 
		init_stack( &tree_stack ); 

		hold_tree_w_lock( tree ); 

		if( tree->root != NULL )
		{

			_node = tree->root; 

			push_stack( &tree_stack, tree->root ); 

			for( ; ; )
			{

				ntstatus = pop_stack( &tree_stack, &element ); 
				if( ntstatus == STATUS_NO_MORE_ENTRIES )
				{
					break; 
				}

				ASSERT( element != NULL ); 
				_sub_tree = ( btree_node* )element; 

				ASSERT( _sub_tree != NULL ); 

				push_stack( &stack, _sub_tree ); 

				for( ; ; )
				{
					ntstatus = pop_stack( &stack, &element ); 
					if( ntstatus == STATUS_NO_MORE_ENTRIES )
					{
						break; 
					}

					ASSERT( element != NULL ); 

					node = ( btree_node* )element; 
					if( node->is_leaf == TRUE )
					{
						for( i = 0; ( ULONG )i < node->num_keys; i ++ )
						{
							ASSERT( node->pointers[ i ] != NULL ); 
							_release_path_tree_node( node->pointers[ i ], &sub_tree ); 

							if( sub_tree != NULL )
							{
								push_stack( &tree_stack, sub_tree ); 
							}
							//else
							//{

							//}
						}

						free_tree_node( node ); 
					}
					else
					{
						for( i = 0; ( ULONG )i < node->num_keys + 1; i ++ )
						{
							ASSERT( node->pointers[ i ] != NULL ); 
							push_stack( &stack, node->pointers[ i ] ); 
						}

						free_tree_node( node ); 
					}
				}
			}
		}

		release_tree_lock( tree ); 

		ASSERT( TRUE == IsListEmpty( &stack.elements ) ); 
		ASSERT( TRUE == IsListEmpty( &tree_stack.elements ) ); 

		uninit_btree_lock( tree ); 
	}while( FALSE );

	return ntstatus; 
}

NTSTATUS __insert_path_comp_node( path_tree *tree, path_tree_node *node_root, LPCWSTR path_comp, ULONG path_comp_len, ULONG path_comp_level, path_tree_node **node_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	TREE_KEY_TYPE path_comp_key; 
	path_tree_node *path_comp_node = NULL; 
	btree_node *new_root; 
	btree_node *root; 
	path_tree_node *_path_node; 

	do 
	{
		ASSERT( tree!= NULL ); 
		ASSERT( TRUE == btree_is_inited( tree ) );
		ASSERT( node_out != NULL ); 
		
#ifdef DBG
#endif //DBG

		*node_out = NULL; 

		if( path_comp_level >= MAX_SUB_DIR_COUNT_IN_PATH )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

#ifdef DBG
		path_comp_node = ( path_tree_node* )allocate_mem( sizeof( path_tree_node ) + sizeof( PATH_TREE_NODE_MAGIC_NUM ) + ( path_comp_len << 1 ) ); 
#else
		path_comp_node = ( path_tree_node* )allocate_mem( sizeof( path_tree_node ) + ( path_comp_len << 1 ) ); 
#endif //DBG
		if( path_comp_node == NULL )
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			break; 
		}

		path_comp_node->root = NULL; 

#ifdef AUTO_CREATE_PATH_ROOT
		ntstatus = make_leaf( tree, &path_comp_node->root ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			ASSERT( path_comp_node->root == NULL ); 
			break; 
		}
		ASSERT( path_comp_node->root != NULL ); 

#endif //AUTO_CREATE_PATH_ROOT

		path_comp_node->magic_num = PATH_TREE_NODE_MAGIC_NUM; 
		memcpy( path_comp_node->dir, path_comp, ( path_comp_len << 1 ) ); 
		path_comp_node->dir[ path_comp_len ] = L'\0'; 
		path_comp_node->level = path_comp_level; 
		ntstatus = calc_path_comp_key( ( LPWSTR )path_comp, path_comp_len, &path_comp_key ); 
		if(	ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		ASSERT( path_comp_key != INVALID_TREE_KEY_VALUE ); 
		
		path_comp_node->key = path_comp_key; 
		path_comp_node->dir_len = path_comp_len; 
		//path_comp_node->prop._class = INVALID_CLASS; 
		//path_comp_node->prop.intelevel= INVALID_INTE_LEVEL; 
		//path_comp_node->prop.conflevel = INVALID_CONF_LEVLEL; 
		//path_comp_node->prop.operate = 0; 
		path_comp_node->sub_path_owned = 0; 
#ifdef DBG

		{
			ULONG *end_magic_num; 
			//path_tree_node *_path_node; 

			//if( node_root != NULL )
			//{
			//	root = node_root->root; 
			//}
			//else
			//{
			//	root = tree->root; 
			//}
			//ntstatus = find_path_comp_node( tree, root, path_comp_key, &_path_node ); 
			//if( ntstatus == STATUS_SUCCESS )
			//{
			//	ASSERT( _path_node != NULL ); 
			//	ASSERT( _path_node->key == path_comp_key ); 
			//	ASSERT( 0 == compare_str( path_comp, path_comp_len, _path_node->dir, _path_node->dir_len ) ); 

			//	ASSERT( FALSE ); 
			//	__asm int 3; 

			//	ntstatus = STATUS_UNSUCCESSFUL; 
			//	break; 
			//}

			end_magic_num = ( ULONG* )( ( BYTE* )path_comp_node + sizeof( path_tree_node ) + ( path_comp_len << 1 ) ); 
			*end_magic_num = PATH_TREE_NODE_MAGIC_NUM; 
		}
#endif //DBG
		

		hold_tree_w_lock( tree ); 

		if( node_root != NULL )
		{
			root = node_root->root; 
		}
		else
		{
			root = tree->root; 
		}

		ntstatus = find_path_comp_node( tree, root, path_comp_key, &_path_node ); 
		if( ntstatus == STATUS_SUCCESS )
		{
			ASSERT( _path_node != NULL ); 
			ASSERT( _path_node->key == path_comp_key ); 
			ASSERT( 0 == compare_str( path_comp, path_comp_len, _path_node->dir, _path_node->dir_len ) ); 

			ASSERT( FALSE ); 
			//__asm int 3; 

			ntstatus = STATUS_UNSUCCESSFUL; 
			break; 
		}

		ntstatus = insert_path_comp_node_lock_free( tree, root, path_comp_key, path_comp_node, &new_root ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			release_tree_lock( tree ); 
			break; 
		}

		if( new_root != NULL )
		{
			if( node_root != NULL )
			{
				node_root->root = new_root; 
			}
			else
			{
				tree->root = new_root; 
			}
		}

		release_tree_lock( tree ); 

		*node_out = path_comp_node; 
	} while ( FALSE );

	if( ntstatus != STATUS_SUCCESS )
	{
		if( NULL != path_comp_node )
		{
#ifdef AUTO_CREATE_PATH_ROOT
			if( NULL != path_comp_node->root )
			{
				free_tree_node( path_comp_node->root ); 
			}
#endif //AUTO_CREATE_PATH_ROOT

			free_mem( path_comp_node ); 
		}
	}

	return ntstatus; 
}

NTSTATUS insert_path_comp_nodes( path_tree *tree, LPCWSTR path_name, ULONG name_len, USHORT region, USHORT inte_level, USHORT conf_level, ULONG _class )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	path_tree_node *node = NULL; 
	path_tree_node *dir_node = NULL;
	path_component path_comp = { 0 }; 
	ULONG i; 

	do 
	{
		ASSERT( tree != NULL ); 
		ASSERT( path_name != NULL ); 
		ASSERT( name_len > 0 ); 

		ntstatus = depart_path( path_name, name_len, &path_comp, 0 ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			ASSERT( path_comp.sub_dir == NULL ); 
			break; 
		}
		
		ASSERT( path_comp.sub_dir != NULL );

		for( i = 0; i < path_comp.sub_dir_count; i ++ )
		{
			ntstatus = _find_path_comp_node( tree, 
				dir_node != NULL ? dir_node->root : tree->root, 
				path_comp.sub_dir[ i ].str,
				( ULONG )path_comp.sub_dir[ i ].str_len, 
				i,
				&node ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				ASSERT( node == NULL ); 

				if( ntstatus == STATUS_NOT_FOUND )
				{
					ntstatus = __insert_path_comp_node( tree, dir_node, 
						path_comp.sub_dir[ i ].str, 
						path_comp.sub_dir[ i ].str_len, 
						i, 
						&node ); 
					
					if( ntstatus != STATUS_SUCCESS )
					{
						ASSERT( node == NULL ); 
						break; 
					}

					ASSERT( node != NULL ); 
					dump_path_comp_node( node ); 

					dir_node = node; 
				}
				else
				{
					break; 
				}
			}
			else
			{
				ASSERT( node != NULL ); 
				dir_node = node; 
			}
		}

		if( ntstatus == STATUS_SUCCESS )
		{

			ASSERT( node != NULL ); 
			ASSERT( i == path_comp.sub_dir_count );
			node->sub_path_owned = region; 
		}
	} while ( FALSE ); 

	release_path_comp( &path_comp ); 
	return ntstatus; 
}

#ifdef DBG
#define check_root_valid( tree, root ) TRUE //if( *root == NULL ) ASSERT( &tree->root == root ); 
#else
#define check_root_valid( tree, root ) 
#endif //DBG

NTSTATUS _find_path_comp_node( path_tree *tree, btree_node *root_node, LPCWSTR sub_dir, ULONG sub_dir_len, ULONG level, path_tree_node **node_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG dir_name_key; 
	path_tree_node *_node; 
	INT32 ret; 

	do 
	{
		ASSERT( TRUE == btree_is_inited( tree ) ); 
		ASSERT( NULL != node_out );

		*node_out = NULL; 

		if( root_node == NULL )
		{
			ntstatus = STATUS_NOT_FOUND; 
			break; 
		}

		ntstatus = calc_path_comp_key( ( LPWSTR )sub_dir, sub_dir_len, &dir_name_key ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}
		
		ASSERT( INVALID_B_TREE_NODE_KEY != dir_name_key ); 

		ntstatus = find_path_comp_node( tree, root_node, dir_name_key, &_node); 
		if( ntstatus != STATUS_SUCCESS )
		{
			ASSERT( _node == NULL ); 
			break; 
		}

#ifdef DBG
		ret = compare_str( _node->dir, _node->dir_len, sub_dir, sub_dir_len ); 
		if( ret != 0 )
		{
			ntstatus = STATUS_NOT_FOUND; 
			break; 
		}
#endif //DBG

		*node_out = _node; 

	} while ( FALSE ); 
	return ntstatus; 
}

NTSTATUS dump_path_comp_node( path_tree_node *node )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
#ifdef DRIVER
	UNICODE_STRING tmp_str; 
#endif //DRIVER
	ULONG i; 

	do 
	{
#ifdef DRIVER
		tmp_str.Buffer = ( PWCH )node->dir; 
		tmp_str.Length = ( USHORT )( node->dir_len << 1 ); 
		tmp_str.MaximumLength = ( USHORT )( node->dir_len << 1 ); 

		dbg_print( MSG_INFO, "node sub directory name is %wZ\n", &tmp_str ); 
#endif //DRIVER

		dbg_print( MSG_INFO, "path node magic number is 0x%0.8x\n", node->magic_num ); 
		ASSERT( PATH_TREE_NODE_MAGIC_NUM == node->magic_num ); 
#ifdef DBG
		{
			ULONG *end_magic_num; 

			ASSERT( node->dir_len <= MAX_NATIVE_NAME_SIZE ); 
			end_magic_num = ( ULONG * )( ( BYTE* )node + ( node->dir_len << 1 ) + sizeof( *node ) ); 
			ASSERT( PATH_TREE_NODE_MAGIC_NUM == *end_magic_num ); 
			dbg_print( MSG_INFO, "end magic number is 0x%0.8x\n", *end_magic_num ); 
		}
#endif //DBG
		dbg_print( MSG_INFO, "node path name is %ws key is 0x%0.8x level is %u\n", node->dir, node->key, node->level ); 

		if( NULL != node->root )
		{
			dbg_print( MSG_INFO, "node is leaf ? %u parent 0x%0.8x next 0x%0.8x\n", node->root->is_leaf, node->root->parent, node->root->next ); 
			if( node->root->is_leaf == TRUE )
			{
				for( i = 0; i < node->root->num_keys; i ++ )
				{
					dbg_print( MSG_INFO, "%uth key %u data 0x%0.8x\n", i, node->root->keys[ i ], node->root->pointers[ i ] ); 
				}
			}
			else
			{
				for( i = 0; i < node->root->num_keys; i ++ )
				{
					dbg_print( MSG_INFO, "%uth data %u key 0x%0.8x\n", i, node->root->pointers[ i ], node->root->keys[ i ] ); 
				}

				dbg_print( MSG_INFO, "%uth data %u \n", i, node->root->pointers[ i ] ); 
			}
		}

	} while ( FALSE );

	return ntstatus; 
}

NTSTATUS find_path_node( path_tree *tree, LPCWSTR path_name, ULONG name_len, path_tree_node **node_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	path_component path_comp; 
	ULONG i; 
	path_tree_node *_node; 
	btree_node *parent_node; 

	do 
	{
		ASSERT( tree != NULL ); 
		ASSERT( TRUE == btree_is_inited( tree ) ); 
		ASSERT( path_name != NULL ); 
		ASSERT( name_len > 0 ); 
		ASSERT( node_out != NULL ); 

		*node_out = NULL; 

		ntstatus = depart_path( path_name, name_len, &path_comp, 0 ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		hold_tree_r_lock( tree ); 
		
		parent_node = tree->root; 

		for( i = 0; i < path_comp.sub_dir_count; i ++ )
		{
			ntstatus = _find_path_comp_node( tree, parent_node, path_comp.sub_dir[ i ].str, path_comp.sub_dir[ i ].str_len, i, &_node ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				ASSERT( NULL == _node ); 
				break; 
			}

			ASSERT( NULL != _node ); 

			dump_path_comp_node( _node ); 

			if( i == path_comp.sub_dir_count - 1 )
			{
				continue; 
			}

			if( _node->root == NULL )
			{
				ntstatus = STATUS_NOT_FOUND; 

				_node = NULL; 
				break; 
			}

			parent_node = _node->root; 
		}

		release_tree_lock( tree ); 

	} while ( FALSE );
	
#ifdef DBG
	if( ntstatus == STATUS_SUCCESS )
	{
		ASSERT( i == path_comp.sub_dir_count ); 
	}
#endif //DBG
	*node_out = _node; 

	release_path_comp( &path_comp ); 
	return ntstatus; 
}

NTSTATUS find_path_node_lock_free( path_tree *tree, LPCWSTR path_name, ULONG name_len, path_tree_node **root_out, path_tree_node **node_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	path_component path_comp; 
	ULONG i; 
	path_tree_node *_node = NULL; 
	path_tree_node *_root_node = NULL; 
	btree_node *parent_node; 

	do 
	{
		ASSERT( tree != NULL ); 
		ASSERT( TRUE == btree_is_inited( tree ) ); 
		ASSERT( path_name != NULL ); 
		ASSERT( name_len > 0 ); 
		ASSERT( node_out != NULL ); 
		ASSERT( root_out != NULL ); 

		*node_out = NULL; 
		*root_out = NULL; 

		ntstatus = depart_path( path_name, name_len, &path_comp, 0 ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		parent_node = tree->root; 

		for( i = 0; i < path_comp.sub_dir_count; i ++ )
		{
			ntstatus = _find_path_comp_node( tree, parent_node, path_comp.sub_dir[ i ].str, path_comp.sub_dir[ i ].str_len, i, &_node ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				ASSERT( NULL == _node ); 
				break; 
			}

			ASSERT( NULL != _node ); 

			dump_path_comp_node( _node ); 


			if( i == path_comp.sub_dir_count - 1 )
			{
				continue; 
			}

			if( _node->root == NULL )
			{
				ntstatus = STATUS_NOT_FOUND; 

				_node = NULL; 
				break; 
			}

			_root_node = _node; 
			parent_node = _node->root; 
		}

	} while ( FALSE );

#ifdef DBG
	if( ntstatus == STATUS_SUCCESS )
	{
		ASSERT( i == path_comp.sub_dir_count ); 
	}
#endif //DBG
	*node_out = _node; 
	*root_out = _root_node; 

	release_path_comp( &path_comp ); 

	return ntstatus; 
}

NTSTATUS get_path_name_level( LPCWSTR path_name, ULONG name_len, ULONG *path_comp_count )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG sub_dir_begin; 
	ULONG sub_dir_end; 
	ULONG sub_dir_count; 
	BOOLEAN path_traversed = FALSE; 
	INT32 i; 
	
	ASSERT( path_comp_count != NULL );
	ASSERT( name_len > 0 ); 

	*path_comp_count = 0; 

	do 
	{
		sub_dir_begin = 0; 
		sub_dir_end = 0; 
		sub_dir_count = 0; 

		for( i = 0; ( ULONG )i < name_len; i ++ )
		{
#define PATH_DELIM_CH L'\\'

			if( path_name[ i ] == L'\0' )
			{
				path_traversed = TRUE; 

				sub_dir_end = i; 
				if( sub_dir_end > sub_dir_begin )
				{
					sub_dir_count ++; 
				}
				else
				{
					ASSERT( FALSE ); 
				}

				break; 
			}

			if( path_name[ i ] == PATH_DELIM_CH )
			{
				sub_dir_end = i; 

#define WINDOWS_ROOT_DIR_NAME_INDEX 0
				{
					if( sub_dir_end > sub_dir_begin )
					{
						sub_dir_count ++; 

						if( sub_dir_count >= MAX_SUB_DIR_COUNT_IN_PATH )
						{
							ntstatus = STATUS_UNSUCCESSFUL; 
							break; 
						}

					}

					sub_dir_begin = sub_dir_end + 1; 
				}
			}
		}

		if( path_traversed == FALSE )
		{
			sub_dir_end = name_len; 
			if( sub_dir_end > sub_dir_begin )
			{
				sub_dir_count ++; 
			}
			else
			{
				ASSERT( FALSE ); 
			}
		}

		*path_comp_count = sub_dir_count; 

	} while ( FALSE );

	return ntstatus; 
}

NTSTATUS traverse_path_node( path_tree *tree, LPCWSTR path_name, ULONG name_len, path_tree_node *nodes_out[ MAX_SUB_DIR_COUNT_IN_PATH ], ULONG *nodes_count )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	path_component path_comp; 
	ULONG i; 
	path_tree_node *_node; 
	btree_node *parent_node; 
	ULONG check_path_level; 
	BYTE _nodes_count; 

	do 
	{
		ASSERT( tree != NULL ); 
		ASSERT( TRUE == btree_is_inited( tree ) ); 
		ASSERT( path_name != NULL ); 
		ASSERT( name_len > 0 ); 
		ASSERT( nodes_out != NULL ); 
		ASSERT( nodes_count != NULL ); 

		*nodes_count = 0; 

		ntstatus = depart_path( path_name, name_len, &path_comp, 0 ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		hold_tree_r_lock( tree ); 

		parent_node = tree->root; 

		if( path_comp.sub_dir_count > MAX_SUB_DIR_COUNT_IN_PATH )
		{
			dbg_print( MSG_ERROR, "the file path have too more sub directory, all level is %u\n", path_comp.sub_dir_count ); 

			check_path_level = MAX_SUB_DIR_COUNT_IN_PATH; 
		}
		else
		{
			check_path_level = path_comp.sub_dir_count; 
		}

		_nodes_count = 0; 
		for( i = 0; i < check_path_level; i ++ )
		{
			ntstatus = _find_path_comp_node( tree, parent_node, path_comp.sub_dir[ i ].str, path_comp.sub_dir[ i ].str_len, i, &_node ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				if( i > 0 )
				{
					ntstatus = STATUS_NO_MORE_PATH_COMPONENT; 
				}

				ASSERT( NULL == _node ); 
				break; 
			}

			ASSERT( NULL != _node ); 

			dump_path_comp_node( _node ); 

			if( i == path_comp.sub_dir_count - 1 )
			{
				nodes_out[ i ] = _node; 
				_nodes_count ++; 
				continue; 
			}

			if( _node->root == NULL )
			{
				ntstatus = STATUS_NO_MORE_PATH_COMPONENT; 
				nodes_out[ i ] = _node; 
				_nodes_count ++; 
				break; 
			}

			nodes_out[ i ] = _node; 
			_nodes_count ++; 
			parent_node = _node->root; 
		}

		release_tree_lock( tree ); 

	} while ( FALSE );

	*nodes_count = _nodes_count; 

	release_path_comp( &path_comp ); 

	return ntstatus; 
}

NTSTATUS trim_space_right( LPCWSTR path_name, ULONG name_len, ULONG *name_len_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 i; 

	do 
	{
		ASSERT( path_name != NULL ); 

		if( name_len == 0 )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		for( i = ( INT32 )name_len -1; i >= 0; i -- )
		{
			if( path_name[ i ] == L' ' )
			{
				continue; 
			}
			else
			{
				break; 
			}
		}
	}while( FALSE );

	*name_len_out = ( ULONG )i + 1; 
	return ntstatus; 
}

NTSTATUS depart_path( LPCWSTR path_name, ULONG name_len, path_component *path_comp, ULONG flags )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG sub_dir_count = 0; 
	ULONG sub_dir_begin; 
	ULONG sub_dir_end; 
	ULONG i; 
	BOOLEAN path_traversed = FALSE; 

	do 
	{
		ASSERT( path_name != NULL ); 
		ASSERT( name_len > 0 ); 

		path_comp->sub_dir_count = 0; 
		
		path_comp->sub_dir = ( arr_str* )malloc( sizeof( arr_str ) * MAX_SUB_DIR_COUNT_IN_PATH ); 

		if( path_comp->sub_dir == NULL )
		{
			path_comp->path_name = NULL; 
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			break; 
		}

		path_comp->path_name = path_name; 
	
		sub_dir_begin = 0; 
		sub_dir_end = 0; 

		for( i = 0; i < name_len; i ++ )
		{
#define PATH_DELIM_CH L'\\'

			if( path_name[ i ] == L'\0' )
			{
				path_traversed = TRUE; 

				sub_dir_end = i; 
				if( sub_dir_end > sub_dir_begin )
				{
					path_comp->sub_dir[ sub_dir_count ].str = path_name + sub_dir_begin; 
					path_comp->sub_dir[ sub_dir_count ].str_len = ( USHORT )( sub_dir_end - sub_dir_begin ); 

					sub_dir_count ++; 
				}
				else
				{
					ASSERT( FALSE ); 
				}

				path_comp->sub_dir_count = sub_dir_count; 

				break; 
			}

			if( path_name[ i ] == PATH_DELIM_CH )
			{
				sub_dir_end = i; 

#define WINDOWS_ROOT_DIR_NAME_INDEX 0
				//do 
				{
					if( sub_dir_end > sub_dir_begin )
					{
						path_comp->sub_dir[ sub_dir_count ].str = path_name + sub_dir_begin; 
						path_comp->sub_dir[ sub_dir_count ].str_len = ( USHORT )( sub_dir_end - sub_dir_begin ); 

						sub_dir_count ++; 

						if( sub_dir_count >= MAX_SUB_DIR_COUNT_IN_PATH )
						{
							ntstatus = STATUS_UNSUCCESSFUL; 
							break; 
						}

					}

					sub_dir_begin = sub_dir_end + 1; 
				}
			}
		}

		if( path_traversed == FALSE )
		{
			sub_dir_end = name_len; 
			if( sub_dir_end > sub_dir_begin )
			{
				path_comp->sub_dir[ sub_dir_count ].str = path_name + sub_dir_begin; 
				path_comp->sub_dir[ sub_dir_count ].str_len = ( USHORT )( sub_dir_end - sub_dir_begin ); 

				sub_dir_count ++; 
			}
			else
			{
				ASSERT( FALSE ); 
			}
		}

		path_comp->sub_dir_count = sub_dir_count; 

	} while ( FALSE );

	if( ntstatus != STATUS_SUCCESS )
	{
		if( path_comp->sub_dir != NULL )
		{
			free_mem( path_comp->sub_dir ); 
		}
	}
	return ntstatus; 
}

NTSTATUS release_path_comp( path_component *path_comp )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		if( path_comp->sub_dir != NULL )
		{
			free_mem( path_comp->sub_dir ); 
		}
	}while( FALSE ); 

	return ntstatus; 
}

NTSTATUS test_path_tree()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	path_tree _path_tree; 
	btree_node *new_root; 
	path_tree_node *node_test; 
	path_tree_node *nodes_in_path[ MAX_SUB_DIR_COUNT_IN_PATH ] = { 0 }; 
	ULONG nodes_count; 
	WCHAR test_path[ MAX_NATIVE_NAME_SIZE ]; 
	INT32 i;
	INT32 j; 
	ULONG key1; 
	ULONG key2; 

	do 
	{
		ntstatus = init_path_tree( &_path_tree, 3 ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

#define TEST_PATH L"1\\2\\3\\3\\4\\5\\6\\7\\8\\9\\10"
#define TEST_PATH1 L"C:\\TEST%u\\TEST%u\\TEST%u\\TEST%u\\TEST%u.EXE"
#define TEST_PATH2 L"C:\\TesT%u\\TeST%u\\tESt%u\\teSt%u\\teST%u.ExE"

		ntstatus = calc_path_comp_key( TEST_PATH1, CONST_STR_LEN( TEST_PATH1 ), &key1 ); 
		ntstatus = calc_path_comp_key( TEST_PATH2, CONST_STR_LEN( TEST_PATH2 ), &key2 ); 
		ASSERT( key1 == key2 ); 

		for( i = 0; i < 10; i ++ )
		{
#ifdef DRIVER
			RtlStringCbPrintfW( test_path, sizeof( test_path ) - sizeof( WCHAR ), TEST_PATH2, i, i, i, i, i ); 
#else
			wsprintfW( test_path, TEST_PATH2, i, i, i, i, i ); 
#endif //DRIVER
			
			ntstatus = insert_path_comp_nodes( &_path_tree, test_path, wcslen( test_path ), 5, 10, 10, 1000 ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				ASSERT( FALSE );
				break; 
			}

			print_tree( &_path_tree, _path_tree.root, _path_tree.tree_order ); 

			ntstatus = find_path_node( &_path_tree, test_path, wcslen( test_path ), &node_test ); 

			if( ntstatus == STATUS_SUCCESS )
			{
				ASSERT( node_test != NULL ); 
			}
			else
			{
				ASSERT( FALSE ); 
			}

			ntstatus = traverse_path_node( &_path_tree, test_path, wcslen( test_path ), nodes_in_path, &nodes_count ); 
			if( ntstatus == STATUS_SUCCESS )
			{

				ASSERT( nodes_count > 0 ); 
				ASSERT( nodes_in_path[ nodes_count -1 ] != NULL ); 

				for( j = nodes_count - 1; j >= 0; j -- )
				{
					dump_path_comp_node( nodes_in_path[ j ] ); 
				}
			}

			ntstatus = del_path_node( &_path_tree, test_path, wcslen( test_path ) ); 
		}

		uninit_path_tree( &_path_tree ); 

	}while( FALSE );

	return ntstatus; 
}

#define FIND_BTREE_NODE 1
#define ADD_BTREE_NODE 2
#define DEL_BTREE_NODE 3

NTSTATUS test_btree()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	WCHAR instruction;
	btree tree; 
	WCHAR path_name[ MAX_NATIVE_NAME_SIZE ]; 
	ULONG name_len; 
	ULONG path_key; 
	path_tree_node *path_node; 
	btree_node *new_root; 
	ULONG btree_test_mode = ADD_BTREE_NODE; 
	INT32 i; 
	ULONG test_value; 
	INT32 test_time; 

	do 
	{
#define TEST_BTREE_ORDER MIN_BTREE_ORDER
		ntstatus = init_btree( &tree, TEST_BTREE_ORDER ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		for( test_time = 0; test_time < 1; test_time ++ )
		{
			name_len = 0; 

#ifndef DRIVER
			while( ( instruction = getwchar( ) ) != EOF )
			{
				if( name_len >= MAX_PATH )
				{
					path_name[ name_len - 1 ] = L'\0'; 
					break; 
				}

				if( instruction == L'\r' || instruction == L'\n' )
				{
					path_name[ name_len ] = L'\0'; 
					break; 
				}

				path_name[ name_len ] = instruction; 
				name_len ++; 
			}

			if( 0 == name_len )
			{
				continue; 
			}

			if( 0 == wcscmp( path_name, L"find node" ) )
			{
				btree_test_mode = FIND_BTREE_NODE; 
			}
			else if( 0 == wcscmp( path_name, L"del node" ) )
			{
				btree_test_mode = DEL_BTREE_NODE; 
			}
			else
			{
				if( btree_test_mode != ADD_BTREE_NODE )
				{
					btree_test_mode = ADD_BTREE_NODE; 
				}
			}
#else
			btree_test_mode = ADD_BTREE_NODE; 
#endif //DRIVER

#define TEST_BTREE_DELETE_INDEX 300
			btree_test_mode = ADD_BTREE_NODE; 
			for( i = 0; i < 3000; i ++ )
			{

				if( i > 0 )
				{
					if( 0 == ( i % TEST_BTREE_DELETE_INDEX ) )
					{
						if( btree_test_mode == ADD_BTREE_NODE )
						{
							btree_test_mode = FIND_BTREE_NODE; 
						}
						else if( btree_test_mode == DEL_BTREE_NODE )
						{
							btree_test_mode = ADD_BTREE_NODE; 
						}
						else if( btree_test_mode == FIND_BTREE_NODE )
						{
							btree_test_mode = DEL_BTREE_NODE; 
						}
						else
						{
							btree_test_mode = ADD_BTREE_NODE; 
							ASSERT( FALSE ); 
						}
					}
				}

				if( btree_test_mode == ADD_BTREE_NODE )
				{
					test_value = ( i % TEST_BTREE_DELETE_INDEX );
				}
				else if( btree_test_mode == DEL_BTREE_NODE )
				{
					test_value = ( i % TEST_BTREE_DELETE_INDEX ); 
				}
				else if( btree_test_mode == FIND_BTREE_NODE )
				{
					test_value = ( i % TEST_BTREE_DELETE_INDEX ); 
				}
#ifdef DRIVER
				RtlStringCbPrintfW( path_name, sizeof( path_name ) - sizeof( WCHAR ), L"%u", test_value ); 
#else
				wsprintfW( path_name, L"%u", test_value ); 
#endif //DRIVER
				ntstatus = calc_path_comp_key( path_name, name_len, &path_key ); 
				if( ntstatus != STATUS_SUCCESS )
				{
					continue; 
				}

				ASSERT( path_key != INVALID_B_TREE_NODE_KEY ); 

				switch( btree_test_mode )
				{
				case ADD_BTREE_NODE:
					{
						ntstatus = make_path_node( &tree, path_key, path_name, name_len, 0,  &path_node ); 
						if( ntstatus != STATUS_SUCCESS )
						{
							ASSERT( path_node == NULL ); 
							break; 
						}

						ASSERT( path_node != NULL ); 

						hold_tree_w_lock( &tree ); 
						ntstatus = insert_path_comp_node_lock_free( &tree, tree.root, path_key, path_node, &new_root ); 
						if( ntstatus != STATUS_SUCCESS )
						{
							release_tree_lock( &tree ); 
							break; 
						}

						if( NULL != new_root )
						{
							tree.root = new_root; 
						}

						release_tree_lock( &tree ); 

						print_tree( &tree, tree.root, tree.tree_order );
					}
					break; 
				case DEL_BTREE_NODE:
					{
						ntstatus = del_path_comp_node( &tree, tree.root, path_name, name_len, &new_root ); 
						if( ntstatus != STATUS_SUCCESS )
						{
							break; 
						}

						if( new_root == FREED_ROOT_POINTER_VALUE )
						{
							tree.root = NULL; 
						}
						else if( new_root != NULL )
						{
							tree.root = new_root; 
						}

						if( tree.root != NULL )
						{
							print_tree( &tree, tree.root, tree.tree_order ); 
						}
					}
					break; 
				case FIND_BTREE_NODE:
					{
						path_tree_node *node_found; 

						ntstatus = find_path_comp_node( &tree, tree.root, path_key, &node_found ); 
						if( ntstatus != STATUS_SUCCESS )
						{
							log_trace( ( MSG_ERROR, "find the path %ws key 0x%0.8x error 0x%0.8x\n", path_name, path_key, ntstatus ) );
							break; 
						}

						log_trace( ( MSG_ERROR, "find the path %ws key 0x%0.8x successfully\n", path_name, path_key ) ); 

						ASSERT( node_found != NULL ); 
						dump_path_comp_node( node_found ); 
					}
					break; 
				default:
					break; 
				}
			}
		}
	} while ( FALSE ); 

	return ntstatus;
}


int _cdecl main( int argc, char ** argv )
{
	INT32 ret = 0; 

#ifndef DRIVER
	_CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF ); 
#endif //DRIVER

	ret = test_path_tree();
}

NTSTATUS check_path_access( path_tree *tree, LPCWSTR path_name, ULONG name_len, ULONG operate )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	path_tree_node *path_comp_node[ MAX_SUB_DIR_COUNT_IN_PATH ]; 
	ULONG path_node_found; 
	INT32 i; 

	do 
	{
		ASSERT( TRUE == is_valid_operation( operate ) ); 

		ntstatus = traverse_path_node( tree, path_name, name_len, path_comp_node, &path_node_found ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}
		
		if( i < 0 )
		{
			ntstatus = STATUS_ACCESS_DENIED;	
			break; 
		}
	} while ( FALSE );

	return ntstatus; 
}

NTSTATUS del_path_node( path_tree *tree, LPCWSTR name, ULONG name_len )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	path_tree_node *path_comp_node; 
	path_tree_node *node_root; 
	btree_node *new_root; 

	do 
	{
		ASSERT( tree != NULL ); 
		ASSERT( TRUE == btree_is_inited( tree ) ); 
		ASSERT( name != NULL ); 

		hold_tree_w_lock( tree ); 

		do 
		{
			ntstatus = find_path_node_lock_free( tree, name, name_len, &node_root, &path_comp_node ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				break; 
			}

			if( node_root == NULL )
			{
				ASSERT( FALSE ); 
				break; 
			}

			ASSERT( path_comp_node != NULL );

#ifdef DBG
			{
				path_tree_node *test_node; 
				ntstatus = find_path_comp_node( tree, node_root->root, path_comp_node->key, &test_node ); 
				if( test_node == NULL )
				{
					ASSERT( FALSE ); 
				}
			}
#endif //DBG
			ntstatus = delete_tree_node( tree, node_root->root, path_comp_node->key, &new_root ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				break; 
			}

			if( new_root == FREED_ROOT_POINTER_VALUE )
			{
				node_root->root = NULL; 
			}
			else if( new_root != NULL )
			{
				node_root->root = new_root; 
			}
		} while ( FALSE );

		release_tree_lock( tree ); 
	} while ( FALSE );

	return ntstatus; 
}

NTSTATUS release_path_tree_node( path_tree_node *node )
{
	ASSERT( node != NULL ); 
	//ASSERT( node->root != NULL ); 

	dbg_print( MSG_INFO, "enter %s\n", __FUNCTION__ ); 

	dump_path_comp_node( node ); 

	ASSERT( PATH_TREE_NODE_MAGIC_NUM == node->magic_num ); 
#ifdef DBG
	{
		ULONG *end_magic_num; 

		ASSERT( node->dir_len <= MAX_NATIVE_NAME_SIZE ); 
		end_magic_num = ( ULONG * )( ( BYTE* )node + ( node->dir_len << 1 ) + sizeof( *node ) ); 
		ASSERT( PATH_TREE_NODE_MAGIC_NUM == *end_magic_num ); 
	}
#endif //DBG

	if( node->root != NULL )
	{
		free_tree_node( node->root ); 
	}

	free( node ); 

	dbg_print( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, 0 ); 
	return STATUS_SUCCESS; 
}