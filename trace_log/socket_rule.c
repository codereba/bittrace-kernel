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

#include "rbtree.h"
#include "hash_table.h"
#include "acl_cache.h"
#include "acl_define.h"
#include "trace_log_api.h"
#include "sys_event_define.h"
#include "socket_rule.h"

rb_tree socket_rule_rbt = { 0 }; 

typedef NTSTATUS ( CALLBACK* release_rb_node_callback )( rb_node *node ); 

NTSTATUS CALLBACK release_socket_rule( rb_node *node )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	socket_rule_item *rule_item; 

	rule_item = ( socket_rule_item* )CONTAINING_RECORD( node, socket_rule_item, rb_node ); 

	FREE_TAG_POOL( rule_item ); 

	return ntstatus; 
}

NTSTATUS release_rbt( rb_tree *tree, release_rb_node_callback release_func )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	rb_node *node; 
	ASSERT( tree != NULL ); 

	hold_rbt_lock( tree ); 

	for( ; ; )
	{
		node = rb_first( &tree->root ); 
		if( node == NULL )
		{
			goto _return; 
		}

		rb_erase( node, &tree->root ); 

		if( release_func != NULL )
		{
			release_func( node ); 
		}
	}

_return: 
	release_rbt_lock( tree );  
	return ntstatus; 
}

//NTSTATUS rb_check_socket_action( rb_tree *tree, LPCWSTR app, ipv4_socket_action *socket_action, data_trace_option *trace_option, action_response_type *resp )
//{
//	NTSTATUS ntstatus = STATUS_SUCCESS; 
//	INT32 _ret; 
//	struct rb_node* n; 
//	socket_rule_item* socket_rule; 
//	socket_rule_item* rule_found = NULL; 
//	BOOLEAN lock_held = FALSE; 
//
//	ASSERT( tree != NULL ); 
//	ASSERT( resp != NULL ); 
//	ASSERT( socket_action != NULL ); 
//	ASSERT( is_valid_prot_type( socket_action->prot ) == TRUE ); 
//
//	*resp = ACTION_ALLOW; 
//
//	hold_rbt_lock( tree ); 
//	lock_held = TRUE; 
//
//	n = tree->root.rb_node; 
//
//	while( n )
//	{
//		socket_rule = rb_entry( n, socket_rule_item, rb_node );
//
//		ASSERT( socket_rule->ref_count > 0 ); 
//
//		if( socket_rule->rule.rule.socket.dest_ip != NULL )
//		{
//
//			//Note the ip value comparing must be taken by the small byte order.
//			if( socket_action->dest_ip > socket_rule->rule.rule.socket.dest_ip->param.ip.ip_begin )
//			{
//				n = n->rb_right; 
//			}
//			else
//			{
//				n = n->rb_left; 
//			}
//
//			if( socket_action->dest_ip < socket_rule->rule.rule.socket.dest_ip->param.ip.ip_begin )
//			{
//				goto _continue; 
//			}
//
//			if(	socket_action->dest_ip > socket_rule->rule.rule.socket.dest_ip->param.ip.ip_end )
//			{
//				goto _continue; 
//			}
//		}
//		else
//		{
//			if( socket_action->dest_ip > 0 )
//			{
//				n = n->rb_right; 
//			}
//			else
//			{
//				n = n->rb_left; 
//			}
//		}
//
//		if( app != NULL && socket_rule->rule.rule.socket.app != NULL )
//		{
//			_ret = compare_define_name_no_case( socket_rule->rule.rule.socket.app->param.app.app_name, app ); 
//			if( _ret != 0 )
//			{
//				goto _continue; 
//			}
//		}
//
//		if( socket_rule->rule.rule.socket.dest_port != NULL )
//		{
//			if( socket_rule->rule.rule.socket.dest_port->param.port.type != ALL_PROT 
//				&& socket_action->prot != socket_rule->rule.rule.socket.dest_port->param.port.type )
//			{
//				goto _continue; 
//			}
//		}
//
//		if( socket_rule->rule.rule.socket.src_ip != NULL )
//		{
//			if( socket_action->src_ip < socket_rule->rule.rule.socket.src_ip->param.ip.ip_begin 
//				|| socket_action->src_ip > socket_rule->rule.rule.socket.src_ip->param.ip.ip_end )
//			{
//				goto _continue; 
//			}
//		}
//		//else
//		//{
//		//	if( socket_action->src_ip > 0 )
//		//	{
//		//		n = n->rb_right; 
//		//	}
//		//	else
//		//	{
//		//		n = n->rb_left; 
//		//	}
//		//}
//
//		if( socket_rule->rule.rule.socket.src_port != NULL )
//		{
//			if( socket_action->src_port < socket_rule->rule.rule.socket.src_port->param.port.port_begin
//				|| socket_action->src_port > socket_rule->rule.rule.socket.src_port->param.port.port_end )
//			{
//				goto _continue; 
//			}
//		}
//
//		if( socket_rule->rule.rule.socket.dest_port != NULL )
//		{
//			if( socket_action->dest_port < socket_rule->rule.rule.socket.dest_port->param.port.port_begin
//				|| socket_action->dest_port > socket_rule->rule.rule.socket.dest_port->param.port.port_end )
//			{
//				goto _continue; 
//			}
//		}
//		
//		rule_found = socket_rule; 
//		break; 
//		
//_continue:
//		__asm nop; 
//	}
//
//	if( rule_found == NULL )
//	{
//		ntstatus = STATUS_NOT_FOUND; 
//		goto _return; 
//	}
//
//	ASSERT( rule_found->ref_count > 0 ); 
//	ASSERT( is_valid_response_type( rule_found->rule.action ) == TRUE ); 
//
//	if( rule_found->rule.action == ACTION_BLOCK )
//	{
//		*resp = ACTION_BLOCK; 
//	}
//
//	if( trace_option != NULL )
//	{
//		*trace_option = rule_found->rule.trace_option; 
//	}
//
//_return:
//
//	if( lock_held == TRUE )
//	{
//		release_rbt_lock( tree ); 
//	}
//
//	return ntstatus;
//}

#ifdef REVERSE_ORDER_ACL
INT32 compare_socket_info( action_response_type resp, socket_rule_define *socket_define, socket_rule_desc *socket, INT32 *is_greater )
#else
INT32 compare_socket_info( socket_rule_define *socket_define, socket_rule_desc *socket, INT32 *is_greater )
#endif //REVERSE_ORDER_ACL
{
	INT32 ret = FALSE; 
#ifdef DBG
	INT32 _is_greater = 0x10288383; 
#else
	INT32 _is_greater; 
#endif //DBG
	ASSERT( socket != NULL 
		&& socket_define != NULL ); 

	ASSERT( is_greater != NULL ); 

#define INVALID_IP 0 

#ifdef REVERSE_ORDER_ACL 
	if( resp == socket->resp )
	{
#endif //REVERSE_ORDER_ACL 
		if( socket_define->dest_ip != NULL )
		{
			if( socket->desc.socket.dest_ip.ip.ip_begin > socket_define->dest_ip->param.ip.ip_begin )
			{
				_is_greater = TRUE;
			}
			else
			{
				_is_greater = FALSE; 
			}

			ret = compare_value_region_define( ( ULONG )socket->desc.socket.dest_ip.ip.ip_begin, 
				( ULONG )socket->desc.socket.dest_ip.ip.ip_end, 
				( ULONG )socket_define->dest_ip->param.ip.ip_begin, 
				( ULONG )socket_define->dest_ip->param.ip.ip_end ); 

			if( ret == FALSE )
			{
				goto _return; 
			}
		}
		else
		{
			if( socket->desc.socket.dest_ip.ip.ip_begin > 0 )
			{
				_is_greater = TRUE;
			}
			else
			{
				_is_greater = FALSE; 
			}
		}

		if( socket_define->src_ip != NULL )
		{
			ret = compare_value_region_define( ( ULONG )socket->desc.socket.src_ip.ip.ip_begin, 
				( ULONG )socket->desc.socket.src_ip.ip.ip_end, 
				( ULONG )socket_define->src_ip->param.ip.ip_begin, 
				( ULONG )socket_define->src_ip->param.ip.ip_end ); 
			if(  ret == FALSE  )
			{
				goto _return; 
			}
		}

		if( socket_define->src_port != NULL )
		{
			ret = compare_value_region_define( socket->desc.socket.src_port.port.port_begin, 
				socket->desc.socket.src_port.port.port_end, 
				socket_define->src_port->param.port.port_begin, 
				socket_define->src_port->param.port.port_end ); 
			if( ret == FALSE )
			{
				goto _return; 
			}
		}

		if( socket_define->dest_port != NULL )
		{
			ret = compare_value_region_define( socket->desc.socket.dest_port.port.port_begin, 
				socket->desc.socket.dest_port.port.port_end, 
				socket_define->dest_port->param.port.port_begin, 
				socket_define->dest_port->param.port.port_end ); 
			if( ret == FALSE )
			{
				goto _return; 
			}
		}

#ifdef REVERSE_ORDER_ACL 
	}
	else
	{
		if( socket_define->dest_ip != NULL )
		{
			if( socket->desc.socket.dest_ip.ip.ip_begin > socket_define->dest_ip->param.ip.ip_begin )
			{
				_is_greater = TRUE;
			}
			else
			{
				_is_greater = FALSE; 
			}

			if( socket->desc.socket.dest_ip.ip.ip_begin != socket_define->dest_ip->param.ip.ip_begin 
				|| socket->desc.socket.dest_ip.ip.ip_end != socket_define->dest_ip->param.ip.ip_end )
			{
				goto _return; 
			}
		}
		else
		{
			if( socket->desc.socket.dest_ip.ip.ip_begin > 0 )
			{
				_is_greater = TRUE;
			}
			else
			{
				_is_greater = FALSE; 
			}

			if( socket->desc.socket.dest_ip.ip.ip_begin != 0 
				|| socket->desc.socket.dest_ip.ip.ip_end != 0 )
			{
				goto _return; 
			}
		}

		if( socket_define->src_ip != NULL )
		{
			if( socket->desc.socket.src_ip.ip.ip_begin != socket_define->src_ip->param.ip.ip_begin 
				|| socket->desc.socket.src_ip.ip.ip_end != socket_define->src_ip->param.ip.ip_end )
			{
				goto _return; 
			}
		}

		if( socket_define->src_port != NULL )
		{
			if(socket->desc.socket.src_port.port.port_begin != socket->desc.socket.src_port.port.port_end 
				|| socket_define->src_port->param.port.port_end || socket_define->src_port->param.port.port_end )
			{
				goto _return; 
			}
		}

		if( socket_define->dest_port != NULL )
		{
			if( socket->desc.socket.dest_port.port.port_begin != socket_define->dest_port->param.port.port_begin
				|| socket->desc.socket.dest_port.port.port_end != socket_define->dest_port->param.port.port_end )
			{
				goto _return; 
			}
		}
	}
#endif //REVERSE_ORDER_ACL 

	ret = TRUE; 

_return:
	*is_greater = _is_greater; 
	
	ASSERT( ret == FALSE || ret == TRUE ); 

	return ret; 
}

NTSTATUS rb_search_socket_rule_lock_free( 
	rb_tree *tree, 
	socket_rule_desc *socket_rule, 
	socket_rule_item** rule_found ) 
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 ret; 
	rb_node ** p;
	rb_node * parent = NULL;
	socket_rule_item *_rule_found;
	INT32 is_greater; 

	ASSERT( tree != NULL ); 
	ASSERT( check_access_rule_input_valid( socket_rule, FALSE ) == STATUS_SUCCESS ); 

	if( rule_found != NULL )
	{
		*rule_found = NULL; 
	}

	p = &tree->root.rb_node; 
	while (*p)
	{
		parent = *p;
		_rule_found = ( socket_rule_item* )CONTAINING_RECORD(parent, socket_rule_item, rb_node );

		ASSERT( _rule_found->rule.type == SOCKET_RULE_TYPE ); 

		ret = compare_socket_info( /*rule_found->rule.action, */&_rule_found->rule.rule.socket, socket_rule, &is_greater );  
		if( ret == TRUE )
		{
			goto _return; 
		}
		else
		{
			if( is_greater == FALSE )
				p = &( *p )->rb_left;
			else 
				p = &( *p )->rb_right;
		}
	}

	ntstatus = STATUS_NOT_FOUND; 
	_rule_found = NULL; 

_return:

	if( rule_found != NULL )
	{
		*rule_found = _rule_found; 
	}

	return ntstatus;
}

NTSTATUS __rb_insert_socket_rule( rb_tree *tree, socket_rule_desc *socket_rule, 
struct rb_node** node_found, socket_rule_item** rule_alloc )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 ret; 
	rb_node **p; 
	rb_node *parent = NULL;
	socket_rule_item *_rule_found; 
	socket_rule_item *_rule_alloc = NULL; 
	INT32 is_greater; 

	ASSERT( tree != NULL ); 

	if( node_found != NULL )
	{
		*node_found = NULL; 
	}

	if( rule_alloc != NULL )
	{
		*rule_alloc = NULL; 
	}

	p = &tree->root.rb_node; 

	while( *p != NULL )
	{
		parent = *p;
		_rule_found = rb_entry( parent, socket_rule_item, rb_node );

		ret = compare_socket_info( &_rule_found->rule.rule.socket, socket_rule, &is_greater );  
		if( ret == TRUE )
		{
			ntstatus = STATUS_LIST_ITEM_ALREADY_EXIST; 
			goto _return; 
		}
		else
		{
			if( is_greater == FALSE )
				p = &( *p )->rb_left;
			else 
				p = &( *p )->rb_right;
		}
	}

	_rule_found = NULL; 

	ntstatus = alloc_access_rule( socket_rule, &_rule_alloc ); 
	if( !NT_SUCCESS( ntstatus ) )
	{
		ASSERT( _rule_alloc == NULL ); 
		goto _return; 
	}


	rb_link_node( &_rule_alloc->rb_node, parent, p );

	ASSERT( _rule_alloc->ref_count == 0 ); 
	_rule_alloc->ref_count ++; 

_return:
	if( node_found != NULL )
	{
		if( _rule_found != NULL )
		{
			*node_found = &_rule_found->rb_node; 
		}
	}

	if( rule_alloc != NULL )
	{
		*rule_alloc = _rule_alloc; 
	}

	return ntstatus;
}

NTSTATUS rb_insert_socket_rule( socket_rule_desc *socket_rule, rb_node **node_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	rb_node *_node_found; 
	socket_rule_item *rule_alloc;
	
	if( node_out != NULL )
	{
		*node_out = NULL; 
	}

	ntstatus = __rb_insert_socket_rule( &socket_rule_rbt, socket_rule, &_node_found, &rule_alloc ); 
	
	if( !NT_SUCCESS( ntstatus ) )
	{
#ifdef DBG
		if( ntstatus = STATUS_LIST_ITEM_ALREADY_EXIST )
		{
			ASSERT( _node_found != NULL && rule_alloc == NULL ); 
		}
		else
		{
			ASSERT( _node_found == NULL && rule_alloc == NULL ); 
		}
#endif //DBG
	}
	else
	{
		ASSERT( rule_alloc != NULL ); ; 
		ASSERT( _node_found == NULL ); 

		rb_insert_color( &rule_alloc->rb_node, &socket_rule_rbt.root ); 
	}

	if( node_out != NULL )
	{
		if( rule_alloc != NULL )
		{
			*node_out = &rule_alloc->rb_node; 
		}
		else
		{
			*node_out = _node_found; 
		}
	}

//_return:
	return ntstatus;
}
