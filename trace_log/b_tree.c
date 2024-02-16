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
#include "fs_mng_api.h"
#endif //DRIVER

//#define JUST_TEST 1
#define HAVE_LEAF_NODE 1
#include "b_tree.h"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           

#if defined(ASSERT) 
#undef ASSERT
#endif //ASSERT

#if defined(_DEBUG)
#include <assert.h>

#define ASSERT(x) if( ( x ) == FALSE ) __asm int 3; 
//#define ASSERT(x) __assume(x)
#else
#define ASSERT(x) 
#endif

#define DBG_BRK() 
/*
 *  bpt.c  
 */

/*
 *
 *  bpt:  B+ Tree Implementation
 *  Copyright (C) 2010  Amittai Aviram  http://www.amittai.com
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *  Author:  Amittai Aviram 
 *    http://www.amittai.com
 *    amittai.aviram@yale.edu or afa13@columbia.edu
 *    Department of Computer Science
 *    Yale University
 *    P. O. Box 208285
 *    New Haven, CT 06520-8285
 *  Date:  26 June 2010
 *  Last modified: 6 August 2011 
 *
 *  This implementation demonstrates the B+ tree data structure
 *  for educational purposes, includin insertion, deletion, search, and display
 *  of the search path, the leaves, or the whole tree.
 *  
 *  Must be compiled with a C99-compliant C compiler such as the latest GCC.
 *
 *  Usage:  bpt [order]
 *  where order is an optional argument
 *  (integer MIN_BTREE_ORDER <= order <= MAX_BTREE_ORDER)
 *  defined as the maximal number of pointers in any node.
 *
 */

// Uncomment the line below if you are compiling on Windows.
// #define WINDOWS
#ifdef DRIVER
#define printf( fmt, ... ) dbg_print( MSG_INFO, fmt, __VA_ARGS__ ) 
#define malloc( size ) allocate_mem( size ) 
#define free( size ) free_mem( size )
#else
#include <stdio.h>
#include <stdlib.h>
#endif //DRIVER

/* Finds the appropriate place to
 * split a node that is too big into two.
 */
FORCEINLINE int cut( int length ) {
	if (length % 2 == 0)
		return length/2;
	else
		return length/2 + 1;
}

#ifndef __cplusplus
#define false 0
#define true 1
#endif //__cplusplus
// GLOBALS.

/* The order determines the maximum and minimum
 * number of entries (keys and pointers) in any
 * node.  Every node has at most order - 1 keys and
 * at least (roughly speaking) half that number.
 * Every leaf has as many pointers to data as keys,
 * and every internal node has one more pointer
 * to a subtree than the number of keys.
 * This global variable is initialized to the
 * default value.
 */

/* The user can toggle on and off the "verbose"
 * property, which causes the pointer addresses
 * to be printed out in hexadecimal notation
 * next to their corresponding keys.
 */

// FUNCTION DEFINITIONS.

// OUTPUT AND UTILITIES

#ifndef DRIVER
/* Copyright and license notice to user at startup. 
 */
void license_notice( void ) {
	printf("bpt version %s -- Copyright (C) 2010  Amittai Aviram "
			"http://www.amittai.com\n", Version);
	printf("This program comes with ABSOLUTELY NO WARRANTY; for details "
			"type `show w'.\n"
			"This is free software, and you are welcome to redistribute it\n"
			"under certain conditions; type `show c' for details.\n\n");
}


/* Routine to print portion of GPL license to stdout.
 */
void print_license( int license_part ) {
	int start, end, line;
	FILE * fp;
	char buffer[0x100];

	switch(license_part) {
	case LICENSE_WARRANTEE:
		start = LICENSE_WARRANTEE_START;
		end = LICENSE_WARRANTEE_END;
		break;
	case LICENSE_CONDITIONS:
		start = LICENSE_CONDITIONS_START;
		end = LICENSE_CONDITIONS_END;
		break;
	default:
		return;
	}

	fp = fopen(LICENSE_FILE, "r");
	if (fp == NULL) {
		perror("print_license: fopen");
		exit(EXIT_FAILURE);
	}
	for (line = 0; line < start; line++)
		fgets(buffer, sizeof(buffer), fp);
	for ( ; line < end; line++) {
		fgets(buffer, sizeof(buffer), fp);
		printf("%s", buffer);
	}
	fclose(fp);
}


/* First message to the user.
 */
void usage_1( ULONG order ) {
	printf("B+ Tree of Order %d.\n", order);
	printf("Following Silberschatz, Korth, Sidarshan, Database Concepts, 5th ed.\n\n");
	printf("To build a B+ tree of a different order, start again and enter the order\n");
	printf("as an integer argument:  bpt <order>  ");
	printf("(%d <= order <= %d).\n", MIN_BTREE_ORDER, MAX_BTREE_ORDER);
	printf("To start with input from a file of newline-delimited integers, \n"
			"start again and enter ");
	printf("the order followed by the filename:\n"
			"bpt <order> <inputfile> .\n");
}


/* Second message to the user.
 */
void usage_2( void ) {
	printf("Enter any of the following commands after the prompt > :\n");
	printf("\ti <k>  -- Insert <k> (an integer) as both key and value).\n");
	printf("\tf <k>  -- Find the value under key <k>.\n");
	printf("\tp <k> -- Print the path from the root to key k and its associated value.\n");
	printf("\tr <k1> <k2> -- Print the keys and values found in the range "
			"[<k1>, <k2>\n");
	printf("\td <k>  -- Delete key <k> and its associated value.\n");
	printf("\tx -- Destroy the whole tree.  Start again with an empty tree of the same order.\n");
	printf("\tt -- Print the B+ tree.\n");
	printf("\tl -- Print the keys of the leaves (bottom row of the tree).\n");
	printf("\tv -- Toggle output of pointer addresses (\"verbose\") in tree and leaves.\n");
	printf("\tq -- Quit. (Or use Ctl-D.)\n");
	printf("\t? -- Print this help message.\n");
}


/* Brief usage note.
 */
void usage_3( void ) {
	printf("Usage: ./bpt [<order>]\n");
	printf("\twhere %d <= order <= %d .\n", MIN_BTREE_ORDER, MAX_BTREE_ORDER);
}

#endif //DRIVER

/* Helper function for printing the
 * tree out.  See print_tree.
 */
NTSTATUS enqueue( btree *tree, btree_node* new_node )
{
	btree_node * node;
	
	ASSERT( tree != NULL ); 
	ASSERT( new_node != NULL ); 
	
	//if( new_node->is_leaf != FALSE )
	//{
	//	DBG_BRK(); 
	//}

	if( tree->queue == NULL )
	{
		tree->queue = new_node;
		tree->queue->next = NULL;
	}
	else
	{
		node = tree->queue; 
		
		while( node->next != NULL ) 
		{
			if( node == new_node )
			{
				log_trace( ( MSG_ERROR, "input node 0x%0.8x again.\n", node ) ); 
				DBG_BRK(); 
			}

			node = ( btree_node* )node->next; 
		}

		node->next = ( btree_base_node* )new_node; 
		new_node->next = NULL;
	}

	return STATUS_SUCCESS; 
}


/* Helper function for printing the
 * tree out.  See print_tree.
 */
btree_node * dequeue( btree *tree )
{

	btree_node * n;
	
	ASSERT( NULL != tree ); 
	
	n = tree->queue; 

	tree->queue = ( btree_node* )tree->queue->next;
	
	n->next = NULL;
	return n;
}

#ifndef DRIVER
/* Prints the bottom row of keys
 * of the tree (with their respective
 * pointers, if the verbose_output flag is set.
 */

void print_leaves( btree_node* root, ULONG order )
{
	ULONG i;
	btree_node * node;
	
	ASSERT( root != NULL ); 

	if( root == NULL )
	{
		printf("Empty tree.\n");
		return;
	}

	node = root; 
	while( FALSE == node->is_leaf )
	{
		node = node->pointers[ 0 ]; 
	}

	while( TRUE )
	{
		for( i = 0; i < node->num_keys; i++ )
		{
			printf( "%lx ", ( ULONG )node->pointers[ i ] ); 
			printf( "%d ", node->keys[ i ] ); 
		}

		printf( "%lx ", ( ULONG )node->pointers[ order - 1 ] ); 

		if( node->pointers[ order - 1 ] != NULL )
		{
			printf(" | ");
			node = node->pointers[ order - 1 ]; 
		}
		else
		{
			break;
		}
	}

	printf("\n");
}

#endif //DRIVER

/* Utility function to give the height
 * of the tree, which length in number of edges
 * of the path from the root to any leaf.
 */
ULONG height( btree_node* root )
{	
	ULONG h = 0;	
	btree_node * node = root;
	
	while( !node->is_leaf )
	{
		node = node ->pointers[ 0 ]; 
		h++; 
	}

	return h; 
}

/* Utility function to give the length in edges
 * of the path from any btree_node to the root.
 */
ULONG path_to_root( btree_node * root, btree_node * child ) 
{
	ULONG length = 0;
	btree_node *c = child;

	while( c != root )
	{
		c = ( btree_node* )c->parent;
		length++;
	}

	return length;
}

/* Prints the B+ tree in the command
 * line in level (rank) order, with the 
 * keys in each node and the '|' symbol
 * to separate nodes.
 * With the verbose_output flag set.
 * the values of the pointers corresponding
 * to the keys also appear next to their respective
 * keys, in hexadecimal notation.
 */
void print_tree( btree *tree, btree_node *root, ULONG order ) {

	btree_node *node = NULL;
	ULONG i = 0;
	ULONG rank = 0;
	ULONG new_rank = 0; 
	path_tree_node *path_node; 

	ASSERT( tree != NULL ); 
	ASSERT( root != NULL ); 

	do 
	{
		ASSERT( tree != NULL ); 

		if( root == NULL )
		{
			dbg_print( MSG_INFO, "Empty tree.\n");
			break;
		}

		tree->queue = NULL; 

		enqueue( tree, root ); 

		while( tree->queue != NULL )
		{
			node = dequeue( tree );
			if( node->parent != NULL && node== node->parent->pointers[ 0 ] )
			{
				new_rank = path_to_root( root, node ); 

				if( new_rank != rank ) 
				{
					rank = new_rank;
					dbg_print( MSG_INFO, "\n");
				}
			}

			dbg_print( MSG_INFO, "(%lx)", ( ULONG )node ); 

			for( i = 0; i < node->num_keys; i++ )
			{
				dbg_print( MSG_INFO, "%lx ", ( ULONG )node->pointers[ i ] );
				if( TRUE == node->is_leaf )
				{
					path_node = ( path_tree_node* )node->pointers[ i ]; 
					dbg_print( MSG_INFO, "%ws ", path_node->dir ); ; 
				}

				dbg_print( MSG_INFO, "%u ", node->keys[ i ] ); 
			}

			if( FALSE == node->is_leaf )
			{
				BOOLEAN is_btree_node; 
			
				ASSERT( node->num_keys > 0 ); 

				is_btree_node = ( ( btree_node* )node->pointers[ 0 ] )->is_leaf; 

				for( i = 0; i <= node->num_keys; i++ )
				{
					//if( ( ( btree_node* )node->pointers )->is_leaf != FALSE )
					//{
					//	DBG_BRK(); 
					//}

					if( ( ( btree_node* )node->pointers[ i ] )->is_leaf != is_btree_node )
					{
						DBG_BRK(); 
					}

					enqueue( tree, node->pointers[ i ] ); 
				}
			}

			if( TRUE == node->is_leaf )
			{
				dbg_print( MSG_INFO, "=>0x%0.8x ", ( ULONG )node->pointers[ order - 1 ] ); 
			}
			else
			{
				dbg_print( MSG_INFO, "%lx ", ( ULONG )node->pointers[ node->num_keys ] );
			}
			dbg_print( MSG_INFO, "| ");
		}
		dbg_print( MSG_INFO, "\n" );

	}while( FALSE );
}


/* Finds the record under a given key and prints an
* appropriate message to stdout.
*/
void find_and_print( btree *tree, btree_node * root, TREE_KEY_TYPE key, ULONG order )
{
	NTSTATUS ntstatus; 
	path_tree_node *node; 

	do 
	{	
		ntstatus = find_path_comp_node( tree, root, key, &node );
		if( ntstatus != STATUS_SUCCESS )
		{
			ASSERT( node == NULL ); 
			break; 
		}

		ASSERT( node != NULL ); 

		dbg_print( MSG_INFO, "Record not found under key %d.\n", key );
		dbg_print( MSG_INFO, "Record at %lx -- key %d.\n", ( ULONG )node, key  );
	}while ( FALSE );
}

/* Finds and prints the keys, pointers, and values within a range
 * of keys between key_start and key_end, including both bounds.
 */
void find_and_print_range( btree *tree, btree_node * root, TREE_KEY_TYPE key_start, TREE_KEY_TYPE key_end, ULONG order )
{
	NTSTATUS ntstatus; 
	ULONG i;
	ULONG array_size = key_end - key_start + 1;
	TREE_KEY_TYPE *returned_keys; 
	PVOID *returned_pointers;
	ULONG num_found; 
	
	returned_keys = ( TREE_KEY_TYPE* )malloc( sizeof( TREE_KEY_TYPE ) * array_size ); 
	returned_pointers = ( PVOID* )malloc( sizeof( PVOID ) * array_size ); 

	ntstatus = find_tree_range( tree,
		root, 
		key_start, 
		key_end, 
		returned_keys, 
		returned_pointers, 
		&num_found, 
		order ); 

	if( ntstatus != STATUS_SUCCESS )
	{
		ASSERT( 0 == num_found ); 
		printf("None found.\n");
	}
	else
	{
		for( i = 0; i < num_found; i++ )
		{
			dbg_print( MSG_INFO, "Key: %d   Location: %lx \n",
					returned_keys[ i ],
					( ULONG )returned_pointers[ i ] );
		}
	}
}

/* Finds keys and their pointers, if present, in the range specified
 * by key_start and key_end, inclusive.  Places these in the arrays
 * returned_keys and returned_pointers, and returns the number of
 * entries found.
 */
NTSTATUS find_tree_range( btree *tree, btree_node *root, ULONG key_start, ULONG key_end, 
		ULONG returned_keys[], void * returned_pointers[], ULONG *node_count, ULONG order ) 
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG i, num_found;
	btree_node * _node; 
	BOOLEAN lock_held = FALSE; 

	do 
	{
		ASSERT( tree != NULL ); 
		ASSERT( node_count != NULL ); 
		ASSERT( returned_keys != NULL ); 
		ASSERT( returned_pointers != NULL ); 

		num_found = 0;

		hold_tree_r_lock( tree ); 
		lock_held = TRUE; 

		ntstatus = find_tree_leaf_lock_free( tree, root, key_start, &_node );
		if( ntstatus != STATUS_SUCCESS )
		{
			ASSERT( _node == NULL ); 
			break; 
		}
		
		ASSERT( _node != NULL ); 

		for( i = 0; i < _node->num_keys && _node->keys[ i ] < key_start; i++ ) ;

		if( i == _node->num_keys )
		{
			break; 
		}

		while( _node != NULL )
		{
			for ( ; i < _node->num_keys && _node->keys[ i ] <= key_end; i++ )
			{
				returned_keys[ num_found ] = _node->keys[ i ];
				returned_pointers[num_found] = _node->pointers[ i ];
				num_found++;
			}

			_node = _node->pointers[order - 1];
			i = 0;
		}

		*node_count = num_found; 

	}while( FALSE );

	if( lock_held == TRUE )
	{
		release_tree_lock( tree ); 
	}
	return ntstatus;
}

NTSTATUS dump_btree_node( btree_node *node )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG i; 

	do 
	{
		ASSERT( node != NULL ); 

		dbg_print( MSG_INFO, "node is leaf ? %u parent 0x%0.8x next 0x%0.8x\n", node->is_leaf, node->parent, node->next ); 

		for( i = 0; i < node->num_keys; i ++ )
		{
			dbg_print( MSG_INFO, "%uth key %u data 0x%0.8x\n", i, node->keys[ i ], node->pointers[ i ] ); 
		}

		dbg_print( MSG_INFO, "[" );

		for( i = 0; i < node->num_keys; i++)
		{
			dbg_print( MSG_INFO, "%u ", node->keys[i] );
		}

		dbg_print( MSG_INFO, "%u] ", node->keys[ i ] );

		printf("Leaf [");
		for( i = 0; (ULONG )i < node->num_keys - 1; i++ )
		{
			printf("%u ", node->keys[i]);
		}

		printf("%u] ->\n", node->keys[i]);

	} while ( FALSE );

	return ntstatus; 
}

/* Traces the path from the root to a leaf, searching
 * by key.  Displays information about the path
 * if the verbose flag is set.
 * Returns the leaf containing the given key.
 */
NTSTATUS find_tree_leaf_lock_free( btree *tree, btree_node * root, TREE_KEY_TYPE key, btree_node **node_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	int i = 0;
	btree_node *node = root; 

	do 
	{
		ASSERT( tree != NULL ); 
		ASSERT( root != NULL ); 
		ASSERT( node_out != NULL ); 

		*node_out = NULL; 

		if( node == NULL )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			dbg_print( MSG_INFO, "empty tree \n");
			break; 
		}

		//hold_tree_r_lock( tree); 

		while( FALSE == node->is_leaf )
		{
			i = 0; 

			dump_btree_node( node ); 

			while( ( ULONG )i < node->num_keys )
			{
				if( key >= node->keys[ i ] ) 
				{
					i++;
				}
				else 
				{
					break;
				}
			}

			//if( i == node->num_keys )
			//{
			//	ntstatus = STATUS_NOT_FOUND; 
			//	break; 
			//}

			dbg_print( MSG_INFO, "%d ->\n", i );
			node = ( btree_node* )node->pointers[ i ]; 
		}

		//release_tree_lock( tree ); 

	} while ( FALSE );

	*node_out = node; 
	return ntstatus; 
}

/* Finds and returns the record to which
 * a key refers.
 */
NTSTATUS find_path_comp_node( btree *tree, btree_node *root, TREE_KEY_TYPE key, path_tree_node** node_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	ULONG i = 0;
	btree_node *node; 
	BOOLEAN lock_held = FALSE; 
	
	do 
	{
		log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

		//ASSERT( root != NULL ); 
		ASSERT( node_out != NULL ); 

		*node_out = NULL; 

		if( root == NULL )
		{
			ntstatus = STATUS_NOT_FOUND; 
			break; 
		}

		hold_tree_r_lock( tree ); 
		lock_held = TRUE; 

		ntstatus = find_tree_leaf_lock_free( tree, root, key, &node );
		if( ntstatus != STATUS_SUCCESS )
		{
			ASSERT( node == NULL );  
			break; 
		}

		ASSERT( node != NULL ); 

		for( i = 0; i < node->num_keys; i++ )
		{
			if( node->keys[i] == key )
			{
				break;
			}
		}
		
		if( i == node->num_keys )
		{
			ntstatus = STATUS_NOT_FOUND; 
			break; 
		}
		else
		{
			*node_out = ( path_tree_node* )node->pointers[ i ];
		}
		
	}while( FALSE );

	if( lock_held == TRUE )
	{
		release_tree_lock( tree ); 
	}

	dbg_print( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ); 

	return ntstatus; 
}

//btree_node * _find( btree_node * root, TREE_KEY_TYPE key, bool verbose )
//{
//	int i = 0;
//	btree_node * c = find_tree_leaf( root, key, verbose );
//	if (c == NULL) return NULL;
//	for (i = 0; ( ULONG )i < c->num_keys; i++)
//		if (c->keys[i] == key) break;
//	if (i == c->num_keys) 
//		return NULL;
//	else
//		return c; 
//}

/* Finds the appropriate place to
 * split a node that is too big into two.
 */

// INSERTION

#if 0
/* Creates a new record to hold the value
 * to which a key refers.
 */
record * make_record(int value)
{
	record * new_record = NULL; 
	
	do 
	{
		new_record = ( record* )malloc( sizeof( record ) ); 

		if( new_record == NULL )
		{
#ifndef DRIVER
			perror("Record creation.");
			exit(EXIT_FAILURE);
#else
			break; 
#endif //DRIVER
		}
		else
		{
			new_record->value = value;
		}
	}while( FALSE );

	return new_record;
}
#endif //0

/* Creates a new general node, which can be adapted
 * to serve as either a leaf or an internal node.
 */
NTSTATUS make_node( btree *tree, btree_node **node_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	btree_node *new_node = NULL; 

	do 
	{ 

		ASSERT( node_out != NULL ); 
		ASSERT( NULL != tree ); 
		//ASSERT( TRUE == btree_is_inited( tree ) ); 

		*node_out = NULL; 

		new_node = ( btree_node* )malloc( sizeof( btree_node ) );
		if( NULL == new_node ) 
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			break; 
		}

		new_node->keys = NULL; 
		new_node->pointers = NULL; 

		ntstatus = init_tree_node( tree, new_node ); 
	
		if( ntstatus != STATUS_SUCCESS )
		{
			ASSERT( new_node->pointers == NULL ); 
			ASSERT( new_node->keys == NULL ); 
			break; 
		}

		ASSERT( new_node->pointers != NULL ); 
		ASSERT( new_node->keys != NULL ); 

	}while( FALSE ); 

	if( ntstatus != STATUS_SUCCESS )
	{
		if( new_node != NULL )
		{
			if( new_node->keys != NULL )
			{
				free( new_node->keys ); 
			}

			if( new_node->pointers != NULL )
			{
				free( new_node->pointers );
			}
		
			free( new_node ); 
			//new_node = NULL; 
		}
	}
	else
	{
		*node_out = new_node; 
	}

	return ntstatus; 
}

NTSTATUS uninit_btree_lock( btree *tree )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	ASSERT( tree != NULL ); 
	ASSERT( tree->lock != NULL ); 

	do
	{
#ifdef DRIVER
		ExDeleteResourceLite( &tree->lock ); 
#else
		CloseHandle( tree->lock ); 
#endif //DRIVER

	}while( FALSE ); 

	return ntstatus; 
}

/* Creates a new leaf by creating a node
 * and then adapting it appropriately.
 */
NTSTATUS make_leaf( btree *tree, btree_node **node_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	btree_node *leaf = NULL; 

	do 
	{
		ASSERT( tree != NULL ); 
		//ASSERT( btree_is_inited( tree ) ); 
		ASSERT( node_out != NULL ); 

		*node_out = NULL; 

		ntstatus = make_node( tree, &leaf ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			ASSERT( leaf == NULL ); 
			break; 
		}

		ASSERT( leaf != NULL ); 

		leaf->is_leaf = TRUE;
		*node_out = leaf; 

	} while ( FALSE ); 

	return ntstatus; 
}


/* Helper function used in insert_into_parent
 * to find the index of the parent's pointer to 
 * the node to the left of the key to be inserted.
 */
int get_left_index( btree_node *parent, btree_node *left )
{
	INT32 left_index = 0;

	ASSERT( parent != NULL );                                                                     
	ASSERT( parent->is_leaf == FALSE ); 

	while( ( ULONG )left_index <= parent->num_keys 
		&& parent->pointers[ left_index ] != left )
	{
		left_index++;
	}
	
	return left_index;
}

/* Inserts a new pointer to a record and its corresponding
 * key into a leaf.
 * Returns the altered leaf.
 */
#define INVALID_TREE_KEY_VALUE ( TREE_KEY_TYPE )( -1 )

NTSTATUS insert_into_leaf( btree_node *root, TREE_KEY_TYPE key, btree_node *node )
{
	//NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG i; 
	ULONG insertion_point; 

	ASSERT( root != NULL ); 
	ASSERT( key != INVALID_TREE_KEY_VALUE ); 
	ASSERT( node != NULL ); 
	ASSERT( node->keys != NULL ); 
	ASSERT( node->pointers != NULL ); 


	insertion_point = 0;
	while( ( ULONG )insertion_point < root->num_keys 
		&& root->keys[ insertion_point ] < key )
	{
		insertion_point++;
	}

	if( root->keys[ insertion_point ] == key )
	{
#if 0
		if( node->dir[ node->dir_len ] != L'\0' )
		{
			node->dir[ node->dir_len ] = L'\0';  
		}

		dbg_print( MSG_WARNING, "the key of the two name of the path components is same.%ws:%ws\n", root->dir, node->dir ); 
#endif //0
		DBG_BRK(); 
		//ASSERT( FALSE ); 
	}

	for( i = root->num_keys; i > insertion_point; i-- )
	{
		root->keys[ i ] = root->keys[ i - 1 ];
		root->pointers[ i ] = root->pointers[ i - 1 ];
	}

	root->keys[ insertion_point ] = key;
	root->pointers[ insertion_point ] = ( PVOID )node;
	root->num_keys ++;
	
	return STATUS_SUCCESS;
}

NTSTATUS _insert_path_comp_node( btree *tree, btree_node *root, TREE_KEY_TYPE key, path_tree_node *path_node )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG i; 
	ULONG insertion_point; 
	path_tree_node *_path_node; 

	ASSERT( tree != NULL ); 
	ASSERT( TRUE == btree_is_inited( tree ) ); 
	ASSERT( root != NULL ); 
	ASSERT( key != INVALID_TREE_KEY_VALUE ); 
	ASSERT( path_node != NULL ); 
	//ASSERT( path_node->root->keys != NULL ); 
	//ASSERT( path_node->root->pointers != NULL ); 

	do 
	{
		ASSERT( TRUE == root->is_leaf ); 

		if( root->num_keys >= tree->tree_order )
		{
			ASSERT( FALSE ); 
			ntstatus = STATUS_INVALID_PARAMETER; 
			BTREE_BUG_CHECK( STATUS_INVALID_PARAMETER ); 
			break; 
		}

		insertion_point = 0;
		while( ( ULONG )insertion_point < root->num_keys 
			&& root->keys[ insertion_point ] < key )
		{
			insertion_point++;
		}

#ifdef DBG
		if( root->keys[ insertion_point ] == key )
		{
			if( path_node->dir[ path_node->dir_len ] != L'\0' )
			{
				path_node->dir[ path_node->dir_len ] = L'\0';  
			}

			_path_node = ( path_tree_node* )root->pointers[ insertion_point ]; 

			dbg_print( MSG_WARNING, "the key of the two name of the path components is same.%ws:%ws\n", _path_node->dir, path_node->dir ); 
			DBG_BRK(); 
#ifdef KEY_CANT_CONFLICT
			ntstatus = STATUS_UNSUCCESSFUL; 
			break; 
#endif //KEY_CANT_CONFLICT
		}
#endif //DBG

		for( i = root->num_keys; i > insertion_point; i-- )
		{
			root->keys[ i ] = root->keys[ i - 1 ];
			root->pointers[ i ] = root->pointers[ i - 1 ];
		}

		root->keys[ insertion_point ] = key;
		root->pointers[ insertion_point ] = ( PVOID )path_node;
		root->num_keys ++;
	}while( FALSE );

	return ntstatus;
}

/* Inserts a new key and pointer to a node
 * into a node, causing the node's size to exceed
 * the order, and causing the node to split into two.
 */
NTSTATUS insert_btree_node_by_split( btree *tree, 
	btree_node *root, 
	btree_node *old_node, 
	ULONG left_index, 
	TREE_KEY_TYPE key, 
	btree_node *right, 
	btree_node **node_out, 
	TREE_KEY_TYPE *node_key_out, 
	btree_node *node_alloc, 
	btree_node ** new_root )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG i, j, split; 
	TREE_KEY_TYPE k_prime; 
	btree_node *_new_node = NULL; 
	btree_node *new_node; 
	btree_node *child;
	TREE_KEY_TYPE temp_keys[ MAX_BTREE_ORDER + 1 ]; 
	PVOID temp_pointers[ MAX_BTREE_ORDER + 1 ]; 
#ifdef DBG
	BOOLEAN is_leaf; 
#endif //DBG

	ASSERT( tree != NULL ); 
	ASSERT( TRUE == btree_is_inited( tree ) ); 
	ASSERT( old_node->num_keys < tree->tree_order ); 
	ASSERT( node_key_out != NULL ); 
	ASSERT( node_out != NULL ); 

	do 
	{
		dbg_print( MSG_INFO, "enter %s\n", __FUNCTION__ ); 

		*node_key_out = INVALID_TREE_KEY_VALUE; 
		*node_out = NULL; 

		//ULONG *temp_keys;
		//btree_node **temp_pointers;

		/* First create a temporary set of keys and pointers
		* to hold everything in order, including
		* the new key and pointer, inserted in their
		* correct places. 
		* Then create a new node and copy half of the 
		* keys and pointers to the old node and
		* the other half to the new.
		*/

		//temp_pointers = malloc( (order + 1) * sizeof(node *) );
		//if (temp_pointers == NULL) {
		//	perror("Temporary pointers array for splitting nodes.");
		//	exit(EXIT_FAILURE);
		//}
		//temp_keys = malloc( order * sizeof(int) );
		//if (temp_keys == NULL) {
		//	perror("Temporary keys array for splitting nodes.");
		//	exit(EXIT_FAILURE);
		//}

		for( i = 0, j = 0; i < old_node->num_keys + 1; i++, j++)
		{
			if( j == left_index + 1 )
				j++; 

			temp_pointers[ j ] = old_node->pointers[ i ]; 
		}

		for( i = 0, j = 0; i < old_node->num_keys; i++, j++ )
		{
			if( j == left_index )
				j++;

			temp_keys[ j ] = old_node->keys[ i ];
		}

		temp_pointers[ left_index + 1 ] = right;
		temp_keys[ left_index ] = key;

		/* Create the new node and copy
		* half the keys and pointers to the
		* old and half to the new.
		*/  
		split = cut( tree->tree_order );

		if( node_alloc != NULL )
		{
			new_node = node_alloc; 

#ifdef DBG
			if( new_node->is_leaf == TRUE )
			{
				ASSERT( FALSE ); 
				new_node->is_leaf = FALSE; 
			}
#endif //DBG

		}
		else
		{
			ntstatus = make_node( tree, &_new_node ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				ASSERT( _new_node == NULL ); 
				break; 
			}

			new_node = _new_node; 
		}

		dbg_print( MSG_INFO, "make a new node 0x%0.8x\n", new_node ); 

		ASSERT( new_node != NULL ); 

		old_node->num_keys = 0;
		for( i = 0; i < split - 1; i++ )
		{
			old_node->pointers[ i ] = temp_pointers[ i ];
			old_node->keys[ i ] = temp_keys[ i ];
			old_node->num_keys ++;
		}

		old_node->pointers[ i ] = temp_pointers[ i ];

		ASSERT( i == split - 1 ); 

		k_prime = temp_keys[ split - 1 ]; 

		for( ++i, j = 0; i < btree_node_max_sub_node_count( tree->tree_order ); i++, j++ )
		{
			new_node->pointers[ j ] = temp_pointers[ i ];
			new_node->keys[ j ] = temp_keys[ i ];
			new_node->num_keys ++;
		}

		new_node->pointers[ j ] = temp_pointers[ i ];

#ifdef DBG
		for( i = 0; i < split - 1; i ++ )
		{
			ASSERT( old_node->keys[ i ] != k_prime ); 
		}

		for( i = 0; i < btree_node_max_sub_node_count( tree->tree_order ) - split; i ++ )
		{
			ASSERT( new_node->keys[ i ] != k_prime ); 
		}
#endif //DBG

		//free(temp_pointers);
		//free(temp_keys);

#ifdef DBG
		is_leaf = ( ( btree_node* )new_node->pointers[ 0 ] )->is_leaf; 
#endif //DBG


		new_node->parent = old_node->parent;
		for( i = 0; i <= new_node->num_keys; i++ )
		{

			child = ( btree_node* )new_node->pointers[ i ]; 

#ifdef DBG
			ASSERT( child->parent == old_node || child->parent == NULL ); 

			if( is_leaf != child->is_leaf )
			{
				DBG_BRK(); 
			}
#endif //DBG

			child->parent = new_node; 
		}

		/* Insert a new key into the parent of the two
		* nodes resulting from the split, with
		* the old node to the left and the new to the right.
		*/

		*node_out = new_node; 
		*node_key_out = k_prime; 

	}while( FALSE );

	if( ntstatus != STATUS_SUCCESS )
	{
		if( _new_node != NULL )
		{
			free_tree_node( _new_node ); 
		}
	}

	dbg_print( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ); 

	return ntstatus; 
}

typedef struct _insert_nodes
{
	btree_node *all_nodes; 
	ULONG nodes_count; 
} insert_nodes, *pinsert_nodes; 

//NTSTATUS allocate_insert_nodes(btree *tree, 
//	btree_node* parent, 
//	btree_node* sibling, 
//	TREE_KEY_TYPE key, 
//	btree_node* path_node, 
//	btree_node** node_out, 
//	TREE_KEY_TYPE *node_key_out,  
//	btree_node** new_root )
//{
//	NTSTATUS ntstatus = STATUS_SUCCESS; 
//
//	do 
//	{
//		ntstatus = make_leaf( tree, &new_node ); 
//		if( ntstatus != STATUS_SUCCESS )
//		{
//			ASSERT( new_node == NULL ); 
//			break; 
//		}
//
//	}while( FALSE );
//
//	return ntstatus; 
//}

NTSTATUS release_preallocate_nodes_depends( preallocate_nodes *all_nodes )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		ASSERT( all_nodes != NULL ); 

		{
			if( all_nodes->nodes != NULL )
			{
				free_mem( all_nodes->nodes ); 
			}

			all_nodes->nodes = NULL; 
			all_nodes->node_count = 0; 
		}

	} while ( FALSE ); 

	return ntstatus; 
}

NTSTATUS release_preallocate_nodes( preallocate_nodes *all_nodes )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 i; 

	do 
	{
		ASSERT( all_nodes != NULL ); 

		if( all_nodes->node_count == 0 || all_nodes->nodes == NULL )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		for( i = 0; ( ULONG )i < all_nodes->node_count; i ++ )
		{
			if( all_nodes->nodes[ i ] != NULL )
			{
				free_mem( all_nodes->nodes[ i ] ); 
			}
			else
			{
				ASSERT( FALSE ); 
			}
		}

		free_mem( all_nodes->nodes ); 

	} while ( FALSE );

	all_nodes->node_count = 0; 
	all_nodes->nodes = NULL; 

	return ntstatus; 
}

NTSTATUS preallocate_need_nodes( btree *tree, 
	btree_node* root, 
	btree_node* sibling, 
	preallocate_nodes *nodes_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG _node_count = 1; 
	btree_node *parent; 
	btree_node **_all_node_out = NULL; 
	INT32 i; 

	do 
	{
		dbg_print( MSG_INFO, "enter %s\n", __FUNCTION__ ); 

		ASSERT( tree != NULL ); 
		ASSERT( TRUE == btree_is_inited( tree ) ); 
		ASSERT( sibling != NULL ); 
		ASSERT( sibling->is_leaf == TRUE ); 
		ASSERT( nodes_out != NULL ); 

		nodes_out->node_count = 0; 
		nodes_out->nodes = NULL; 

		if( sibling->num_keys < btree_leaf_max_key_count( tree->tree_order ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			dbg_print( MSG_FATAL_ERROR, "why split the node that have more space %u to save new pointer\n", sibling->num_keys ); 
			BTREE_BUG_CHECK( STATUS_INVALID_PARAMETER ); 
			break; 
		}

		dbg_print( MSG_INFO, "sibling is 0x%0.8x\n", sibling ); 

		dbg_print( MSG_INFO, "allocate 1 leaf node for the new data entry, need nodes count: %u\n", _node_count ); 

		parent = sibling->parent; 

		for( ; ; )
		{
			if( parent == NULL )
			{
				_node_count ++; 

				dbg_print( MSG_INFO, "allocate 1 node for changing original root to new position, need nodes count: %u\n", _node_count ); 
				break; 
			}

			ASSERT( parent->is_leaf == FALSE ); 

			if( parent->num_keys >= btree_node_max_key_count( tree->tree_order ) )
			{
				_node_count ++; 

				dbg_print( MSG_INFO, "allocate 1 node for allocate the parent 0x%0.8x of the node contain allocated node, need nodes count: %u\n", parent, _node_count ); 
			}
			else
			{
				break; 
			}

			dbg_print( MSG_INFO, "locate to the node 0x%0.8x parent 0x%0.8x\n", parent, parent->parent ); 
			parent = parent->parent; 
		}

		_all_node_out = ( btree_node** )allocate_mem( sizeof( btree_node* ) * _node_count ); 
		if( _all_node_out == NULL )
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			break; 
		}

		memset( _all_node_out, 0, sizeof( btree_node* ) * _node_count ); 

		ntstatus = make_leaf( tree, &_all_node_out[ 0 ] ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		for( i = 1; ( ULONG )i < _node_count; i ++ )
		{ 
			ntstatus = make_node( tree, &_all_node_out[ i ] ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				break; 
			}
		}

		nodes_out->nodes = _all_node_out; 
		nodes_out->node_count = _node_count; 

	}while( FALSE );

	if( ntstatus != STATUS_SUCCESS )
	{
		for( i = 0; ( ULONG )i < _node_count; i ++ )
		{
			if( NULL != _all_node_out[ i ] )
			{
				free_mem( _all_node_out[ i ] ); 
			}
		}

		free_mem( _all_node_out ); 

		ASSERT( nodes_out->node_count == 0 ); 
		ASSERT( nodes_out->nodes == NULL ); 
	}

	dbg_print( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ); 

	return ntstatus; 
}

/* Inserts a new key and pointer
 * to a new record into a leaf so as to exceed
 * the tree's order, causing the leaf to be split
 * in half.
 */

NTSTATUS insert_path_comp_node_by_split( btree *tree, 
	btree_node* parent, 
	btree_node* sibling, 
	TREE_KEY_TYPE key, 
	btree_node* path_node, 
	btree_node* pre_allocate_node, 
	btree_node** node_out, 
	TREE_KEY_TYPE *node_key_out,  
	btree_node** new_root )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	btree_node *_new_node = NULL; 
	btree_node *new_node; 
	//TREE_KEY_TYPE* temp_keys = NULL; 
	//PVOID *temp_pointers = NULL; 
	ULONG insertion_index, split, new_key, i, j;
	TREE_KEY_TYPE temp_keys[ MAX_BTREE_ORDER + 1 ]; 
	PVOID temp_pointers[ MAX_BTREE_ORDER + 1 ]; 
	ULONG order; 

	do 
	{
		dbg_print( MSG_INFO, "enter %s\n", __FUNCTION__ ); 

		ASSERT( tree != NULL ); 
		ASSERT( parent != NULL ); 
		ASSERT( sibling != NULL ); 
		ASSERT( path_node != NULL ); 
		ASSERT( node_key_out != NULL ); 
		ASSERT( node_out != NULL ); 
		
		ASSERT( key != INVALID_TREE_KEY_VALUE ); 

		*node_key_out = INVALID_TREE_KEY_VALUE; 
		*node_out = NULL; 

		order = tree->tree_order; 

		if( TRUE == parent->is_leaf ? ( parent->num_keys < btree_node_max_key_count( order ) ) : FALSE )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		if( pre_allocate_node != NULL )
		{
			new_node = pre_allocate_node; 
			if( new_node->is_leaf == FALSE )
			{
				ASSERT( FALSE ); 
				new_node->is_leaf = TRUE; 
			}
		}
		else
		{
			ntstatus = make_leaf( tree, &_new_node ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				ASSERT( _new_node == NULL ); 
				break; 
			}
		
			new_node = _new_node; 
		}

		ASSERT( new_node != NULL ); 

		dbg_print( MSG_INFO, "make a new node 0x%0.8x\n", new_node ); 

		//temp_keys = ( TREE_KEY_TYPE* )malloc( order * sizeof( TREE_KEY_TYPE ) );
		//if( NULL == temp_keys )
		//{
		//	ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		//	break; 
		//}

		//temp_pointers = ( PVOID* )malloc( order * sizeof( PVOID ) );
		//if( NULL == temp_pointers )
		//{
		//	ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
		//	break; 
		//}

		insertion_index = 0;
		while( insertion_index < tree->tree_order - 1 
			&& sibling->keys[ insertion_index ] < key )
		{
			insertion_index++;
		}

		for( i = 0, j = 0; ( ULONG )i < sibling->num_keys; i++, j++ )
		{
			if( j == insertion_index )
			{
				j++;
			}

			temp_keys[ j ] = sibling->keys[ i ]; 
			temp_pointers[ j ] = sibling->pointers[ i ]; 
		}

		temp_keys[ insertion_index ] = key; 
		temp_pointers[ insertion_index ] = path_node;

		sibling->num_keys = 0;

		split = cut( order ); 

		for( i = 0; i < split; i++ )
		{
			sibling->pointers[ i ] = temp_pointers[ i ];
			sibling->keys[ i ] = temp_keys[ i ];
			sibling->num_keys++; 
		}

		for( i = split, j = 0; i < order; i++, j++ )
		{
			new_node->pointers[ j ] = temp_pointers[ i ]; 
			new_node->keys[ j ] = temp_keys[ i ]; 
			new_node->num_keys ++; 
		}

		//free( temp_pointers ); 
		//free( temp_keys ); 

		new_node->pointers[ btree_sibling_node_index( order ) ] = sibling->pointers[ btree_sibling_node_index( order ) ]; 
		sibling->pointers[ btree_sibling_node_index( order ) ] = new_node; 

		memset( &sibling->pointers[ sibling->num_keys ], 
			0, 
			sizeof( sibling->pointers[ 0 ] ) * ( btree_leaf_max_key_count( order ) - sibling->num_keys ) ); 

		//for( i = leaf->num_keys; i < order - 1; i++ )
		//{
		//	leaf->pointers[ i ] = NULL; 
		//}

		memset( &new_node->pointers[ new_node->num_keys ] , 
			0, 
			sizeof( new_node->pointers[ 0 ] ) * ( btree_leaf_max_key_count( order ) - new_node->num_keys ) ); 

		//for( i = new_leaf->num_keys; i < order - 1; i++ )
		//{
		//	new_leaf->pointers[ i ] = NULL; 
		//}

#ifdef DBG
		for( i = 0; i < btree_leaf_max_key_count( order ); i ++ )
		{
			if( i < sibling->num_keys )
			{
				ASSERT( sibling->pointers[ i ] != NULL ); 
			}
			else
			{
				ASSERT( sibling->pointers[ i ] == NULL ); 
			}
		}

		for( i = 0; i < btree_leaf_max_key_count( order ); i ++ )
		{
			if( i < new_node->num_keys )
			{	
				ASSERT( new_node->pointers[ i ] != NULL ); 
			}
			else
			{
				ASSERT( new_node->pointers[ i ] == NULL ); 
			}
		}
#endif //DBG

		new_node->parent = sibling->parent;
		new_key = new_node->keys[ 0 ]; 

		*node_out = new_node; 
		*node_key_out = new_key; 
	}while( FALSE );

	dbg_print( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ); 

	return ntstatus; 
}


/* Inserts a new key and pointer to a node
* into a node into which these can fit
* without violating the B+ tree properties.
*/
NTSTATUS insert_into_node( btree *tree, btree_node *root, btree_node *node, 
	ULONG left_index, TREE_KEY_TYPE key, btree_node *right )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG i; 
	ULONG order; 

	do 
	{
		order = tree->tree_order; 

#define INVALID_B_TREE_NODE_INDEX ( ULONG )( -1 )
		if( left_index == INVALID_B_TREE_NODE_INDEX )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			ASSERT( FALSE ); 
			break; 
		}

		ASSERT( FALSE == node->is_leaf ); 

#ifdef DBG
		for( i = 0; i <= node->num_keys; i ++ )
		{
			if( node->pointers[ i ] == right )
			{
				DBG_BRK(); 
			}
		}
#endif //DBG

		if( node->num_keys >= btree_node_max_key_count( order ) )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		for( i = node->num_keys; i > left_index; i-- )
		{
			node->pointers[ i + 1 ] = node->pointers[ i ]; 

			node->keys[ i ] = node->keys[ i - 1 ]; 
		}

		node->pointers[ left_index + 1 ] = right; 

		node->keys[ left_index ] = key; 

		node->num_keys++; 
	}while( FALSE );


 	return ntstatus;
}

/* Inserts a new key and pointer to a node
 * into a node, causing the node's size to exceed
 * the order, and causing the node to split into two.
 */

/* Inserts a new node (leaf or internal node) into the B+ tree.
* Returns the root of the tree after insertion.
*/

#ifdef DBG
NTSTATUS insert_path_comp_node_into_parent( btree *tree, 
	btree_node *root, 
	btree_node *left, 
	TREE_KEY_TYPE key, 
	btree_node *right, 
	node_insert_info *insert_info, 
	btree_node *node_alloc, 
	btree_node **new_root, 
	BOOLEAN *make_new_node )
#else
NTSTATUS insert_path_comp_node_into_parent( btree *tree, 
	btree_node *root, 
	btree_node *left, 
	TREE_KEY_TYPE key, 
	btree_node *right, 
	node_insert_info *insert_info, 
	btree_node *node_alloc, 
	btree_node **new_root )
#endif //DBG
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG left_index; 
	btree_node *parent; 
	btree_node *_root; 

	do
	{
		dbg_print( MSG_INFO, "enter %s\n", __FUNCTION__ ); 
		ASSERT( tree != NULL ); 
		ASSERT( TRUE == btree_is_inited( tree ) ); 
		ASSERT( root != NULL ); 
		ASSERT( left != NULL ); 
		ASSERT( new_root != NULL ); 
		ASSERT( INVALID_TREE_KEY_VALUE != key ); 
		ASSERT( right != NULL ); 
		ASSERT( insert_info != NULL ); 

#ifdef DBG
		ASSERT( NULL != make_new_node ); 
		*make_new_node = FALSE; 
#endif //DBG
		//*new_root = NULL; 

		insert_info->left_index = ( ULONG )-1; 
		insert_info->node = NULL; 
		insert_info->parent = NULL; 
		insert_info->node_key = INVALID_TREE_KEY_VALUE; 

		parent = ( btree_node* )left->parent;

		/* Case: new root. */

		if( NULL == parent )
		{
			if( node_alloc == NULL )
			{
				ASSERT( FALSE ); 
				BTREE_BUG_CHECK( STATUS_UNSUCCESSFUL ); 
				break; 
			}

#ifdef DBG
			*make_new_node = TRUE; 
#endif //DBG
			ntstatus = insert_path_comp_node_to_new_root( tree, left, key, right, node_alloc, &_root ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				ASSERT( NULL == _root ); 
				BTREE_BUG_CHECK( ntstatus ); 
				break; 
			}

			ASSERT( NULL != _root ); 
			//parent = _root; 
			
			if( *new_root != NULL )
			{
				DBG_BRK(); 
				BTREE_BUG_CHECK( STATUS_INVALID_PARAMETER ); 
			}

			*new_root = _root; 
			break; 
		}


		/* Case: leaf or node. (Remainder of
		* function body.)  
		*/

		/* Find the parent's pointer to the left 
		* node.
		*/

 		left_index = get_left_index( parent, left );


		/* Simple case: the new key fits into the node. 
		*/

		if( parent->num_keys < btree_node_max_key_count( tree->tree_order ) )
		{
			ntstatus = insert_into_node( tree, root, parent, left_index, key, right ); 
			dbg_print( MSG_INFO, "insert the suitable parent 0x%0.8x\n", parent ); 

#ifdef DBG
			if( node_alloc != NULL )
			{
				ASSERT( FALSE ); 
				BTREE_BUG_CHECK( STATUS_UNSUCCESSFUL ); 
			}
#endif //DBG
			break; 
		}

		/* Harder case:  split a node in order 
		* to preserve the B+ tree properties.
		*/
		{
			btree_node *node_inserted; 
			TREE_KEY_TYPE key_inserted; 

			ASSERT( *new_root == NULL ); 

#ifdef DBG
			if( node_alloc == NULL )
			{
				ASSERT( FALSE ); 
				BTREE_BUG_CHECK( STATUS_UNSUCCESSFUL ); 
			}
#endif //DBG

#ifdef DBG
			*make_new_node = TRUE; 
#endif //DBG

			ntstatus = insert_btree_node_by_split( tree, root, parent, left_index, key, right, &node_inserted, &key_inserted, node_alloc, new_root );
			if( ntstatus != STATUS_SUCCESS )
			{
				break; 
			}

			ASSERT( node_inserted != NULL ); 
			ASSERT( key_inserted != INVALID_TREE_KEY_VALUE ); 

			insert_info->parent = parent; 
			insert_info->node = node_inserted; 
			insert_info->node_key = key_inserted; 
			insert_info->left_index = left_index; 

			ntstatus = STATUS_MORE_PROCESSING_REQUIRED; 
		}

	}while( FALSE ); 

	dbg_print( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ); 

	return ntstatus; 
}

/* Creates a new root for two subtrees
* and inserts the appropriate key into
* the new root.
*/

NTSTATUS insert_path_comp_node_to_new_root( btree *tree, btree_node *left, TREE_KEY_TYPE key, btree_node *right, btree_node *node_alloc, btree_node **root_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	btree_node *root; 
	btree_node *_root = NULL; 

	do
	{
		log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

		ASSERT( tree != NULL ); 
		ASSERT( TRUE == btree_is_inited( tree ) ); 

		ASSERT( root_out != NULL ); 

		*root_out = NULL; 

		if( node_alloc != NULL )
		{
			root = node_alloc; 

#ifdef DBG
			if( root->is_leaf == TRUE )
			{
				ASSERT( FALSE ); 
				root->is_leaf = FALSE; 
			}
#endif //DBG

		}
		else 
		{
			ntstatus = make_node( tree, &_root ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				ASSERT( _root == NULL ); 
				break; 
			}

			root = _root; 
		}

		ASSERT( root != NULL ); 

		dbg_print( MSG_INFO, "make a new node 0x%0.8x\n", root ); 

		root->keys[ 0 ] = key;
		root->pointers[ 0 ] = left;
		root->pointers[ 1 ] = right; 

		root->num_keys++;
		root->parent = NULL;
		left->parent = ( btree_base_node* )root;
		right->parent = ( btree_base_node* )root;

		*root_out = root; 

	}while( FALSE ); 

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 

	if( ntstatus != STATUS_SUCCESS )
	{
		if( _root != NULL )
		{
			free_tree_node( _root ); 
		}
	}

	return ntstatus;
}

/* Master insertion function.
 * Inserts a key and an associated value into
 * the B+ tree, causing the tree to be adjusted
 * however necessary to maintain the B+ tree
 * properties.
 */

#ifndef DRIVER
#define KeBugCheckEx( status_code, param1, param2, param3, param4 ) 
#endif //DRIVER

NTSTATUS insert_path_comp_node_lock_free( btree *tree, btree_node *root, TREE_KEY_TYPE key, path_tree_node *path_node, btree_node **new_root ) 
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	//record * pointer; 
	btree_node *leaf; 
	preallocate_nodes need_nodes = { 0 }; 
	path_tree_node *_path_node; 
	//BOOLEAN lock_held = FALSE; 
	//btree_node *new_node; 

	/* The current implementation ignores
	 * duplicates.
	 */

	do 
	{
		ASSERT( tree != NULL ); 
		ASSERT( TRUE == btree_is_inited( tree ) ); 

		//ASSERT( root != NULL ); 
		ASSERT( key != INVALID_TREE_KEY_VALUE ); 
		ASSERT( new_root != NULL ); 

		*new_root = NULL; 

		if( path_node == NULL )
		{
			DBG_BRK(); 
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		if( root == NULL ) 
		{
			DBG_BRK(); 
			
			ntstatus = make_leaf( tree, &leaf ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				break; 
			}

			ASSERT( leaf != NULL ); 
			ASSERT( leaf->num_keys == 0 ); 

			leaf->keys[ 0 ] = key; 
			leaf->pointers[ 0 ] = path_node; 
			leaf->num_keys = 1; 

			*new_root = leaf; 
			//ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		ntstatus = find_path_comp_node( tree, root, key, &_path_node ); 
		if( ntstatus == STATUS_SUCCESS )
		{
			ASSERT( _path_node != NULL ); 
			ASSERT( _path_node->key == key ); 
			ASSERT( 0 == compare_str( path_node->dir, path_node->dir_len, _path_node->dir, _path_node->dir_len ) ); 

			ASSERT( FALSE ); 
			//__asm int 3; 

			ntstatus = STATUS_UNSUCCESSFUL; 
			break; 
		}

		/* Create a new record for the
		* value.
		*/

		/* Case: the tree already exists.
		* (Rest of function body.)
		*/

		/* Case: leaf has room for key and pointer.
		*/
		
		//hold_w_res_lock( tree->lock ); 

		ntstatus = find_tree_leaf_lock_free( tree, root, key, &leaf ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		ASSERT( leaf != NULL ); 
		if( leaf->num_keys >= btree_leaf_max_key_count( tree->tree_order ) )
		{
			btree_node *leaf_inserted; 
			TREE_KEY_TYPE leaf_key; 
			node_insert_info insert_info; 
			btree_node *left; 
			ULONG pre_alloc_node_used = 0; 
			BOOLEAN make_new_node; 

			//__asm int 3; 

			insert_info.left_index = -1; 
			insert_info.node = NULL; 
			insert_info.parent = NULL; 
			insert_info.node_key = INVALID_TREE_KEY_VALUE; 

			ntstatus = preallocate_need_nodes( tree, root, leaf, &need_nodes ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				ASSERT( FALSE ); 
				break; 
			}

			ASSERT( need_nodes.node_count > 0 ); 
			ASSERT( need_nodes.nodes != NULL ); 

			/* 
			 * Case:  leaf must be split.
			 */

			ntstatus = insert_path_comp_node_by_split( tree, root, leaf, key, ( btree_node* )path_node, need_nodes.nodes[ 0 ], &leaf_inserted, &leaf_key, new_root ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				ASSERT( FALSE ); 
				dbg_print( MSG_FATAL_ERROR, "insert node by split error 0x%0.8x\n", ntstatus ); 
				KeBugCheckEx( ntstatus, ( ULONG_PTR )( ULONG )'pert', ( ULONG_PTR )( ULONG )'tlps', ( ULONG_PTR )path_node, ( ULONG_PTR )leaf_key ); 
				break; 
			}

			ASSERT( leaf_inserted != NULL ); 
			ASSERT( leaf_key != INVALID_TREE_KEY_VALUE ); 

			pre_alloc_node_used += 1; 
			left = leaf; 
			for( ; ; )
			{
				if( pre_alloc_node_used >= need_nodes.node_count + 1 )
				{
					ASSERT( FALSE ); 

					ntstatus = STATUS_UNSUCCESSFUL; 
					KeBugCheckEx( ntstatus, ( ULONG_PTR )( ULONG )'pert', ( ULONG_PTR )( ULONG )'tlps', ( ULONG_PTR )path_node, ( ULONG_PTR )leaf_key ); 
					
					break; 
				}

#ifdef DBG
				ntstatus = insert_path_comp_node_into_parent( tree, 
					root, 
					left, 
					leaf_key, 
					leaf_inserted, 
					&insert_info, 
					pre_alloc_node_used >= need_nodes.node_count ? NULL : need_nodes.nodes[ pre_alloc_node_used ], 
					new_root, 
					&make_new_node ); 
#else
				ntstatus = insert_path_comp_node_into_parent( tree, 
					root, 
					left, 
					leaf_key, 
					leaf_inserted, 
					&insert_info, 
					pre_alloc_node_used >= need_nodes.node_count ? NULL : need_nodes.nodes[ pre_alloc_node_used ], 
					new_root ); 
#endif //DBG
				if( ntstatus != STATUS_SUCCESS )
				{
					if( ntstatus != STATUS_MORE_PROCESSING_REQUIRED )
					{
						dbg_print( MSG_FATAL_ERROR, "insert node into parent 0x%0.8x error 0x%0.8x\n", left, ntstatus ); 
						KeBugCheckEx( ntstatus, ( ULONG_PTR )( ULONG )'pert', ( ULONG_PTR )( ULONG )'tlps', ( ULONG_PTR )path_node, ( ULONG_PTR )leaf_key ); 
						break; 
					}

					ASSERT( TRUE == is_valid_insert_info( &insert_info ) ); 

					left = insert_info.parent; 
					leaf_key = insert_info.node_key; 
					leaf_inserted = insert_info.node; 
				}
				else
				{
					ASSERT( FALSE == is_valid_insert_info( &insert_info ) ); 

#ifdef DBG
					if( make_new_node == TRUE )
					{
						pre_alloc_node_used ++; 
					}
					else
					{
						dbg_print( MSG_INFO, "the previous parent node have enough space to save the new node\n" ); 
					}
#else
					if( pre_alloc_node_used < need_nodes.node_count )
					{
						pre_alloc_node_used ++; 
					}
#endif //DBG
					ASSERT( pre_alloc_node_used == need_nodes.node_count ); 
					break; 
				}

				pre_alloc_node_used ++; 
			}

			release_preallocate_nodes_depends( &need_nodes ); 
			break; 
		}	
		else
		{
			ntstatus = _insert_path_comp_node( tree, leaf, key, path_node ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				log_trace( ( MSG_ERROR, "insert leaf error 0x%0.8x\n", ntstatus ) ); 
				break; 
			}
		}
	}while( FALSE );

	//if( lock_held == TRUE )
	//{
	//	release_tree_lock( tree ); 
	//}

	if( ntstatus != STATUS_SUCCESS )
	{
		ASSERT( need_nodes.node_count == 0 ); 
		ASSERT( need_nodes.nodes == NULL ); 

		release_preallocate_nodes( &need_nodes ); 
	}

	return ntstatus; 
}

//ULONG calc_path_comp_key( LPCWSTR sub_dir, ULONG sub_dir_len ); 
#include "crc.h"

/* flag values */
#define FL_UNSIGNED   1       /* wcstoul called */
#define FL_NEG        2       /* negative sign found */
#define FL_OVERFLOW   4       /* overflow occured */
#define FL_READDIGIT  8       /* we've read at least one correct digit */

/* Asserts */
/* We use !! below to ensure that any overloaded operators used to evaluate expr do not end up at operator || */
#define _ASSERT_EXPR(expr, msg) 

#ifndef _VALIDATE_RETURN
#define _VALIDATE_RETURN( expr, errorcode, retexpr )                           \
	{                                                                          \
	int _Expr_val=!!(expr);                                                \
	_ASSERT_EXPR( ( _Expr_val ), _CRT_WIDE(#expr) );                       \
	if ( !( _Expr_val ) )                                                  \
		{                                                                      \
		errno = errorcode;                                                 \
		return ( retexpr );                                                \
}                                                                      \
}
#endif  /* _VALIDATE_RETURN */

int _wchartodigit(wchar_t ch)
{
#define DIGIT_RANGE_TEST(zero)  \
	if (ch < zero)              \
	return -1;              \
	if (ch < zero + 10)         \
	{                           \
	return ch - zero;       \
}

	DIGIT_RANGE_TEST(0x0030)        // 0030;DIGIT ZERO
		if (ch < 0xFF10)                // FF10;FULLWIDTH DIGIT ZERO
		{
			DIGIT_RANGE_TEST(0x0660)    // 0660;ARABIC-INDIC DIGIT ZERO
				DIGIT_RANGE_TEST(0x06F0)    // 06F0;EXTENDED ARABIC-INDIC DIGIT ZERO
				DIGIT_RANGE_TEST(0x0966)    // 0966;DEVANAGARI DIGIT ZERO
				DIGIT_RANGE_TEST(0x09E6)    // 09E6;BENGALI DIGIT ZERO
				DIGIT_RANGE_TEST(0x0A66)    // 0A66;GURMUKHI DIGIT ZERO
				DIGIT_RANGE_TEST(0x0AE6)    // 0AE6;GUJARATI DIGIT ZERO
				DIGIT_RANGE_TEST(0x0B66)    // 0B66;ORIYA DIGIT ZERO
				DIGIT_RANGE_TEST(0x0C66)    // 0C66;TELUGU DIGIT ZERO
				DIGIT_RANGE_TEST(0x0CE6)    // 0CE6;KANNADA DIGIT ZERO
				DIGIT_RANGE_TEST(0x0D66)    // 0D66;MALAYALAM DIGIT ZERO
				DIGIT_RANGE_TEST(0x0E50)    // 0E50;THAI DIGIT ZERO
				DIGIT_RANGE_TEST(0x0ED0)    // 0ED0;LAO DIGIT ZERO
				DIGIT_RANGE_TEST(0x0F20)    // 0F20;TIBETAN DIGIT ZERO
				DIGIT_RANGE_TEST(0x1040)    // 1040;MYANMAR DIGIT ZERO
				DIGIT_RANGE_TEST(0x17E0)    // 17E0;KHMER DIGIT ZERO
				DIGIT_RANGE_TEST(0x1810)    // 1810;MONGOLIAN DIGIT ZERO


				return -1;
		}
#undef DIGIT_RANGE_TEST

		// FF10;FULLWIDTH DIGIT ZERO
		if (ch < 0xFF10 + 10)
		{
			return ch - 0xFF10;
		}
		return -1;

}

#include <limits.h>

#define _tolower(_Char)    ( (_Char)-'A'+'a' )
#define _toupper(_Char)    ( (_Char)-'a'+'A' )

#ifndef iswspace
#define iswspace(_c) ( ( _c ) == ' ' || ( _c ) == '	' )
#endif //iswspace

#ifndef iswalpha
#define iswalpha( _c ) ( ( ( _c ) >='0' && ( _c ) <= '9' ) || ( ( _c ) >= 'a' && ( _c ) <= 'f' ) || ( ( _c ) >= 'A' && ( _c ) <= 'F' ) ) 
#endif //iswalpha

static unsigned long __cdecl wcsntoxl (
        const wchar_t *nptr,
		ULONG cch_len, 
        const wchar_t **endptr,
        int ibase,
        int flags
        )
{
    const wchar_t *p;
    wchar_t c;
    unsigned long number;
    unsigned digval;
    unsigned long maxval;

    /* validation section */
    if (endptr != NULL)
    {
        /* store beginning of string in endptr */
        *endptr = nptr;
    }

#ifdef DRIVER
	if( nptr == NULL )
	{
		return 0; 
	}

	if( ibase != 0 && ( ibase < 2 || ibase > 36 ) )
	{
		return 0; 
	}

#else
    _VALIDATE_RETURN(nptr != NULL, EINVAL, 0L);
    _VALIDATE_RETURN(ibase == 0 || (2 <= ibase && ibase <= 36), EINVAL, 0L);
#endif //DRIVER

    p = nptr;           /* p is our scanning pointer */
    number = 0;         /* start with zero */

    c = *p++;           /* read char */
	cch_len --; 

    while ( iswspace(c) )
	{
		if( cch_len == 0 )
		{
			return 0; 
		}

        c = *p++;       /* skip whitespace */
		cch_len --; 
	}

    if (c == '-') {
        flags |= FL_NEG;    /* remember minus sign */
        c = *p++;
		cch_len --; 
		if( cch_len == 0 )
		{
			return 0; 
		}
    }
    else if (c == '+')
	{
        c = *p++;       /* skip sign */
		cch_len --; 
		if( cch_len == 0 )
		{
			return 0; 
		}
	}

    if (ibase == 0) {
        /* determine base free-lance, based on first two chars of
           string */
        if (_wchartodigit(c) != 0)
            ibase = 10;
        else if (*p == L'x' || *p == L'X')
            ibase = 16;
        else
            ibase = 8;
    }

    if (ibase == 16) {
        /* we might have 0x in front of number; remove if there */
        if (_wchartodigit(c) == 0 && (*p == L'x' || *p == L'X')) {
            ++p;
			cch_len --; 
			if( cch_len == 0 )
			{
				return 0; 
			}

            c = *p++;   /* advance past prefix */
			cch_len --; 
			if( cch_len == 0 )
			{
				return 0; 
			}
		}
    }

    /* if our number exceeds this, we will overflow on multiply */
    maxval = ULONG_MAX / ibase;


    for (;;) {  /* exit in middle of loop */

        /* convert c to value */
        if ( (digval = _wchartodigit(c)) != -1 )
            ;
        else if ( iswalpha(c))
            digval = _toupper(c) - L'A' + 10;
        else
            break;

        if (digval >= (unsigned)ibase)
            break;      /* exit loop if bad digit found */

        /* record the fact we have read one digit */
        flags |= FL_READDIGIT;

        /* we now need to compute number = number * base + digval,
           but we need to know if overflow occured.  This requires
           a tricky pre-check. */

        if (number < maxval || (number == maxval &&
        (unsigned long)digval <= ULONG_MAX % ibase)) {
            /* we won't overflow, go ahead and multiply */
            number = number * ibase + digval;
        }
        else {
            /* we would have overflowed -- set the overflow flag */
            flags |= FL_OVERFLOW;
            if (endptr == NULL) {
                /* no need to keep on parsing if we
                   don't have to return the endptr. */
                break;
            }
        }

		ASSERT( cch_len >= 0 ); 

		if( cch_len == 0 )
		{
			break; 
		}

        c = *p++;       /* read next digit */
		cch_len --; 
    }

    --p;                /* point to place that stopped scan */

    if (!(flags & FL_READDIGIT)) {
        /* no number there; return 0 and point to beginning of
           string */
        if (endptr)
            /* store beginning of string in endptr later on */
            p = nptr;
        number = 0L;        /* return 0 */
    }
    else if ( (flags & FL_OVERFLOW) ||
          ( !(flags & FL_UNSIGNED) &&
            ( ( (flags & FL_NEG) && (number > -LONG_MIN) ) ||
              ( !(flags & FL_NEG) && (number > LONG_MAX) ) ) ) )
    {
        /* overflow or signed overflow occurred */
        
		//errno = ERANGE;
        if ( flags & FL_UNSIGNED )
            number = ULONG_MAX;
        else if ( flags & FL_NEG )
            number = (unsigned long)(-LONG_MIN);
        else
            number = LONG_MAX;
    }

    if (endptr != NULL)
        /* store pointer to char that stopped the scan */
        *endptr = p;

    if (flags & FL_NEG)
        /* negate result if there was a neg sign */
        number = (unsigned long)(-(long)number);

    return number;          /* done. */
}

unsigned long __cdecl wcsntoul (
	const wchar_t *nptr,
	ULONG cc_len, 
	wchar_t **endptr,
	int ibase
	)
{
	return wcsntoxl(nptr, cc_len, (const wchar_t **)endptr, ibase, FL_UNSIGNED);
}

NTSTATUS calc_path_comp_key( LPWSTR sub_dir, ULONG sub_dir_len, ULONG *key_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	INT32 ret; 
	UINT32 key; 
	ULONG buf_len; 

	//ULONG i; 

	ASSERT( key_out != NULL ); 

#ifdef JUST_TEST
	{
#ifdef DRIVER
		UNICODE_STRING unicode_str; 
		unicode_str.Buffer = ( PWCH )sub_dir; 
		unicode_str.Length = unicode_str.MaximumLength = ( USHORT )( sub_dir_len << 1 ); 

		RtlUnicodeStringToInteger( &unicode_str, 10, &key ); 
#else
		LPWSTR tmp_str; 
		key = wcsntoul ( sub_dir, sub_dir_len, &tmp_str, 10 ); 
#endif //DRIVER

		return key; 
	}
#endif //JUST_TEST

	//for( i = 0; i < sub_dir_len; i ++ )
	//{
	//	if( sub_dir[ i ] >= L'a' && sub_dir[ i ] <= L'z' )
	//	{
	//		sub_dir[ i ] += L'A' - L'a'; 
	//	}
	//}

	buf_len = sub_dir_len << 1; 

	ret = crc32( CRC_STRING_ONCE, sub_dir, &key, &buf_len ); 
	if( ret != 0 )
	{
		key = INVALID_TREE_KEY_VALUE; 
		ntstatus = STATUS_UNSUCCESSFUL; 
	}

	dbg_print( MSG_INFO, "calculate the crc code for the string the buffer size is %u return size is %u\n", 
		sub_dir_len << 1, 
		buf_len ); 

	*key_out = key; 

	return ntstatus; 
}

INT32 is_valid_tree_node( btree_node *node, ULONG order )
{
	INT32 ret = TRUE; 

	ASSERT( node != NULL ); 

	do 
	{
		if( node->num_keys > order )
		{
			ret = FALSE; 
			break; 
		}

		//if( L'\0' == *node->dir )
		//{
		//	ret = FALSE; 
		//	break; 
		//}

		//if( 0 == node->dir_len )
		//{
		//	ret = FALSE; 
		//	break; 
		//}

		//if( wcsnlen( node->dir, ARRAYSIZE( node->dir ) ) != node->dir_len )
		//{
		//	ret = FALSE; 
		//	break; 
		//}

	} while ( FALSE );

	return ret; 
}

//NTSTATUS insert_node_in_level( btree_node *parent, ULONG key, btree_node *node, ULONG level, ULONG order )
//{
//	NTSTATUS ntstatus = STATUS_SUCCESS; 
//	//ULONG i; 
//
//	do 
//	{
//		ASSERT( parent != NULL ); 
//		ASSERT( node != NULL );  
//
//		if( parent->level != level - 1 )
//		{
//			ntstatus = STATUS_INVALID_PARAMETER; 
//			break; 
//		}
//
//		
//#ifdef DBG
//		if( is_valid_tree_node( node, order ) )
//		{
//			DBG_BRK(); 
//			break; 
//		}
//		{
//			ULONG sub_dir_key; 
//			sub_dir_key = calc_path_comp_key( node->dir, node->dir_len ); 
//			if( sub_dir_key != key )
//			{
//				DBG_BRK(); 
//				break; 
//			}
//		}
//#endif //DBG
//
//		if( ntstatus == STATUS_SUCCESS )
//		{
//			break; 
//		}
//	}while( FALSE ); 
//	
//	return ntstatus; 
//}

// DELETION.

/* Utility function for deletion.  Retrieves
 * the index of a node's nearest neighbor (sibling)
 * to the left if one exists.  If not (the node
 * is the leftmost child), returns -1 to signify
 * this special case.
 */
NTSTATUS get_neighbor_index( btree_node *n, ULONG *index_found )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG i;

	/* Return the index of the key to the left
	* of the pointer in the parent pointing
	* to n.  
	* If n is the leftmost child, this means
	* return -1.
	*/

	ASSERT( index_found != NULL ); 

	do 
	{
		*index_found = -1; 

		for( i = 0; i <= n->parent->num_keys; i++ )
		{
			if( n->parent->pointers[ i ] == n )
			{
				break; 
			}
		}

		if( i <= n->parent->num_keys )
		{
			*index_found = i - 1; 
			break; 
		}

		// Error state.
		log_trace( ( MSG_INFO, "Search for nonexistent pointer to node in parent.\n" ) );
		log_trace( ( MSG_INFO, "Node:  %#lx\n", ( ULONG )n ) ); 
		ntstatus = STATUS_UNSUCCESSFUL; 
	}while( FALSE );
	
	return ntstatus; 
}


NTSTATUS remove_entry_from_node( btree *tree, btree_node *node, TREE_KEY_TYPE key, btree_node *pointer )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG num_pointers;
	ULONG key_index; 
	ULONG pointer_index; 
	ULONG i; 

	do 
	{
		log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

		ASSERT( tree != NULL ); 
		ASSERT( TRUE == btree_is_inited( tree ) ); 
		ASSERT( node != NULL ); 

		// Remove the key and shift other keys accordingly.
		key_index = 0; 

		while( node->keys[ key_index ] != key )
		{
			key_index ++;
		}

		for( i = key_index + 1; i < node->num_keys; i ++ )
		{
			node->keys[ i - 1 ] = node->keys[ i ];
		}

		// Remove the pointer and shift other pointers accordingly.
		// First determine number of pointers.
		num_pointers = node->is_leaf ? node->num_keys : node->num_keys + 1;
		pointer_index = 0;

		while( node->pointers[ pointer_index ] != pointer )
		{
			pointer_index++;
		}

#ifdef DBG
		if( TRUE == node->is_leaf )
		{
			ASSERT( key_index == pointer_index ); 
		}
		else
		{
			ASSERT( key_index == pointer_index || key_index == pointer_index - 1 ); 
		}
#endif //DBG
		
		for( ++pointer_index; pointer_index < num_pointers; pointer_index++ )
		{
			node->pointers[ pointer_index - 1 ] = node->pointers[ pointer_index ];
		}

		//memmove( &node->pointers[ i - 1 ], &node->pointers[ i ], ( sizeof( node->pointers[ 0 ] ) * node->num_keys - i - 1 ) )
		
		// One key fewer.
		node->num_keys--; 
		ASSERT( node->num_keys >= 0 ); 

		// Set the other pointers to NULL for tidiness.
		// A leaf uses the last pointer to point to the next leaf.
		if( TRUE == node->is_leaf )
		{
			for( key_index = node->num_keys; key_index < btree_leaf_max_key_count( tree->tree_order ); key_index ++ )
			{		
				node->pointers[ key_index ] = NULL;
			}

			log_trace( ( MSG_INFO, "the next leaf pointer of the deleted tree leaf is 0x%0.8x\n", node->pointers[ btree_sibling_node_index( tree->tree_order ) ] ) ); 
		}
		else
		{
			for( pointer_index = node->num_keys + 1; pointer_index < btree_node_max_sub_node_count( tree->tree_order ); pointer_index ++ )
			{
				node->pointers[ pointer_index ] = NULL;
			}
		}
	}while( FALSE );

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 

	return ntstatus;
}

NTSTATUS adjust_root( btree_node* root, btree_node **new_root )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	btree_node *_new_root;

	/* Case: nonempty root.
	 * Key and pointer have already been deleted,
	 * so nothing to be done.
	 */

	do 
	{
		ASSERT( root != NULL ); 
		ASSERT( new_root != NULL ); 

		//__asm int 3; 

#ifdef DBG
		if( *new_root != NULL )
		{
			log_trace( ( MSG_ERROR, "the deletion operation adjust root more than one time!!! previous root is 0x%0.8x\n", *new_root ) ); 
			ASSERT( FALSE ); 
		}
#endif //DBG

		*new_root = NULL; 

		if( root->num_keys > 0 )
		{
			_new_root = root; 
			break; 
		}

		/* Case: empty root. 
		*/

		// If it has a child, promote 
		// the first (only) child
		// as the new root.

		if( FALSE == root->is_leaf )
		{
			_new_root = root->pointers[ 0 ];
			_new_root->parent = NULL;
		}

		// If it is a leaf (has no children),
		// then the whole tree is empty.

		else
		{
			_new_root = FREED_ROOT_POINTER_VALUE;
		}

		free_tree_node( root ); 

		//free( root->keys );
		//free( root->pointers );
		//free( root ); 
	}while( FALSE );

	*new_root = _new_root; 
	return ntstatus;
}

/* Coalesces a node that has become
 * too small after deletion
 * with a neighboring node that
 * can accept the additional entries
 * without exceeding the maximum.
 */

NTSTATUS coalesce_nodes( btree *tree, btree_node *root, btree_node *node, btree_node *neighbor, ULONG neighbor_index, ULONG k_prime, del_node_info *del_info, btree_node **new_root )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG i, j, neighbor_insertion_index, n_start, n_end, new_k_prime;
	btree_node *tmp; 
	//btree_node *_root; 
	BOOLEAN split; 
	ULONG order; 

	ASSERT( NULL != tree ); 
	ASSERT( TRUE == btree_is_inited( tree ) ); 
	ASSERT( NULL != root ); 
	
	/* Swap neighbor with node if node is on the
	 * extreme left and neighbor is to its right.
	 */

	order = tree->tree_order; 

	if( neighbor_index == -1 )
	{
		tmp = node;
		node = neighbor;
		neighbor = tmp;
	}

	/* Starting point in the neighbor for copying
	 * keys and pointers from n.
	 * Recall that n and neighbor have swapped places
	 * in the special case of n being a leftmost child.
	 */

	neighbor_insertion_index = neighbor->num_keys;

	/*
	 * Nonleaf nodes may sometimes need to remain split,
	 * if the insertion of k_prime would cause the resulting
	 * single coalesced node to exceed the limit order - 1.
	 * The variable split is always false for leaf nodes
	 * and only sometimes set to true for nonleaf nodes.
	 */

	split = FALSE;

	/* Case:  nonleaf node.
	 * Append k_prime and the following pointer.
	 * If there is room in the neighbor, append
	 * all pointers and keys from the neighbor.
	 * Otherwise, append only cut(order) - 2 keys and
	 * cut(order) - 1 pointers.
	 */

	if( FALSE == node->is_leaf )
	{

		/* Append k_prime.
		 */

		neighbor->keys[ neighbor_insertion_index ] = k_prime;
		neighbor->num_keys++;


		/* Case (default):  there is room for all of n's keys and pointers
		 * in the neighbor after appending k_prime.
		 */

		n_end = node->num_keys;

		/* Case (special): k cannot fit with all the other keys and pointers
		 * into one coalesced node.
		 */
		n_start = 0; // Only used in this special case.
		if( node->num_keys + neighbor->num_keys >= order )
		{
			split = TRUE;
			n_end = cut( order ) - 2; 
		}

		for( i = neighbor_insertion_index + 1, j = 0; j < n_end; i++, j++ )
		{
			neighbor->keys[ i ] = node->keys[ j ];
			neighbor->pointers[ i ] = node->pointers[ j ];
			neighbor->num_keys++;
			node->num_keys--;
			n_start++;
		}

		/* The number of pointers is always
		 * one more than the number of keys.
		 */

		neighbor->pointers[i] = node->pointers[j];

		/* If the nodes are still split, remove the first key from
		 * n.
		 */
		if( TRUE == split )
		{
			new_k_prime = node->keys[ n_start ];
			for( i = 0, j = n_start + 1; i < node->num_keys; i++, j++ )
			{
				node->keys[ i ] = node->keys[ j ];
				node->pointers[ i ] = node->pointers[ j ];
			}
			
			node->pointers[i] = node->pointers[j];
			node->num_keys--;
		}

		/* All children must now point up to the same parent.
		 */

		for (i = 0; i < neighbor->num_keys + 1; i++) {
			tmp = (btree_node *)neighbor->pointers[i];
			log_trace( ( MSG_INFO, "move the neighbor leftmost pointer parent from 0x%0.8x to 0x%0.8x\n", tmp->parent, neighbor ) ); 
			tmp->parent = ( btree_base_node* )neighbor;
		}
	}

	/* In a leaf, append the keys and pointers of
	 * n to the neighbor.
	 * Set the neighbor's last pointer to point to
	 * what had been n's right neighbor.
	 */

	else
	{
		ASSERT( FALSE == neighbor->is_leaf 
			&& FALSE == node->is_leaf ); 

		for( i = neighbor_insertion_index, j = 0; j < node->num_keys; i++, j++ )
		{
			neighbor->keys[ i ] = node->keys[ j ];
			neighbor->pointers[ i ] = node->pointers[ j ];
			neighbor->num_keys++;
		}
	
		neighbor->pointers[ order - 1 ] = node->pointers[ order - 1 ];
	}

	if( FALSE == split )
	{
		ASSERT( *new_root == NULL ); 

		del_info->node_key = k_prime; 
		del_info->node = node; 

		ntstatus = STATUS_MORE_PROCESSING_REQUIRED; 
	}
	else
	{
		for (i = 0; i < node->parent->num_keys; i++)
		{
			if( node->parent->pointers[ i + 1 ] == node )
			{
				node->parent->keys[ i ] = new_k_prime; 
				break;
			}
		}
	}

	return ntstatus; 
}


/* Redistributes entries between two nodes when
 * one has become too small after deletion
 * but its neighbor is too big to append the
 * small node's entries without exceeding the
 * maximum
 */
NTSTATUS redistribute_nodes( btree *tree, btree_node *root, btree_node *node, btree_node *neighbor, ULONG neighbor_index, ULONG k_prime_index, ULONG k_prime )
{  
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG i;
	btree_node * tmp;

	/* Case: n has a neighbor to the left. 
	 * Pull the neighbor's last key-pointer pair over
	 * from the neighbor's right end to n's left end.
	 */

	if( neighbor_index != -1 ) 
	{
		if( FALSE == node->is_leaf )
		{
			//sibling node
			node->pointers[ node->num_keys + 1 ] = node->pointers[ node->num_keys ];
		}
		
		for( i = node->num_keys; i > 0; i-- )
		{
			node->keys[ i ] = node->keys[ i - 1 ]; 
			node->pointers[ i ] = node->pointers[ i - 1 ];
		}

		if( FALSE == node->is_leaf )
		{
			node->pointers[ 0 ] = neighbor->pointers[ neighbor->num_keys ]; 

			tmp = ( btree_node* )node->pointers[ 0 ];

			log_trace( ( MSG_INFO, "move the neighbor leftmost pointer parent from 0x%0.8x to 0x%0.8x\n", tmp->parent, node ) ); 

			tmp->parent = ( btree_base_node* )node;
			neighbor->pointers[neighbor->num_keys] = NULL;
			
			node->keys[ 0 ] = k_prime;
			node->parent->keys[k_prime_index] = neighbor->keys[neighbor->num_keys - 1];
		}
		else 
		{
			node->pointers[ 0 ] = neighbor->pointers[neighbor->num_keys - 1];
			neighbor->pointers[neighbor->num_keys - 1] = NULL;
			node->keys[0] = neighbor->keys[neighbor->num_keys - 1];
			node->parent->keys[k_prime_index] = node->keys[0];
		}
	}

	/* Case: n is the leftmost child.
	 * Take a key-pointer pair from the neighbor to the right.
	 * Move the neighbor's leftmost key-pointer pair
	 * to n's rightmost position.
	 */

	else
	{  
		if( TRUE == node->is_leaf ) 
		{
			node->keys[ node->num_keys ] = neighbor->keys[ 0 ];
			node->pointers[node->num_keys] = neighbor->pointers[ 0 ];
			node->parent->keys[ k_prime_index ] = neighbor->keys[ 1 ];
		}
		else
		{
			ASSERT( node->num_keys < tree->tree_order - 2 ); 

			node->keys[node->num_keys] = k_prime;
			node->pointers[node->num_keys + 1] = neighbor->pointers[ 0 ];
			tmp = (btree_node *)node->pointers[ node->num_keys + 1 ];

			log_trace( ( MSG_INFO, "move the neighbor leftmost pointer parent from 0x%0.8x to 0x%0.8x\n", tmp->parent, node ) ); 

			tmp->parent = ( btree_base_node* )node;
			ASSERT( node->parent == neighbor->parent ); 

			node->parent->keys[ k_prime_index ] = neighbor->keys[0];
		}

		for( i = 0; i < neighbor->num_keys - 1; i++ )
		{
			neighbor->keys[ i ] = neighbor->keys[ i + 1 ];
			neighbor->pointers[ i ] = neighbor->pointers[ i + 1 ];
		}

		if( FALSE == node->is_leaf )
		{
			neighbor->pointers[ i ] = neighbor->pointers[ i + 1 ]; 
		}
	}

	/* n now has one more key and one more pointer;
	 * the neighbor has one fewer of each.
	 */

	node->num_keys++; 
	neighbor->num_keys--; 

	return ntstatus; 
}

#define INVALID_CONF_LEVLEL 0xffff
#define INVALID_INTE_LEVEL 0xffff 
#define INVALID_CLASS 0xffffffff

/* Deletes an entry from the B+ tree.
 * Removes the record and its key and pointer
 * from the leaf, and then makes all appropriate
 * changes to preserve the B+ tree properties.
 */

NTSTATUS delete_entry( btree *tree, btree_node *root, btree_node *node, TREE_KEY_TYPE key, void *pointer, del_node_info *del_info, btree_node **new_root )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG min_keys;
	btree_node * neighbor;
	ULONG neighbor_index;
	ULONG k_prime_index, k_prime;
	ULONG capacity;
	btree_node *_new_root = NULL; 
	ULONG order; 

	// Remove key and pointer from node.

	do
	{
		ASSERT( tree != NULL ); 
		ASSERT( btree_is_inited( tree ) ); 
		ASSERT( new_root != NULL ); 
		ASSERT( del_info != NULL ); 

		order = tree->tree_order; 

		*new_root = NULL; 
		del_info->node = NULL; 
		del_info->node_key = INVALID_TREE_KEY_VALUE; 

		ntstatus = remove_entry_from_node( tree, node, key, pointer );
		if( ntstatus != STATUS_SUCCESS )
		{
			//_new_root = root; 
			dbg_print( MSG_FATAL_ERROR, "remove the pointer ( key:0x%0.8x, pointer:%p )from node error 0x%0.8x\n", key, pointer, ntstatus ); 
			ASSERT( FALSE ); 
			break; 
		}

		/* Case:  deletion from the root. 
		*/

		if( node == root ) 
		{
			ntstatus = adjust_root( root, &_new_root ); 
			ASSERT( ntstatus == STATUS_SUCCESS ); 
			if( ntstatus != STATUS_SUCCESS )
			{
				dbg_print( MSG_FATAL_ERROR, "adjust the tree root 0x%0.8x error 0x%0.8x\n", root, ntstatus ); 
			}
			break; 
		}

		/* Case:  deletion from a node below the root.
		* (Rest of function body.)
		*/

		/* Determine minimum allowable size of node,
		* to be preserved after deletion.
		*/

		min_keys = node->is_leaf ? cut( tree->tree_order - 1 ) : cut( tree->tree_order ) - 1;

		/* Case:  node stays at or above minimum.
		* (The simple case.)
		*/

		if( node->num_keys >= min_keys )
		{
			//_new_root = root; 
			break; 
		}

		/* Case:  node falls below minimum.
		* Either coalescence or redistribution
		* is needed.
		*/

		/* Find the appropriate neighbor node with which
		* to coalesce.
		* Also find the key (k_prime) in the parent
		* between the pointer to node n and the pointer
		* to the neighbor.
		*/

		ASSERT( node->parent != NULL ); 

		ntstatus = get_neighbor_index( node, &neighbor_index ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			ASSERT( FALSE ); 
			break; 
		}

		k_prime_index = neighbor_index == ( ULONG )-1 ? 0 : neighbor_index;
		k_prime = node->parent->keys[ k_prime_index ];

		neighbor = neighbor_index == ( ULONG )-1 ? ( btree_node* )node->parent->pointers[ 1 ] : 
			( btree_node* )node->parent->pointers[ neighbor_index ];

		capacity = node->is_leaf ? order : tree->tree_order - 1;

		/* Coalescence. */

		if( neighbor->num_keys + node->num_keys < capacity )
		{
			ntstatus = coalesce_nodes( tree, root, node, neighbor, neighbor_index, k_prime, del_info, &_new_root );
		}
		/* Redistribution. */

		else
		{
			ntstatus = redistribute_nodes( tree, root, node, neighbor, neighbor_index, k_prime_index, k_prime );
		}

	}while( FALSE ); 

	*new_root = _new_root; 

#ifdef DBG
	if( ntstatus != STATUS_SUCCESS && ntstatus != STATUS_MORE_PROCESSING_REQUIRED )
	{
		ASSERT( FALSE ); 
	}
#endif //DBG

	return ntstatus; 
}

/* Master deletion function.
*/

#define is_valid_del_node_info( info ) ( ( info )->node != NULL && ( info )->node_key != INVALID_TREE_KEY_VALUE )

NTSTATUS delete_tree_node( btree *tree, btree_node *root, TREE_KEY_TYPE key, btree_node **new_root )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	btree_node *key_leaf;
	path_tree_node *path_node;
	del_node_info del_info; 

	do
	{
		log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__) ); 

		del_info.node = NULL; 
		del_info.node_key = INVALID_TREE_KEY_VALUE; 
	
		ASSERT( tree != NULL ); 
		ASSERT( TRUE == btree_is_inited( tree ) ); 
		ASSERT( new_root != NULL ); 

		*new_root = NULL; 

		hold_tree_w_lock( tree ); 

		ntstatus = find_path_comp_node( tree, root, key, &path_node  ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			ASSERT( path_node == NULL ); 
			break; 
		}

#if 0
		if( path_node->root != NULL )
		{
			ntstatus = uninit_path_sub_tree( tree, path_node->root ); 
		}
#endif //0

		if( path_node->root != NULL && path_node->root->num_keys > 0 )
		{
			//__asm int 3; 

			//path_node->prop._class = INVALID_CLASS; 
			//path_node->prop.conflevel = INVALID_CONF_LEVLEL; 
			//path_node->prop.intelevel = INVALID_INTE_LEVEL; 

			dbg_print( MSG_ERROR, "delete the path node that still have the sub node %u\n", path_node->root->num_keys ); 
			
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		ASSERT( path_node != NULL ); 

		ntstatus = find_tree_leaf_lock_free( tree, root, key, &key_leaf );
		if( ntstatus != STATUS_SUCCESS )
		{
			ASSERT( key_leaf == NULL ); 
			break; 
		}

		ASSERT( key_leaf != NULL ); 

		{
			btree_node *del_node; 
			btree_node *_parent; 
			TREE_KEY_TYPE del_key; 

			del_node = ( btree_node* )path_node; 
			_parent = key_leaf; 
			del_key = key; 

			for( ; ; )
			{
				ntstatus = delete_entry( tree, root, _parent, del_key, del_node, &del_info, new_root ); 
				if( ntstatus != STATUS_SUCCESS )
				{
					if( ntstatus != STATUS_MORE_PROCESSING_REQUIRED )
					{
						break; 
					}

					ASSERT( TRUE == is_valid_del_node_info( &del_info ) ); 

					_parent = del_info.node->parent; 
					del_key = del_info.node_key; 
					del_node = del_info.node; 

					if( ( PVOID )del_node != ( PVOID )path_node )
					{
						//__asm int 3; 
						ASSERT( del_node->is_leaf == FALSE ); 

						ntstatus = free_tree_node( del_node ); 
					}
				}
				else
				{
					ASSERT( FALSE == is_valid_del_node_info( &del_info ) ); 
					break; 
				}
			}
		}

		ntstatus = release_path_tree_node( path_node ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

#ifdef DBG
		path_node = NULL; 
#endif //DBG
	}while( FALSE ); 

	release_tree_lock( tree ); 

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 

#ifdef DBG
	if( ntstatus != STATUS_SUCCESS )
	{
		ASSERT( FALSE ); 
	}
#endif //DBG

	return ntstatus;
}

NTSTATUS del_path_comp_node( btree *tree, btree_node *parent, LPCWSTR path_comp_name, ULONG name_len, btree_node **new_root )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG path_comp_key; 
	//btree_node *_parent; 

	do 
	{
		ASSERT( NULL != tree ); 
		ASSERT( TRUE == btree_is_inited( tree ) ); 
		ASSERT( path_comp_name != NULL ); 
		ASSERT( name_len > 0 ); 
		ASSERT( new_root != NULL ); 

		*new_root = NULL; 

		ntstatus = calc_path_comp_key( ( LPWSTR )path_comp_name, name_len, &path_comp_key ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			ASSERT( path_comp_key == INVALID_TREE_KEY_VALUE ); 
			break; 
		}

		ASSERT( path_comp_key != INVALID_TREE_KEY_VALUE ); 

		ntstatus = delete_tree_node( tree, parent, path_comp_key, new_root ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			//ASSERT( _parent == NULL ); 
			break; 
		}

		//ASSERT( *new_root != NULL ); 

		//must update the parent to new 
	}while( FALSE );

	return ntstatus; 
}

NTSTATUS destroy_tree_nodes( btree_node * root )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG i; 

	if( TRUE == root->is_leaf )
	{
		for( i = 0; i < root->num_keys; i++ )
		{
			free( root->pointers[ i ] ); 
		}
	}
	else
	{
		for( i = 0; i < root->num_keys + 1; i++ )
		{
			destroy_tree_nodes(root->pointers[i]);
		}
	}
			
	free( root->pointers );
	free( root->keys );
	free( root ); 

	return ntstatus; 
}

NTSTATUS destroy_tree( btree *tree, btree_node* root, btree_node **new_root )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	ASSERT( tree != NULL ); 
	ASSERT( TRUE == btree_is_inited( tree ) ); 
	
	hold_tree_w_lock( tree ); 
	ntstatus = destroy_tree_nodes( root ); 
	release_tree_lock( tree ); 

#ifndef DRIVER
	ASSERT( tree->lock != NULL ); 
	CloseHandle( tree->lock ); 
	tree->lock = NULL; 
#else
	uninit_res_lock( &tree->lock ); 
#endif //DRIVER

	return ntstatus; 
}

NTSTATUS init_btree( btree *tree, ULONG order )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	btree_node *new_leaf = NULL; 
	BOOLEAN lock_inited = FALSE; 

	ASSERT( tree != NULL ); 

	do 
	{
		if( order < MIN_BTREE_ORDER || order > MAX_BTREE_ORDER )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		tree->tree_order = 0; 
#ifndef DRIVER
		tree->lock = NULL; 
#endif //DRIVER
		tree->queue = NULL; 
		tree->root = NULL; 

#ifndef DRIVER
		tree->lock = CreateMutex( NULL, FALSE, NULL ); 
		if( tree->lock == NULL )
		{
			ntstatus = STATUS_UNSUCCESSFUL; 
			break; 
		}
#else
		ntstatus = init_res_lock( &tree->lock ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}
#endif //DRIVER

		lock_inited = TRUE; 

		tree->tree_order = order; 
		tree->root = NULL; 

		//ntstatus = make_leaf( tree, &new_leaf ); 
		//if( ntstatus != STATUS_SUCCESS )
		//{
		//	break; 
		//}

		//ASSERT( new_leaf != NULL ); 

		//tree->root = new_leaf; 
	}while( FALSE );

	if( ntstatus != STATUS_SUCCESS )
	{
		if( new_leaf != NULL )
		{
			free( new_leaf ); 
		
			if( tree->root != NULL )
			{
				tree->root = NULL; 
			}
		}

		if( lock_inited != FALSE )
		{
#ifdef DRIVER
			uninit_res_lock( &tree->lock ); 
#else
			if( tree->lock != NULL )
			{
				CloseHandle( tree->lock ); 
				tree->lock = NULL; 
			}
			else
			{
				ASSERT( FALSE ); 
			}
#endif //DRIVER
		}
	}

	return ntstatus; 
}

#define MAX_PATH_COMP_LEVEL 260

NTSTATUS make_path_node( btree *tree, ULONG key, LPCWSTR path_comp_name, ULONG name_len, ULONG level, path_tree_node **node_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	path_tree_node *path_node = NULL; 

	do 
	{
		log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__  ) ); 

		ASSERT( NULL != tree ); 
		ASSERT( TRUE == btree_is_inited( tree ) ); 
		ASSERT( NULL != path_comp_name ); 
		ASSERT( 0 < name_len ); 

		*node_out = NULL; 

		if( level > MAX_PATH_COMP_LEVEL )
		{
			ntstatus = STATUS_INVALID_PARAMETER; 
			break; 
		}

		path_node = ( path_tree_node* )malloc( sizeof( path_tree_node ) + ( name_len << 1 ) ); 
		if( path_node == NULL )
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			break; 
		}
		
		path_node->root = ( btree_node* )malloc( sizeof( btree_node ) ); 

		if( path_node->root == NULL )
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES; 
			break; 
		}

		path_node->root->keys = NULL; 
		path_node->root->pointers = NULL; 

		ntstatus = init_tree_node( tree, path_node->root ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		ASSERT( path_node->root->keys != NULL ); 
		ASSERT( path_node->root->pointers != NULL ); 

		path_node->root->is_leaf = TRUE; 

		memcpy( path_node->dir, path_comp_name, name_len << 1 ); 

		path_node->dir[ name_len ] = L'\0'; 
		path_node->level = level; 
		path_node->dir_len = name_len; 
		path_node->key = key; 

		//free( path_node->root ); 
		//free( path_node ); 

	}while( FALSE ); 

	if( ntstatus != STATUS_SUCCESS )
	{
		if( path_node != NULL )
		{
			if( path_node->root != NULL )
			{
				free( path_node->root ); 
			}

			free( path_node ); 
		}
	}
	else
	{
		*node_out = path_node; 
	}

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 

	return ntstatus; 
}

/********************************************************
transaction function.
********************************************************/

NTSTATUS remove_redundant_entry( btree *tree )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	return ntstatus; 
}

NTSTATUS continue_need_action( btree *tree )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	return ntstatus; 
}

NTSTATUS begin_transaction( btree *tree )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	return ntstatus; 
}

NTSTATUS end_transaction( btree *tree )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	return ntstatus; 
}
