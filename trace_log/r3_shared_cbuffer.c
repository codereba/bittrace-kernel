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
#else
#include "common_func.h"
#include "ring0_2_ring3.h"
#endif //DRIVER

#include "r3_shared_vm.h"
#include "cbuffer.h"
#include "r3_shared_cbuffer.h"

//notice:call this function must in driver entry, because it not record the process of mapping.

NTSTATUS init_ring3_share_cbuffer_r0( ULONG item_size, ULONG item_count_bit, r3_shared_cbuf *cbuf_out )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	ULONG buf_size; 
	BOOLEAN cbuf_inited = FALSE; 
	BOOLEAN shared_vm_inited = FALSE; 

	do
	{
		ASSERT( cbuf_out != NULL ); 

		buf_size = item_size * ( 1 << item_count_bit ); 

		ntstatus = create_r3_shared_vm_base( buf_size, &cbuf_out->r3_vm ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			ASSERT( cbuf_out->r3_vm.r3_addr == NULL ); 
			ASSERT( cbuf_out->r3_vm.r0_addr == NULL ); 
			ASSERT( cbuf_out->r3_vm.mdl == NULL ); 

			break; 
		}

		shared_vm_inited = TRUE; 

		ASSERT( cbuf_out->r3_vm.r3_addr == NULL ); 
		ASSERT( cbuf_out->r3_vm.r0_addr != NULL ); 
		ASSERT( cbuf_out->r3_vm.mdl != NULL ); 
		ASSERT( cbuf_out->r3_vm.vm_size == item_size * ( 1 << item_count_bit ) ); 

		ntstatus = create_safe_cbuffer( &cbuf_out->cbuf, 
			cbuf_out->r3_vm.r0_addr, 
			item_count_bit, 
			item_size, 
			NULL ); 

		if( ntstatus != STATUS_SUCCESS )
		{
			break; 
		}

		ASSERT( cbuf_out->cbuf.cbuf == cbuf_out->r3_vm.r0_addr ); 

		//IoInitializeRemoveLock( &cbuf_out->run_down_lock, R3_CBUFFER_REMOVE_LOCK_TAG ); 
		cbuf_inited = TRUE; 
	}while( FALSE ); 

	if( ntstatus != STATUS_SUCCESS )
	{
		if( cbuf_inited == TRUE )
		{
			uninit_safe_cbuffer( &cbuf_out->cbuf ); 
		}

		if( shared_vm_inited == TRUE )
		{
			destroy_r3_shared_vm_base( &cbuf_out->r3_vm ); 
		}
	}

	return ntstatus; 
}

NTSTATUS uninit_ring3_share_cbuffer( PEPROCESS eproc, r3_shared_cbuf *cbuf )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do
	{
		ASSERT( cbuf != NULL );

		if( cbuf->cbuf.cbuf == NULL )
		{
			ASSERT( FALSE && "release cbuffer that points to null" ); 
		}
		else
		{
			do 
			{
				ntstatus = is_valid_cbuffer( cbuf->cbuf.cbuf ); 
				if( ntstatus != STATUS_SUCCESS )
				{
					ntstatus = STATUS_SUCCESS; 
					ASSERT( FALSE && "cbuffer memory is cruppted" ); 
				}

				uninit_safe_cbuffer( &cbuf->cbuf ); 

			}while( FALSE );
		}

		ntstatus = is_valid_r3_shared_vm( &cbuf->r3_vm ); 

		if( ntstatus != STATUS_SUCCESS )
		{
			dbg_print( MSG_ERROR, "release the have not mapped vm\n" ); 
		}

		if( eproc == NULL )
		{
			if( cbuf->r3_vm.r3_addr != NULL ) 
			{
				KeBugCheck( STATUS_UNSUCCESSFUL ); 
			}
		}

		ASSERT( cbuf->r3_vm.r3_addr == NULL ); 
		
		ntstatus = destroy_r3_shared_vm( eproc, &cbuf->r3_vm ); 

		if( ntstatus == STATUS_SUCCESS )
		{
			cbuf->r3_vm.mdl = NULL; 
			cbuf->r3_vm.r0_addr = NULL; 
			cbuf->r3_vm.r3_addr = NULL; 
			cbuf->r3_vm.vm_size = 0; 
		}
		else
		{
			if( ntstatus != STATUS_UNSUCCESSFUL )
			{
				ASSERT( FALSE ); 
			}

			cbuf->r3_vm.mdl = NULL; 
			cbuf->r3_vm.r0_addr = NULL; 
			cbuf->r3_vm.r3_addr = NULL; 
			cbuf->r3_vm.vm_size = 0; 

			ASSERT( FALSE ); 
		}

	}while( FALSE ); 

	return ntstatus; 
}

NTSTATUS uninit_ring3_share_cbuffer_r0( r3_shared_cbuf *cbuf )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do
	{
		ASSERT( cbuf != NULL ); 

		if( cbuf->cbuf.cbuf == NULL )
		{
			ASSERT( FALSE && "release cbuffer that points to null" ); 
		}
		else
		{
			do 
			{
				ntstatus = is_valid_cbuffer( cbuf->cbuf.cbuf ); 
				if( ntstatus != STATUS_SUCCESS )
				{
					ntstatus = STATUS_SUCCESS; 
					ASSERT( FALSE && "cbuffer memory is cruppted" ); 
				}

				uninit_safe_cbuffer( &cbuf->cbuf ); 

			}while( FALSE );
		}

		ntstatus = is_valid_r3_shared_vm( &cbuf->r3_vm ); 

		if( ntstatus != STATUS_SUCCESS )
		{
			dbg_print( MSG_ERROR, "release the have not mapped vm\n" ); 
		}

		if( cbuf->r3_vm.r3_addr != NULL ) 
		{
			KeBugCheck( STATUS_UNSUCCESSFUL ); 
		}

		ASSERT( cbuf->r3_vm.r3_addr == NULL ); 

		ntstatus = destroy_r3_shared_vm_base( &cbuf->r3_vm ); 

		if( ntstatus == STATUS_SUCCESS )
		{
			cbuf->r3_vm.mdl = NULL; 
			cbuf->r3_vm.r0_addr = NULL; 
			cbuf->r3_vm.r3_addr = NULL; 
			cbuf->r3_vm.vm_size = 0; 
		}
		else
		{
			dbg_print( MSG_FATAL_ERROR, "why destroy the ring 0 part of the virtual address mapping, the mapping have ring3 address:0x%0.8x.\n", 
				cbuf->r3_vm.r3_addr ); 
			
			if( ntstatus != STATUS_UNSUCCESSFUL )
			{
				ASSERT( FALSE ); 
			}

			cbuf->r3_vm.mdl = NULL; 
			cbuf->r3_vm.r0_addr = NULL; 
			cbuf->r3_vm.r3_addr = NULL; 
			cbuf->r3_vm.vm_size = 0; 

			ASSERT( FALSE ); 
		}

	}while( FALSE ); 

	return ntstatus; 
}
