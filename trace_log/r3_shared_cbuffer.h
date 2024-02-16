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

#ifndef __MAP_CBUFFER_H__
#define __MAP_CBUFFER_H__

typedef struct _r3_shared_cbuf
{
	//IO_REMOVE_LOCK run_down_lock; 
#ifdef __cplusplus
	//C_ASSERT( FALSE && "now support c version of the ring3 cbuffer" ); 
	r3_shared_vm r3_vm; 
#else
	r3_shared_vm r3_vm; 
#endif //__cplusplus

#define r0_cbuf ( ( cbuffer_t* )r3_vm.r0_addr ); 
#define r3_cbuf ( ( cbuffer_t* )r3_vm.r3_addr ); 

	safe_cbuffer cbuf; 
} r3_shared_cbuf, *pr3_shared_cbuf; 

#define R3_CBUFFER_REMOVE_LOCK_TAG ( ULONG )'mrbc'

NTSTATUS init_ring3_share_cbuffer_r0( ULONG item_size, 
								  ULONG item_count_bit, 
								  r3_shared_cbuf *cbuf_out ); 

NTSTATUS uninit_ring3_share_cbuffer( PEPROCESS eproc, r3_shared_cbuf *cbuf );

NTSTATUS uninit_ring3_share_cbuffer_r0( r3_shared_cbuf *cbuf ); 

#endif //__MAP_CBUFFER_H__