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

#ifndef __AIO_H__
#define __AIO_H__

typedef struct _aio_queue
{
	LIST_ENTRY irp_queue; 
	KSPIN_LOCK queue_lock; 
	IO_CSQ aio_safe_queue; 
	LARGE_INTEGER polling_interval;
	LARGE_INTEGER last_poll_time;
	BOOLEAN stop_queue; 
	PVOID context; 
} aio_queue, *paio_queue; 

extern aio_queue io_queue; 

#include <csq.h>
#include <dontuse.h>

NTSTATUS aio_read( __in PDEVICE_OBJECT DeviceObject, 
				  __in PIRP Irp );
NTSTATUS aio_poll( __in aio_queue* DeviceObject, __in PIRP Irp ); 


NTSTATUS aio_complete_irp_for_file( __in PDEVICE_OBJECT DeviceObject, 
								   __in PIO_STACK_LOCATION irp_sp, 
								   __in PIRP Irp );
VOID aio_insert_irp ( __in PIO_CSQ   Csq,
					 __in PIRP      Irp ); 

NTSTATUS aio_insert_irp_ex(
						   __in struct _IO_CSQ    *Csq,
						   __in PIRP              Irp,
						   __in PVOID             InsertContext
						   ); 

VOID aio_remove_irp( __in  PIO_CSQ Csq, 
					__in  PIRP    Irp ); 

PIRP aio_peek_next_irp( __in  PIO_CSQ Csq,
					   __in  PIRP    Irp,
					   __in  PVOID   PeekContext ); 

NTSTATUS aio_insert_irp_safe( __in PIO_CSQ Csq, 
							 __in PIRP Irp, 
							 PIO_CSQ_IRP_CONTEXT context ); 

//
// aio_acquire_lock modifies the execution level of the current processor.
// 
// KeAcquireSpinLock raises the execution level to Dispatch Level and stores
// the current execution level in the Irql parameter to be restored at a later
// time.  KeAcqurieSpinLock also requires us to be running at no higher than
// Dispatch level when it is called.
//
// The annotations reflect these changes and requirments.
//

__drv_raisesIRQL(DISPATCH_LEVEL)
__drv_maxIRQL(DISPATCH_LEVEL)
VOID aio_acquire_lock( __in                                   PIO_CSQ Csq,
						 __out __drv_out_deref(__drv_savesIRQL) PKIRQL  Irql ); 
//
// aio_release_lock modifies the execution level of the current processor.
// 
// KeReleaseSpinLock assumes we already hold the spin lock and are therefore
// running at Dispatch level.  It will use the Irql parameter saved in a
// previous call to KeAcquireSpinLock to return the thread back to it's original
// execution level.
//
// The annotations reflect these changes and requirments.
//

__drv_requiresIRQL(DISPATCH_LEVEL)
VOID aio_release_lock(
						 __in                                PIO_CSQ Csq,
						 __in __drv_in(__drv_restoresIRQL)   KIRQL   Irql
						 ); 

VOID complete_canceled_irp( __in  PIO_CSQ             pCsq,
						   __in  PIRP                Irp ); 

NTSTATUS init_aio_queue( aio_queue *queue, 
						PVOID context, 
						PKSTART_ROUTINE thread_routine ); 

NTSTATUS uninit_aio_queue( aio_queue *queue ); 

INLINE NTSTATUS init_trace_log_aio_queue( PVOID context )
{
	return init_aio_queue( &io_queue, NULL, NULL ); 
}

INLINE NTSTATUS uninit_trace_log_aio_queue()
{
	return uninit_aio_queue( &io_queue ); 
}

NTSTATUS process_aio_queue( PVOID peek_context ); 

#endif //__AIO_H__




