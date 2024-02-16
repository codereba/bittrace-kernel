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
#include "acl_define.h"
#include "aio.h"

aio_queue io_queue = { 0 }; 

NTSTATUS aio_complete_irp_for_file(__in PDEVICE_OBJECT DeviceObject, 
								           __in PIO_STACK_LOCATION irp_sp, 
								           __in PIRP Irp)
{
	PIRP pending_irp;
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		if( irp_sp == NULL )
		{
			ntstatus = STATUS_INVALID_PARAMETER_1; 
			break; 
		}

		pending_irp = IoCsqRemoveNextIrp( &io_queue.aio_safe_queue,
			irp_sp->FileObject );

		while( pending_irp ) 
		{
			//
			// Cancel the IRP
			//
			pending_irp->IoStatus.Information = 0;
			pending_irp->IoStatus.Status = STATUS_CANCELLED;

			log_trace( ( MSG_INFO, 
				"Cleanup cancelled irp\n" ) ); 

			IoCompleteRequest( pending_irp, IO_NO_INCREMENT );

			pending_irp = IoCsqRemoveNextIrp( &io_queue.aio_safe_queue, 
				irp_sp->FileObject ); 
		}
		log_trace( ( MSG_INFO, "aio_cleanupIrp exit\n" ) ); 
	}while( FALSE );
	return STATUS_SUCCESS; 
}

NTSTATUS aio_insert_irp_ex(
					   __in struct _IO_CSQ    *Csq,
					   __in PIRP              Irp,
					   __in PVOID             InsertContext
					   )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	aio_queue *queue;

	do 
	{
		UNREFERENCED_PARAMETER( InsertContext ); 

		queue = CONTAINING_RECORD( Csq,
			aio_queue, aio_safe_queue );

		InsertTailList( &queue->irp_queue,
			&Irp->Tail.Overlay.ListEntry ); 

	}while( FALSE );

	return ntstatus; 
}

VOID aio_insert_irp( __in PIO_CSQ   Csq, 
					 __in PIRP      Irp )
{
	aio_queue *queue;

	do 
	{
		queue = CONTAINING_RECORD( Csq,
			aio_queue, aio_safe_queue );

		InsertTailList( &queue->irp_queue,
			&Irp->Tail.Overlay.ListEntry ); 

	}while( FALSE );

	return; 
}

VOID aio_remove_irp(
					   __in  PIO_CSQ Csq,
					   __in  PIRP    Irp
					   )
{
	UNREFERENCED_PARAMETER( Csq );

	RemoveEntryList( &Irp->Tail.Overlay.ListEntry );
}

INLINE NTSTATUS is_valid_aio_peek_context( PVOID peek_context )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

#ifdef DBG
	register PFILE_OBJECT file_obj; 

	do 
	{
		if( peek_context == NULL )
		{
			break; 
		}

		file_obj = ( PFILE_OBJECT )peek_context; 

		if( file_obj->Type != IO_TYPE_FILE )
		{
			ntstatus = STATUS_INVALID_PARAMETER_1; 
			break; 
		}

	} while ( FALSE );

#endif //DBG

	return ntstatus; 
}

PIRP aio_peek_next_irp(
						  __in  PIO_CSQ Csq,
						  __in  PIRP    Irp,
						  __in  PVOID   PeekContext
						  )
{
	aio_queue      *queue;
	PIRP                    nextIrp = NULL;
	PLIST_ENTRY             nextEntry;
	PLIST_ENTRY             listHead;
	PIO_STACK_LOCATION     irpStack;

	queue = CONTAINING_RECORD( Csq,
		aio_queue, 
		aio_safe_queue );

	listHead = &queue->irp_queue;

	ASSERT( STATUS_SUCCESS == is_valid_aio_peek_context( PeekContext ) ); 

	if( Irp == NULL )
	{
		nextEntry = listHead->Flink;
	}
	else
	{
		nextEntry = Irp->Tail.Overlay.ListEntry.Flink;
	}

	while( nextEntry != listHead )
	{

		nextIrp = CONTAINING_RECORD(nextEntry, IRP, Tail.Overlay.ListEntry);

		irpStack = IoGetCurrentIrpStackLocation(nextIrp);

		if( PeekContext )
		{
			if( irpStack->FileObject == ( PFILE_OBJECT )PeekContext )
			{
				break;
			}
		} 
		else 
		{
			break;
		}

		nextIrp = NULL;
		nextEntry = nextEntry->Flink;
	}

	return nextIrp;

}

__drv_raisesIRQL(DISPATCH_LEVEL)
__drv_maxIRQL(DISPATCH_LEVEL)
VOID aio_acquire_lock(
						 __in                                   PIO_CSQ Csq,
						 __out __drv_out_deref(__drv_savesIRQL) PKIRQL  Irql
						 )
{
	aio_queue *queue;

	queue = CONTAINING_RECORD( Csq,
		aio_queue, 
		aio_safe_queue );

#pragma prefast(suppress: __WARNING_BUFFER_UNDERFLOW, "Underflow using expression 'devExtension->QueueLock'")
	KeAcquireSpinLock( &queue->queue_lock, Irql);
}

__drv_requiresIRQL(DISPATCH_LEVEL)
VOID aio_release_lock(
						 __in                                PIO_CSQ Csq,
						 __in __drv_in(__drv_restoresIRQL)   KIRQL   Irql
						 )
{
	aio_queue *queue;

	{
		KIRQL irql; 
		irql = KeGetCurrentIrql(); 
	}

	queue = CONTAINING_RECORD( Csq,
		aio_queue, 
		aio_safe_queue );

#pragma prefast(suppress: __WARNING_BUFFER_UNDERFLOW, "Underflow using expression 'devExtension->QueueLock'")
	KeReleaseSpinLock( &queue->queue_lock, Irql );
}

VOID complete_canceled_irp(
						   __in  PIO_CSQ             pCsq,
						   __in  PIRP                Irp
						   )
{

	UNREFERENCED_PARAMETER(pCsq);

	Irp->IoStatus.Status = STATUS_CANCELLED;
	Irp->IoStatus.Information = 0;
	log_trace(( MSG_INFO, "cancelled irp\n"));
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

NTSTATUS init_aio_queue( aio_queue *queue, 
						PVOID context, 
						PKSTART_ROUTINE thread_routine )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	HANDLE thread_handle = NULL; 

	do 
	{
		log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

		ASSERT( queue != NULL ); 

		KeInitializeSpinLock( &queue->queue_lock );

		InitializeListHead( &queue->irp_queue );

		PAGED_CODE();	
		ntstatus = IoCsqInitializeEx( &queue->aio_safe_queue, 
			aio_insert_irp_ex,
			aio_remove_irp,
			aio_peek_next_irp,
			aio_acquire_lock,
			aio_release_lock,
			complete_canceled_irp );
		
		if( ntstatus != STATUS_SUCCESS )
		{
			log_trace( ( MSG_FATAL_ERROR, "create cancel safe queue error 0x%0.8x\n", ntstatus ) ); 
			break; 
		}

		KeQuerySystemTime( &queue->last_poll_time );

		queue->stop_queue = FALSE;
		queue->context = context; 
	} while ( FALSE );

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 

	return ntstatus; 
}

NTSTATUS uninit_aio_queue( aio_queue *queue )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	PIRP irp; 

	PAGED_CODE();

	do 
	{
		log_trace( ( MSG_INFO, "enter %s\n", __FUNCTION__ ) ); 

		ASSERT( queue != NULL ); 
	}while( FALSE );

	log_trace( ( MSG_INFO, "leave %s 0x%0.8x\n", __FUNCTION__, ntstatus ) ); 

	return ntstatus; 
}

NTSTATUS process_aio_queue( PVOID peek_context )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	PIRP irp; 

	do 
	{
		for( ; ; )
		{
			irp = IoCsqRemoveNextIrp( &io_queue.aio_safe_queue, peek_context ); 

			if( NULL == irp )
			{
				log_trace( ( MSG_INFO, "Oops, a queued irp got cancelled\n" ) );
				break; // go back to waiting
			}

			irp->IoStatus.Status = STATUS_CANCELLED; 
			irp->IoStatus.Information = 0; 

			log_trace( ( MSG_ERROR, "cleanup cancelled irp 0x%0.8x\n", irp ) ); 

			IoCompleteRequest( irp, IO_NO_INCREMENT ); 
		}
	}while( FALSE );
	return ntstatus; 
}

LARGE_INTEGER time_complete_delay = { 10000 * 1000 * 10 }; 

NTSTATUS aio_poll( __in aio_queue* queue, __in PIRP Irp )
{
   LARGE_INTEGER currentTime;
   KeQuerySystemTime (&currentTime);
   if (currentTime.QuadPart < (time_complete_delay.QuadPart +
      io_queue.last_poll_time.QuadPart))
   {
      Irp->IoStatus.Information = 0;
      return STATUS_PENDING;
   }

   KeQuerySystemTime (&io_queue.last_poll_time);
   return STATUS_SUCCESS;
}

NTSTATUS aio_insert_irp_safe(__in PIO_CSQ Csq, 
							 __in PIRP irp, 
							 PIO_CSQ_IRP_CONTEXT context)
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	BOOLEAN in_critical_region = FALSE; 

	do 
	{
		if( irp->Tail.Overlay.DriverContext[ 3 ] != NULL )
		{
			ASSERT( FALSE );
			log_trace( ( MSG_FATAL_ERROR, "the driver context [3] member of irp is already used!!!\n" ) ); 
		}

		ASSERT( KeGetCurrentIrql() <= APC_LEVEL ); 

		IoMarkIrpPending( irp ); 

		KeEnterCriticalRegion();
		in_critical_region = TRUE;

		ntstatus = IoCsqInsertIrpEx( &io_queue.aio_safe_queue, irp, NULL, NULL ); 
		if( ntstatus != STATUS_SUCCESS )
		{
			if( in_critical_region == TRUE )
			{
				KeLeaveCriticalRegion();
			}
			break; 
		}

		if( in_critical_region == TRUE )
		{
			KeLeaveCriticalRegion();
		}

	}while( FALSE );

	return ntstatus; 
}
