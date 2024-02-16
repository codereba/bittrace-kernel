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
#include <fltKernel.h>
#include "r3_interface.h"
#include "trace_log_api.h"
#include "fs_mng.h"

r3_interface ring3_interface = { 0 }; 
NTSTATUS register_r3_interface( PDRIVER_OBJECT drv_obj, PUNICODE_STRING reg_path, PFLT_FILTER_UNLOAD_CALLBACK unload_callback )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 
	UNICODE_STRING port_name;
	PSECURITY_DESCRIPTOR sd = NULL; 
	OBJECT_ATTRIBUTES oa; 

#ifdef INTEGRATE_DRIVERS_FUNCTION
	const FLT_REGISTRATION filter_reg = {

		sizeof( FLT_REGISTRATION ),         //  Size
		FLT_REGISTRATION_VERSION,           //  Version
		0,                                  //  Flags
		fsmon_context_reg,                //  Context Registration.
		fsmon_callbacks,                          //  Operation callbacks
		unload_callback,                      //  FilterUnload
		fs_mng_instance_setup,               //  InstanceSetup
		fs_mng_query_tear_down,               //  InstanceQueryTeardown
		NULL,                               //  InstanceTeardownStart
		NULL,                               //  InstanceTeardownComplete
		NULL,                               //  GenerateFileName
		NULL,                               //  GenerateDestinationFileName
		NULL                                //  NormalizeNameComponent
#if FSMON_VISTA
		,
		fs_mng_ktm_notify              //  KTM notification callback
#endif // FSMON_VISTA
	}; 
#else
    CONST FLT_REGISTRATION filter_reg = {
        sizeof( FLT_REGISTRATION ),         //  Size
        FLT_REGISTRATION_VERSION,           //  Version
        0,                                  //  Flags
        NULL,                               //  Context
        NULL,                               //  Operation callbacks
        unload_callback,                          //  MiniFilterUnload
        r3_interface_setup,                   //  InstanceSetup
        NULL,                               //  InstanceQueryTeardown
        NULL,                               //  InstanceTeardownStart
        NULL,                               //  InstanceTeardownComplete
        NULL,NULL                           //  NameProvider callbacks
    };

#endif //INTEGRATE_DRIVERS_FUNCTION


	ASSERT( unload_callback != NULL ); 
	ASSERT( drv_obj != NULL ); 
	ASSERT( reg_path != NULL ); 

	do 
	{
		UNREFERENCED_PARAMETER( reg_path );

		log_trace( ( MSG_INFO, "ring3 interface registered\n" ) ); 

		ExInitializeResourceLite( &ring3_interface.res_lock ); 
		ExInitializeResourceLite( &ring3_interface.service_lock ); 

#ifdef CLIENT_EPROC_PROTECT
		//ExInitializeResourceLite( &ring3_interface.client_proc_lock ); 
		IoInitializeRemoveLock( &ring3_interface.client_proc_lock ); 
#endif //CLIENT_EPROC_PROTECT

		ntstatus = FltRegisterFilter( drv_obj,
			&filter_reg,
			&ring3_interface.filter );

		if( !NT_SUCCESS( ntstatus ) )
		{
			break; 
		}

		RtlInitUnicodeString( &port_name, RING3_INTERFACE_PORT_NAME ); 

		ntstatus = FltBuildDefaultSecurityDescriptor( &sd, FLT_PORT_ALL_ACCESS);
		if( !NT_SUCCESS( ntstatus ) )
		{
			log_trace( ( MSG_ERROR, "create the ring3 port error 0x%0.8x'n", ntstatus ) ); 
			break; 
		}

		ASSERT( sd != NULL ); 

#define RING3_PORT_COUNT 2

		InitializeObjectAttributes( &oa, &port_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd );
		
		ntstatus = FltCreateCommunicationPort( ring3_interface.filter,
			&ring3_interface.service_port,
			&oa,
			NULL,
			r3_port_connect,
			r3_port_disconnect,
			r3_port_notify,
			RING3_PORT_COUNT ); 

		FltFreeSecurityDescriptor( sd ); 

		if( !NT_SUCCESS( ntstatus ) )
		{
			log_trace( ( MSG_ERROR, "create the communication port error 0x%0.8x\n", ntstatus ) ); 
			break; 
		}

		set_fs_mon_context( //drv_obj, 
			ring3_interface.filter ); 

		ntstatus = FltStartFiltering( ring3_interface.filter ); 

		if( !NT_SUCCESS( ntstatus ) )
		{
			log_trace( ( MSG_ERROR, "start filtering error 0x%0.8x\n", ntstatus ) ); 
			break; 
		}

	} while ( FALSE );

    if( !NT_SUCCESS( ntstatus ) )
	{
		if( ring3_interface.service_port != NULL )
		{
			FltCloseCommunicationPort( ring3_interface.service_port );
		}

		if( ring3_interface.filter != NULL )
		{
			FltUnregisterFilter( ring3_interface.filter );
		}

		ExDeleteResourceLite( &ring3_interface.res_lock ); 
		ExDeleteResourceLite( &ring3_interface.service_lock ); 
    }

    return ntstatus;
}

NTSTATUS r3_port_connect( IN PFLT_PORT ClientPort,
						__in_opt PVOID ServerPortCookie,
						__in_bcount_opt( SizeOfContext ) PVOID ConnectionContext,
						__in ULONG SizeOfContext,
						__deref_out_opt PVOID *ConnectionCookie )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{

		if( ConnectionContext == NULL )
		{
			if( ring3_interface.client_process != NULL 
				|| ring3_interface.client_port != NULL)
			{
				log_trace( ( MSG_INFO, "client port connection again...?" ) ); 
				break; 
			}

			ring3_interface.client_process = PsGetCurrentProcess();
			ring3_interface.client_port = ClientPort;
			ring3_interface.client_cookie = 1;

			ASSERT( NULL != ring3_interface.client_process ); 

			ObReferenceObject( ring3_interface.client_process ); 

			*ConnectionCookie = &ring3_interface.client_cookie;
		}
		else
		{
			ring3_interface.ioctl_port = ClientPort;
			ring3_interface.ioctl_cookie = 1;
			*ConnectionCookie = &ring3_interface.ioctl_cookie;
		}
	} while ( FALSE );

	return ntstatus; 
}

VOID r3_port_disconnect( __in_opt PVOID ConnectionCookie ) 
{
	if( &ring3_interface.client_cookie == ConnectionCookie)
	{
		NTSTATUS ntstatus; 

		ASSERT( ring3_interface.client_cookie == 1 );
		
#ifdef CLIENT_EPROC_PROTECT
		ntstatus = IoAcquireRemoveLock( &ring3_interface.client_proc_lock, NULL ); 
		if( ntstatus == STATUS_SUCCESS )
		{
			IoReleaseRemoveLockAndWait( &ring3_interface.client_proc_lock, NULL ); 
		}
		else
		{
			ASSERT( FALSE && "hold client remove lock error" ); 
		}
#endif //CLIENT_EPROC_PROTECT

		if( ring3_interface.client_process != NULL )
		{
			ObDereferenceObject( ring3_interface.client_process ); 
		}
		else
		{
			ASSERT( FALSE && "disconnecting the client port that process have not setting." ); 
		}

		FltCloseClientPort( ring3_interface.filter, &ring3_interface.client_port ); 
		ring3_interface.client_port = NULL;

		ring3_interface.client_cookie = 0;

		ring3_interface.client_process = NULL;
	}
	else if( &ring3_interface.ioctl_cookie == ConnectionCookie )
	{
		FltCloseClientPort( ring3_interface.filter, &ring3_interface.ioctl_port ); 

		ring3_interface.ioctl_port = NULL; 

		ring3_interface.ioctl_cookie = 0;
	}
	else
	{
		ASSERT( FALSE && "unknown port to disconnecting" ); 
	}
}

NTSTATUS r3_port_notify( IN PVOID PortCookie,
							 IN PVOID InputBuffer OPTIONAL, 
							 IN ULONG InputBufferLength, 
							 OUT PVOID OutputBuffer OPTIONAL, 
							 IN ULONG OutputBufferLength, 
							 OUT PULONG ReturnOutputBufferLength )
{
	NTSTATUS ntstatus = STATUS_SUCCESS;
	ULONG ioctl_code;

	__try
	{
		*ReturnOutputBufferLength = 0;

		if( &ring3_interface.ioctl_cookie != PortCookie )
		{
			ntstatus = STATUS_UNSUCCESSFUL;
			log_trace( ( MSG_ERROR, "the notifying message is not from the io control port %p, but is %p\n", 
				&ring3_interface.ioctl_cookie, 
				PortCookie ) ); 

			__leave; 
		}

		if( InputBufferLength == sizeof( ULONG ) )
		{
			ioctl_code = *( (PULONG )InputBuffer ); 

			switch( ioctl_code )
			{
			case FSCTL_ACQUIRE_RESOURCE_EXCLUSIVE:
				{
					KeEnterCriticalRegion(); 
					ExAcquireResourceExclusiveLite( &ring3_interface.service_lock, TRUE );
					break;
				}
			case FSCTL_RELEASE_RESOURCE_EXCLUSIVE:
				{
					ExReleaseResourceLite( &ring3_interface.service_lock );
					KeLeaveCriticalRegion();
					break;
				}
			case FSCTL_ACQUIRE_RESOURCE_SHARE:
				{
					KeEnterCriticalRegion();
					ExAcquireResourceSharedLite( &ring3_interface.service_lock, TRUE );
					break;
				}
			case FSCTL_RELEASE_RESOURCE_SHARE:
				{
					ExReleaseResourceLite( &ring3_interface.service_lock );
					KeLeaveCriticalRegion();
					break;
				}
			}
		}

		__leave;
	}
	__finally
	{
	}

	return ntstatus;
}

NTSTATUS unreg_r3_interface()
{

    PAGED_CODE();

    log_trace( ( MSG_INFO,
                "deregister ring3 interface \n" ) );

	_hold_w_res_lock( &ring3_interface.res_lock );

	if( ring3_interface.service_port != NULL )
	{
		FltCloseCommunicationPort( ring3_interface.service_port );
		ring3_interface.service_port = NULL;
	}

    FltUnregisterFilter( ring3_interface.filter );

	ring3_interface.filter = NULL; 

    _release_res_lock( &ring3_interface.res_lock ); 

    ExDeleteResourceLite( &ring3_interface.res_lock ); 
	ExDeleteResourceLite( &ring3_interface.service_lock );

    return STATUS_SUCCESS;
}


NTSTATUS r3_interface_setup ( __in PCFLT_RELATED_OBJECTS FltObjects,
							 __in FLT_INSTANCE_SETUP_FLAGS Flags,
							 __in DEVICE_TYPE VolumeDeviceType,
							 __in FLT_FILESYSTEM_TYPE VolumeFilesystemType )
{

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    return STATUS_FLT_DO_NOT_ATTACH;
}

NTSTATUS r3_dev_priv_open( __in PIRP irp )
{
    NTSTATUS ntstatus;

    UNREFERENCED_PARAMETER( irp );

    PAGED_CODE();

    log_trace( ( MSG_INFO, __FUNCTION__ " entry ( Irp = %p )\n", irp ) );

    _hold_w_res_lock( &ring3_interface.res_lock );

    if (FlagOn( ring3_interface.flags, GLOBAL_DATA_F_CDO_OPEN_HANDLE ) ||
        FlagOn( ring3_interface.flags, GLOBAL_DATA_F_CDO_OPEN_REF )) {

        //
        //  Sanity - if we have a handle open against this CDO
        //  we must have an outstanding reference as well
        //

        ASSERT( !FlagOn( ring3_interface.flags, GLOBAL_DATA_F_CDO_OPEN_HANDLE ) 
			|| FlagOn( ring3_interface.flags, GLOBAL_DATA_F_CDO_OPEN_REF ) );

        ntstatus = STATUS_DEVICE_ALREADY_ATTACHED;

        log_trace( ( MSG_INFO, __FUNCTION__ " -> Device open failure. Device already opened. ( Irp = %p, Flags = 0x%x, status = 0x%x )\n",
                     irp,
                     ring3_interface.flags,
                     ntstatus ) );

    } 
	else 
	{

        //
        //  Flag that the CDO is opened so that we will fail future creates
        //  until the CDO is closed by the current caller
        //
        //
        //  If we suceed the create we are guaranteed to get a Cleanup (where we
        //  will reset GLOBAL_DATA_F_CDO_OPEN_HANDLE) and Close (where we will
        //  reset GLOBAL_DATA_F_CDO_OPEN_REF)
        //

        SetFlag( ring3_interface.flags, GLOBAL_DATA_F_CDO_OPEN_REF );
        SetFlag( ring3_interface.flags, GLOBAL_DATA_F_CDO_OPEN_HANDLE );

        ntstatus = STATUS_SUCCESS;

        log_trace( ( MSG_INFO, __FUNCTION__ " -> Device open successful. ( Irp = %p, Flags = 0x%x, status = 0x%x )\n",
                     irp,
                     ring3_interface.flags,
                     ntstatus ) );
    }


    //
    //  The filter may want to do additional processing here to set up the structures it
    //  needs to service this create request.
    //


	_release_res_lock( &ring3_interface.res_lock );


	log_trace( ( MSG_INFO, __FUNCTION__ " exit ( Irp = %p, status = 0x%x )\n",
		irp,
		ntstatus ) );


    return ntstatus;
}

NTSTATUS r3_dev_priv_cleanup( __in PIRP irp )
{
    NTSTATUS ntstatus;

    UNREFERENCED_PARAMETER( irp );

    PAGED_CODE();


    log_trace( ( MSG_INFO, __FUNCTION__ " entry ( Irp = %p )\n",
                 irp ) );


    _hold_w_res_lock( &ring3_interface.res_lock );

    ASSERT( FlagOn( ring3_interface.flags, GLOBAL_DATA_F_CDO_OPEN_REF ) &&
            FlagOn( ring3_interface.flags, GLOBAL_DATA_F_CDO_OPEN_HANDLE ) ); 

    ClearFlag( ring3_interface.flags, GLOBAL_DATA_F_CDO_OPEN_HANDLE ); 

    ntstatus = STATUS_SUCCESS;

    log_trace( ( MSG_INFO, __FUNCTION__ " -> Device cleanup successful. ( Irp = %p, Flags = 0x%x, status = 0x%x )\n",
                 irp,
                 ring3_interface.flags,
                 ntstatus ) );


    _release_res_lock( &ring3_interface.res_lock );

    log_trace( ( MSG_INFO, __FUNCTION__ " exit ( Irp = %p, status = 0x%x )\n",
                 irp,
                 ntstatus ) );
    return ntstatus;
}

NTSTATUS r3_dev_priv_close( __in PIRP irp )
{
    NTSTATUS ntstatus;

    UNREFERENCED_PARAMETER( irp );

    PAGED_CODE();

    log_trace( ( MSG_INFO, __FUNCTION__ " entry ( Irp = %p )\n",
                 irp ) );

    _hold_w_res_lock( &ring3_interface.res_lock );

    ASSERT( FlagOn( ring3_interface.flags, GLOBAL_DATA_F_CDO_OPEN_REF ) &&
            !FlagOn( ring3_interface.flags, GLOBAL_DATA_F_CDO_OPEN_HANDLE ));

    ClearFlag( ring3_interface.flags, GLOBAL_DATA_F_CDO_OPEN_REF );

    ntstatus = STATUS_SUCCESS;

    log_trace( ( MSG_INFO, "%s -> Device close successful. ( Irp = %p, Flags = 0x%x, status = 0x%x )\n",
		__FUNCTION__, 
		irp,
		ring3_interface.flags,
		ntstatus ) ); 

    _release_res_lock( &ring3_interface.res_lock );


    log_trace( ( MSG_INFO, __FUNCTION__ "exit ( Irp = %p, status = 0x%x )\n",
                 irp,
                 ntstatus ) );


    return ntstatus;

}

DRIVER_DISPATCH r3_dev_maj_func;

NTSTATUS r3_dev_maj_func(
    __in PDEVICE_OBJECT dev_obj,
    __in PIRP irp )
{
    NTSTATUS status;
    PIO_STACK_LOCATION irpSp;

    UNREFERENCED_PARAMETER( dev_obj );

    PAGED_CODE();

    status = STATUS_SUCCESS;

    irpSp = IoGetCurrentIrpStackLocation(irp);

    log_trace( ( MSG_INFO, __FUNCTION__ "entry ( Irp = %p, irpSp->MajorFunction = 0x%x )\n",
                 irp,
                 irpSp->MajorFunction ) );

    switch( irpSp->MajorFunction )
	{
        case IRP_MJ_CREATE:
        {
            status = r3_dev_priv_open( irp );

            irp->IoStatus.Status = status;

            if(NT_SUCCESS(status))
            {
                irp->IoStatus.Information = FILE_OPENED;
            }
            else
            {
                irp->IoStatus.Information = 0;
            }

            IoCompleteRequest( irp, IO_NO_INCREMENT );

            break;
        }

        case IRP_MJ_CLOSE:
        {

            r3_dev_priv_close( irp );

            irp->IoStatus.Status = STATUS_SUCCESS;
            irp->IoStatus.Information = 0;

            IoCompleteRequest( irp, IO_NO_INCREMENT );

            break;
        }

        case IRP_MJ_CLEANUP:
        {

            r3_dev_priv_cleanup( irp );

            irp->IoStatus.Status = STATUS_SUCCESS;
            irp->IoStatus.Information = 0;

            IoCompleteRequest( irp, IO_NO_INCREMENT );

            break;
        }

        default:
        {
            log_trace( ( MSG_INFO, "Unsupported Major Function 0x%x ( Irp = %p )\n",
                         irpSp->MajorFunction,
                         irp ) );

            irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
            irp->IoStatus.Information = 0;

            IoCompleteRequest( irp, IO_NO_INCREMENT );

            status = STATUS_INVALID_DEVICE_REQUEST;
        }
    }


    log_trace( ( MSG_INFO, __FUNCTION__ " exit ( Irp = %p, irpSp->MajorFunction = 0x%x, status = 0x%x )\n",
                 irp,
                 irpSp->MajorFunction,
                 status ) );

    return status;
}
