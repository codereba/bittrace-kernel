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
#include "trace_common.h"
#include "trace_log_api.h"
#include "tracedrv_tm.h"      //  this is the file that will be auto generated

#if (WINVER >= _WIN32_WINNT_VISTA)
#include "trace_common_events.h"  
#endif //(WINVER >= _WIN32_WINNT_VISTA)

#ifdef ALLOC_PRAGMA
#pragma alloc_text( PAGE, init_etw_context )
#pragma alloc_text( PAGE, uninit_etw_context )

#pragma alloc_text( PAGE, init_wpp_trace )
#pragma alloc_text( PAGE, uninit_wpp_trace )
#endif // ALLOC_PRAGMA

#if (WINVER >= _WIN32_WINNT_VISTA)
NTSTATUS init_etw_context()
{
	NTSTATUS ntstatus = STATUS_SUCCESS;
	do 
	{
		log_trace( ( MSG_INFO, "enter %s\n"__FUNCTION__ ) );

		//
		// Register with ETW
		//
		ntstatus = EventRegisterBitTrace();
		if( ntstatus != STATUS_SUCCESS ) 
		{
			break; 
		}

	}while( FALSE );

	return STATUS_SUCCESS;
}

NTSTATUS uninit_etw_context()
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		PAGED_CODE();

		KdPrint( ( "%s \n", __FUNCTION__ ) ); 
		ntstatus = EventUnregisterBitTrace(); 
	} while ( FALSE );

	return ntstatus; 
}
#endif //(WINVER >= _WIN32_WINNT_VISTA)

//#ifdef WINNT
NTSTATUS init_wpp_trace( PDRIVER_OBJECT drv_obj, 
						   PUNICODE_STRING reg_path, 
						   PDEVICE_OBJECT dev_obj )
{
	NTSTATUS ntstatus = STATUS_SUCCESS;

	//
	// include this macro to support Win2K.
	//
	WPP_SYSTEMCONTROL( drv_obj );
	WPP_INIT_TRACING( dev_obj, reg_path );


	return ntstatus;
}

NTSTATUS uninit_wpp_trace( IN PDRIVER_OBJECT drv_obj )
{
	PDEVICE_OBJECT dev_obj; 
	PAGED_CODE(); 

	log_trace( ( MSG_INFO, "%s \n", __FUNCTION__ ) );

	//
	// Get pointer to Device object
	//    
	dev_obj = drv_obj->DeviceObject;

	// 
	// Cleanup using DeviceObject on Win2K. Make sure
	// this is same deviceobject that used for initializing.
	// On XP the Parameter is ignored
	WPP_CLEANUP( dev_obj ); 

	return STATUS_SUCCESS; 
}

//lower level log will recorded more possibly.
EVENT_DESCRIPTOR trace_event_desc = { 5, 0, 0, 0, 0, 0, 0 }; 

// {81953F4C-C721-4a96-88D8-503DC236FCEB}
static const GUID trace_activity_id = 
{ 0x81953f4c, 0xc721, 0x4a96, { 0x88, 0xd8, 0x50, 0x3d, 0xc2, 0x36, 0xfc, 0xeb } };

#define MAXLOGGERS                            64

BOOLEAN bittrace_enabled()
{
	BOOLEAN is_enabled ; 

	do 
	{
		is_enabled = TRUE; 

#if (NTDDI_VERSION >= NTDDI_VISTA)
		is_enabled = EtwEventEnabled( etw_trace_handle, &trace_event_desc ); 
#else
		{
			TRACEHANDLE handle; 
			ULONG  LoggerId = (ULONG)-1 ; 

			handle = WPP_CONTROL(0).Logger; 
			
			LoggerId = WmiGetLoggerId( handle ); 

			if (LoggerId < 1 || LoggerId >= MAXLOGGERS)
			{
				is_enabled = FALSE; 
			}
			else
			{
				is_enabled = TRUE; 
			}
		}

#endif //(NTDDI_VERSION >= NTDDI_VISTA)
	} while ( FALSE );

	return is_enabled; 
}

NTSTATUS write_trace_data( PVOID data, ULONG data_len, ULONG msg_no )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		ASSERT( data != NULL ); 
		ASSERT( data_len > 0 ); 

#if (WINVER >= _WIN32_WINNT_VISTA)

		{
			EVENT_DATA_DESCRIPTOR event_data[ 1 ];
			EventDataDescCreate( &event_data[ 0 ], ( PVOID* )data, data_len ); 

			/*******************************************************************
			activity id will group some events to make a set of events .
			*******************************************************************/
			ntstatus = EtwWrite( etw_trace_handle, &trace_event_desc, NULL, 1, event_data );
		}
#else
#define WMI_MESSAGE_2K3_MAX_DATA_PARAM_SIZE ( ULONG )0x1FD0

		ntstatus = WPP_TRACE( WPP_LEVEL_FLAGS_LOGGER(TRACE_LEVEL_ERROR, FLAG_ONE)
			0, 
			WPP_LOCAL_TraceGuids+0,  
			( USHORT )msg_no, 
			data, 
			data_len, 
			NULL, 
			0 ); 

#endif //(WINVER >= _WIN32_WINNT_VISTA)

	}while( FALSE );

	return ntstatus; 
}

NTSTATUS write_trace_data_ex( PVOID data, ULONG data_size, PVOID data2, ULONG data2_size, ULONG msg_no )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
		ASSERT( data != NULL ); 
		ASSERT( data_size > 0 );

#if (WINVER >= _WIN32_WINNT_VISTA)

		{
			EVENT_DATA_DESCRIPTOR event_data[ 2 ];
			EventDataDescCreate( &event_data[ 0 ], ( PVOID* )data, data_size ); 

			if( data2 != NULL 
				&& data2_size != 0 )
			{
				EventDataDescCreate( &event_data[ 1 ], ( PVOID* )data2, data2_size );

				/*******************************************************************
				activity id will group some events to make a set of events .
				*******************************************************************/
				ntstatus = EtwWrite( etw_trace_handle, &trace_event_desc, NULL, 2, event_data );
			}
			else
			{
				ntstatus = EtwWrite( etw_trace_handle, &trace_event_desc, NULL, 1, event_data ); 
			}
		}
#else
#define WMI_MESSAGE_2K3_MAX_DATA_PARAM_SIZE ( ULONG )0x1FD0

		if( data2 != NULL 
			&& data2_size != 0 )
		{
			ntstatus = WPP_TRACE( WPP_LEVEL_FLAGS_LOGGER(TRACE_LEVEL_ERROR, FLAG_ONE)
				0, 
				WPP_LOCAL_TraceGuids+0,  
				( USHORT )msg_no, 
				data, 
				data_size, 
				data2, 
				data2_size, 
				NULL, 
				0 ); 
		}
		else
		{
			ntstatus = WPP_TRACE( WPP_LEVEL_FLAGS_LOGGER(TRACE_LEVEL_ERROR, FLAG_ONE)
				0, 
				WPP_LOCAL_TraceGuids+0,  
				( USHORT )msg_no, 
				data, 
				data_size, 
				NULL, 
				0 ); 
		}

#endif //(WINVER >= _WIN32_WINNT_VISTA)

	}while( FALSE );

	return ntstatus; 
}

