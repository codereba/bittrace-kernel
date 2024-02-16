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

#ifndef __R3_INTERFACE_H__
#define __R3_INTERFACE_H__

NTSTATUS r3_dev_maj_func( __in PDEVICE_OBJECT dev_obj, __in PIRP irp );

NTSTATUS r3_dev_priv_open( __in PIRP irp );

NTSTATUS r3_dev_priv_cleanup( __in PIRP irp );

NTSTATUS r3_dev_priv_close( __in PIRP irp ); 

#define GLOBAL_DATA_F_CDO_OPEN_REF      0x00000001

#define GLOBAL_DATA_F_CDO_OPEN_HANDLE   0x00000002

typedef struct _r3_interface
{
    PFLT_FILTER filter; 

	ERESOURCE service_lock; 

	PFLT_PORT service_port; 
	BOOLEAN client_cookie; 
	PFLT_PORT client_port; 
	PEPROCESS client_process; 
	IO_REMOVE_LOCK client_proc_lock;

	BOOLEAN ioctl_cookie; 
	PFLT_PORT ioctl_port; 
	PEPROCESS ioctl_process;

    ULONG flags;

    ERESOURCE res_lock;
    
#if DBG
    ULONG dbg_level;
#endif

} r3_interface, *pr3_interface; 

extern r3_interface ring3_interface; 

NTSTATUS r3_interface_setup ( __in PCFLT_RELATED_OBJECTS FltObjects,
							 __in FLT_INSTANCE_SETUP_FLAGS Flags,
							 __in DEVICE_TYPE VolumeDeviceType,
							 __in FLT_FILESYSTEM_TYPE VolumeFilesystemType ); 

NTSTATUS unreg_r3_interface(); 

NTSTATUS register_r3_interface( PDRIVER_OBJECT drv_obj, PUNICODE_STRING reg_path, PFLT_FILTER_UNLOAD_CALLBACK unload_callback ); 

NTSTATUS r3_port_connect( IN PFLT_PORT ClientPort,
						__in_opt PVOID ServerPortCookie,
						__in_bcount_opt( SizeOfContext ) PVOID ConnectionContext,
						__in ULONG SizeOfContext,
						__deref_out_opt PVOID *ConnectionCookie ); 

VOID r3_port_disconnect( __in_opt PVOID ConnectionCookie ) ; 

NTSTATUS r3_port_notify( IN PVOID PortCookie,
							 IN PVOID InputBuffer OPTIONAL, 
							 IN ULONG InputBufferLength, 
							 OUT PVOID OutputBuffer OPTIONAL, 
							 IN ULONG OutputBufferLength, 
							 OUT PULONG ReturnOutputBufferLength ); 


#define FSCTL_LSUEE_BASE    0xBCDE
#define FSCTL_CREATE_MOMMUNICAT_EVENT_FOR_R3_WAIT CTL_CODE(FSCTL_LSUEE_BASE,0x0E02,METHOD_BUFFERED,FILE_ALL_ACCESS)
#define FSCTL_DELETE_MOMMUNICAT_EVENT_FOR_R3_WAIT CTL_CODE(FSCTL_LSUEE_BASE,0x0E03,METHOD_BUFFERED,FILE_ALL_ACCESS)

#define FSCTL_CREATE_MOMMUNICAT_EVENT_FOR_R0_WAIT CTL_CODE(FSCTL_LSUEE_BASE,0x0E04,METHOD_BUFFERED,FILE_ALL_ACCESS)
#define FSCTL_DELETE_MOMMUNICAT_EVENT_FOR_R0_WAIT CTL_CODE(FSCTL_LSUEE_BASE,0x0E05,METHOD_BUFFERED,FILE_ALL_ACCESS)

#define FSCTL_GET_USB_CONROL_DATA                 CTL_CODE(FSCTL_LSUEE_BASE,0x0E06,METHOD_BUFFERED,FILE_ALL_ACCESS)
#define FSCTL_SET_USB_CONTROL_RESULT              CTL_CODE(FSCTL_LSUEE_BASE,0x0E07,METHOD_BUFFERED,FILE_ALL_ACCESS)

#define FSCTL_ADD_USB_CONTROL_POLICY              CTL_CODE(FSCTL_LSUEE_BASE,0x0E08,METHOD_BUFFERED,FILE_ALL_ACCESS)
#define FSCTL_DELETE_USB_CONTROL_POLICY           CTL_CODE(FSCTL_LSUEE_BASE,0x0E09,METHOD_BUFFERED,FILE_ALL_ACCESS)
#define FSCTL_SET_USB_SYSTEM_INFORMATION          CTL_CODE(FSCTL_LSUEE_BASE,0x0E0A,METHOD_BUFFERED,FILE_ALL_ACCESS)

#define FSCTL_GET_SUB_PROTECT_STATUS              CTL_CODE(FSCTL_LSUEE_BASE,0x0E0E,METHOD_BUFFERED,FILE_ALL_ACCESS)
#define FSCTL_SET_SUB_PROTECT_STATUS              CTL_CODE(FSCTL_LSUEE_BASE,0x0E0F,METHOD_BUFFERED,FILE_ALL_ACCESS)

#define FSCTL_ACQUIRE_RESOURCE_EXCLUSIVE          CTL_CODE(FSCTL_LSUEE_BASE,0x0E10,METHOD_BUFFERED,FILE_ALL_ACCESS)
#define FSCTL_RELEASE_RESOURCE_EXCLUSIVE          CTL_CODE(FSCTL_LSUEE_BASE,0x0E11,METHOD_BUFFERED,FILE_ALL_ACCESS)

#define FSCTL_ACQUIRE_RESOURCE_SHARE              CTL_CODE(FSCTL_LSUEE_BASE,0x0E12,METHOD_BUFFERED,FILE_ALL_ACCESS)
#define FSCTL_RELEASE_RESOURCE_SHARE              CTL_CODE(FSCTL_LSUEE_BASE,0x0E13,METHOD_BUFFERED,FILE_ALL_ACCESS)

#endif //__R3_INTERFACE_H__