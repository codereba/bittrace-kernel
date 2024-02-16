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

#ifndef __PROC_INFO_H__
#define __PROC_INFO_H__

/*******************************************************************************************
加入自设的进程，线程管理信息结构的目的：
1.通过加入进程管理信息，使得在DISPATCH_LEVEL可以访问相应记录在NONPAGED POOL中的信息。
2.通过进程管理信息访问具体的信息内容，这种方法比较集中，而使用WINDOWS本身的方式进行访问，
访问的过程是离散的，而且步骤可能会更复杂。
3.但对NONPAGED POOL内存的占用更多。
最大值估算：
1.系统同时最多260个进程。
大约等于260 * 1024 = 260K，应该是可以承受的。
*******************************************************************************************/
#define INVALID_TRACE_DATA_SIZE ( -1 )
typedef struct _PROCESS_INFO
{
	LIST_ENTRY entry;
	LIST_ENTRY tmp_entry; 
	//LIST_ENTRY threads; 

	DWORD ref_count;
	PEPROCESS eproc;
	ULONG proc_id;
	WCHAR proc_name[ MAX_NATIVE_NAME_SIZE ]; 
	ULONG proc_name_len; 
	BOOLEAN proc_name_inited; 
	LONG trace_data_size; 
}PROCESS_INFO, *PPROCESS_INFO; 

/***********************************************************************************
使用自定义的数据结构来保存系统行为的环境信息，包括：
每个进程的数据结构：
进程名称
进程路径
进程ID

每个线程的数据结构：
线程ID

通过分析，线程的数据结构内容只有一个成员，不需要制做单独的数据结构

进程需要以上数据结构。
***********************************************************************************/
//typedef struct _THREAD_INFO
//{
//	LIST_ENTRY entry; 
//
//	PROCESS_INFO *proc; 
//	PETHREAD ethread; 
//	action_context ctx; 
//}THREAD_INFO, *PTHREAD_INFO; 

#define CREATE_NEW_PROCESS_INFO 0x00000001
NTSTATUS retrieve_proc_name_info( PROCESS_INFO *proc_info ); 
NTSTATUS init_proc_info( PROCESS_INFO *proc_info, PEPROCESS eproc, ULONG flags ); 
#define NEED_RETRIEVE_PROC_NAME 0x01000000

PROCESS_INFO* get_proc_info( PEPROCESS eproc, ULONG flags, ULONG *status); 
PROCESS_INFO* get_proc_info_by_proc_id( ULONG proc_id ); 
NTSTATUS reset_proc_name_record( PEPROCESS eproc ); 

DWORD release_proc_info( PROCESS_INFO *proc_info ); 

//PROCESS_INFO* get_proc_info_by_proc_id( ULONG proc_id ); 
NTSTATUS remove_proc_info( IN HANDLE proc_id ); 
NTSTATUS remove_all_proc_info( IN HANDLE proc_id ); 
NTSTATUS release_all_proc_info(); 
NTSTATUS init_proc_info_manage(); 
NTSTATUS uninit_proc_info_manage(); 

#endif //__PROC_INFO_H__
