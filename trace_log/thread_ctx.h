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

#ifndef __THREAD_CTX_H__
#define __THREAD_CTX_H__

typedef struct _thread_ctx
{
	ref_obj; 
	action_context ctx; 
}thread_ctx, *pthread_ctx; 

NTSTATUS add_thread_ctx( HANDLE thread_id )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
	}while( FALSE ); 

	return ntstatus; 
}

typedef struct _sys_action_deteail
{
	
}sys_action_deteail, *psys_action_deteail; 

NTSTATUS check_set_thread_action( HANDLE thread_id, sys_action_deteail *action )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
	}while( FALSE ); 

	return ntstatus; 
}

NTSTATUS ref_thread_ctx( thread_ctx *ctx )
{

	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
	}while( FALSE ); 

	return ntstatus; 
}

NTSTATUS deref_thread_ctx( thread_ctx *ctx )
{

	NTSTATUS ntstatus = STATUS_SUCCESS; 

	do 
	{
	}while( FALSE ); 

	return ntstatus; 
}

#endif //__THREAD_CTX_H__