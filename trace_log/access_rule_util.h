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

#ifndef __ACCESS_RULE_UTIL_H__
#define __ACCESS_RULE_UTIL_H__



NTSTATUS pre_get_class_param_define( param_define_input *param_input )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	ASSERT( param_input != NULL ); 

	if( *param_input->cls.class_name == L'\0' )
	{
		ASSERT( "class define name is null string" && FALSE ); 
		ntstatus = STATUS_SUCCESS_NOT_NEED_CONTINUE; 
		goto _return; 
	}

_return:
	return ntstatus; 
}

NTSTATUS pre_get_param_define( param_define_input *param_input, param_define_type type )
{
	NTSTATUS ntstatus = STATUS_SUCCESS; 

	ASSERT( param_input != NULL );

	ASSERT( is_valid_param_define_type( type ) ); 
	if( type == APP_DEFINE )
	{
		if( *param_input->app.app_name == L'\0' )
		{
			ntstatus = STATUS_SUCCESS_NOT_NEED_CONTINUE; 
			goto _return; 
		}
	}
	else if( type == COM_DEFINE )
	{
		if( *param_input->com.com_name == L'\0' )
		{
			ASSERT( "com define name is null string" && FALSE ); 

			ntstatus = STATUS_SUCCESS_NOT_NEED_CONTINUE; 
			goto _return; 
		}
	}
	else if( type == FILE_DEFINE )
	{
		if( *param_input->file.file_path == L'\0' )
		{
			ASSERT( "file define name is null string" && FALSE ); 

			ntstatus = STATUS_SUCCESS_NOT_NEED_CONTINUE; 
			goto _return; 
		}
	}
	else if( type == REG_DEFINE )
	{
		if( *param_input->file.file_path == L'\0' )
		{
			ASSERT( "reg define name is null string" && FALSE ); 

			ntstatus = STATUS_SUCCESS_NOT_NEED_CONTINUE; 
			goto _return; 
		}
	}
	else if( type == IP_DEFINE )
	{
		if( param_input->ip.ip_begin == 0 
			&& param_input->ip.ip_end == 0 )
		{
			ASSERT( "ip define is 0" && FALSE ); 

			ntstatus = STATUS_SUCCESS_NOT_NEED_CONTINUE; 
			goto _return; 
		}
	}
	else if( type == PORT_DEFINE )
	{
		if( param_input->port.port_begin == 0 
			&& param_input->port.port_end == 0 )
		{
			ASSERT( "port define is 0" && FALSE ); 

			ntstatus = STATUS_SUCCESS_NOT_NEED_CONTINUE; 
			goto _return; 
		}
	}
	else if( type == URL_DEFINE )
	{
		if( *param_input->url.url == L'\0' )
		{
			ASSERT( "url define is null string" && FALSE ); 

			ntstatus = STATUS_SUCCESS_NOT_NEED_CONTINUE; 
			goto _return; 
		}
	}
	else
	{
		ASSERT( "invalid param define type" && FALSE ); 
	}

_return:
	return ntstatus; 
}


#endif //__ACCESS_RULE_UTIL_H__