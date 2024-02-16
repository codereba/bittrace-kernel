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

#ifndef __ACTION_SETUP_H__
#define __ACTION_SETUP_H__

#define MAX_CMD_LEN 1024
#define COLLECT_CURRENT_PROCESS_CONTEXT 0x00000001

ULONG get_param_data_type_len( param_info *param ); 

NTSTATUS copy_param_data( BYTE *data_buf, 
						 ULONG buf_len, 
						 param_info *param, 
						 ULONG *param_data_len ); 

NTSTATUS test_action_data_setup(); 

NTSTATUS construct_param_struct_data( param_info all_params[ ], 
									 ULONG param_count, 
									 PVOID struct_data_buf, 
									 ULONG buf_len,  
									 ULONG *struct_data_len ); 

#endif //__ACTION_SETUP_H__