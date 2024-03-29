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

#ifndef __FAST_IO_DISPATCH_H__
#define __FAST_IO_DISPATCH_H__


#define DEBUG_TRACE_CDO_ALL_OPERATIONS 0x80000000
#define DEBUG_TRACE_CDO_FASTIO_OPERATIONS 0x40000000 
#define DEBUG_TRACE_ERROR 0x20000000

NTSTATUS load_fast_io_dispatch( PDRIVER_OBJECT drv_obj ); 

#endif //__FAST_IO_DISPATCH_H__