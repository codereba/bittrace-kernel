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
#include "trace_log_api.h"
#include "fast_io_dispatch.h"

#pragma alloc_text( PAGE,     fast_io_check_if_possible )
#pragma alloc_text( PAGE,     fast_io_read )
#pragma alloc_text( PAGE,     fast_io_write )
#pragma alloc_text( PAGE,     fast_io_query_basic_info )
#pragma alloc_text( PAGE,     fast_io_query_standard_info )
#pragma alloc_text( PAGE,     fast_io_lock )
#pragma alloc_text( PAGE,     fast_io_unlock_single )
#pragma alloc_text( PAGE,     fast_io_unlock_all )
#pragma alloc_text( PAGE,     fast_io_unlock_all_by_key )
#pragma alloc_text( PAGE,     trace_log_fast_io_dev_control )
#pragma alloc_text( PAGE,     fast_io_query_network_open_info )
#pragma alloc_text( PAGE,     fast_io_mdl_read )
#pragma alloc_text( NONPAGED, fast_io_mdl_read_complete )
#pragma alloc_text( PAGE,     fast_io_prepare_mdl_write )
#pragma alloc_text( NONPAGED, fast_io_mdl_write_complete )
#pragma alloc_text( PAGE,     fast_io_read_compressed )
#pragma alloc_text( PAGE,     fast_io_write_compressed )
#pragma alloc_text( NONPAGED, fast_io_mdl_read_complete_compressed )
#pragma alloc_text( NONPAGED, fast_io_mdl_write_complete_compressed )
#pragma alloc_text( PAGE,     fast_io_query_open )


//
//  Fast IO dispatch routines
//

FAST_IO_DISPATCH trace_log_fast_io_dispatch =
{
	sizeof(FAST_IO_DISPATCH),
		fast_io_check_if_possible,           //  CheckForFastIo
		fast_io_read,                      //  FastIoRead
		fast_io_write,                     //  FastIoWrite
		fast_io_query_basic_info,            //  FastIoQueryBasicInfo
		fast_io_query_standard_info,         //  FastIoQueryStandardInfo
		fast_io_lock,                      //  FastIoLock
		fast_io_unlock_single,              //  FastIoUnlockSingle
		fast_io_unlock_all,                 //  FastIoUnlockAll
		fast_io_unlock_all_by_key,            //  FastIoUnlockAllByKey
		trace_log_fast_io_dev_control,             //  FastIoDeviceControl
		NULL,                               //  AcquireFileForNtCreateSection
		NULL,                               //  ReleaseFileForNtCreateSection
		NULL,                               //  FastIoDetachDevice
		fast_io_query_network_open_info,      //  FastIoQueryNetworkOpenInfo
		NULL,                               //  AcquireForModWrite
		fast_io_mdl_read,                   //  MdlRead
		fast_io_mdl_read_complete,           //  MdlReadComplete
		fast_io_prepare_mdl_write,           //  PrepareMdlWrite
		fast_io_mdl_write_complete,          //  MdlWriteComplete
		fast_io_read_compressed,            //  FastIoReadCompressed
		fast_io_write_compressed,           //  FastIoWriteCompressed
		fast_io_mdl_read_complete_compressed, //  MdlReadCompleteCompressed
		fast_io_mdl_write_complete_compressed, //  MdlWriteCompleteCompressed
		fast_io_query_open,                 //  FastIoQueryOpen
		NULL,                               //  ReleaseForModWrite
		NULL,                               //  AcquireForCcFlush
		NULL,                               //  ReleaseForCcFlush
};

/////////////////////////////////////////////////////////////////////////////
//
//                      FastIO Handling routines
//
/////////////////////////////////////////////////////////////////////////////



BOOLEAN
fast_io_check_if_possible(
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __in BOOLEAN CheckForReadOperation,
    __out PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for checking to see
    whether fast I/O is possible for this file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be operated on.

    FileOffset - Byte offset in the file for the operation.

    Length - Length of the operation to be performed.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    LockKey - Provides the caller's key for file locks.

    CheckForReadOperation - Indicates whether the caller is checking for a
        read (TRUE) or a write operation.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(FileOffset);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Wait);
    UNREFERENCED_PARAMETER(LockKey);
    UNREFERENCED_PARAMETER(CheckForReadOperation);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, fail the operation
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoCheckIfPossible -> Unsupported FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject ) ) );

    IoStatus->Status = STATUS_INVALID_DEVICE_REQUEST;
    IoStatus->Information = 0;

    return TRUE;
}


BOOLEAN 
fast_io_read(
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __out_bcount(Length) PVOID Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for reading from a
    file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be read.

    FileOffset - Byte offset in the file of the read.

    Length - Length of the read operation to be performed.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    LockKey - Provides the caller's key for file locks.

    Buffer - Pointer to the caller's buffer to receive the data read.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(FileOffset);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Wait);
    UNREFERENCED_PARAMETER(LockKey);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, fail the operation
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoRead -> Unsupported FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject ) ) );

    IoStatus->Status = STATUS_INVALID_DEVICE_REQUEST;
    IoStatus->Information = 0;

    return TRUE;
}



BOOLEAN
fast_io_write(
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __in_bcount(Length) PVOID Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for writing to a
    file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be written.

    FileOffset - Byte offset in the file of the write operation.

    Length - Length of the write operation to be performed.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    LockKey - Provides the caller's key for file locks.

    Buffer - Pointer to the caller's buffer that contains the data to be
        written.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(FileOffset);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Wait);
    UNREFERENCED_PARAMETER(LockKey);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, fail the operation
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoWrite -> Unsupported FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject) ) );

    IoStatus->Status = STATUS_INVALID_DEVICE_REQUEST;
    IoStatus->Information = 0;

    return TRUE;
}

BOOLEAN
fast_io_query_basic_info(
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __out PFILE_BASIC_INFORMATION Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for querying basic
    information about the file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be queried.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    Buffer - Pointer to the caller's buffer to receive the information about
        the file.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(Wait);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, fail the operation
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoQueryBasicInfo -> Unsupported FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject) ) );

    IoStatus->Status = STATUS_INVALID_DEVICE_REQUEST;
    IoStatus->Information = 0;

    return TRUE;
}




BOOLEAN
fast_io_query_standard_info(
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __out PFILE_STANDARD_INFORMATION Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for querying standard
    information about the file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be queried.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    Buffer - Pointer to the caller's buffer to receive the information about
        the file.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/
{
    PAGED_CODE();
    ASSERT(IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(Wait);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, fail the operation
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoQueryStandardInfo -> Unsupported FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject) ) );

    IoStatus->Status = STATUS_INVALID_DEVICE_REQUEST;
    IoStatus->Information = 0;

    return TRUE;
}


BOOLEAN
fast_io_lock(
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PLARGE_INTEGER Length,
    __in PEPROCESS ProcessId,
    __in ULONG Key,
    __in BOOLEAN FailImmediately,
    __in BOOLEAN ExclusiveLock,
    __out PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for locking a byte
    range within a file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be locked.

    FileOffset - Starting byte offset from the base of the file to be locked.

    Length - Length of the byte range to be locked.

    ProcessId - ID of the process requesting the file lock.

    Key - Lock key to associate with the file lock.

    FailImmediately - Indicates whether or not the lock request is to fail
        if it cannot be immediately be granted.

    ExclusiveLock - Indicates whether the lock to be taken is exclusive (TRUE)
        or shared.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(FileOffset);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(FailImmediately);
    UNREFERENCED_PARAMETER(ExclusiveLock);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, fail the operation
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoLock -> Unsupported FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject) ) );

    IoStatus->Status = STATUS_INVALID_DEVICE_REQUEST;
    IoStatus->Information = 0;

    return TRUE;
}


BOOLEAN
fast_io_unlock_single(
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PLARGE_INTEGER Length,
    __in PEPROCESS ProcessId,
    __in ULONG Key,
    __out PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for unlocking a byte
    range within a file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be unlocked.

    FileOffset - Starting byte offset from the base of the file to be
        unlocked.

    Length - Length of the byte range to be unlocked.

    ProcessId - ID of the process requesting the unlock operation.

    Key - Lock key associated with the file lock.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(FileOffset);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, fail the operation
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoUnlockSingle -> Unsupported FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject ) ) );

    IoStatus->Status = STATUS_INVALID_DEVICE_REQUEST;
    IoStatus->Information = 0;

    return TRUE;
}



BOOLEAN
fast_io_unlock_all(
    __in PFILE_OBJECT FileObject,
    __in PEPROCESS ProcessId,
    __out PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for unlocking all
    locks within a file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be unlocked.

    ProcessId - ID of the process requesting the unlock operation.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/
{
    PAGED_CODE();
    ASSERT(IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, fail the operation
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoUnlockAll -> Unsupported FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject ) ) );

    IoStatus->Status = STATUS_INVALID_DEVICE_REQUEST;
    IoStatus->Information = 0;

    return TRUE;
}


BOOLEAN
fast_io_unlock_all_by_key(
    __in PFILE_OBJECT FileObject,
    __in PVOID ProcessId,
    __in ULONG Key,
    __out PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for unlocking all
    locks within a file based on a specified key.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be unlocked.

    ProcessId - ID of the process requesting the unlock operation.

    Key - Lock key associated with the locks on the file to be released.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/
{
    PAGED_CODE();
    ASSERT(IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, fail the operation
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoUnlockAllByKey -> Unsupported FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject ) ) );

    IoStatus->Status = STATUS_INVALID_DEVICE_REQUEST;
    IoStatus->Information = 0;

    return TRUE;
}


NTSTATUS
_trace_log_dev_ctrl(
						   __in PDEVICE_OBJECT DeviceObject,
						   __in ULONG IoControlCode,
						   __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
						   __in ULONG InputBufferLength,
						   __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer,
						   __in ULONG OutputBufferLength,
						   __out PIO_STATUS_BLOCK IoStatus,
						   __in_opt PIRP Irp
						   )
{
	return STATUS_SUCCESS; 
}

NTSTATUS load_fast_io_dispatch( PDRIVER_OBJECT drv_obj )
{
#pragma prefast(suppress:__WARNING_INACCESSIBLE_MEMBER, "The Cdo sample is allowed to set the FastIo Dispatch routine because he is setting up a Cdo.")
	drv_obj->FastIoDispatch = &trace_log_fast_io_dispatch;

	return STATUS_SUCCESS; 
}

BOOLEAN
trace_log_fast_io_dev_control(
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
    __in ULONG InputBufferLength,
    __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferLength,
    __in ULONG IoControlCode,
    __out PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject)
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for device I/O control
    operations on a file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object representing the device to be
        serviced.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    InputBuffer - Optional pointer to a buffer to be passed into the driver.

    InputBufferLength - Length of the optional InputBuffer, if one was
        specified.

    OutputBuffer - Optional pointer to a buffer to receive data from the
        driver.

    OutputBufferLength - Length of the optional OutputBuffer, if one was
        specified.

    IoControlCode - I/O control code indicating the operation to be performed
        on the device.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/
{
    PAGED_CODE();
    ASSERT(IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(Wait);

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_CDO_SUPPORTED_OPERATIONS,
                ("[Cdo]: CdoFastIoDeviceControl Entry ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject ) ) );

    //
    //  The caller will update the IO status block
    //

    _trace_log_dev_ctrl( DeviceObject,
                                IoControlCode,
                                InputBuffer,
                                InputBufferLength,
                                OutputBuffer,
                                OutputBufferLength,
                                IoStatus,
                                NULL );

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_CDO_SUPPORTED_OPERATIONS,
                ("[Cdo]: CdoFastIoDeviceControl Exit ( FileObject = %p, DeviceObject = %p, Status = 0x%x )\n",
                 FileObject,
                 DeviceObject,
                 IoStatus->Status ) ) );

    return TRUE;
}

BOOLEAN
fast_io_query_network_open_info(
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __out PFILE_NETWORK_OPEN_INFORMATION Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for querying network
    information about a file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be queried.

    Wait - Indicates whether or not the caller can handle the file system
        having to wait and tie up the current thread.

    Buffer - Pointer to a buffer to receive the network information about the
        file.

    IoStatus - Pointer to a variable to receive the final status of the query
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PAGED_CODE();
    ASSERT(IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(Wait);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, fail the operation
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoQueryNetworkOpenInfo -> Unsupported FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject ) ) );

    IoStatus->Status = STATUS_INVALID_DEVICE_REQUEST;
    IoStatus->Information = 0;

    return TRUE;
}


BOOLEAN
fast_io_mdl_read(
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __deref_out PMDL *MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for reading a file
    using MDLs as buffers.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object that is to be read.

    FileOffset - Supplies the offset into the file to begin the read operation.

    Length - Specifies the number of bytes to be read from the file.

    LockKey - The key to be used in byte range lock checks.

    MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
        chain built to describe the data read.

    IoStatus - Variable to receive the final status of the read operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(FileOffset);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(LockKey);
    UNREFERENCED_PARAMETER(MdlChain);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, fail the operation
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoMdlRead -> Unsupported FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject ) ) );

    IoStatus->Status = STATUS_INVALID_DEVICE_REQUEST;
    IoStatus->Information = 0;

    return TRUE;
}

BOOLEAN
fast_io_mdl_read_complete (
    __in PFILE_OBJECT FileObject,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for completing an
    MDL read operation.

    This function simply invokes the file system's corresponding routine, if
    it has one.  It should be the case that this routine is invoked only if
    the MdlRead function is supported by the underlying file system, and
    therefore this function will also be supported, but this is not assumed
    by this driver.

Arguments:

    FileObject - Pointer to the file object to complete the MDL read upon.

    MdlChain - Pointer to the MDL chain used to perform the read operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE, depending on whether or not it is
    possible to invoke this function on the fast I/O path.

--*/

{
    ASSERT(IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(MdlChain);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, return not supported
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoMdlReadComplete -> Unsupported as FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject ) ) );

    return FALSE;
}

BOOLEAN
fast_io_prepare_mdl_write(
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __deref_out PMDL *MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for preparing for an
    MDL write operation.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object that will be written.

    FileOffset - Supplies the offset into the file to begin the write operation.

    Length - Specifies the number of bytes to be write to the file.

    LockKey - The key to be used in byte range lock checks.

    MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
        chain built to describe the data written.

    IoStatus - Variable to receive the final status of the write operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PAGED_CODE();
    ASSERT(IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(FileOffset);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(LockKey);
    UNREFERENCED_PARAMETER(MdlChain);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, fail the operation
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoPrepareMdlWrite -> Unsupported FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject ) ) );

    IoStatus->Status = STATUS_INVALID_DEVICE_REQUEST;
    IoStatus->Information = 0;

    return TRUE;
}




BOOLEAN
fast_io_mdl_write_complete(
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for completing an
    MDL write operation.

    This function simply invokes the file system's corresponding routine, if
    it has one.  It should be the case that this routine is invoked only if
    the PrepareMdlWrite function is supported by the underlying file system,
    and therefore this function will also be supported, but this is not
    assumed by this driver.

Arguments:

    FileObject - Pointer to the file object to complete the MDL write upon.

    FileOffset - Supplies the file offset at which the write took place.

    MdlChain - Pointer to the MDL chain used to perform the write operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE, depending on whether or not it is
    possible to invoke this function on the fast I/O path.

--*/
{
    ASSERT(IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(FileOffset);
    UNREFERENCED_PARAMETER(MdlChain);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, return not supported
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoMdlWriteComplete -> Unsupported as FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject ) ) );


    return FALSE;
}


/*********************************************************************************
        UNIMPLEMENTED FAST IO ROUTINES

        The following four Fast IO routines are for compression on the wire
        which is not yet implemented in NT.

        NOTE:  It is highly recommended that you include these routines (which
               do a pass-through call) so your filter will not need to be
               modified in the future when this functionality is implemented in
               the OS.

        FastIoReadCompressed, FastIoWriteCompressed,
        FastIoMdlReadCompleteCompressed, FastIoMdlWriteCompleteCompressed
**********************************************************************************/



BOOLEAN
fast_io_read_compressed(
	__in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __out_bcount(Length) PVOID Buffer,
    __deref_out PMDL *MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __out_bcount(CompressedDataInfoLength) struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    __in ULONG CompressedDataInfoLength,
    __in PDEVICE_OBJECT DeviceObject)
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for reading compressed
    data from a file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object that will be read.

    FileOffset - Supplies the offset into the file to begin the read operation.

    Length - Specifies the number of bytes to be read from the file.

    LockKey - The key to be used in byte range lock checks.

    Buffer - Pointer to a buffer to receive the compressed data read.

    MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
        chain built to describe the data read.

    IoStatus - Variable to receive the final status of the read operation.

    CompressedDataInfo - A buffer to receive the description of the compressed
        data.

    CompressedDataInfoLength - Specifies the size of the buffer described by
        the CompressedDataInfo parameter.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/
{
    PAGED_CODE();
    ASSERT(IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(FileOffset);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(LockKey);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(MdlChain);
    UNREFERENCED_PARAMETER(CompressedDataInfo);
    UNREFERENCED_PARAMETER(CompressedDataInfoLength);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, fail the operation
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoReadCompressed -> Unsupported FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject ) ) );

    IoStatus->Status = STATUS_INVALID_DEVICE_REQUEST;
    IoStatus->Information = 0;

    return TRUE;
}



BOOLEAN
fast_io_write_compressed(
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __in_bcount(Length) PVOID Buffer,
    __deref_out PMDL *MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __in_bcount(CompressedDataInfoLength) struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    __in ULONG CompressedDataInfoLength,
    __in PDEVICE_OBJECT DeviceObject)
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for writing compressed
    data to a file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object that will be written.

    FileOffset - Supplies the offset into the file to begin the write operation.

    Length - Specifies the number of bytes to be write to the file.

    LockKey - The key to be used in byte range lock checks.

    Buffer - Pointer to the buffer containing the data to be written.

    MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
        chain built to describe the data written.

    IoStatus - Variable to receive the final status of the write operation.

    CompressedDataInfo - A buffer to containing the description of the
        compressed data.

    CompressedDataInfoLength - Specifies the size of the buffer described by
        the CompressedDataInfo parameter.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PAGED_CODE();
    ASSERT(IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(FileOffset);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(LockKey);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(MdlChain);
    UNREFERENCED_PARAMETER(CompressedDataInfo);
    UNREFERENCED_PARAMETER(CompressedDataInfoLength);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, fail the operation
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoWriteCompressed -> Unsupported FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject ) ) );

    IoStatus->Status = STATUS_INVALID_DEVICE_REQUEST;
    IoStatus->Information = 0;

    return TRUE;
}




BOOLEAN
fast_io_mdl_read_complete_compressed(
									__in PFILE_OBJECT FileObject,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject)
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for completing an
    MDL read compressed operation.

    This function simply invokes the file system's corresponding routine, if
    it has one.  It should be the case that this routine is invoked only if
    the read compressed function is supported by the underlying file system,
    and therefore this function will also be supported, but this is not assumed
    by this driver.

Arguments:

    FileObject - Pointer to the file object to complete the compressed read
        upon.

    MdlChain - Pointer to the MDL chain used to perform the read operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE, depending on whether or not it is
    possible to invoke this function on the fast I/O path.

--*/
{
    ASSERT(IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(MdlChain);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, return not supported
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoMdlReadCompleteCompressed -> Unsupported as FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject ) ) );

    return FALSE;
}



BOOLEAN
fast_io_mdl_write_complete_compressed( 
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject)
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for completing a
    write compressed operation.

    This function simply invokes the file system's corresponding routine, if
    it has one.  It should be the case that this routine is invoked only if
    the write compressed function is supported by the underlying file system,
    and therefore this function will also be supported, but this is not assumed
    by this driver.

Arguments:

    FileObject - Pointer to the file object to complete the compressed write
        upon.

    FileOffset - Supplies the file offset at which the file write operation
        began.

    MdlChain - Pointer to the MDL chain used to perform the write operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE, depending on whether or not it is
    possible to invoke this function on the fast I/O path.

--*/
{
    ASSERT(IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(FileOffset);
    UNREFERENCED_PARAMETER(MdlChain);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, return not supported
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoMdlWriteCompleteCompressed -> Unsupported as FastIO call ( FileObject = %p, DeviceObject = %p )\n",
                 FileObject,
                 DeviceObject ) ) );

    return FALSE;
}

BOOLEAN
fast_io_query_open(
    __in PIRP Irp,
    __out PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    __in PDEVICE_OBJECT DeviceObject)
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for opening a file
    and returning network information for it.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    Irp - Pointer to a create IRP that represents this open operation.  It is
        to be used by the file system for common open/create code, but not
        actually completed.

    NetworkInformation - A buffer to receive the information required by the
        network about the file being opened.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/
{
    PAGED_CODE();
    ASSERT(IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));

    UNREFERENCED_PARAMETER(NetworkInformation);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    //  This is our CDO, fail the operation
    //

    log_trace( ( DEBUG_TRACE_CDO_ALL_OPERATIONS | DEBUG_TRACE_CDO_FASTIO_OPERATIONS | DEBUG_TRACE_ERROR,
                ("[Cdo]: CdoFastIoQueryOpen -> Unsupported FastIO call ( Irp = %p, DeviceObject = %p )\n",
                 Irp,
                 DeviceObject ) ) );

    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;

    return TRUE;
}

