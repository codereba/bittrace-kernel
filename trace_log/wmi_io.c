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
#include "wmi_io.h"

WMILIB_CONTEXT wmilibContext = { 0 };

NTSTATUS trace_log_wmi(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )
{
    PIO_STACK_LOCATION      irpSp;
    NTSTATUS status;
    PWMILIB_CONTEXT wmilibContext;
    SYSCTL_IRP_DISPOSITION disposition; 

    PAGED_CODE();

    DebugPrint((2, "DiskPerfWmi: DeviceObject %X Irp %X\n",
                    DeviceObject, Irp));
    wmilibContext = &WmilibContext;
    if (wmilibContext->GuidCount == 0)  // wmilibContext is not valid
    {
        DebugPrint((3, "DiskPerfWmi: WmilibContext invalid"));
        return DiskPerfSendToNextDriver(DeviceObject, Irp);
    }

    irpSp = IoGetCurrentIrpStackLocation(Irp);

        DebugPrint((3, "DiskPerfWmi: Calling WmiSystemControl\n"));
        status = WmiSystemControl(wmilibContext,
                                    DeviceObject,
                                    Irp,
                                    &disposition);
        switch (disposition)
        {
            case IrpProcessed:
            {
                break;
            }

            case IrpNotCompleted:
            {
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                break;
            }

//          case IrpForward:
//          case IrpNotWmi:
            default:
            {
                status = DiskPerfSendToNextDriver(DeviceObject, Irp);
                break;
            }
        }
    return(status);

}