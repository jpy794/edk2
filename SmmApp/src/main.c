#include <IndustryStandard/Q35MchIch9.h> // ICH9_APM_CNT
#include <Library/BaseLib.h>             // CpuDeadLoop()
#include <Library/DebugLib.h>            // DEBUG()
#include <Library/MmServicesTableLib.h>  // gMmst
#include <Protocol/MmCpuIo.h>            // EFI_MM_CPU_IO_PROTOCOL

#define ICH9_APM_CNT_SMM_APP 0x05

STATIC EFI_HANDLE mDispatchHandle;
STATIC EFI_MM_CPU_IO_PROTOCOL *mMmCpuIo;

STATIC
EFI_STATUS
EFIAPI
SmmAppMmi(
    IN EFI_HANDLE DispatchHandle, IN CONST VOID *Context OPTIONAL,
    IN OUT VOID *CommBuffer OPTIONAL, IN OUT UINTN *CommBufferSize OPTIONAL
) {
    EFI_STATUS Status;
    UINT8 ApmControl;

    //
    // Assert that we are entering this function due to our root MMI handler
    // registration.
    //
    ASSERT(DispatchHandle == mDispatchHandle);
    //
    // When MmiManage() is invoked to process root MMI handlers, the caller (the
    // MM Core) is expected to pass in a NULL Context. MmiManage() then passes
    // the same NULL Context to individual handlers.
    //
    ASSERT(Context == NULL);
    //
    // Read the MMI command value from the APM Control Port, to see if this is
    // an MMI we should care about.
    //
    Status =
        mMmCpuIo->Io.Read(mMmCpuIo, MM_IO_UINT8, ICH9_APM_CNT, 1, &ApmControl);
    if (EFI_ERROR(Status)) {
        DEBUG(
            (DEBUG_ERROR, "%a: failed to read ICH9_APM_CNT: %r\n", __func__,
             Status)
        );
        //
        // We couldn't even determine if the MMI was for us or not.
        //
        goto Fatal;
    }

    if (ApmControl != ICH9_APM_CNT_SMM_APP) {
        //
        // The MMI is not for us.
        //
        return EFI_WARN_INTERRUPT_SOURCE_QUIESCED;
    }

    DEBUG((DEBUG_INFO, "%a(): smi\n", __FUNCTION__));

    //
    // We've handled this MMI.
    //
    return EFI_SUCCESS;

Fatal:
    ASSERT(FALSE);
    CpuDeadLoop();
    //
    // We couldn't handle this MMI.
    //
    return EFI_INTERRUPT_PENDING;
}

EFI_STATUS EFIAPI
SmmAppMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
    EFI_STATUS Status;

    DEBUG((DEBUG_INFO, "%a(): enter\n", __FUNCTION__));

    //
    // Errors from here on are fatal; we cannot allow the boot to proceed if we
    // can't set up this driver to handle CPU hotplug.
    //
    // First, collect the protocols needed later. All of these protocols are
    // listed in our module DEPEX.
    //
    Status = gMmst->MmLocateProtocol(
        &gEfiMmCpuIoProtocolGuid, NULL /* Registration */, (VOID **)&mMmCpuIo
    );
    if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, "%a: locate MmCpuIo: %r\n", __func__, Status));
        goto Fatal;
    }

    Status = gMmst->MmiHandlerRegister(
        SmmAppMmi,
        NULL, // HandlerType: root MMI handler
        &mDispatchHandle
    );

    DEBUG((DEBUG_INFO, "%a(): exit\n", __FUNCTION__));

    return EFI_SUCCESS;

Fatal:
    ASSERT(FALSE);
    CpuDeadLoop();
    return Status;
}
