#include <IndustryStandard/Q35MchIch9.h> // ICH9_APM_CNT
#include <Library/BaseLib.h>             // CpuDeadLoop()
#include <Library/DebugLib.h>            // DEBUG()
#include <Library/MmServicesTableLib.h>  // gMmst
#include <Library/SmmServicesTableLib.h> // gSmst
#include <Protocol/MmCpuIo.h>            // EFI_MM_CPU_IO_PROTOCOL
#include <Protocol/SmmCpu.h>             // EFI_SMM_CPU_PROTOCOL

#include "crypto.h"

#define ICH9_APM_CNT_SMM_APP 0x05

#define SMM_APP_MMI_SERVICE 0x01
#define SMM_APP_MMI_UPDATE 0x02

#define KEYLEN 2048
#define RSA_N_LEN 1024
#define RSA_E_LEN 10

#define MAX_FILE_LEN 1024
#define MAX_SIGNATURE_LEN 256

struct SignedFile {
    UINT8 signature[MAX_SIGNATURE_LEN];
    INTN signatureLen;
    UINT8 data[MAX_FILE_LEN];
    INTN dataLen;
} __attribute__((aligned(4096)));

struct PublicKey {
    UINT8 N[RSA_N_LEN];
    INTN NLen;
    UINT8 E[RSA_E_LEN];
    INTN ELen;
} __attribute__((aligned(4096)));

STATIC EFI_HANDLE mDispatchHandle;
STATIC EFI_MM_CPU_IO_PROTOCOL *mMmCpuIo;
STATIC EFI_SMM_CPU_PROTOCOL *mSmmCpu;

STATIC
EFI_STATUS
EFIAPI
HandleService(UINT64 Arg0, UINT64 Arg1) {
    DEBUG((DEBUG_INFO, "smi: serving\n"));
    // TODO: fake a service here
    return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
HandleUpdate(UINT64 Arg0, UINT64 Arg1) {
    DEBUG((DEBUG_INFO, "smi: updating\n"));
    // TODO: do service update here
    BOOLEAN result;
    struct SignedFile *file = (struct SignedFile*)Arg0;

    // TODO: change this
    struct PublicKey *publicKey = (struct PublicKey*)Arg1;
    // UINT8 RSA_N[RSA_N_LEN];
    // UINT8 RSA_E[RSA_E_LEN];
    
    // char package[32];
    // UINT8 signature[256];
    // result = VerifyPackage((VOID*)package, 32, signature, 256, RSA_N, rsa_n_len, RSA_E, rsa_e_len);
    result = VerifyPackage((VOID*)file->data, file->dataLen, file->signature, file->signatureLen, publicKey->N, publicKey->NLen, publicKey->E, publicKey->ELen);
    DEBUG((DEBUG_INFO, "VerifyPackage result: %d\n", result));

    return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
ReadSaveRegister(IN EFI_MM_SAVE_STATE_REGISTER Register, OUT UINT64 *Value) {
    EFI_STATUS Status;
    UINTN CpuIndex;

    // FIXME: force use single core
    CpuIndex = 0;

    Status = mSmmCpu->ReadSaveState(
        mSmmCpu, sizeof(UINT64), Register, CpuIndex, Value
    );

    if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, "smi: failed to read Rdi\n"));
        return Status;
    }
    return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
SmmAppMmi(
    IN EFI_HANDLE DispatchHandle, IN CONST VOID *Context OPTIONAL,
    IN OUT VOID *CommBuffer OPTIONAL, IN OUT UINTN *CommBufferSize OPTIONAL
) {
    EFI_STATUS Status;
    UINT8 ApmControl;
    UINT64 Rdi;
    UINT64 Rsi;
    UINT64 R10;

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

    Status = ReadSaveRegister(EFI_SMM_SAVE_STATE_REGISTER_RDI, &Rdi);
    if (EFI_ERROR(Status)) {
        goto Fatal;
    }
    Status = ReadSaveRegister(EFI_SMM_SAVE_STATE_REGISTER_RSI, &Rsi);
    if (EFI_ERROR(Status)) {
        goto Fatal;
    }
    Status = ReadSaveRegister(EFI_SMM_SAVE_STATE_REGISTER_R10, &R10);
    if (EFI_ERROR(Status)) {
        goto Fatal;
    }

    switch (Rdi) {
    case SMM_APP_MMI_SERVICE:
        Status = HandleService(Rsi, R10);
        if (EFI_ERROR(Status)) {
            goto Fatal;
        }
        break;
    case SMM_APP_MMI_UPDATE:
        Status = HandleUpdate(Rsi, R10);
        if (EFI_ERROR(Status)) {
            goto Fatal;
        }
        break;
    default:
        DEBUG((DEBUG_INFO, "smi: invalid smm app mmi id\n"));
        break;
    }

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

    // Locate the SMM CPU Protocol
    Status = gSmst->SmmLocateProtocol(
        &gEfiSmmCpuProtocolGuid, NULL, (VOID **)&mSmmCpu
    );
    if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, "%a: locate SmmCpu: %r\n", __func__, Status));
        goto Fatal;
    }

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
