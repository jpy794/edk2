#include "crypto.h"


BOOLEAN VerifyPackage(VOID* package, UINTN packageSize, CONST UINT8  * Signature, UINTN SignatureSize, CONST UINT8 * publicKeyN, UINTN publicKeySizeN, CONST UINT8 * publicKeyE, UINTN publicKeySizeE) {
    EFI_STATUS Status;
    // VOID* Context;
    UINTN HashSize;
    UINT8 Hash[32];
    // EFI_BOOT_SERVICES* gBS;

    // if (packageSize < 32 || SignatureSize < 256 || publicKeySize < 32) {
    //     DEBUG((DEBUG_ERROR, "Invalid package, signature or public key size\n"));
    //     return FALSE;
    // }

    // Status = gBS->LocateProtocol(&gEfiHashProtocolGuid, NULL, &Context);
    // if (EFI_ERROR(Status)) {
    //     DEBUG((DEBUG_ERROR, "LocateProtocol failed\n"));
    //     return FALSE;
    // }

    HashSize = 32;
    Status = Sha256HashAll(package, packageSize, Hash);
    if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, "Sha256HashAll failed\n"));
        return FALSE;
    }


    VOID* RsaContext1 = RsaNew();
    if (RsaContext1 == NULL) {
        DEBUG((DEBUG_ERROR, "RsaNew failed\n"));
        return FALSE;
    }
    if (
        (! RsaSetKey(RsaContext1, RsaKeyN, publicKeyN, publicKeySizeN)) || 
        (! RsaSetKey(RsaContext1, RsaKeyE, publicKeyE, publicKeySizeE))
    ) {
        DEBUG((DEBUG_ERROR, "RsaSetKey failed\n"));
        return FALSE;
    }
// BOOLEAN
// EFIAPI
// RsaPkcs1Verify (
//   IN  VOID         *RsaContext,
//   IN  CONST UINT8  *MessageHash,
//   IN  UINTN        HashSize,
//   IN  CONST UINT8  *Signature,
//   IN  UINTN        SigSize
//   );
    Status = RsaPkcs1Verify(RsaContext1, Hash, HashSize, Signature, SignatureSize);
    if (!EFI_ERROR(Status)) {
        return TRUE;
    }

    return FALSE;
}
