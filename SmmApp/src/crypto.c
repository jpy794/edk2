#include "crypto.h"

// DEBUG print buffer
void print_buffer(const unsigned char *buffer, UINTN len) {
    for (UINTN i = 0; i < len; i++) {
        // printf("%02x", buffer[i]);
        DEBUG((DEBUG_INFO, "%02x", buffer[i]));
    }
    DEBUG((DEBUG_INFO, "\n"));
}

BOOLEAN VerifyPackage(VOID* package, UINTN packageSize, CONST UINT8  * Signature, UINTN SignatureSize, CONST UINT8 * publicKeyN, UINTN publicKeySizeN, CONST UINT8 * publicKeyE, UINTN publicKeySizeE) {
    EFI_STATUS Status;
    BOOLEAN result;
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

    // Hash256
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
    // DEBUG((DEBUG_INFO, "PACKAGE \n"));
    // print_buffer(package, packageSize);
    // DEBUG((DEBUG_INFO, "PACKAGE SIZE: %d\n", packageSize));
    // DEBUG((DEBUG_INFO, "RsaPkcs1Verify\n"));
    // print_buffer(Hash, HashSize);
    // DEBUG((DEBUG_INFO, "HASH SIZE: %d\n", HashSize));
    // print_buffer(Signature, SignatureSize);
    // DEBUG((DEBUG_INFO, "SIGNATURE SIZE: %d\n", SignatureSize));
    // print_buffer(publicKeyN, publicKeySizeN);
    // DEBUG((DEBUG_INFO, "key N SIZE: %d\n", publicKeySizeN));
    // print_buffer(publicKeyE, publicKeySizeE);
    // DEBUG((DEBUG_INFO, "key E SIZE: %d\n", publicKeySizeE));
    // result = RsaPkcs1Verify(RsaContext1, Hash, HashSize, Signature, SignatureSize);
    result = RsaPkcs1Verify(RsaContext1, package, packageSize, Signature, SignatureSize);
    return result;
}
