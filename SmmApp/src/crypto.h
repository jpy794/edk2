#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <Library/BaseCryptLib.h>
#include <Library/DebugLib.h>
// #include <Library/HashLib.h>

BOOLEAN VerifyPackage(VOID* package, UINTN packageSize, CONST UINT8  * Signature, UINTN SignatureSize, CONST UINT8 * publicKeyN, UINTN publicKeySizeN, CONST UINT8 * publicKeyE, UINTN publicKeySizeE);

#endif
