//
//  AuthHelper.c
//  proxymate
//
//  C wrappers for deprecated Security framework APIs that Swift refuses
//  to call directly.
//

#include "AuthHelper.h"
#include <Security/Security.h>
#include <Security/SecureTransport.h>

// MARK: - AuthorizationExecuteWithPrivileges wrapper

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

OSStatus AuthHelperExecute(AuthorizationRef auth,
                           const char *tool,
                           char *const *arguments,
                           FILE **pipe) {
    return AuthorizationExecuteWithPrivileges(auth, tool, kAuthorizationFlagDefaults, arguments, pipe);
}

// MARK: - SSLContext wrappers for MITM

SSLContextRef MITMCreateSSLContext(SSLProtocolSide side,
                                   SSLConnectionType connType) {
    return SSLCreateContext(NULL, side, connType);
}

OSStatus MITMSetIOFuncs(SSLContextRef ctx,
                        SSLReadFunc readFunc,
                        SSLWriteFunc writeFunc) {
    return SSLSetIOFuncs(ctx, readFunc, writeFunc);
}

OSStatus MITMSetConnection(SSLContextRef ctx,
                           SSLConnectionRef connection) {
    return SSLSetConnection(ctx, connection);
}

OSStatus MITMSetCertificate(SSLContextRef ctx,
                            CFArrayRef certChain) {
    return SSLSetCertificate(ctx, certChain);
}

OSStatus MITMHandshake(SSLContextRef ctx) {
    return SSLHandshake(ctx);
}

OSStatus MITMRead(SSLContextRef ctx,
                  void *data,
                  size_t dataLength,
                  size_t *processed) {
    return SSLRead(ctx, data, dataLength, processed);
}

OSStatus MITMWrite(SSLContextRef ctx,
                   const void *data,
                   size_t dataLength,
                   size_t *processed) {
    return SSLWrite(ctx, data, dataLength, processed);
}

OSStatus MITMClose(SSLContextRef ctx) {
    OSStatus status = SSLClose(ctx);
    CFRelease(ctx);
    return status;
}

#pragma clang diagnostic pop
