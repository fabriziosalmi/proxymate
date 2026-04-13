//
//  AuthHelper.h
//  proxymate
//

#ifndef AuthHelper_h
#define AuthHelper_h

#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <stdio.h>

// MARK: - SSLContext wrappers (deprecated since macOS 10.15, still functional)

/// Create an SSL context for MITM use.
SSLContextRef _Nullable MITMCreateSSLContext(SSLProtocolSide side,
                                              SSLConnectionType connType);

/// Set IO callbacks on an SSL context.
OSStatus MITMSetIOFuncs(SSLContextRef _Nonnull ctx,
                        SSLReadFunc _Nonnull readFunc,
                        SSLWriteFunc _Nonnull writeFunc);

/// Set the connection ref (opaque pointer passed to IO callbacks).
OSStatus MITMSetConnection(SSLContextRef _Nonnull ctx,
                           SSLConnectionRef _Nonnull connection);

/// Set the certificate chain for server-side SSL.
OSStatus MITMSetCertificate(SSLContextRef _Nonnull ctx,
                            CFArrayRef _Nonnull certChain);

/// Perform the SSL handshake.
OSStatus MITMHandshake(SSLContextRef _Nonnull ctx);

/// Read decrypted data from the SSL session.
OSStatus MITMRead(SSLContextRef _Nonnull ctx,
                  void * _Nonnull data,
                  size_t dataLength,
                  size_t * _Nonnull processed);

/// Write data to be encrypted and sent via the SSL session.
OSStatus MITMWrite(SSLContextRef _Nonnull ctx,
                   const void * _Nonnull data,
                   size_t dataLength,
                   size_t * _Nonnull processed);

/// Close and release the SSL context.
OSStatus MITMClose(SSLContextRef _Nonnull ctx);

#endif
