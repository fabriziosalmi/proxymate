//
//  AuthHelper.h
//  proxymate
//

#ifndef AuthHelper_h
#define AuthHelper_h

#include <Security/Security.h>
#include <stdio.h>

/// Wrapper around the deprecated AuthorizationExecuteWithPrivileges.
/// Runs `tool` with `arguments` as root using the given authorization.
/// If `pipe` is non-NULL, it receives a FILE* for the child's stdout.
OSStatus AuthHelperExecute(AuthorizationRef _Nonnull auth,
                           const char * _Nonnull tool,
                           char * _Nullable const * _Nonnull arguments,
                           FILE * _Nullable * _Nullable pipe);

#endif
