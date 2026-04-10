//
//  AuthHelper.c
//  proxymate
//
//  Thin C wrapper around AuthorizationExecuteWithPrivileges. The function
//  is deprecated since 10.7 and Swift refuses to call APIs deprecated before
//  10.9, so we wrap it in a non-deprecated C function.
//

#include "AuthHelper.h"
#include <Security/Security.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

OSStatus AuthHelperExecute(AuthorizationRef auth,
                           const char *tool,
                           char *const *arguments,
                           FILE **pipe) {
    return AuthorizationExecuteWithPrivileges(auth, tool, kAuthorizationFlagDefaults, arguments, pipe);
}

#pragma clang diagnostic pop
