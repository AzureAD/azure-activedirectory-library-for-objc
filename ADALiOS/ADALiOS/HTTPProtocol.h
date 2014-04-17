// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

#pragma once

//Intercepts HTTPS protocol for the application in order to allow
//TLS with client-authentication. Such authentication is the base
//of workplace joined devices. The class is not thread-safe.
@interface HTTPProtocol : NSURLProtocol <NSURLConnectionDelegate, NSURLConnectionDataDelegate>

/* Sets the identity to be used for the client TLS authentication (required with workplace join). */
+(void) setIdentity:(SecIdentityRef) identity;

/* Sets the certificate to be used for the client TLS authentication (required with workplace join). */
+(void) setCertificate:(SecCertificateRef) certificate;

/* Releases the identity data. Typically called at the end of the client TLS session. */
+(void) clearCertificate;

/* Releases the certificate data. Typically called at the end of the client TLS session. */
+(void) clearIdentity;

@end
