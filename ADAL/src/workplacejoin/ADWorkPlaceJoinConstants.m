// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "ADWorkPlaceJoinConstants.h"

//NSString *const AD_TELEMETRY_EVENT_API_EVENT              = @"Microsoft.ADAL.api_event";

NSString* const kADALDefaultSharedGroup                = @"com.microsoft.workplacejoin";
NSString* const kADALPrivateKeyIdentifier               = @"com.microsoft.workplacejoin.privatekey\0";
NSString* const kADALPublicKeyIdentifier                = @"com.microsoft.workplacejoin.publickey\0";
NSString* const kADALUpnIdentifier                      = @"com.microsoft.workplacejoin.registeredUserPrincipalName";
NSString* const kADALApplicationIdentifierPrefix        = @"applicationIdentifierPrefix";
NSString* const kADALOauthRedirectUri                  = @"ms-app://windows.immersivecontrolpanel";
NSString* const kADALProtectionSpaceDistinguishedName   = @"MS-Organization-Access";
//
//#pragma mark Error strings
NSString* const kADALErrorDomain                        = @"com.microsoft.workplacejoin.errordomain";
NSString* const kADALAlreadyWorkplaceJoined             = @"This device is already workplace joined";
NSString* const kADALInvalidUPN                         = @"Invalid UPN";
NSString* const kADALUnabletoWriteToSharedKeychain      = @"Unable to write to shared access group: %@";
NSString* const kADALUnabletoReadFromSharedKeychain     = @"Unable to read from shared access group: %@ with error code: %@";
NSString* const kADALDuplicateCertificateEntry          = @"Duplicate workplace certificate entry";
NSString* const kADALCertificateInstallFailure          = @"Install workplace certificate failure";
NSString* const kADALCertificateDeleteFailure           = @"Delete workplace certificate failure";
NSString* const kADALUpnMismatchOnJoin                  = @"Original upn: %@ does not match the one we recieved from DRS: %@";
NSString* const kADALWwwAuthenticateHeader              = @"WWW-Authenticate";
NSString* const kADALPKeyAuthUrn                        = @"urn:http-auth:PKeyAuth?";
NSString* const kADALPKeyAuthHeader                     = @"x-ms-PkeyAuth";
NSString* const kADALPKeyAuthHeaderVersion              = @"1.0";
NSString* const kADALPKeyAuthName                       = @"PKeyAuth";

#pragma mark general
NSString* const kADALOID                                = @"1.2.840.113556.1.5.284.2";


