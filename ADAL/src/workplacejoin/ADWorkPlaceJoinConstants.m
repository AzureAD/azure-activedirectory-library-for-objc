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

NSString* const _defaultSharedGroup                = @"com.microsoft.workplacejoin";
NSString* const privateKeyIdentifier               = @"com.microsoft.workplacejoin.privatekey\0";
NSString* const publicKeyIdentifier                = @"com.microsoft.workplacejoin.publickey\0";
NSString* const upnIdentifier                      = @"com.microsoft.workplacejoin.registeredUserPrincipalName";
NSString* const applicationIdentifierPrefix        = @"applicationIdentifierPrefix";
NSString* const _oauthRedirectUri                  = @"ms-app://windows.immersivecontrolpanel";
NSString* const protectionSpaceDistinguishedName   = @"MS-Organization-Access";
//
//#pragma mark Error strings
NSString* const errorDomain                        = @"com.microsoft.workplacejoin.errordomain";
NSString* const alreadyWorkplaceJoined             = @"This device is already workplace joined";
NSString* const invalidUPN                         = @"Invalid UPN";
NSString* const unabletoWriteToSharedKeychain      = @"Unable to write to shared access group: %@";
NSString* const unabletoReadFromSharedKeychain     = @"Unable to read from shared access group: %@ with error code: %@";
NSString* const duplicateCertificateEntry          = @"Duplicate workplace certificate entry";
NSString* const certificateInstallFailure          = @"Install workplace certificate failure";
NSString* const certificateDeleteFailure           = @"Delete workplace certificate failure";
NSString* const upnMismatchOnJoin                  = @"Original upn: %@ does not match the one we recieved from DRS: %@";
NSString* const wwwAuthenticateHeader              = @"WWW-Authenticate";
NSString* const pKeyAuthUrn                        = @"urn:http-auth:PKeyAuth?";
NSString* const pKeyAuthHeader                     = @"x-ms-PkeyAuth";
NSString* const pKeyAuthHeaderVersion              = @"1.0";
NSString* const pKeyAuthName                       = @"PKeyAuth";

#pragma mark general
NSString* const OID                                = @"1.2.840.113556.1.5.284.2";


