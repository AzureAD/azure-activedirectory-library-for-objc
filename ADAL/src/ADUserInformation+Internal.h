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

#import <Foundation/Foundation.h>
#import "ADUserInformation.h"

extern NSString *const ID_TOKEN_SUBJECT;
extern NSString *const ID_TOKEN_TENANTID;
extern NSString *const ID_TOKEN_UPN;
extern NSString *const ID_TOKEN_GIVEN_NAME;
extern NSString *const ID_TOKEN_FAMILY_NAME;
extern NSString *const ID_TOKEN_UNIQUE_NAME;
extern NSString *const ID_TOKEN_EMAIL;
extern NSString *const ID_TOKEN_IDENTITY_PROVIDER;
extern NSString *const ID_TOKEN_TYPE;
extern NSString *const ID_TOKEN_JWT_TYPE;
extern NSString *const ID_TOKEN_OBJECT_ID;
extern NSString *const ID_TOKEN_GUEST_ID;

@interface ADUserInformation (Internal)

/*! Factory method to extract user information from the AAD id_token parameter.
 @param idToken The contents of the id_token parameter, as passed by the server.
 @param homeAccountId Unique AAD account identifier across tenants based on user's home OID/home tenantId.
 */
+ (ADUserInformation *)userInformationWithIdToken:(NSString *)idToken
                                    homeAccountId:(NSString *)homeAccountId
                                            error:(ADAuthenticationError * __autoreleasing *)error;

- (id)initWithIdToken:(NSString *)idToken
        homeAccountId:(NSString *)homeAccountId
                error:(ADAuthenticationError * __autoreleasing *)error;

+ (ADAuthenticationError *)invalidIdTokenError;

@end
