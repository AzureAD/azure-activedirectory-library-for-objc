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

// Note that this enum must parallel WebAuthenticationStatus
enum IPAuthenticationStatus
{
    AuthenticationFailed    = 0,
    AuthenticationSucceeded = 1,
    AuthenticationCancelled = 2,
};

@class IPAccessToken;
@class IPAuthorization;

@interface IPAuthenticationResult : NSObject

@property (readonly) enum IPAuthenticationStatus status;

@property (strong, readonly) IPAuthorization *authorization;
@property (strong, readonly) NSString        *error;
@property (strong, readonly) NSString        *errorDescription;

- (id)initWithAuthorization:(IPAuthorization *)authorization;
- (id)initWithError:(NSString *)error description:(NSString *)errorDescription;
- (id)initWithError:(NSString *)error description:(NSString *)errorDescription status:(int)status;

@end
