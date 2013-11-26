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

#import "IPConstants.h"
#import "IPAuthorization.h"
#import "IPAuthorization.h"

#import "IPAuthenticationResult.h"

#import "NSURLExtensions.h"

@interface IPAuthenticationResult ( )
@end

@implementation IPAuthenticationResult
{
}

- (id)init
{
    NSAssert( false, @"IPAuthenticationResult init should never be called" );
    
    self = nil;
    
    return self;
}

- (id)initWithAuthorization:(IPAuthorization *)authorization
{
    if ( !authorization )
        return nil;
    
    if ( ( self = [super init] ) != nil )
    {
        _status        = AuthenticationSucceeded;
        _authorization = authorization;
    }
    
    return self;
}

- (id)initWithError:(NSString *)error description:(NSString *)errorDescription
{
    return [self initWithError:error
                   description:errorDescription
                        status:AuthenticationFailed];
}

- (id)initWithError:(NSString *)error description:(NSString *)errorDescription status:(int)status
{
    if ( ( self = [super init] ) != nil )
    {
        _status           = status;
        _authorization    = nil;
        _error            = [error copy];
        _errorDescription = [errorDescription copy];
    }
    
    return self;
}

@end
