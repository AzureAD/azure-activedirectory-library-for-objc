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

#import "BVTestInstance.h"
#import <ADALiOS/ADAL.h>

@implementation BVTestInstance

const NSString* AUTHORITY = @"Authority";
const NSString* CLIENT_ID = @"ClientId";
const NSString* RESOURCE = @"Resource";
const NSString* REDIRECT_URI = @"RedirectUri";
const NSString* USER_ID= @"UserId";
const NSString* PASSWORD= @"Password";
const NSString* SUPPORTS_VALIDATION= @"SupportsValidation";
const NSString* EXTRA_QUERYPARAMETERS= @"ExtraQueryParameters";
const NSString* ENABLE_FULLSCREEN= @"FullScreen";
const NSString* REQUEST_TIMEOUT = @"RequestTimeout";

+ (id) getInstance: (NSDictionary*) contents
{
    static BVTestInstance *instance = nil;
    static dispatch_once_t onceToken;
    
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
        instance->_originalContents = contents;
        [instance loadProperties:instance->_originalContents];
    });
    
    return instance;
}

- (void) loadProperties: (NSDictionary*) contents
{
    self->_authority            = [contents objectForKey:AUTHORITY];
    self->_clientId             = [contents objectForKey:CLIENT_ID];
    self->_resource             = [contents objectForKey:RESOURCE];
    self->_redirectUri          = [contents objectForKey:REDIRECT_URI];
    self->_userId               = [contents objectForKey:USER_ID];
    self->_password             = [contents objectForKey:PASSWORD];
    NSString* va = [contents objectForKey:SUPPORTS_VALIDATION];
    self->_validateAuthority    = [va boolValue];
    self->_extraQueryParameters = [contents objectForKey:EXTRA_QUERYPARAMETERS];
    
    va = [contents objectForKey:ENABLE_FULLSCREEN];
    if (va) {
        self->_enableFullScreen    = [va boolValue];
    }else{
        self->_enableFullScreen   = [[ADAuthenticationSettings sharedInstance] enableFullScreen];
    }
    
    va = [contents objectForKey:REQUEST_TIMEOUT];
    if (va) {
        self->_requestTimeout    = [va intValue];
    }else{
        self->_requestTimeout   = [[ADAuthenticationSettings sharedInstance] requestTimeOut];
    }
}


-(void) updateValues: (NSDictionary*) contents
{
    [self loadProperties:contents];
}


-(void) restoreDefaults
{
    [self loadProperties:_originalContents];
}

@end
