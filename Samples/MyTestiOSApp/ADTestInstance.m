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

#import "ADTestInstance.h"
#import <ADAL/ADAL.h>

@implementation ADTestInstance

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
    static ADTestInstance *instance = nil;
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
