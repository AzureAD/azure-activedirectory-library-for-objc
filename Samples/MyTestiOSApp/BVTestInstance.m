// Created by Boris Vidolov on 1/29/14.
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

@implementation BVTestInstance

-(id) initWithDictionary: (NSDictionary*) contents
{
    self = [super init];
    if (!self)
    {
        return nil;
    }
    self->_authority            = [contents objectForKey:@"Authority"];
    self->_clientId             = [contents objectForKey:@"ClientId"];
    self->_resource             = [contents objectForKey:@"Resource"];
    self->_redirectUri          = [contents objectForKey:@"RedirectUri"];
    self->_userId               = [contents objectForKey:@"UserId"];
    self->_password             = [contents objectForKey:@"Password"];
    self->_validateAuthority    = (BOOL)[contents objectForKey:@"SupportsValidation"];
    
    return self;
}

@end
