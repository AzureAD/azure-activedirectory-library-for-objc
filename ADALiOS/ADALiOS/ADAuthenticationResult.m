// Created by Boris Vidolov on 10/10/13.
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


#import "ADAuthenticationResult.h"
#import "ADALiOS.h"

@implementation ADAuthenticationResult

//Explicit @synthesize is needed for the internal category to work:
@synthesize accessTokenType = _accessTokenType;
@synthesize accessToken = _accessToken;
@synthesize refreshToken = _refreshToken;
@synthesize expiresOn = _expiresOn;
@synthesize status = _status;
@synthesize multiResourceRefreshToken = _multiResourceRefreshToken;
@synthesize error = _error;
@synthesize tenantId = _tenantId;
@synthesize userInformation = _userInformation;

-(id) init
{
    //Ensure that the default init doesn't work:
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}


@end
