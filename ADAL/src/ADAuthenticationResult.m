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


#import "ADAuthenticationResult.h"
#import "ADTokenCacheItem.h"
#import "ADAL_Internal.h"

@implementation ADAuthenticationResult

//Explicit @synthesize is needed for the internal category to work:
@synthesize tokenCacheItem = _tokenCacheItem;
@synthesize status = _status;
@synthesize error = _error;
@synthesize multiResourceRefreshToken = _multiResourceRefreshToken;
@synthesize correlationId = _correlationId;
@synthesize extendedLifeTimeToken = _extendedLifeTimeToken;

- (id)init
{
    //Ensure that the default init doesn't work:
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

/* Implements the accessToken property */
- (NSString*)accessToken
{
    return self.tokenCacheItem.accessToken;
}

#define STATUS_ENUM_CASE(_enum) case _enum: return @#_enum;

+ (NSString*)stringForResultStatus:(ADAuthenticationResultStatus)status
{
    switch (status)
    {
            STATUS_ENUM_CASE(AD_FAILED);
            STATUS_ENUM_CASE(AD_SUCCEEDED);
            STATUS_ENUM_CASE(AD_USER_CANCELLED);
    }
}

- (NSString*)description
{
    return [NSString stringWithFormat:@"(error=%@, mrrt=%@, status=%@, item=%@, correlationId=%@)",
            _error, _multiResourceRefreshToken ? @"YES" : @"NO", [ADAuthenticationResult stringForResultStatus:_status], _tokenCacheItem, [_correlationId UUIDString]];
}

@end
