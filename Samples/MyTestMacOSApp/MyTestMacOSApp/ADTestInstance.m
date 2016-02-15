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

@implementation ADTestInstance

@synthesize authority = _authority;
@synthesize clientId  = _clientId;
@synthesize resource  = _resource;
@synthesize redirectUri = _redirectUri;
@synthesize userId = _userId;
@synthesize validateAuthority = _validateAuthority;
@synthesize extraQueryParameters = _extraQueryParameters;
@synthesize password = _password;


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
    NSString* va = [contents objectForKey:@"SupportsValidation"];
    self->_validateAuthority    = [va boolValue];
    self->_extraQueryParameters = [contents objectForKey:@"extraQueryParameters"];
    
    return self;
}

@end
