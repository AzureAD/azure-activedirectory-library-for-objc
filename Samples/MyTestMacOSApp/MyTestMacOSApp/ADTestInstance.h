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

//Identifies one testable instance, e.g.
//an AAD tenant with suitable user name password
//and a client accessing a resource
@interface ADTestInstance : NSObject
{
//@private:
    NSString *_authority;
    NSString *_clientId;
    NSString *_resource;
    NSString *_redirectUri;
    NSString *_userId;
    NSString *_password;
    NSString *_extraQueryParameters;
    BOOL      _validateAuthority;
}

-(id) initWithDictionary: (NSDictionary*) contents;

@property (retain) NSString* authority;
@property BOOL      validateAuthority;
@property (retain) NSString* clientId;
@property (retain) NSString* resource;
@property (retain) NSString* redirectUri;
@property (retain) NSString* userId;
@property (retain) NSString* password;//used for automation in the tests
@property (retain) NSString* extraQueryParameters;//Typically null and set by tests when needed

@end
