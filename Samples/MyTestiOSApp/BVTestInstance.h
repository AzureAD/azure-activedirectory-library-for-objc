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

#import <Foundation/Foundation.h>

//Identifies one testable instance, e.g.
//an AAD tenant with suitable user name password
//and a client accessing a resource
@interface BVTestInstance : NSObject

-(id) initWithDictionary: (NSDictionary*) contents;

@property NSString* authority;
@property BOOL      validateAuthority;
@property NSString* clientId;
@property NSString* resource;
@property NSString* redirectUri;
@property NSString* userId;
@property NSString* password;//used for automation in the tests
@property NSString* extraQueryParameters;//Typically null and set by tests when needed

@end
