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

extern NSString* const sAADTestInstance;

//A helper class for reading the test authorities, usernames, etc.
//Reads the authorities from the TestData.plist file.
@interface ADTestAppSettings : NSObject
{
    NSMutableDictionary *_testAuthorities;
}


//Returns a dictionary with the name of the test instances as keys.
//The values are instances of BVTestInstance class.
@property (readonly) NSDictionary* testAuthorities;

//In case of code coverage build, stores the code coverage data.
//The method does nothing in the other configurations.
-(void) flushCodeCoverage;

@end
