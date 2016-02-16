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

#import "ADTestAppSettings.h"
#import "ADTestInstance.h"

NSString* const sAADTestInstance = @"AAD Instance";

@implementation ADTestAppSettings

-(id) init
{
    self = [super init];
    if (!self)
    {
        return nil;
    }
    
    NSString* path = [[NSBundle mainBundle] pathForResource:@"TestData" ofType:@"plist"];
    if (!path || !path.length)
    {
        return nil;
    }
    
    NSDictionary* all = [NSDictionary dictionaryWithContentsOfFile:path];
    NSMutableDictionary* testAuthorities = [[NSMutableDictionary alloc] initWithCapacity:all.count];
    for(NSDictionary* instanceName in all.allKeys)
    {
        NSDictionary* instanceData = [all objectForKey:instanceName];
        if (!instanceData || ![instanceData isKindOfClass:[NSDictionary class]])
        {
            NSLog(@"Bad data for the instance: '%@'. Contents: %@", instanceName, instanceData);
            continue;
        }
        ADTestInstance* instance = [ADTestInstance getInstance:instanceData];
        [testAuthorities setObject:instance forKey:instanceName];
        break;
    }
    _testAuthorities = testAuthorities;
    return self;
}

- (void)dealloc
{
    [_testAuthorities release];
    _testAuthorities = nil;
    
    [super dealloc];
}

@end
