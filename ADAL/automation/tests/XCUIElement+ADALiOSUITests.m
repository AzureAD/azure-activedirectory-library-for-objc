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

#import "XCUIElement+ADALiOSUITests.h"

@implementation XCUIElement (ADALiOSUITests)

- (void)clearText
{
    if (![self.value isKindOfClass:NSString.class])
    {
        return;
    }
    
    [self pressForDuration:0.5];
    
    NSString *string = (NSString *)self.value;
    string = [@"" stringByPaddingToLength:string.length withString:XCUIKeyboardKeyDelete startingAtIndex:0];
    
    [self typeText:string];
}

- (void)selectAll:(XCUIApplication *)app
{
    [self pressForDuration:0.5];
    [app.menuItems[@"Select All"] tap];
}

- (void)forceTap
{
    if ([[[UIDevice currentDevice] systemVersion] floatValue] >= 11.0f)
    {
        [self tap];
    }
    else
    {
        __auto_type coordinate = [self coordinateWithNormalizedOffset:CGVectorMake(0, 0)];
        [coordinate tap];
    }
}

@end