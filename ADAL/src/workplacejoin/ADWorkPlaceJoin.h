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
#import "ADRegistrationInformation.h"

@class ADWorkPlaceJoin;

@interface ADWorkPlaceJoin : NSObject
{
    NSString* _sharedGroup;
}

/// Returns a static instance of the WorkPlaceJoin class which can then be used
/// to perform a join, leave, verify if the device is joined and get the
/// registered UPN in the event the device is joined.
+ (ADWorkPlaceJoin*) WorkPlaceJoinManager;

/*! Represents the shared access group used by this api. */
@property (readwrite, retain) NSString* sharedGroup;

/// Will look at the shared application keychain in search for a certificate
/// Certificate found returns true
/// Certificate not found returns false
- (BOOL)isWorkPlaceJoined;

- (ADRegistrationInformation*) getRegistrationInformation;

@end

