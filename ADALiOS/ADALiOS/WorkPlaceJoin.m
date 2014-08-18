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

#import "WorkPlaceJoin.h"
#import "WorkPlaceJoinUtil.h"
#import "WorkPlaceJoinConstants.h"
#import "RegistrationInformation.h"
#import <UIKit/UIKit.h>
#import <MessageUI/MessageUI.h>


@implementation WorkPlaceJoin

NSArray *_upnParts;
NSString *_userPrincipalName;
UIViewController * _callingViewController;
WorkplaceJoinLeaveCallback leaveCompletionBlock;

static WorkPlaceJoin* wpjManager;

NSString* _oauthClientId;

#pragma mark - Public Methods

+ (WorkPlaceJoin*) WorkPlaceJoinManager
{
    if (!wpjManager)
    {
        wpjManager = [[self alloc] init];
    }
    
    return wpjManager;
}

- (id)init {
    self = [super init];
    if (self) {
        [WorkPlaceJoinUtil WorkPlaceJoinUtilManager].workplaceJoin = self;
        _sharedGroup = [NSString stringWithFormat:@"%@.%@", [[WorkPlaceJoinUtil WorkPlaceJoinUtilManager]  getApplicationIdentifierPrefix], _defaultSharedGroup];
    }
    return self;
}

- (BOOL)isWorkPlaceJoined
{
    [[WorkPlaceJoinUtil WorkPlaceJoinUtilManager]  Log:@"Is workplace joined"];
    RegistrationInformation *userRegInfo = [self getRegistrationInformation];
    BOOL certExists = [userRegInfo certificate] != NULL;
    [userRegInfo releaseData];
    return certExists;
}

- (RegistrationInformation*) getRegistrationInformation {
    return [[WorkPlaceJoinUtil WorkPlaceJoinUtilManager]  getRegistrationInformation:_sharedGroup error:nil];
}

@end
