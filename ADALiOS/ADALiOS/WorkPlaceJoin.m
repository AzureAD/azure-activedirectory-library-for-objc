//
//  WorkPlaceJoin.m
//  WorkPlaceJoin
//
//  Created by Roger Toma on 3/6/14.
//  Copyright (c) 2014 Roger Toma. All rights reserved.
//

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
    SecCertificateRef certificate = NULL;
    RegistrationInformation *userRegInfo = [[WorkPlaceJoinUtil WorkPlaceJoinUtilManager]  getRegistrationInformation:_sharedGroup error:nil];
    
    certificate = [userRegInfo certificate];
    
    return (certificate != NULL);
}

@end
