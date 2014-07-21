//
//  WorkPlaceJoin.h
//  WorkPlaceJoin
//
//  Created by Roger Toma on 3/6/14.
//  Copyright (c) 2014 Roger Toma. All rights reserved.
//

#import <Foundation/Foundation.h>


@class WorkPlaceJoin;

/// WorkPlaceJoin Delegates
/// We have 2 delegates one for success and one for failure
@protocol WorkPlaceJoinDelegate

/// In the event an error ocurred during the discovery, authentication, the
/// didFailJoinWithError delegate is triggered providing the error encountered
/// Errors as a direct results of this API contain error code 200 @domain
/// "WorkPlace Join"
- (void)workplaceClient:(WorkPlaceJoin*)workplaceClient
   didFailJoinWithError:(NSError*)error;

/// If the calling application has set this delegate all logging will go through
/// the delegate.  If it is not set all logging will happen to [WorkPlaceJoinUtil WorkPlaceJoinUtilManager] Log:.
- (void)workplaceClient:(WorkPlaceJoin*)workplaceClient
   logMessage:(NSString*)logMessage;

@end

/*! The completion block declaration for leave */
typedef void(^WorkplaceJoinLeaveCallback)(NSError*);

@interface WorkPlaceJoin : NSObject <NSURLConnectionDelegate>

@property (weak, nonatomic) id <WorkPlaceJoinDelegate> delegate;

/*! Represents the shared access group used by this api. */
@property (readwrite) NSString* sharedGroup;

/// Returns a static instance of the WorkPlaceJoin class which can then be used
/// to perform a join, leave, verify if the device is joined and get the
/// registered UPN in the event the device is joined.
+ (WorkPlaceJoin*) WorkPlaceJoinManager;

/// Will look at the shared application keychain in search for a certificate
/// Certificate found returns true
/// Certificate not found returns false
- (BOOL)isWorkPlaceJoined;


@end

