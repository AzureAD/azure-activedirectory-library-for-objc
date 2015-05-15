//
//  ADLogHandler.h
//  MyTestADBrokerApp
//
//  Created by Kanishk Panwar on 5/14/15.
//  Copyright (c) 2015 Microsoft Corp. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WorkplacejoinAPI/WorkplaceJoin.h>

@interface ADLogHandler : NSObject<WorkPlaceJoinLoggerDelegate>

+(id) configureLoggers;

@end
