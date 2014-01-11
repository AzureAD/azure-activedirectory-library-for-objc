//
//  MyTestiOSAppTests.m
//  MyTestiOSAppTests
//
//  Created by Boris Vidolov on 9/13/13.
//  Copyright (c) 2013 MS. All rights reserved.
//

#import <XCTest/XCTest.h>
#import <ADALiOS/ADAuthenticationContext.h>
#import "BVTestAppDelegate.h"

@interface MyTestiOSAppTests : XCTestCase

@end

@implementation MyTestiOSAppTests

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testExample
{
    //TBD
}

- (void)testExample2
{
//    NSString* authority = @"https://login.windows.net/msopentechbv.onmicrosoft.com";//OmerCan: params.authority
//    NSString* clientId = @"c3c7f5e5-7153-44d4-90e6-329686d48d76";//OmerCan: @"c4acbce5-b2ed-4dc5-a1b9-c95af96c0277"
//    NSString* resourceString = @"http://localhost/TodoListService";
//    NSString* redirectUri = @"http://todolistclient/";//OmerCan: @"https://omercantest.onmicrosoft.adal/hello"
////    [weakSelf setStatus:[NSString stringWithFormat:@"Authority: %@", params.authority]];
//    ADAuthenticationError* error;
//    ADAuthenticationContext* context = [ADAuthenticationContext contextWithAuthority:authority error:&error];
//    XCTAssertNotNil(context);
//    [context.tokenCacheStore removeAll];//Clear the cache12
//    __block ADAuthenticationResult* localResult;
//    
//    [context acquireToken:resourceString clientId:clientId
//              redirectUri:[NSURL URLWithString:redirectUri]
//                   userId:@"boris@msopentechbv.onmicrosoft.com"
//          completionBlock:^(ADAuthenticationResult *result)
//    {
//        localResult = result;
//    }];
//    NSDate* firstTimeOut = [NSDate dateWithTimeIntervalSinceNow:3];//Waits for 10 seconds.
//    while (!localResult && [[NSDate dateWithTimeIntervalSinceNow:0] compare:firstTimeOut] != NSOrderedDescending)
//    {
//        [[NSRunLoop mainRunLoop] runMode:NSDefaultRunLoopMode beforeDate:firstTimeOut];
//    }
//    UIWindow* window = [[UIApplication sharedApplication] keyWindow];
//    [window sendEvent:<#(UIEvent *)#>]
//    XCTAssertNotNil(window);
//    NSDate* timeOut = [NSDate dateWithTimeIntervalSinceNow:10];//Waits for 10 seconds.
//    while (!localResult && [[NSDate dateWithTimeIntervalSinceNow:0] compare:timeOut] != NSOrderedDescending)
//    {
//        [[NSRunLoop mainRunLoop] runMode:NSDefaultRunLoopMode beforeDate:timeOut];
//    }
//    if (!localResult)
//    {
//        XCTFail("Time out.");
//        return;
//    }
}


@end
