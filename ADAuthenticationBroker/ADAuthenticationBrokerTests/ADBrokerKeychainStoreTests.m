#import <XCTest/XCTest.h>
#import <libkern/OSAtomic.h>
#import "ADBrokerKeychainTokenCacheStore.h"

const int sMaxLoggerThreadsDuration = 5;//In seconds
const int sMaxLoggerTestThreads = 100;
volatile int32_t sLoggerTestThreadsCompleted = 0;
dispatch_semaphore_t sLoggerTestCompletedSignal;

@interface ADLoggerTests : XCTestCase

@end

@implementation ADLoggerTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

- (void)testDifferentHashKey
{
    ADBrokerKeychainTokenCacheStore *store = [[ADBrokerKeychainTokenCacheStore  alloc] initWithAppKey:@"key1"];
    //[store ad]
    
}

@end