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

#import "ADTelemetry.h"
#import "ADTelemetryDefaultEvent.h"
#import "ADTelemetryEventInterface.h"
#import "ADTelemetryEventStrings.h"
#import "ADLogger.h"

#if !TARGET_OS_IPHONE
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#endif

#define SET_IF_NOT_NIL(DICT, NAME, OBJECT) \
{ \
if (OBJECT) \
{ \
[(DICT) addObject:[[ADTelemetryProperty alloc] initWithName:(NAME) value:(OBJECT)]]; \
} \
}

@implementation ADTelemetryDefaultEvent

@synthesize propertyMap = _propertyMap;

- (id)init
{
    //Ensure that the appropriate init function is called. This will cause the runtime to throw.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

- (id)initWithName:(NSString*)eventName
         requestId:(NSString*)requestId
     correlationId:(NSUUID*)correlationId
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _propertyMap = [[self defaultParameters] mutableCopy];
    SET_IF_NOT_NIL(_propertyMap, AD_TELEMETRY_REQUEST_ID, requestId);
    SET_IF_NOT_NIL(_propertyMap, AD_TELEMETRY_CORRELATION_ID, [correlationId UUIDString]);
    _defaultPropertyCount = [_propertyMap count];
    
    SET_IF_NOT_NIL(_propertyMap, AD_TELEMETRY_EVENT_NAME, eventName);
    
    return self;
}

- (id)initWithName:(NSString*)eventName
           context:(id<ADRequestContext>)requestParams
{
    return [self initWithName:eventName requestId:requestParams.telemetryRequestId correlationId:requestParams.correlationId];
}

- (void)setProperty:(NSString*)name value:(NSString*)value
{
    // value can be empty but not nil
    if ([NSString adIsStringNilOrBlank:name] || !value)
    {
        return;
    }
    
    [_propertyMap addObject:[[ADTelemetryProperty alloc] initWithName:name value:value]];
}

- (NSArray*)getProperties
{
    return _propertyMap;
}

- (void)setStartTime:(NSDate*)time
{
    if (!time)
    {
        return;
    }
    
    [_propertyMap addObject:[[ADTelemetryProperty alloc] initWithName:@"start_time" value:[self getStringFromDate:time]]];
}

- (void)setStopTime:(NSDate*)time
{
    if (!time)
    {
        return;
    }
    
    [_propertyMap addObject:[[ADTelemetryProperty alloc] initWithName:@"stop_time" value:[self getStringFromDate:time]]];
}

- (void)setResponseTime:(NSTimeInterval)responseTime
{
    //the property is set in milliseconds
    [_propertyMap addObject:[[ADTelemetryProperty alloc] initWithName:AD_TELEMETRY_RESPONSE_TIME
                                                                value:[NSString stringWithFormat:@"%f", responseTime*1000]]];
}

- (NSString*)getStringFromDate:(NSDate*)date
{
    static NSDateFormatter* s_dateFormatter = nil;
    static dispatch_once_t s_dateOnce;
    
    dispatch_once(&s_dateOnce, ^{
        s_dateFormatter = [[NSDateFormatter alloc] init];
        [s_dateFormatter setTimeZone:[NSTimeZone timeZoneWithName:@"UTC"]];
        [s_dateFormatter setDateFormat:@"yyyy-MM-dd HH:mm:ss.SSSS"];
    });
    
    return [s_dateFormatter stringFromDate:date];
}

- (void)addAggregatedPropertiesToDictionary:(NSMutableDictionary*)eventToBeDispatched
{
    for (int i=0; i<[self getDefaultPropertyCount]; i++)
    {
        NSString* propertyName = [(ADTelemetryProperty*)_propertyMap[i] name];
        NSString* propertyValue = [(ADTelemetryProperty*)_propertyMap[i] value];
        [eventToBeDispatched setObject:propertyValue forKey:propertyName];
    }
}

- (NSArray*)defaultParameters
{
    static NSMutableArray* s_defaultParameters;
    static dispatch_once_t s_parametersOnce;
    
    dispatch_once(&s_parametersOnce, ^{
        
        s_defaultParameters = [NSMutableArray new];
        
#if TARGET_OS_IPHONE
        //iOS:
        NSString* deviceId = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
        NSString* applicationName = [[NSBundle mainBundle] bundleIdentifier];
#else
        CFStringRef macSerialNumber = nil;
        CopySerialNumber(&macSerialNumber);
        NSString* deviceId = CFBridgingRelease(macSerialNumber);
        NSString* applicationName = [[NSProcessInfo processInfo] processName];
#endif
        
        SET_IF_NOT_NIL(s_defaultParameters, @"device_id", [deviceId adComputeSHA256]);
        SET_IF_NOT_NIL(s_defaultParameters, @"application_name", applicationName);
        SET_IF_NOT_NIL(s_defaultParameters, @"application_version", [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"]);
        
        NSDictionary* adalId = [ADLogger adalId];
        for (NSString* key in adalId)
        {
            SET_IF_NOT_NIL(s_defaultParameters, key, [adalId objectForKey:key]);
        }
    });
    
    return s_defaultParameters;
}

- (NSInteger)getDefaultPropertyCount
{
    return _defaultPropertyCount;
}

#if !TARGET_OS_IPHONE
// Returns the serial number as a CFString.
// It is the caller's responsibility to release the returned CFString when done with it.
void CopySerialNumber(CFStringRef *serialNumber)
{
    if (serialNumber != NULL) {
        *serialNumber = NULL;
        
        io_service_t    platformExpert = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                                     IOServiceMatching("IOPlatformExpertDevice"));
        
        if (platformExpert) {
            CFTypeRef serialNumberAsCFString =
            IORegistryEntryCreateCFProperty(platformExpert,
                                            CFSTR(kIOPlatformSerialNumberKey),
                                            kCFAllocatorDefault, 0);
            if (serialNumberAsCFString) {
                *serialNumber = serialNumberAsCFString;
            }
            
            IOObjectRelease(platformExpert);
        }
    }
}
#endif

@end
