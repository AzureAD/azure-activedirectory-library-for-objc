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

#import "ADDefaultEvent.h"
#import "ADEventInterface.h"

@implementation ADDefaultEvent

@synthesize propertyMap = _propertyMap;

- (id)init
{
    //Ensure that the appropriate init function is called. This will cause the runtime to throw.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

- (id)initWithName:(NSString*)eventName
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _propertyMap = [[self defaultParameters] mutableCopy];
    [_propertyMap addObject:@[@"event_name", eventName]];
    
    return self;
}

- (void)setProperty:(NSString*)name value:(NSString*)value
{
    // value can be empty but not nil
    if ([NSString adIsStringNilOrBlank:name] || !value)
    {
        return;
    }
    
    [_propertyMap addObject:@[name, value]];
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
    
    [_propertyMap addObject:@[@"start_time", [self getStringFromDate:time]]];
}

- (void)setStopTime:(NSDate*)time
{
    if (!time)
    {
        return;
    }
    
    [_propertyMap addObject:@[@"stop_time", [self getStringFromDate:time]]];
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

#define SET_IF_NOT_NIL(DICT, NAME, OBJECT) \
{ \
if (OBJECT) \
{ \
[(DICT) addObject:@[(NAME), (OBJECT)]]; \
} \
}

- (NSArray*)defaultParameters
{
    static NSMutableArray* s_defaultParameters = nil;
    static dispatch_once_t s_parametersOnce;
    
    dispatch_once(&s_parametersOnce, ^{
        
        s_defaultParameters = [NSMutableArray new];
        
#if TARGET_OS_IPHONE
        //iOS:
        NSString* deviceId = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
        NSString* deviceName = [[UIDevice currentDevice] name];
        SET_IF_NOT_NIL(s_defaultParameters, @"device_id", [[deviceId dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0]);
        SET_IF_NOT_NIL(s_defaultParameters, @"device_name", [[deviceName dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0]);
        
        SET_IF_NOT_NIL(s_defaultParameters, @"application_name", [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleDisplayName"]);
        SET_IF_NOT_NIL(s_defaultParameters, @"sdk_id", @"iOS");
#else
        SET_IF_NOT_NIL(s_defaultParameters, @"application_name",  [[NSProcessInfo processInfo] processName]);
        SET_IF_NOT_NIL(s_defaultParameters, @"sdk_id", @"OSX");
#endif
        
        SET_IF_NOT_NIL(s_defaultParameters, @"application_version", [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"]);
        SET_IF_NOT_NIL(s_defaultParameters, @"sdk_version", ADAL_VERSION_NSSTRING);
        
    });
    
    return s_defaultParameters;
}

- (NSInteger)getDefaultPropertyCount
{
    return [[self defaultParameters] count];
}

- (void)dealloc
{
    SAFE_ARC_RELEASE(_propertyMap);
    _propertyMap = nil;
    
    SAFE_ARC_SUPER_DEALLOC();
}


@end