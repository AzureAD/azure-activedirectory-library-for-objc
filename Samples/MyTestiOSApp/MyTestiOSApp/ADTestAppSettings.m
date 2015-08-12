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

#import "ADTestAppSettings.h"
#import <objc/runtime.h>

@interface UIControl (settingKey)

@property NSString* settingKey;

@end

static NSString* const kADTASettingKey = @"kADTASettingKey";

@implementation UIControl (settingKey)

- (NSString*)settingKey
{
    return objc_getAssociatedObject(self, (__bridge const void *)(kADTASettingKey));
}

- (void)setSettingKey:(NSString *)settingKey
{
    objc_setAssociatedObject(self, (__bridge const void *)(kADTASettingKey), settingKey, OBJC_ASSOCIATION_COPY);
}

@end

@interface ADTestAppSettings ()
{
    NSDictionary* _defaultEnvironment;
    NSString* _environmentKey;
}

@end

static ADTestAppSettings* s_defaultSettings = nil;

@implementation ADTestAppSettings

+ (void)initialize
{
    s_defaultSettings = [[ADTestAppSettings alloc] init];
}

+ (ADTestAppSettings*)defaultSettings
{
    return s_defaultSettings;
}

- (id)init
{
    if (!(self = [self initWithKey:nil]))
    {
        return nil;
    }
    
    return self;
}

- (id)initWithKey:(NSString*)environmentKey
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    if (environmentKey == nil)
    {
        _environmentKey = @"DefaultEnvironment";
    }
    else
    {
        _environmentKey = environmentKey;
    }
    
    [self loadEnvironment];
    
    return self;
}

- (void)loadEnvironment
{
    NSString* defaultsPath = [[NSBundle mainBundle] pathForResource:@"Environments" ofType:@"plist"];
    if (defaultsPath != nil)
    {
        _defaultEnvironment = [[NSDictionary dictionaryWithContentsOfFile:defaultsPath] objectForKey:_environmentKey];
    }
    else
    {
        _defaultEnvironment = nil;
    }
}

- (id)objectForKey:(NSString*)key
{
    id val = [[[NSUserDefaults standardUserDefaults] dictionaryForKey:_environmentKey] objectForKey:key];
    if (val)
    {
        return val;
    }
    
    return [_defaultEnvironment objectForKey:key];
}

- (void)setValue:(id)value forKey:(NSString *)key
{
    NSMutableDictionary* env = [[[NSUserDefaults standardUserDefaults] dictionaryForKey:_environmentKey] mutableCopy];
    if (!env)
    {
        env = [NSMutableDictionary new];
    }
    [env setObject:value forKey:key];
    [[NSUserDefaults standardUserDefaults] setValue:env forKey:_environmentKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

- (id)objectForKey:(NSString*)key
             class:(Class)class
{
    id val = [[[NSUserDefaults standardUserDefaults] dictionaryForKey:_environmentKey] objectForKey:key];
    if (val && [val isKindOfClass:class])
    {
        return val;
    }
    
    val = [_defaultEnvironment objectForKey:key];
    if (!val || ![val isKindOfClass:class])
    {
        return nil;
    }
    
    return val;
}

- (NSString*)stringForKey:(NSString*)key
{
    return [self objectForKey:key class:[NSString class]];
}

- (NSArray*)arrayForKey:(NSString*)key
{
    return [self objectForKey:key class:[NSArray class]];
}

- (NSNumber*)numberForKey:(NSString *)key
{
    return [self objectForKey:key class:[NSNumber class]];
}

- (BOOL)boolForKey:(NSString*)key
{
    return [[self objectForKey:key class:[NSNumber class]] boolValue];
}

- (void)reset
{
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:_environmentKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

- (NSString*)authority
{
    return [self stringForKey:@"authority"];
}

- (NSString*)clientId
{
    return [self stringForKey:@"client_id"];
}

- (NSString*)userId
{
    return [self stringForKey:@"user_id"];
}

- (NSString*)redirectUri
{
    return [self stringForKey:@"redirect_uri"];
}

- (NSString*)extraQueryParams
{
    return [self stringForKey:@"extra_query_parameters"];
}

- (NSArray*)scopes
{
    return [self arrayForKey:@"scopes"];
}

- (NSArray*)additionalScopes
{
    return [self arrayForKey:@"additional_scopes"];
}

- (BOOL)validateAuthority
{
    return [self boolForKey:@"validate_authority"];
}

- (BOOL)fullScreen
{
    return [self boolForKey:@"full_screen"];
}

- (int)timeout
{
    return [self numberForKey:@"timeout"].intValue;
}

- (void)populateControl:(UIControl*)control
{
    NSString* settingKey = [control settingKey];
    NSAssert(settingKey, @"You must set a settingKey user-defined key value in IB for this control!");
    if ([control isKindOfClass:[UITextField class]])
    {
        UITextField* textField = (UITextField*)control;
        [textField setText:[self stringForKey:settingKey]];
        [textField addTarget:self action:@selector(textFieldDidEndEditing:) forControlEvents:UIControlEventEditingDidEnd];
    }
    else if ([control isKindOfClass:[UISwitch class]])
    {
        UISwitch* uiSwitch = (UISwitch*)control;
        [uiSwitch setOn:[self boolForKey:settingKey]];
        [uiSwitch addTarget:self action:@selector(switchChanged:) forControlEvents:UIControlEventValueChanged];
    }
    else
    {
        NSAssert(nil, @"unrecognized type %@", NSStringFromClass([control class]));
    }
}
         
- (void)switchChanged:(UISwitch*)sender
{
    NSString* settingKey = [sender settingKey];
    [self setValue:[NSNumber numberWithBool:[sender isOn]] forKey:settingKey];
}

- (void)textFieldDidEndEditing:(UITextField *)textField
{
    NSString* settingKey = [textField settingKey];
    [self setValue:[textField text] forKey:settingKey];
}

@end
