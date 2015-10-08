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
@protected
    NSDictionary* _defaultEnvironment;
}

@end

static ADUserDefaultsSettings* s_defaultSettings = nil;

#define GET_STRING_PROPERTY(_property) - (NSString*)_property { return [self stringForKey:@""#_property]; }
#define GET_STRING_PROPERTY_KEY(_property, _key) - (NSString*)_property { return [self stringForKey:@_key]; }
#define GET_ARRAY_PROPERTY(_property) - (NSArray*)_property { return [self arrayForKey:@""#_property]; }
#define GET_ARRAY_PROPERTY_KEY(_property, _key) - (NSArray*)_property { return [self arrayForKey:@_key]; }
#define GET_BOOL_PROPERTY(_property) - (BOOL)_property { return [self boolForKey:@""#_property]; }
#define GET_BOOL_PROPERTY_KEY(_property, _key) - (BOOL)_property { return [self boolForKey:@_key]; }

@implementation ADTestAppSettings

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    [self loadEnvironment];
    
    return self;
}

- (id)initWithDictionary:(NSDictionary*)dictionary
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _defaultEnvironment = dictionary;
    
    return self;
}

- (void)loadEnvironment
{
    NSString* defaultsPath = [[NSBundle mainBundle] pathForResource:@"Environments" ofType:@"plist"];
    if (defaultsPath != nil)
    {
        _defaultEnvironment = [[NSDictionary dictionaryWithContentsOfFile:defaultsPath] objectForKey:@"DefaultEnvironment"];
    }
    else
    {
        _defaultEnvironment = nil;
    }
}

- (ADMutableTestAppSettings*)mutableCopy
{
    return [[ADMutableTestAppSettings alloc] initWithDictionary:_defaultEnvironment];
}

- (id)objectForKey:(NSString*)key
{
    return [_defaultEnvironment objectForKey:key];
}

- (id)objectForKey:(NSString*)key
             class:(Class)class
{
    id val = [_defaultEnvironment objectForKey:key];
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

GET_STRING_PROPERTY(authority)
GET_STRING_PROPERTY_KEY(clientId, "client_id")
GET_STRING_PROPERTY_KEY(redirectUri, "redirect_uri")
GET_STRING_PROPERTY_KEY(extraQueryParameters, "extra_query_parameters")
GET_STRING_PROPERTY_KEY(userId, "user_id")
GET_STRING_PROPERTY(password)
GET_ARRAY_PROPERTY(scopes)
GET_ARRAY_PROPERTY_KEY(additionalScopes, "additional_scopes")
GET_BOOL_PROPERTY_KEY(validateAuthority, "validate_authority")
GET_BOOL_PROPERTY_KEY(fullScreen, "full_screen")

- (int)timeout
{
    return [self numberForKey:@"timeout"].intValue;
}

@end

@implementation ADMutableTestAppSettings
{
@protected
    NSMutableDictionary* _mutableSettings;
}

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _mutableSettings = [self->_defaultEnvironment mutableCopy];
    self->_defaultEnvironment = _mutableSettings;
    
    return self;
}

- (id)initWithDictionary:(NSDictionary*)dictionary
{
    if (!(self = [super initWithDictionary:dictionary]))
    {
        return nil;
    }
    
    return self;
}

- (void)setValue:(id)value forKey:(NSString *)key
{
    [_mutableSettings setValue:value forKey:key];
}

- (void)setAuthority:(NSString *)authority
{
    [self setValue:authority forKeyPath:@"authority"];
}

- (void)setValidateAuthority:(BOOL)validateAuthority
{
    [self setValue:[NSNumber numberWithBool:validateAuthority] forKey:@"validate_authority"];
}

- (void)setExtraQueryParameters:(NSString *)extraQueryParameters
{
    [self setValue:extraQueryParameters forKeyPath:@"extra_query_parameters"];
}

@end

@implementation ADUserDefaultsSettings
{
    NSString* _environmentKey;
}

+ (void)initialize
{
    s_defaultSettings = [[ADUserDefaultsSettings alloc] init];
}

+ (ADUserDefaultsSettings*)defaultSettings
{
    return s_defaultSettings;
}

- (id)init
{
    return [self initWithKey:@"DefaultEnvironment"];
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
    
    NSDictionary* userOverrides = [[NSUserDefaults standardUserDefaults] dictionaryForKey:_environmentKey];
    for (id key in userOverrides)
    {
        [_mutableSettings setValue:[userOverrides valueForKey:key] forKey:key];
    }
    
    return self;
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
    
    [super setValue:value forKey:key];
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
        if ([_defaultEnvironment valueForKey:settingKey])
        {
            [uiSwitch setOn:[self boolForKey:settingKey]];
        }
        [uiSwitch addTarget:self action:@selector(switchChanged:) forControlEvents:UIControlEventValueChanged];
    }
    else if ([control isKindOfClass:[UISegmentedControl class]])
    {
        UISegmentedControl* segmentedControl = (UISegmentedControl*)control;
        if ([_defaultEnvironment valueForKey:settingKey])
        {
            [segmentedControl setSelectedSegmentIndex:[self numberForKey:settingKey].integerValue];
        }
        [segmentedControl addTarget:self action:@selector(selectionDidChange:) forControlEvents:UIControlEventValueChanged];
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

- (void)selectionDidChange:(UISegmentedControl*)segmentedControl
{
    NSString* settingKey = [segmentedControl settingKey];
    [self setValue:[NSNumber numberWithInteger:[segmentedControl selectedSegmentIndex]] forKey:settingKey];
}

- (void)reset
{
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:_environmentKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

@end
