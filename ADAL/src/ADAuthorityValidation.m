//
//  ADAdfsValidation.m
//  ADAL
//
//  Created by Jason Kim on 12/14/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import "ADAuthorityValidation.h"
#import "ADDrsDiscoveryRequest.h"
#import "ADWebFingerRequest.h"

static NSString* const sWebFinger = @".well-known/webfinger?";
static NSString* const sTrustedRelation = @"http://schemas.microsoft.com/rel/trusted-realm";

@implementation ADAuthorityValidation

+ (ADAuthorityValidation *)sharedInstance
{
    static ADAuthorityValidation *singleton = nil;
    static dispatch_once_t onceToken;
    
    dispatch_once(&onceToken, ^{
        singleton = [[ADAuthorityValidation alloc] init];
    });
    
    return singleton;
}

- (id)init
{
    self = [super init];
    if (!self) {
        return nil;
    }
    
    _validatedAdfsAuthorities = [NSMutableDictionary new];
    
    return self;
}

#pragma mark - caching
- (BOOL)addValidAuthority:(NSString *)authority domain:(NSString *)domain
{
    // Get authority mapping or create one if one does not exist
    NSMutableSet *set = [_validatedAdfsAuthorities objectForKey:authority];
    if (!set)
    {
        set = [NSMutableSet new];
        [_validatedAdfsAuthorities setObject:set forKey:authority];
    }
    
    // Add domain to the set of valid domains for the authority
    [set addObject:domain];
    
    return YES;
}

- (BOOL)isAuthorityValidated:(NSString *)authority domain:(NSString *)domain
{
    // Check for authority
    NSSet *domains = [_validatedAdfsAuthorities objectForKey:authority];
    if ([domains containsObject:domain])
    {
        return YES;
    }
    
    return NO;
}

#pragma mark - ADFS authority validation
- (void)validateADFSAuthority:(NSString *)authority
                       domain:(NSString *)domain
              completionBlock:(void (^)(BOOL validated, ADAuthenticationError *error))completionBlock
{
    // Check cache first
    if([self isAuthorityValidated:authority domain:domain])
    {
        completionBlock(YES, nil);
        return;
    }
    
    
    
    // DRS discovery
    [ADDrsDiscoveryRequest requestDrsDiscoveryForDomain:domain
                                               adfsType:AD_ADFS_ON_PREMS
                                                context:self
                                        completionBlock:^(id result, ADAuthenticationError *error)
    {
        (void)error;
        if (!result)
        {
            [ADDrsDiscoveryRequest requestDrsDiscoveryForDomain:domain
                                                       adfsType:AD_ADFS_CLOUD
                                                        context:self
                                                completionBlock:^(id result, ADAuthenticationError *error)
            {
                if (!result)
                {
                    NSString *newErrorMessage = [NSString stringWithFormat:@"DRS discovery error - %@", error.errorDetails];
                    ADAuthenticationError *newError = [ADAuthenticationError errorFromAuthenticationError:error.code
                                                                                             protocolCode:nil
                                                                                             errorDetails:newErrorMessage
                                                                                            correlationId:_correlationId];
                    completionBlock(NO, newError);
                }
                else
                {
                    [self requestWebFingerWithMetaData:result
                                             authority:authority
                                       completionBlock:^(BOOL validated, ADAuthenticationError *error)
                    {
                        // if validated, add to the cache
                        if(validated)
                        {
                            [self addValidAuthority:authority domain:domain];
                        }
                        
                        completionBlock(validated, error);
                    }];
                }
            }];
        }
        else
        {
            [self requestWebFingerWithMetaData:result
                                     authority:authority
                               completionBlock:^(BOOL validated, ADAuthenticationError *error)
            {
                // if validated, add to the cache
                if(validated)
                {
                    [self addValidAuthority:authority domain:domain];
                }
                completionBlock(validated, error);
            }];
        }
    }];
}



- (void)requestWebFingerWithMetaData:(id)metaData
                           authority:(NSString *)authority
                     completionBlock:(void (^)(BOOL validated, ADAuthenticationError *error))completionBlock
{
    ADAuthenticationError *error = nil;
    NSString *passiveEndpoint = [self passiveEndpointFromDRSMetaData:metaData];
    if ([NSString adIsStringNilOrBlank:passiveEndpoint])
    {
        NSString *errorMessage = @"PassiveAuthEndpoint not found in DRS discovery payload";
        error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION
                                                       protocolCode:nil
                                                       errorDetails:errorMessage
                                                      correlationId:_correlationId];
        completionBlock(NO, error);
    }
    else
    {
        [ADWebFingerRequest requestWebFinger:passiveEndpoint
                                   authority:authority
                                     context:self
                             completionBlock:^(id result, ADAuthenticationError *error) {
                                 
                                 BOOL validated = NO;
                                 if (result)
                                 {
                                     validated = [self isRealmTrustedFromWebFingerPayload:result
                                                                                authority:authority];
                                 }
                                 completionBlock(validated, error);
                             }];
    }
}

#pragma mark - Helper functions

/*! Checks whether the authority is an ADFS or not by looking for "adfs" in the the url path.
 e.g./ "https://.../adfs", or "https://.../adfs/...". */
+ (BOOL)isAdfsAuthority:(NSString *)authority
{
    NSURL *fullUrl = [NSURL URLWithString:authority.lowercaseString];
    NSArray *paths = fullUrl.pathComponents;
    
    if (paths.count < 2)
    {
        return NO;
    }
    else
    {
        NSString *tenant = [paths objectAtIndex:1];
        if ([@"adfs" isEqualToString:tenant])
        {
            return YES;
        }
        return NO;
    }
}


- (NSString*)passiveEndpointFromDRSMetaData:(id)metaData
{
    return [[metaData objectForKey:@"IdentityProviderService"] objectForKey:@"PassiveAuthEndpoint"];
}

- (BOOL)isRealmTrustedFromWebFingerPayload:(id)json
                                 authority:(NSString *)authority
{
    NSArray *links = [json objectForKey:@"links"];
    for (id link in links)
    {
        NSString *rel = [link objectForKey:@"rel"];
        NSString *target = [link objectForKey:@"href"];
        
        NSURL *authorityURL = [NSURL URLWithString:authority];
        NSString *authorityHost = [NSString stringWithFormat:@"%@://%@", authorityURL.scheme, authorityURL.host];
        
        if ([rel caseInsensitiveCompare:sTrustedRelation] == NSOrderedSame &&
            [target caseInsensitiveCompare:authorityHost] == NSOrderedSame)
        {
            return YES;
        }
    }
    return NO;
}

@end
