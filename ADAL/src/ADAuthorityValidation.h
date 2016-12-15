//
//  ADAdfsValidation.h
//  ADAL
//
//  Created by Jason Kim on 12/14/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ADAuthorityValidation : NSObject<ADRequestContext> {
    NSMutableDictionary *_validatedAdfsAuthorities;
}

+ (ADAuthorityValidation *)sharedInstance;

// Cache
- (BOOL)addValidAuthority:(NSString *)authority domain:(NSString *)domain;
- (BOOL)isAuthorityValidated:(NSString *)authority domain:(NSString *)domain;

// Request
- (void)validateADFSAuthority:(NSString *)authority
                       domain:(NSString *)domain
              completionBlock:(void (^)(BOOL validated, ADAuthenticationError *error))completionBlock;

+ (BOOL)isAdfsAuthority:(NSString *)authority;

// To conform to ADRequestContext
@property NSUUID *correlationId;
@property NSString *telemetryRequestId;

@end
