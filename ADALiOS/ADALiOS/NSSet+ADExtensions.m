//
//  NSSet+ADExtensions.m
//  ADALiOS
//
//  Created by Ryan Pangrle on 7/10/15.
//  Copyright (c) 2015 MS Open Tech. All rights reserved.
//

#import "NSSet+ADExtensions.h"

@implementation NSSet (ADExtensions)

- (NSString*)adSpaceDeliminatedString
{
    NSMutableString* string = [NSMutableString new];
    
    __block BOOL first = YES;
    
    [self enumerateObjectsUsingBlock:^(id obj, BOOL *stop) {
        if (![obj isKindOfClass:[NSString class]])
        {
            return;
        }
        
        if (!first)
        {
            [string appendString:@" "];
        }
        else
        {
            first = NO;
        }
        
        [string appendString:obj];
    }];
    
    return string;
}

@end
