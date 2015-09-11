//
//  NSString+ADExtentions.m
//  ADALiOS
//
//  Created by Brandon Werner on 9/11/15.
//  Copyright © 2015 MS Open Tech. All rights reserved.
//

#import "NSString+ADExtentions.h"

@implementation NSString (ADExtensions)

- (NSString*)adSpaceDeliminatedString
{
    NSMutableString* string = [NSMutableString new];
    
    __block BOOL first = YES;
    
    [self enumerateLinesUsingBlock:^(id obj, BOOL *stop) {
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

- (NSString*)adUrlFormEncode
{
    return [[self adSpaceDeliminatedString] adUrlFormEncode];
}

@end
