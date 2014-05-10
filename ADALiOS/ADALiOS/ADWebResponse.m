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

#import "ADWebResponse.h"

@implementation HTTPWebResponse

@synthesize body = _body;

- (id)init
{
    return nil;
}

- (id)initWithResponse:(NSHTTPURLResponse *)response data:(NSData *)data
{
    if ( response == nil )
    {
        NSAssert( false, @"Invalid Parameters" );
        return nil;
    }
    
    if ( ( self = [super init] ) != nil )
    {
        _response = SAFE_ARC_RETAIN( response );
        _body     = SAFE_ARC_RETAIN( data );
        _bodyText = nil;
    }
    
    return self;
}

- (void)dealloc
{
    DebugLog( @"dealloc" );
    
    SAFE_ARC_RELEASE( _response );
    SAFE_ARC_RELEASE( _body );
    SAFE_ARC_RELEASE( _bodyText );
    
    SAFE_ARC_SUPER_DEALLOC();
}


- (NSDictionary *)headers
{
    return _response.allHeaderFields;
}

- (NSInteger)statusCode
{
    return _response.statusCode;
}

@end
