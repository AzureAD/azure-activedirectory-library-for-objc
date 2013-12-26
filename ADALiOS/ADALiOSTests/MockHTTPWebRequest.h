//
//  MockHTTPWebRequest.h
//  ADALiOS
//
//  Created by Boris Vidolov on 12/20/13.
//  Copyright (c) 2013 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface MockHTTPWebRequest : NSObject

@property (strong, readonly, nonatomic) NSURL               *URL;
@property (strong)                      NSString            *method;
@property (strong, readonly, nonatomic) NSMutableDictionary *headers;

- (id)initWithURL:(NSURL*)url;

- (void)send:( void (^)( NSError *, HTTPWebResponse *) )completionHandler;

@end
