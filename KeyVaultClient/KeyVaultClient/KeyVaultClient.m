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

#import "KeyVaultClient.h"

@implementation KeyVaultClient

+ (instancetype)shared
{
    static dispatch_once_t onceToken;
    static KeyVaultClient *client = nil;
    dispatch_once(&onceToken, ^{
        client = [KeyVaultClient new];
    });
    
    return client;
}

- (void)getSecret:(NSURL *)secret
  completionBlock:(void (^)(NSString *value, NSError *error))completionBlock
{
    NSMutableURLRequest *urlRequest = [[NSMutableURLRequest alloc] initWithURL:[NSURL URLWithString:@"http://localhost:59126"]];
    urlRequest.HTTPMethod = @"POST";
    urlRequest.HTTPBody = [[NSString stringWithFormat:@"{\"url\" : \"%@\"}", secret] dataUsingEncoding:NSUTF8StringEncoding];
    
    [[[NSURLSession sharedSession] dataTaskWithRequest:urlRequest
                                    completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error)
    {
        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
        if (error)
        {
            completionBlock(nil, error);
            return;
        }
        
        if (httpResponse.statusCode != 200)
        {
            // TODO: Handle failure
            completionBlock(nil, [NSError errorWithDomain:@"KeyVaultClient" code:0 userInfo:nil]);
            return;
        }
        
        NSError *jsonError = nil;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        if (!json)
        {
            completionBlock(nil, jsonError);
            return;
        }
        
        NSString *value = json[@"secret"];
        if (!value)
        {
            completionBlock(nil, [NSError errorWithDomain:@"KeyVaultClient" code:1 userInfo:nil]);
            return;
        }
        
        completionBlock(value, nil);
    }] resume];
}

@end
