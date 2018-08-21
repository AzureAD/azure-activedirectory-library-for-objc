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

#import "ADAutoRequestViewController.h"

@interface ADAutoRequestViewController ()

@property (strong, nonatomic) IBOutlet UIButton *requestGo;

@end

@implementation ADAutoRequestViewController

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    
    self.requestInfo.text = nil;
    //@"{\"scopes\":\"https:\\/\\/contoso.com\\/WebApp\\/.default\",\"authority\":\"https:\\/\\/fs.msidlab4.com\\/adfs\",\"resource\":\"https:\\/\\/contoso.com\\/WebApp\",\"user_identifier\":\"opIDLAB@msidlab4.com\",\"prompt_behavior\":\"always\",\"redirect_uri\":\"urn:ietf:wg:oauth:2.0:oob\",\"validate_authority\":false,\"client_id\":\"v1client\"}";
    //nil;//@"{\"web_view\":\"passed_in\",\"scopes\":\"00000003-0000-0ff1-ce00-000000000000\\/.default\",\"authority\":\"https:\\/\\/login.microsoftonline.com\\/common\",\"resource\":\"00000003-0000-0ff1-ce00-000000000000\",\"user_identifier\":\"idlab@msidlab5.onmicrosoft.com\",\"user_identifier_type\":\"optional_displayable\",\"validate_authority\":true,\"redirect_uri\":\"x-msauth-automationapp:\\/\\/com.microsoft.adal.automationapp\",\"client_id\":\"68a10fc3-ead9-41b8-ac5e-5b78af044736\"}";
}

- (IBAction)go:(id)sender
{
    self.requestInfo.editable = NO;
    self.requestGo.enabled = NO;
    [self.requestGo setTitle:@"Running..." forState:UIControlStateDisabled];

    NSError* error = nil;
    NSDictionary* params = [NSJSONSerialization JSONObjectWithData:[self.requestInfo.text dataUsingEncoding:NSUTF8StringEncoding] options:0 error:&error];
    if (!params)
    {
        NSString *errorString = [NSString stringWithFormat:@"Error Domain=%@ Code=%ld Description=%@", error.domain, (long)error.code, error.localizedDescription];
        
        params = @{ @"error" : errorString };
    }
    
    [self dismissViewControllerAnimated:NO completion:^{
        self.completionBlock(params);
    }];
}

@end
