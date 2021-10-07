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


#import "ADALEnrollmentGateway+TestUtil.h"

@implementation ADALEnrollmentGateway (TestUtil)

+ (NSString *)getTestEnrollmentIDJSON
{
    return [NSString stringWithFormat:
            @"{\"enrollment_ids\": [\n"
                "{\n"
                "\"tid\" : \"fda5d5d9-17c3-4c29-9cf9-a27c3d3f03e1\",\n"
                "\"oid\" : \"d3444455-mike-4271-b6ea-e499cc0cab46\",\n"
                "\"home_account_id\" : \"60406d5d-mike-41e1-aa70-e97501076a22\",\n"
                "\"user_id\" : \"mike@contoso.com\",\n"
                "\"enrollment_id\" : \"adf79e3f-mike-454d-9f0f-2299e76dbfd5\"\n"
                "},\n"
                "{\n"
                "\"tid\" : \"fda5d5d9-17c3-4c29-9cf9-a27c3d3f03e1\",\n"
                "\"oid\" : \"6eec576f-dave-416a-9c4a-536b178a194a\",\n"
                "\"home_account_id\" : \"1e4dd613-dave-4527-b50a-97aca38b57ba\",\n"
                "\"user_id\" : \"dave@contoso.com\",\n"
                "\"enrollment_id\" : \"64d0557f-dave-4193-b630-8491ffd3b180\"\n"
                "},\n"
            "]\n"
            "}"];
}

+ (NSString *)getTestResourceJSON
{
    return [NSString stringWithFormat:
            @"{"
                "\"login.microsoftonline.com\":\"https://www.microsoft.com/intune\",\n"
                "\"login.microsoftonline.de\":\"https://www.microsoft.com/intune-de\",\n"
                "\"login.windows.net\":\"https://www.microsoft.com/windowsIntune\"\n"
            "}"];
}

@end
