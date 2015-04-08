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


#import <Foundation/Foundation.h>

#import <sal.h>
#import <port.h>
#import <xCryptLib.h>

@interface ADBrokerCryptoHelper : NSObject


void* XCRYPTLIBAPI xCryptAlloc( size_t cb );


void XCRYPTLIBAPI xCryptFree( void *pv );

CRYPTO_BOOL XCRYPTLIBAPI xCryptRandom(unsigned char* pb, size_t cb);
//
// Callback functions required by xCrypt
//

CRYPTO_RESULT DoKDFUsingxCryptLib(
                                  unsigned char*  pbLabel,
                                  unsigned long   cbLabel,
                                  unsigned char*  pbCtx,
                                  unsigned long   cbCtx,
                                  unsigned char*  pbKey,
                                  unsigned long   cbKey,
                                  unsigned char*  pbDerivedKey,
                                  unsigned long   cbDerivedKey
                                  );

@end
