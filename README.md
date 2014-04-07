#Windows Azure Active Directory Authentication Library (ADAL) Universal build for OSX
=====================================

## This is the ADAL OSX Universal branch

This Branch builds ADAL for OSX as a Universal binary that supports 32bit and 64bit usage WITHOUT Automatic Reference Counting. Note that only the core ADAL library is built as Universal, the ADAL unit tests build as x86_64 and required ARC so do not
attempt to build or run the unit tests in 32bit mode.

## License

Copyright (c) Microsoft Open Technologies, Inc.  All rights reserved. Licensed under the Apache License, Version 2.0 (the "License"); 
