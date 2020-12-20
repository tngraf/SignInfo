# SignInfo

[![License](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0)

This small command line tool displays the code signing/authenticode/certificate information of binaries.  
The output is similar to the output of [Sigcheck](https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck). SignInfo is written in C# and uses only .Net to retrieve all information.

## Usage

```
Usage: SignInfo [-a] [-h] [-i] filename
  
  -a         Show extended version information  
  -h         Show file hashes  
  -i         Show signing chain  
  -nobanner  Quiet (no banner)  
  --help     Show this help information  
```

## Examples

The example binary is `Newtonsoft.Json.dll` from the NuGet package [Newtonsoft.Json 12.0.3](https://www.nuget.org/packages/Newtonsoft.Json/).

### Basic Information

```
SignInfo.exe Newtonsoft.Json.dll

SignInfo 0.1.0 - Signature Information viewer.
Copyright (C) 2020 T. Graf

E:\Newtonsoft.Json.dll
  Verified:        Signed
  Publisher:       Json.NET (.NET Foundation)
  Company:         Newtonsoft
  Description:     Json.NET .NET Standard 2.0
  Product:         Json.NET
  Product Version: 12.0.3+7c3d7f8da7e35dde8fa74188b0decff70f8f10e3
  File Version:    12.0.3.23909
```

### Extended Version Information  

```
SignInfo.exe -a Newtonsoft.Json.dll

SignInfo 0.1.0 - Signature Information viewer.
Copyright (C) 2020 T. Graf

E:\Newtonsoft.Json.dll
  Verified:        Signed
  Publisher:       Json.NET (.NET Foundation)
  Company:         Newtonsoft
  Description:     Json.NET .NET Standard 2.0
  Product:         Json.NET
  Product Version: 12.0.3+7c3d7f8da7e35dde8fa74188b0decff70f8f10e3
  File Version:    12.0.3.23909
  Binary Version:  12.0.3.23909
  Original Name:   Newtonsoft.Json.dll
  Internal Name:   Newtonsoft.Json.dll
  Copyright:       Copyright © James Newton-King 2008
  Comments:        Json.NET is a popular high-performance JSON framework for .NET
```

### File Hashes

```
SignInfo.exe Newtonsoft.Json.dll

SignInfo 0.1.0 - Signature Information viewer.
Copyright (C) 2020 T. Graf

E:\Newtonsoft.Json.dll
  Verified:        Signed
  Publisher:       Json.NET (.NET Foundation)
  Company:         Newtonsoft
  Description:     Json.NET .NET Standard 2.0
  Product:         Json.NET
  Product Version: 12.0.3+7c3d7f8da7e35dde8fa74188b0decff70f8f10e3
  File Version:    12.0.3.23909
  MD5 hash = 9454AE6EB0C6AD77E93A95074BA29266
  SHA1 hash = DF83FCB3639596AD42D5BE8314EF9D672079198B
  SHA256 hash = 99177A4CBE03625768D64A3D73392310372888F74C3EB271CF775E93057A38E6
```

### signing Chain

```
SignInfo.exe Newtonsoft.Json.dll

SignInfo 0.1.0 - Signature Information viewer.
Copyright (C) 2020 T. Graf

E:\Newtonsoft.Json.dll
  Verified:        Signed
  Publisher:       Json.NET (.NET Foundation)
  Company:         Newtonsoft
  Description:     Json.NET .NET Standard 2.0
  Product:         Json.NET
  Product Version: 12.0.3+7c3d7f8da7e35dde8fa74188b0decff70f8f10e3
  File Version:    12.0.3.23909
  Signers:
    Json.NET (.NET Foundation)
      Cert Status: Valid
      Issuer: .NET Foundation Projects Code Signing CA
      Algorithm: sha256RSA
      Serial Number: 0A71A1B0C296F5C79065470A3C20537E
      Thumbprint: 4CFB89FAA49539A58968D81960B3C1258E8F6A34
      Valid from: 25.10.2018 02:00:00
      Valid until: 29.10.2021 14:00:00
      Element error status length: 0
      Valid Usage: DigitalSignature
      Element information:
      Number of element extensions: 9

    .NET Foundation Projects Code Signing CA
      Cert Status: Valid
      Issuer: DigiCert High Assurance EV Root CA
      Algorithm: sha256RSA
      Serial Number: 07B0418DA51E148C331BBCDEB7138323
      Thumbprint: 0F5726A0FE659DDA2D6AC5CB75AC9E769961FD7A
      Valid from: 27.04.2018 14:41:59
      Valid until: 27.04.2028 14:41:59
      Element error status length: 0
      Valid Usage: CrlSign, KeyCertSign, DigitalSignature
      Element information:
      Number of element extensions: 8

    DigiCert High Assurance EV Root CA
      Cert Status: Valid
      Issuer: DigiCert High Assurance EV Root CA
      Algorithm: sha1RSA
      Serial Number: 02AC5C266A0B409B8F0B79F2AE462577
      Thumbprint: 5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25
      Valid from: 10.11.2006 01:00:00
      Valid until: 10.11.2031 01:00:00
      Element error status length: 0
      Valid Usage: CrlSign, KeyCertSign, DigitalSignature
      Element information:
      Number of element extensions: 4
```

**Note:** I found no reliable way to show the signing date and the (time service) counter signers.

### Information on a binary with not fully trusted certificates

```
SignInfo.exe Some.dll

SignInfo 0.1.0 - Signature Information viewer.
Copyright (C) 2020 T. Graf

E:\Some.dll
  Verified:        Certificate chain was processed, but ended with a root certificate that the trusted provider does not trust., , The revocation function was unable to perform a revocation check on the certificate. The revocation function was unable to check revocation because the revocation server was offline.
  Publisher:       www.4wp7.de
  Company:         T. Graf
  Description:     CodeSigningDemo
  Product:         CodeSigningDemo
  Product Version: 0.1
  File Version:    0.1
```

## License

Copyright (C) 2020 T. Graf

Licensed under the **Apache License, Version 2.0** (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
