#Windows Azure Active Directory IdentityModel Extensions for .Net
===========

Note: single modification to version number to make this a drop-in for MSAL nuget available right now.

IdentityModel Extensions for .Net provide assemblies that are interesting for web developers that wish to use federated identity providers for establishing the callers identity. 

## Samples and Documentation

[We provide a full suite of sample applications and documentation on GitHub](https://github.com/azure-samples?query=active-directory) to help you get started with learning the Azure Identity system. This includes tutorials for native clients such as Windows, Windows Phone, iOS, OSX, Android, and Linux. We also provide full walkthroughs for authentication flows such as OAuth2, OpenID Connect, Graph API, and other awesome features. 

## Community Help and Support

We leverage [Stack Overflow](http://stackoverflow.com/) to work with the community on supporting Azure Active Directory and its SDKs, including this one! We highly recommend you ask your questions on Stack Overflow (we're all on there!) Also browser existing issues to see if someone has had your question before. 

We recommend you use the "adal" tag so we can see it! Here is the latest Q&A on Stack Overflow for ADAL: [http://stackoverflow.com/questions/tagged/adal](http://stackoverflow.com/questions/tagged/adal)

## Security Reporting

If you find a security issue with our libraries or services please report it to [secure@microsoft.com](mailto:secure@microsoft.com) with as much detail as possible. Your submission may be eligible for a bounty through the [Microsoft Bounty](http://aka.ms/bugbounty) program. Please do not post security issues to GitHub Issues or any other public site. We will contact you shortly upon receiving the information. We encourage you to get notifications of when security incidents occur by visiting [this page](https://technet.microsoft.com/en-us/security/dd252948) and subscribing to Security Advisory Alerts.

## Contributing

All code is licensed under the Apache 2.0 license and we triage actively on GitHub. We enthusiastically welcome contributions and feedback. See [CONTRIBUTING.md](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/master/CONTRIBUTING.md) for guidelines, branch information, build instructions, and legalese. 

## Assemblies in this repo
----

### 3.x
#### System.IdentityModel.Tokens.Jwt (version 3.x)

* Support for creating, serializing, and validating Json Web Tokens.
* Provides model for config free validation using TokenValidationParameters.

#### Microsoft.IdentityModel.Protocol.Extensions (version 1.x)

* Support for creating and consuming OpenId and WsFederation messages.
* Support for validating Saml and Saml2 tokens using TokenValidationParameters.
* Support for dynamic metatdata retreival.

### 4.x
#### System.IdentityModel.Tokens.Jwt (version 4.x)
#### Microsoft.IdentityModel.Protocol.Extensions (version 2.x)


### 5.x
#### Microsoft.IdentityModel.Tokens (version 5.x)
* Includes types that provide support for cryptographic operations.

#### System.IdentityModel.Tokens.Jwt (version 5.x)

#### System.IdentityModel.Tokens.Saml (version 5.x, currently in beta)
* Includes types that provide support for Saml tokens.

#### Microsoft.IdentityModel.Protocols (version 2.x)
* Provides types that are common across OpenIdConnect and WsFed protocols.

#### Microsoft.IdentityModel.Protocols.OpenIdConnect (version 2.x)
* Includes types that provide support for OpenIdConnect protocol.

#### Microsoft.IdentityModel.Protocols.WsFederation (version 2.x, currently in beta)
* Includes types that provide support for WsFederation protocol.

#### Microsoft.IdentityModel.Logging (version 1.x)
* Includes Event Source based logging support.

## License

Copyright (c) Microsoft Corporation.  All rights reserved. Licensed under the Apache License, Version 2.0 (the "License"); 
