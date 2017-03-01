# IDFocus Extensions for NetIQ Access Manager


## Flexible authentication classes and more

In this project you will find a set of authentication classes for NetIQ Access Manager. These were developed as custom work during IDFocus implementation projects. Most of the modules address some missing functionality or extension point of the standard NAM product. 

#### Utility Authentication Classes

* **Allow or Deny**: classes that always allow or deny an authentication
* **IDP Redirect**: class that redirects to an external (SAML2) IDP when no AG is being used
* **Password Expiration Check**: class that checks for expiring passwords and can force the user to change it before logging in
* **Contract Dependency**: class that checks if a specific contract was previously satisfied, if not then trigger authentication
* **Chain Authentication Classes**: class that allows other classes to be chained in a PAM-style with AND / OR properties
* **Kerberos Force Fallback**: class and filter that allow flexible authentication fallback after Kerberos fails

#### 2-Factor Authentication Classes
* **SMS Token** : class to authenticate using a random code sent in a SMS text message (2FA)
* **TOTP Authentication**: improved class to authenticate using a time-based code from Google Authenticator (2FA)
* **TOTP or SMS Token**: class that can switch between two 2FA method depending on user preference

#### Other Modules
* **WS-Trust IDP Roles**: authorization module that can utilize IDP roles for WS-Trust authorizations
* **Certificate Path Checker**: module for the X509 class that performs specific certificate chain verification
* **Playground**: stuff to learn from with lots of explanation (hopefully)
