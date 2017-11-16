Locale Override Filter (NAM)
===========================

Filter that allows for changing the current locale on every HTTP Servlet request via a Query Parameter or Cookie. The purpose is to allow language selection on the IDP/ AG branding pages.

Here is an example full configuration of the LocaleChangeFilter. 
 
        <!--  Implement Locale Change Filter -->
        <filter>
                <filter-name>LocaleChangeFilter</filter-name>
                <filter-class>nl.idfocus.nam.filter.LocaleChangeFilter</filter-class>
                <description>A JEE filter that allows for changing the current locale on every request via a query parameter and cookie</description>
                <init-param>
                        <param-name>cookieName</param-name>
                        <param-value>nam-language</param-value>
                </init-param>
                <init-param>
                        <param-name>cookieDomain</param-name>
                        <param-value>.idfocus.nl</param-value>
                </init-param>
                <init-param>
                        <param-name>cookiePath</param-name>
                        <param-value>/</param-value>
                </init-param>
                <init-param>
                        <param-name>cookieMaxAge</param-name>
                        <param-value>31536000</param-value>
                </init-param>
                <init-param>
                        <param-name>cookieSecure</param-name>
                        <param-value>true</param-value>
                </init-param>
                <init-param>
                        <param-name>localeQuerystringParam</param-name>
                        <param-value>locale</param-value>
                </init-param>
        </filter>
        <filter-mapping>
                <filter-name>LocaleChangeFilter</filter-name>
                <url-pattern>/*</url-pattern>
        </filter-mapping>        
