Content Security Policy Filter (NAM)
===========================

Adds the 'Content-Security-Policy' or 'Content-Security-Policy-Report-Only' Header to the response for the NAM 4.3 Identity Provider (Tomcat 8). NAM 4.3 only supports antiClickJacking (HTTP Header Security Filter) via X-Content-Type-Options natively which is a legacy non standard implementation. This filters add 'Content-Security-Policy' 2.0 and 3.0 capabilities to primarly bypass iframe content embedding issues with NAM.

Also see: 
 - http://content-security-policy.com/
 - http://www.w3.org/TR/CSP/#directives
 - https://developer.chrome.com/extensions/contentSecurityPolicy
 - https://developer.mozilla.org/en-US/docs/Web/Security/CSP

Normally you will only need a limited number or none of the init parameters. If no init parameter is defined the Header will look like this:

    Content-Security-Policy = default-src 'none'

Here is an example full configuration of the ContentSecurityPolicyFilter. 
 
        <filter>
           <filter-name>ContentSecurityPolicyFilter</filter-name>
           <filter-class>nl.idfocus.nam.filter.ContentSecurityPolicyFilter</filter-class>
           
           <init-param>
               <!-- If not specified the default is false -->
               <param-name>report-only</param-name>
               <param-value>false</param-value>
            </init-param>
            <!-- Optionally add a reporter-uri -->            
           <init-param>
               <param-name>report-uri</param-name>
               <param-value>/nidp/ContentSecurityPolicyReporter</param-value>
            </init-param>
           <init-param>
               <param-name>sandbox</param-name>
               <param-value>true</param-value>
               <!-- true enables the sandbox behaviour - the default is false - one can also specify exceptions, e.g.
               <param-value>allow-forms allow-same-origin</param-value>
               -->
            </init-param>
           <!-- Remember that special keywords have to be put in single quotes, e.g. 'none', 'self' -->
           <init-param>
               <!-- If not specified the default is 'none' -->
               <param-name>default-src</param-name>
               <param-value>'none'</param-value>
            </init-param>
           <init-param>
               <param-name>img-src</param-name>
                <param-value>http://*.example.com</param-value>
            </init-param>
           <init-param>
               <param-name>script-src</param-name>
               <param-value>'self' js.example.com</param-value>
            </init-param>
           <init-param>
               <param-name>style-src</param-name>
               <param-value>'self'</param-value>
            </init-param>  
           <init-param>
               <param-name>connect-src</param-name>
               <param-value>'self'</param-value>
            </init-param> 
           <init-param>
               <param-name>font-src</param-name>
               <param-value>'self'</param-value>
            </init-param>   
           <init-param>
               <param-name>object-src</param-name>
               <param-value>'self'</param-value>
            </init-param>  
           <init-param>
               <param-name>media-src</param-name>
               <param-value>'self'</param-value>
            </init-param> 
           <init-param>
               <param-name>child-src</param-name>
               <param-value>'self'</param-value>
            </init-param>
           <init-param>
               <param-name>frame-ancestors</param-name>
               <param-value>'self' https://www.example.com</param-value>
            </init-param>
           <init-param>
               <param-name>script-src-elem</param-name>
               <param-value>'self'</param-value>
            </init-param>
           <init-param>
               <param-name>script-src-attr</param-name>
               <param-value>'self'</param-value>
            </init-param>
           <init-param>
               <param-name>style-src-elem</param-name>
               <param-value>'nonce-abc'</param-value>
            </init-param>
           <init-param>
               <param-name>style-src-attr</param-name>
               <param-value>'unsafe-inline'</param-value>
            </init-param>
           <init-param>
               <param-name>frame-src</param-name>
               <param-value>'self' https://www.example.com</param-value>
            </init-param>
           <init-param>
               <param-name>worker-src</param-name>
               <param-value>'self' https://www.example.com</param-value>
            </init-param>
           <init-param>
               <param-name>manifest-src</param-name>
               <param-value>'self' https://www.example.com</param-value>
            </init-param>
           <init-param>
               <param-name>prefetch-src</param-name>
               <param-value>'self' https://www.example.com</param-value>
            </init-param>
           <init-param>
               <param-name>base-uri</param-name>
               <param-value>'self' https://www.example.com</param-value>
            </init-param>
           <init-param>
               <param-name>navigate-to</param-name>
               <param-value>'self' https://www.example.com</param-value>
            </init-param>
           <init-param>
               <param-name>report-to</param-name>
               <param-value>csp-endpoint</param-value>
            </init-param>
        </filter>
        
        <filter-mapping> 
           <filter-name>ContentSecurityPolicyFilter</filter-name>
            <url-pattern>/*</url-pattern>
        </filter-mapping>
        
        
Optionally configure a Servlet to log the CSP violations:    
    
         <servlet>
             <servlet-name>ContentSecurityPolicyReporter</servlet-name>
             <servlet-class>nl.idfocus.nam.filter.ContentSecurityPolicyReporter</servlet-class>
         </servlet>
 
         <servlet-mapping>
             <servlet-name>ContentSecurityPolicyReporter</servlet-name>
             <url-pattern>/ContentSecurityPolicyReporter</url-pattern>
         </servlet-mapping>          
