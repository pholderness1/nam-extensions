SameSite Cookie Override Filter (NAM)
===========================

Newer versions of Tomcat (8.5.42 and 9.0.21 onward) offer mechanisms for setting the same-site cookie attribute on cookies. Neither of which are standardised, and neither are compatible between containers. It looks like the earliest point from which the Servlet Specification will contain support for same-site is v5.1. Support for servlet spec v5.1 is likely (but not guaranteed) to arrive in Tomcat 10.X. Most implementations of Java servlets use version 3.1 of the spec. and so a future using v5.1 seems a long way off. 

This solutions contains a new Servlet Filter (SameSiteFilter) for appending the same-site cookie flag to cookies. The SameSiteFilter wraps the HttpResponse with a SameSiteResponseProxy proxy. The proxy overrides the getWriter, sendError, getOutputStream, and sendRedirect Response methods such that any attempt from a Servlet to commit a response back to the client invokes the 'append same site attribute' logic over the current set of Set-Cookie headers.

The basic algorithm is:

1. On writing a response to the client.
2. Extract all Set-Cookie headers.
3. For each header.
  1. Parse the Set-Cookie header to retrieve the cookie name
  2. If the cookie header does not already have the same-site flag set: append the same-site flag to the cookie with the value "None".
  3. Else: copy the header back into the response unmodified.



