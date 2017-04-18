package nl.idfocus.nam.util;

import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.doAnswer;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Locale;
import java.util.Properties;
import java.util.logging.Level;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.novell.nidp.NIDPContext;
import com.novell.nidp.NIDPException;
import com.novell.nidp.NIDPKeys;
import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.NIDPSession;
import com.novell.nidp.NIDPSessionData;
import com.novell.nidp.NIDPTrustStore;
import com.novell.nidp.authentication.AuthClassDefinition;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.common.authority.ConfigAuthority;
import com.novell.nidp.common.authority.UserAuthority;
import com.novell.nidp.common.authority.ldap.LDAPPrincipal;
import com.novell.nidp.common.authority.ldap.LDAPUserAuthority;
import com.novell.nidp.liberty.wsc.impl.WSCToken;
import com.novell.nidp.liberty.wsc.query.WSCQLDAPToken;
import com.novell.nidp.liberty.wsc.query.WSCQSSToken;
import com.novell.nidp.logging.NIDPLog;
import com.novell.nidp.saml2.SAMLConstants;
import com.novell.nidp.servlets.NIDPServletContext;

public class MockNIDP {

    public static LocalAuthenticationClass createAuthClass(String className, Properties classProps) throws Exception {
        try {
            System.out.println("Instantiating authentication class " + className + "...");
            AuthClassDefinition rawDefinition = new AuthClassDefinition("Unit Test", className, classProps);
            LocalAuthenticationClass newClass = rawDefinition.getInstance(getAuthorities(), classProps);
            System.out.println("Done.");
            return newClass;
        } catch (NIDPException e) {
            System.out.println("Error " + e.getErrorID() + ": " + e.getMessage() + " for class " + className + ".");
            throw new Exception("Failed to instantiate");
        }
    }

    public static ArrayList<UserAuthority> getAuthorities() {
        ArrayList<UserAuthority> stores = new ArrayList<>();
        stores.add(getUserAuthority( true ));
        return stores;
    }

    public static NIDPPrincipal getPrincipal() {
        LDAPPrincipal princ = mock(LDAPPrincipal.class);
        LDAPUserAuthority authority = getUserAuthority( true );
        given(princ.getAuthority()).willReturn(authority);
        given(princ.getAuthID()).willReturn("myStore");
        given(princ.getUserIdentifier()).willReturn("cn=mockito,ou=users,o=org");
        given(princ.getUserName()).willReturn("mockito");
        return princ;
    }

    public static NIDPPrincipal getPrincipalWithEmptyStore() {
        LDAPPrincipal princ = mock(LDAPPrincipal.class);
        LDAPUserAuthority authority = getUserAuthority( false );
        given(princ.getAuthority()).willReturn(authority);
        given(princ.getAuthID()).willReturn("myStore");
        given(princ.getUserIdentifier()).willReturn("cn=mockito,ou=users,o=org");
        given(princ.getUserName()).willReturn("mockito");
        return princ;
    }

    public static LDAPUserAuthority getUserAuthority( boolean withprinc )
    {
        LDAPUserAuthority authority = mock(LDAPUserAuthority.class);
        given(authority.isEDir()).willReturn(true);
        given(authority.getID()).willReturn("myStore");
        try {
        	doAnswer(new Answer<Void>() {
        	    public Void answer(InvocationOnMock invocation) {
        	        Object[] args = invocation.getArguments();
        	        System.out.println("modifyAttributes called with arguments: " + 
        	        		((NIDPPrincipal)args[0]).getUserIdentifier() + " " +
        	        		((String[])args[1])[0] + " " +
        	        		((String[])args[2])[0]
        	        		);
        	        return null;
        	      }
        	  }).when(authority).modifyAttributes(any(NIDPPrincipal.class), any(String[].class), any(String[].class));
//        	doNothing().when(authority).modifyAttributes(any(NIDPPrincipal.class), any(String[].class), any(String[].class));
        } catch (NIDPException e) {}
        NIDPPrincipal princ;
        if( withprinc )
        {
        	princ = getPrincipalWithEmptyStore();
        	given(authority.getPrincipalByUniqueName(eq("cn=mockito,ou=users,o=org"), any(ArrayList.class))).willReturn(princ);
        }
        Attributes attrs = getUserAttributes();
        given(authority.getAttributes(any(NIDPPrincipal.class), any(String[].class))).willReturn(attrs);
        return authority;
    }

    public static Attributes getUserAttributes()
    {
    	Attributes attrs = new BasicAttributes();
    	attrs.put("cn", "mockito");
    	attrs.put("mobile", "0612345678");
    	attrs.put("telephoneNumber", "0698765432");
    	attrs.put("company", "idfocus");
    	attrs.put("smsExpiration", "30");
    	attrs.put("totpSecretValuePam", "TTLRB6ULNFYBTUZB\r\n\" TOTP_AUTH\r\n78636072\r\n81915571\r\n52984984\r\n34278800\r\n88440605\r\n");
    	// TTLRB6ULNFYBTUZB
    	attrs.put("totpSecretKey", "bdtVnx+0zTQGKnSSa62lJlU0G/rUgi2j1AtbS0nlXmk=");
    	// [78636072, 81915571, 52984984, 34278800, 88440605]
    	BasicAttribute scratchCodes = new BasicAttribute("totpScratchCodes");
    	scratchCodes.add("lPN3UC30++tp+LE77aJTFg==");
    	scratchCodes.add("0SY5KSZZr+64KQXbeUQJHQ==");
    	scratchCodes.add("LCkpi6g2AwMU+kuJa9kA+A==");
    	scratchCodes.add("W0n0Tyf0J7Z3m/M5nq2Ahg==");
    	scratchCodes.add("wdD1fcFS4UJ3gYkN0QClEw==");
    	attrs.put(scratchCodes);
    	return attrs;
    }

    public static HttpServletRequest getRequest() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        given(req.getRequestURL()).willReturn(new StringBuffer("http://request.url/path?query"));
        given(req.getScheme()).willReturn("https");
        given(req.getLocale()).willReturn(new Locale("en"));
        given(req.getSession()).willReturn(getHttpSession());
//        given(req.getAttribute("javax.servlet.request.X509Certificate")).willReturn(getRdwClientCertificate());
        given(req.getParameter(SAMLConstants.PARM_REQUEST)).willReturn("hZJBj9owEIXvlfofLN8TbwhlFwuQUlBVpG2LgO2hN8cZwKpjp55Js+2vrzcLLK1W9OqZb96bN56gqu2gkUVLB7eGHy0gscfaOpTPlSlvg5NeoUHpVA0oSctN8eleDtIb2QRPXnvLL5nriEKEQMY7zpaLKTfVqLzNYKfHAz2EYVWVKr/Vu1yXd6MSxmV2x9lXCBiBKY98pBBbWDok5Sg+3WSjJBsk2Xib5TLP5bvhN84WcQ3jFPXUgahBKYT1e+MoVtIDkFbfU2eFM1UjetcC0XNWnNzNvcO2hrCB8NNoeFjfvwzquu6fMU/xHTtRFBo5Wx2TeW9cZdz+eiblcxPKj9vtKll92Wz57O0bxia9M9lvHGYX8kkHZeMDKZsordPoIil/p9ZrZSfiL+hlTCOP94Wqv3bckOCR+o6z1GVlbuOt1rA7C1dmbyqBoNsAJ5lXgV5U/Ff15OtzDGS5WHlr9C9WWOu7eQBFMOUUWuDsgw+1ousRPr2YKtn1rZKCcmjAEWciSp29XH7z2R8=");
        given(req.isRequestedSessionIdValid()).willReturn(true);
        return req;
    }

    public static HttpServletResponse getResponse() {
        HttpServletResponse resp = mock(HttpServletResponse.class);
        return resp;
    }

    public static HttpSession getHttpSession() {
        HttpSession session = mock(HttpSession.class);
        // Spying does not work on an interface
        // doReturn("0123456789").when( spy( HttpSession.class ) ).getId();
        // when(spy( HttpSession.class ).getId()).thenReturn("0123456789");
        return session;
    }

    public static NIDPSession getIdpSession() {
        NIDPSession session = mock(NIDPSession.class);
        return session;
    }

    public static NIDPSessionData getSessionData() {
        NIDPSessionData data = mock(NIDPSessionData.class);
        return data;
    }

    public static NIDPContext getNidpContext() {
        NIDPServletContext ctx = mock(NIDPServletContext.class);
        NIDPKeys keys = getNIDPKeys();
        when(ctx.getKeys()).thenReturn(keys);
        ConfigAuthority auth = getConfigAuthority();
        when(ctx.getConfigAuthority()).thenReturn(auth);
        return ctx;
    }

    public static NIDPKeys getNIDPKeys() {
        NIDPKeys data = mock(NIDPKeys.class);
        NIDPTrustStore store = getNIDPTrustStore();
        when(data.getTruststore()).thenReturn(store);
        return data;
    }

    public static ConfigAuthority getConfigAuthority() {
    	ConfigAuthority data = mock(ConfigAuthority.class);
    	UserAuthority ua = getUserAuthority(false);
        when(data.getUserAuthority(any(String.class))).thenReturn(ua);
        return data;
    }

    public static NIDPTrustStore getNIDPTrustStore() {
        NIDPTrustStore data = mock(NIDPTrustStore.class);
        KeyStore store = getKeyStore();
        when(data.getKeyStore()).thenReturn(store);
        return data;
    }

    public static KeyStore getKeyStore() {
        KeyStore store = null;
        try {
            store = KeyStore.getInstance("JKS");
            store.load(null, "changeit".toCharArray());
//            store.setCertificateEntry("rdw", getCertificate(getResourcePath("certs/RDW Issuing CA 1.cer")));
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return store;
    }

    public static String getFileContents(String fileName) throws Exception
    {
        File file = new File(MockNIDP.class.getClassLoader().getResource(fileName).toURI());
    	byte[] contents = Files.readAllBytes(file.toPath());
    	return new String(contents);
    }

    public static X509Certificate getCertificate(String fileName) 
    {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            InputStream is = new FileInputStream(fileName);
            return (X509Certificate) factory.generateCertificate(is);
        } catch (CertificateException | FileNotFoundException e) {
            return null;
        }
    }

    public static X509Certificate[] getClientCertificate(String resource) {
        String fileName = getResourcePath(resource);
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            InputStream is = new FileInputStream(fileName);
            return new X509Certificate[] { (X509Certificate) factory.generateCertificate(is) };
        } catch (CertificateException | FileNotFoundException e) {
            e.printStackTrace();
        }
        return new X509Certificate[] {};
    }

    public static void initiateIDP() {
        // NIDP uses / supports both JKS and BC keystore types
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // NIDPContext is needed for many calls including logging
        NIDPContext.setNIDPContext(MockNIDP.getNidpContext());
        // The secret store tokens need to be initialized in order to be able to build the credential set
        WSCQSSToken.populate(WSCToken.POPULATE_ALWAYS);
        // Does not really work for these
        WSCQLDAPToken.populate(WSCQLDAPToken.POPULATE_IF_ZEROEXIST);
        // Overall logging is disabled but console logging is useful for us
        NIDPLog.setEnabled(true);
        NIDPLog.setConsoleLogEnabled(true);
        NIDPLog.setLevelString(Level.FINEST.toString());
    }

    public static String getResourcePath(String resourceName) {
        try {
            File file = new File(MockNIDP.class.getClassLoader().getResource(resourceName).toURI());
            return file.getPath();
        } catch (URISyntaxException e) {
            return null;
        }
    }
}
