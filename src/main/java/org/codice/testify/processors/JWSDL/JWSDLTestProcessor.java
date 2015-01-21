/*
 * Copyright 2015 Codice Foundation
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package org.codice.testify.processors.JWSDL;

import org.codice.testify.objects.TestifyLogger;
import org.codice.testify.objects.Request;
import org.codice.testify.objects.Response;
import org.codice.testify.processors.TestProcessor;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

import javax.net.ssl.*;
import javax.xml.soap.*;
import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * The JWSDLTestProcessor class is a Testify TestProcessor service to create a SOAP message from a string and retrieve a SOAP response
 * @author Yakov Salzberg
 */
public class JWSDLTestProcessor implements BundleActivator, TestProcessor {

    @Override
    public Response executeTest(Request request) {

        TestifyLogger.debug("Running JWSDLTestProcessor", this.getClass().getSimpleName());

        //Create SOAP connection
        SOAPConnection soapConnection = null;
        try {
            SOAPConnectionFactory soapConnectionFactory = SOAPConnectionFactory.newInstance();
            soapConnection = soapConnectionFactory.createConnection();
        } catch (SOAPException e) {
            TestifyLogger.error("Could not create SOAP connection: " + e.getMessage(), this.getClass().getSimpleName());
        }

        //Create SOAP message
        SOAPMessage soapMessage = null;
        try {

            //Create soap message object
            MessageFactory messageFactory = MessageFactory.newInstance();
            soapMessage = messageFactory.createMessage();
            SOAPPart soapPart = soapMessage.getSOAPPart();

            //Convert test block string to StreamSource
            byte[] buffer = request.getTestBlock().getBytes();
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(buffer);
            StreamSource streamSource = new StreamSource(byteArrayInputStream);

            //Add StreamSource to soap message content
            soapPart.setContent(streamSource);

        } catch (SOAPException e) {
            TestifyLogger.error("Could not create SOAP message: " + e.getMessage(), this.getClass().getSimpleName());
        }

        // Trust all certificates
        try {
            doTrustToCertificates();
        } catch (NoSuchAlgorithmException e) {
            TestifyLogger.error("NoSuchAlgorithmException: " + e.getMessage(), this.getClass().getSimpleName());
            return new Response(null);
        } catch (KeyManagementException e) {
            TestifyLogger.error("KeyManagementException: " + e.getMessage(), this.getClass().getSimpleName());
            return new Response(null);
        }

        //If message and connection were created, send SOAP message and return response
        if (soapConnection != null && soapMessage != null) {

            try {

                SOAPMessage soapResponse = soapConnection.call(soapMessage, request.getEndpoint());
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                soapResponse.writeTo(byteArrayOutputStream);
                return new Response(byteArrayOutputStream.toString());

            } catch (SOAPException e) {
                TestifyLogger.error("Could not send SOAP message: " + e.getMessage(), this.getClass().getSimpleName());
            } catch (IOException e) {
                TestifyLogger.error("Could not write SOAP message to String: " + e.getMessage(), this.getClass().getSimpleName());
            }

        } else {
            TestifyLogger.error("No SOAP connection or message", this.getClass().getSimpleName());
        }

        //If response is not returned for any reason, return a null response
        return new Response(null);
    }

    // Purpose: Accept all certificates
    // Reference: https://gist.github.com/sandeepkunkunuru/7030828
    //
    public static void doTrustToCertificates() throws NoSuchAlgorithmException,KeyManagementException {
        //Security.addProvider(new Provider());
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                return;
            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                return;
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        } };

        //Set HttpsURLConnection settings
        SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(null, trustAllCerts, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        HostnameVerifier hostnameVerifier = new HostnameVerifier() {
            @Override
            public boolean verify(String s, SSLSession sslSession) {
                return s.equalsIgnoreCase(sslSession.getPeerHost());
            }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(hostnameVerifier);
    }

    @Override
    public void start(BundleContext bundleContext) throws Exception {

        //Register the JWSDLTestProcessor service
        bundleContext.registerService(TestProcessor.class.getName(), new JWSDLTestProcessor(), null);

    }

    @Override
    public void stop(BundleContext bundleContext) throws Exception {

    }
}