package com.asterinet.react.tcpsocket;

import android.annotation.SuppressLint;
import android.content.Context;
import android.util.Log;
import android.util.Base64;

import androidx.annotation.NonNull;
import androidx.annotation.RawRes;

import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

final class SSLCertificateHelper {
    private static KeyStore keyStore;
    /**
     * Creates an SSLSocketFactory instance for use with all CAs provided.
     *
     * @return An SSLSocketFactory which trusts all CAs when provided to network clients
     */
    static SSLSocketFactory createBlindSocketFactory() throws GeneralSecurityException {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{new BlindTrustManager()}, null);
        return ctx.getSocketFactory();
    }

    static SSLServerSocketFactory createServerSocketFactory(Context context, @NonNull final String keyStoreResourceUri) throws GeneralSecurityException, IOException {
        char[] password = "".toCharArray();

        InputStream keyStoreInput = getRawResourceStream(context, keyStoreResourceUri);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(keyStoreInput, password);
        keyStoreInput.close();

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("X509");
        keyManagerFactory.init(keyStore, password);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), new TrustManager[]{new BlindTrustManager()}, null);

        return sslContext.getServerSocketFactory();
    }

    static PrivateKey getPrivateKeyFromPEM(byte[] keyBytes) throws Exception {
        String pem = new String(keyBytes);
        PemReader pemReader = new PemReader(new java.io.StringReader(pem));
        PemObject pemObject = pemReader.readPemObject();
        byte[] pemContent = pemObject.getContent();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemContent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    public static TrustManager getTrustManager() {
        KeyStore keyStore2 = keyStore;

        try {
            return new ClientTrustManager(keyStore2);
        } catch (KeyStoreException e6) {
            Log.e("TrustManager", "TrustManagerFactory KeyStoreException: " + e6);
            return null;
        } catch (NoSuchAlgorithmException e7) {
            Log.e("TrustManager", "TrustManagerFactory NoSuchAlgorithmException: " + e7);
            return null;
        }
    }

    /**
     * Creates an SSLSocketFactory instance for use with the CA provided in the resource file.
     *
     * @param context        Context used to open up the CA file
     * @param rawResourceUri Raw resource file to the CA (in .crt or .cer format, for instance)
     * @return An SSLSocketFactory which trusts the provided CA when provided to network clients
     */
    static SSLSocketFactory createCustomTrustedSocketFactory(
        @NonNull final Context context, 
        @NonNull final String rawResUriCert, 
        @NonNull final String rawResUriKey) throws IOException, GeneralSecurityException {
        Log.d(LOG_TAG, "Entering createCustomTrustedSocketFactory");
        boolean logCA = true;
        Certificate ca = null;

        if (logCA) {
            InputStream caInput = getRawResourceStream(context, rawResUriCert);
            Log.d(LOG_TAG, "rawResUriCert: " + rawResUriCert);
            // Read the input stream into a byte array
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = caInput.read(buffer)) != -1) {
                byteArrayOutputStream.write(buffer, 0, bytesRead);
            }
            byte[] caBytes = byteArrayOutputStream.toByteArray();
            caInput.close();

            // Convert the byte array to a string and log it
            String caContent = new String(caBytes);
            Log.d("CA Content", caContent);

            // Convert the byte array back to InputStream
            InputStream caInputForCert = new ByteArrayInputStream(caBytes);

            // Generate the CA Certificate from the raw resource file
            ca = CertificateFactory.getInstance("X.509").generateCertificate(caInputForCert);
            caInputForCert.close();
        } else {

            InputStream caInput = getRawResourceStream(context, rawResUriCert);
            // Generate the CA Certificate from the raw resource file
            ca = CertificateFactory.getInstance("X.509").generateCertificate(caInput);
            caInput.close();
        }

        Log.d(LOG_TAG, "rawResUriKey: " + rawResUriKey);

        InputStream keyInput = getRawResourceStream(context, rawResUriKey);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] keyBuffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = keyInput.read(keyBuffer)) != -1) {
            byteArrayOutputStream.write(keyBuffer, 0, bytesRead);
        }
        byte[] keyBytes = byteArrayOutputStream.toByteArray();
        keyInput.close();
        PrivateKey privateKey = null;
        try {
            privateKey = getPrivateKeyFromPEM(keyBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }


        // Load the key store using the CA
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null, null);
        keyStore.setKeyEntry("lota-remotectl-atv", privateKey, null, new Certificate[]{ca});
        keyStore.setCertificateEntry("lota-remotectl-atv-cert", ca);

        // Initialize the TrustManager with this CA
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, new char[0]);

        //TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        //tmf.init(keyStore);
        TrustManager trustManager = getTrustManager();

        // Create an SSL context that uses the created trust manager
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), new TrustManager[]{trustManager}, null);
        //sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
        return sslContext.getSocketFactory();
    }

    private static InputStream getRawResourceStream(@NonNull final Context context, @NonNull final String resourceUri) throws IOException {
        final int resId = getResourceId(context, resourceUri);
        if (resId == 0)
            return URI.create(resourceUri).toURL().openStream(); // From metro on development
        else return context.getResources().openRawResource(resId); // From bundle in production
    }

    @RawRes
    private static int getResourceId(@NonNull final Context context, @NonNull final String resourceUri) {
        String name = resourceUri.toLowerCase().replace("-", "_");
        try {
            return Integer.parseInt(name);
        } catch (NumberFormatException ex) {
            return context.getResources().getIdentifier(name, "raw", context.getPackageName());
        }
    }

    private static class BlindTrustManager implements X509TrustManager {
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        @SuppressLint("TrustAllX509TrustManager")
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @SuppressLint("TrustAllX509TrustManager")
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }
    }
}
