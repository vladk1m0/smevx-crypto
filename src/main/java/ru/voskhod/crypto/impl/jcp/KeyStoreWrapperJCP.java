package ru.voskhod.crypto.impl.jcp;

import ru.voskhod.crypto.KeyStoreWrapper;

import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class KeyStoreWrapperJCP implements KeyStoreWrapper {

    private final KeyStore ks;

    /**
     * Загружает хранилище ключей указанного типа.
     */
    public KeyStoreWrapperJCP() throws Exception {
        ks = KeyStore.getInstance("HDImageStore");
        ks.load(null);
    }

    public PrivateKey getPrivateKey(String alias, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return (PrivateKey) ks.getKey(alias, password);
    }

    public X509Certificate getX509Certificate(String alias) throws CertificateException, KeyStoreException {
        X509Certificate certificate = (X509Certificate) ks.getCertificate(alias);
        if (certificate == null)
            return null;
        return (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
    }

    public KeyStore getKeyStore() {
        return ks;
    }
}
