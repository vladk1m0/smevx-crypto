package ru.voskhod.crypto;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public interface KeyStoreWrapper {

    PrivateKey getPrivateKey(String alias, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException;

    X509Certificate getX509Certificate(String alias) throws CertificateException, KeyStoreException;

    java.security.KeyStore getKeyStore();
}
