package ru.voskhod.crypto.impl;

import com.google.common.base.Charsets;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import ru.voskhod.crypto.KeyStoreWrapper;

import java.nio.CharBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public final class CachingKeyStoreWrapper implements KeyStoreWrapper {

    private final KeyStoreWrapper original;
    private final Cache<String, PKEntry> keyCache;
    private final LoadingCache<String, X509Certificate> certCache;

    public CachingKeyStoreWrapper(KeyStoreWrapper keyStore, CacheOptions options) {
        this.original = keyStore;
        CacheBuilder<Object, Object> builder = CacheBuilder.newBuilder();
        if (options.getExpireAfterAccess() != null) {
            builder.expireAfterAccess(options.getExpireAfterAccess().longValue(), TimeUnit.MILLISECONDS);
        }
        if (options.getExpireAfterWrite() != null) {
            builder.expireAfterWrite(options.getExpireAfterWrite().longValue(), TimeUnit.MILLISECONDS);
        }
        if (options.getMaxSize() != null) {
            builder.maximumSize(options.getMaxSize().longValue());
        }
        if (options.isCachePrivateKeys()) {
            keyCache = builder.build();
        } else {
            keyCache = null;
        }
        if (options.isCacheCertificates()) {
            certCache = builder.build(new CacheLoader<String, X509Certificate>() {
                public X509Certificate load(String key) throws Exception {
                    return original.getX509Certificate(key);
                }
            });
        } else {
            certCache = null;
        }
    }

    @SuppressWarnings("unchecked")
    private static <T extends Exception> void checkException(Throwable ex, Class<T> cls) throws T {
        if (cls.isInstance(ex)) {
            throw (T) ex;
        }
    }

    private static byte[] hash(char[] password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] data = Charsets.UTF_16.encode(CharBuffer.wrap(password)).array();
        md.update(data);
        return md.digest();
    }

    @Override
    public PrivateKey getPrivateKey(final String alias, final char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (keyCache == null) {
            return original.getPrivateKey(alias, password);
        } else {
            try {
                PKEntry entry = keyCache.get(alias, new Callable<PKEntry>() {
                    public PKEntry call() throws Exception {
                        PrivateKey pk = original.getPrivateKey(alias, password);
                        return new PKEntry(pk, hash(password));
                    }
                });
                if (!Arrays.equals(hash(password), entry.passHash))
                    throw new UnrecoverableKeyException("Wrong password!");
                return entry.pk;
            } catch (ExecutionException ex) {
                Throwable cause = ex.getCause();
                checkException(cause, KeyStoreException.class);
                checkException(cause, NoSuchAlgorithmException.class);
                checkException(cause, UnrecoverableKeyException.class);
                checkException(cause, RuntimeException.class);
                throw new RuntimeException(cause);
            }
        }
    }

    @Override
    public X509Certificate getX509Certificate(String alias) throws CertificateException, KeyStoreException {
        if (certCache == null) {
            return original.getX509Certificate(alias);
        } else {
            try {
                return certCache.get(alias);
            } catch (ExecutionException ex) {
                Throwable cause = ex.getCause();
                checkException(cause, CertificateException.class);
                checkException(cause, KeyStoreException.class);
                checkException(cause, RuntimeException.class);
                throw new RuntimeException(cause);
            }
        }
    }

    @Override
    public KeyStore getKeyStore() {
        return original.getKeyStore();
    }

    private static final class PKEntry {

        private final PrivateKey pk;
        private final byte[] passHash;

        private PKEntry(PrivateKey pk, byte[] passHash) {
            this.pk = pk;
            this.passHash = passHash;
        }
    }
}
