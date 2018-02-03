package ru.voskhod.crypto.impl;

public final class CacheOptions {

    private Long expireAfterAccess = null;
    private Long expireAfterWrite = null;
    private Long maxSize = null;
    private boolean cachePrivateKeys = false;
    private boolean cacheCertificates = false;

    public CacheOptions expireAfterAccess(long ms) {
        expireAfterAccess = ms;
        return this;
    }

    public CacheOptions expireAfterWrite(long ms) {
        expireAfterWrite = ms;
        return this;
    }

    public CacheOptions maxSize(long size) {
        maxSize = size;
        return this;
    }

    public CacheOptions cachePrivateKeys() {
        cachePrivateKeys = true;
        return this;
    }

    public CacheOptions cacheCertificates() {
        cacheCertificates = true;
        return this;
    }

    public Long getExpireAfterAccess() {
        return expireAfterAccess;
    }

    public Long getExpireAfterWrite() {
        return expireAfterWrite;
    }

    public Long getMaxSize() {
        return maxSize;
    }

    public boolean isCachePrivateKeys() {
        return cachePrivateKeys;
    }

    public boolean isCacheCertificates() {
        return cacheCertificates;
    }
}
