package ru.voskhod.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;

public class PipeInputStream extends InputStream {

    private static final int MAX_UPDATE = 65535;

    private final InputStream wrapped;
    private final MessageDigest digest;

    // for non-streamed providers
    private final byte[] digestResult;

    private boolean exhausted = false;
    private long size = 0;

    public PipeInputStream(InputStream arg, MessageDigest argDigest) {
        this.wrapped = arg;
        this.digest = argDigest;
        this.digestResult = null;
    }

    public PipeInputStream(byte[] digestResult) {
        this.wrapped = null;
        this.digest = null;
        this.digestResult = digestResult;
    }

    public byte[] getDigest() {
        return digest != null ? digest.digest() : digestResult;
    }

    public long getSize() {
        return size;
    }

    @Override
    public void close() throws IOException {
        if (wrapped != null) {
            wrapped.close();
        }
    }

    @Override
    public boolean markSupported() {
        return false;
    }

    @Override
    public int read() throws IOException {
        if (wrapped == null || exhausted)
            return -1;

        int value = wrapped.read();
        if (value < 0) {
            exhausted = true;
        } else {
            size++;
            digest.update((byte) value);
        }
        return value;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (wrapped == null || exhausted)
            return -1;

        int read = wrapped.read(b, off, len);
        if (read < 0) {
            exhausted = true;
        } else {
            size += read;
            int updOff = off;
            int updLen = read;
            while (updLen > MAX_UPDATE) {
                digest.update(b, updOff, MAX_UPDATE);
                updOff += MAX_UPDATE;
                updLen -= MAX_UPDATE;
            }
            digest.update(b, updOff, updLen);
            return read;
        }
        return read;
    }
}
