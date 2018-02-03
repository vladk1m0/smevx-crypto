package ru.voskhod.crypto.exceptions;

public class SigLibInitializationException extends RuntimeException {

    private static final long serialVersionUID = -4592247998950557205L;

    public SigLibInitializationException(Throwable cause) {
        super(cause);
    }

    public SigLibInitializationException(String message, Throwable cause) {
        super(message, cause);
    }

    public SigLibInitializationException(String message) {
        super(message);
    }
}
