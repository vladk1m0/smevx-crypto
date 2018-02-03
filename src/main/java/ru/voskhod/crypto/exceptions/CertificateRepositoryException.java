package ru.voskhod.crypto.exceptions;

public class CertificateRepositoryException extends Exception {

    private static final long serialVersionUID = -4609868686143002522L;

    public CertificateRepositoryException(Throwable cause) {
        super(cause);
    }

    public CertificateRepositoryException(String message, Throwable cause) {
        super(message, cause);
    }
}
