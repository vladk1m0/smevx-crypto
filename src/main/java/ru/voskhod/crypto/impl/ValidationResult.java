package ru.voskhod.crypto.impl;

import java.security.cert.X509Certificate;

public class ValidationResult {

    private X509Certificate certificate;
    private boolean valid;
    private String error;
    private Exception exception;

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public Exception getException() {
        return exception;
    }

    public void setException(Exception exception) {
        this.exception = exception;
    }

    @Override
    public String toString() {
        return "\nValidationResult{" +
                "certificate=" + certificate +
                ", valid=" + valid +
                ", error='" + error + '\'' +
                ", exception=" + exception +
                '}';
    }
}
