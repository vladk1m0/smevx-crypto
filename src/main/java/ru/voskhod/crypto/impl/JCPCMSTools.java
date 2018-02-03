package ru.voskhod.crypto.impl;

public class JCPCMSTools {

    /**
     * OIDs для CMS
     */
    public static final String OID_PKCS7 = "1.2.840.113549.1.7";
    public static final String OID_PKCS9 = "1.2.840.113549.1.9";

    // ====== PKCS#7 content types =======
    // data
    public static final String STR_CMS_OID_DATA = OID_PKCS7 + ".1";
    // signedData
    public static final String STR_CMS_OID_SIGNED = OID_PKCS7 + ".2";
    // envelopedData
    public static final String STR_CMS_OID_ENVELOPED = OID_PKCS7 + ".3";
    // signedAndEnvelopedData
    public static final String STR_CMS_OID_SIGNED_AND_ENVELOPED = OID_PKCS7 + ".4";
    // digestedData
    public static final String STR_CMS_OID_DIGESTED = OID_PKCS7 + ".5";
    // encryptedData
    public static final String STR_CMS_OID_ENCRYPTED = OID_PKCS7 + ".6";

    // ====== PKCS#9 OIDs =======
    // contentType
    public static final String STR_CMS_OID_CONT_TYP_ATTR = OID_PKCS9 + ".3";
    // messageDigest
    public static final String STR_CMS_OID_DIGEST_ATTR = OID_PKCS9 + ".4";
    // Signing Time
    public static final String STR_CMS_OID_SIGN_TYM_ATTR = OID_PKCS9 + ".5";
    // Time-stamp token
    public static final String STR_CMS_OID_TS = OID_PKCS9 + ".4";

    // ====== OIDs алгоритмов ГОСТ ======
    // GOST R 34.11-94 - Russian hash algorithm.
    public static final String DIGEST_OID = "1.2.643.2.2.9";
    // GOST R 34.10-2001 - Russian encryption algorithm
    public static final String SIGN_OID = "1.2.643.2.2.19";

    /**
     * GOST digest and sig identifiers
     */
    public static final String GOST_EL_SIGN_NAME = "GOST3411withGOST3410EL";
    public static final String GOST_DIGEST_NAME = "GOST3411";

}