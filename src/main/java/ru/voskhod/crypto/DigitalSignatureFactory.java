package ru.voskhod.crypto;

import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;
import org.apache.xml.security.transforms.Transform;
import ru.voskhod.crypto.exceptions.SigLibInitializationException;
import ru.voskhod.crypto.impl.CacheOptions;
import ru.voskhod.crypto.impl.CachingKeyStoreWrapper;
import ru.voskhod.crypto.impl.DigitalSignatureProcessorImpl;
import ru.voskhod.crypto.impl.SmevTransformSpi;
import ru.voskhod.crypto.impl.csp_tj.TrustedKeyStoreWrapperCSP;
import ru.voskhod.crypto.impl.jcp.KeyStoreWrapperJCP;

public class DigitalSignatureFactory {

    public static final String CSP_TJ_PROVIDER_NAME = "DIGT";
    public static final String JCP_PROVIDER_NAME = "JCP";
    private static String providerName = null;
    private static volatile DigitalSignatureProcessor processor = null;
    private static volatile KeyStoreWrapper keyStoreWrapper = null;

    public static synchronized void init(KeyStoreWrapper keyStoreWrapper, DigitalSignatureProcessor processor) throws SigLibInitializationException {
        DigitalSignatureFactory.keyStoreWrapper = keyStoreWrapper;
        DigitalSignatureFactory.processor = processor;
    }

    public static synchronized void init(String providerName) throws SigLibInitializationException {
        if (processor == null) {
            if (providerName == null) {
                throw new IllegalArgumentException("Метод вызван впервые. Должно быть задано имя провайдера");
            }
            try {
                if (CSP_TJ_PROVIDER_NAME.equals(providerName)) {
                    initXmlSec("com.digt.trusted.xmlsig.SignatureStraightGostR34102001GostR3411");
                    keyStoreWrapper = new TrustedKeyStoreWrapperCSP();
                } else if (JCP_PROVIDER_NAME.equals(providerName)) {
                    initXmlSec("ru.CryptoPro.JCPxml.xmldsig.SignatureGostR34102001$SignatureGostR34102001GostR3411");
                    keyStoreWrapper = new KeyStoreWrapperJCP();
                } else {
                    throw new SigLibInitializationException("Процессор для запрошенного провайдера не найден!");
                }
            } catch (SigLibInitializationException e) {
                throw e;
            } catch (Exception e) {
                throw new SigLibInitializationException("Не удалось инищиализировать фабрику!", e);
            }
            DigitalSignatureFactory.providerName = providerName;
            processor = new DigitalSignatureProcessorImpl();
        } else {
            if (!DigitalSignatureFactory.providerName.equals(providerName)) {
                throw new SigLibInitializationException("Процессор уже инициализирован для криптопровайдера: " + DigitalSignatureFactory.providerName + "!");
            }
        }
    }

    /**
     * Все что происходит здесь - магия. В теории этого делать не нужно, т.к. необходимый конфиг лежит внутри Trusted Java, но без этого не работает.
     * Желающие могут разобратся.
     *
     * @throws ru.voskhod.crypto.exceptions.SigLibInitializationException В слуючае если произошли проблемы.
     *//*
    private static void initXmlSec(String algorithmClassName) throws SigLibInitializationException {
        try {

            // При формировании элемента Signature будут убраны все разрывы между элементами.
            System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");

            // Регистрируем реализации алгоритмов в xmlsec.
            try {
                Class.forName(algorithmClassName);
                SignatureAlgorithm.providerInit();
                SignatureAlgorithm.register(DigitalSignatureProcessorImpl.XMLDSIG_SIGN_METHOD, algorithmClassName);
            } catch (org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException e) {
                // скорее всего кто то уже зарегистрировал этот алгоритм до нас
            } catch (Exception e) {
                    throw new SigLibInitializationException("Не удалось зарегистрировать алгоритм: " + DigitalSignatureProcessorImpl.XMLDSIG_SIGN_METHOD + "/" + algorithmClassName + ". Убедитесь что выбраный провайдер действительно установлен!", e);
            }

            // Готовим конфиг маппинга алгоритмов для JCEMapper.
            String NameSpace = "http://www.xmlsecurity.org/NS/#configuration";
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            Document doc = dbf.newDocumentBuilder().newDocument();
            Element root = doc.createElementNS(NameSpace, "JCEAlgorithmMappings");
            Element algs = doc.createElementNS(NameSpace, "Algorithms");
            Element el1 = doc.createElementNS(NameSpace, "Algorithm");
            // Подпись по ГОСТу.
            el1.setAttribute("URI", DigitalSignatureProcessorImpl.DIGEST_METHOD);
            el1.setAttribute("Description", "GOST R 3411 Digest");
            el1.setAttribute("AlgorithmClass", "MessageDigest");
            el1.setAttribute("RequirementLevel", "OPTIONAL");
            el1.setAttribute("JCEName", "GOST3411");
            algs.appendChild(el1);
            Element el2 = doc.createElementNS(NameSpace, "Algorithm");
            el2.setAttribute("URI", DigitalSignatureProcessorImpl.XMLDSIG_SIGN_METHOD);
            el2.setAttribute("Description", "GOST R 34102001 Digital Signature Algorithm with GOST R 3411 Digest");
            el2.setAttribute("AlgorithmClass", "Signature");
            el2.setAttribute("RequirementLevel", "OPTIONAL");
            el2.setAttribute("JCEName", "GOST3411withGOST3410EL");
            algs.appendChild(el2);
            // SAML отправка.
            Element el3 = doc.createElementNS(NameSpace, "Algorithm");
            el3.setAttribute("URI", "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
            el3.setAttribute("Description", "RSA Signature with SHA-1 message digest");
            el3.setAttribute("AlgorithmClass", "Signature");
            el3.setAttribute("RequirementLevel", "RECOMMENDED");
            el3.setAttribute("JCEName", "SHA1withRSA");
            algs.appendChild(el3);
            // SAML получение.
            Element el4 = doc.createElementNS(NameSpace, "Algorithm");
            el4.setAttribute("URI", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
            el4.setAttribute("Description", "Key Transport RSA-OAEP");
            el4.setAttribute("AlgorithmClass", "KeyTransport");
            el4.setAttribute("RequirementLevel", "REQUIRED");
            el4.setAttribute("RequiredKey", "RSA");
            el4.setAttribute("JCEName", "RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            algs.appendChild(el4);
            Element el5 = doc.createElementNS(NameSpace, "Algorithm");
            el5.setAttribute("URI", "http://www.w3.org/2001/04/xmlenc#aes128-cbc");
            el5.setAttribute("Description", "Block encryption using AES with a key length of 128 bit");
            el5.setAttribute("AlgorithmClass", "BlockEncryption");
            el5.setAttribute("RequirementLevel", "REQUIRED");
            el5.setAttribute("KeyLength", "128");
            el5.setAttribute("RequiredKey", "AES");
            el5.setAttribute("JCEName", "AES/CBC/ISO10126Padding");
            algs.appendChild(el5);
            // SAML и когда-то потом еще нужен.
            root.appendChild(algs);
            doc.appendChild(root);
            Element el6 = doc.createElementNS(NameSpace, "Algorithm");
            el6.setAttribute("URI", "http://www.w3.org/2000/09/xmldsig#sha1");
            el6.setAttribute("Description", "SHA-1 message digest");
            el6.setAttribute("AlgorithmClass", "MessageDigest");
            el6.setAttribute("RequirementLevel", "REQUIRED");
            el6.setAttribute("JCEName", "SHA-1");
            algs.appendChild(el6);
            // Обязательная инициализация xmlsec.
            org.apache.xml.security.Init.init();

            // Реализация дополнительной трансформации.
            try {
                Transform.register(SmevTransformSpi.ALGORITHM_URN, SmevTransformSpi.class.getName());
            } catch (org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException e) {
                // скорее всего кто то уже зарегистрировал этот алгоритм до нас
            } catch (Exception e) {
                    throw e;
            }

            // Передаем собраный конфиг.
            JCEMapper.init(root);

        } catch (SigLibInitializationException e) {
            throw e;
        } catch (Exception e) {
            throw new SigLibInitializationException("Возникли проблемы при инициализации XmlSec!", e);
        }
    }*/

    /**
     * Все что происходит здесь - магия. В теории этого делать не нужно, т.к. необходимый конфиг лежит внутри Trusted Java, но без этого не работает.
     * Желающие могут разобратся.
     *
     * @throws ru.voskhod.crypto.exceptions.SigLibInitializationException В слуючае если произошли проблемы.
     */
    private static void initXmlSec(String algorithmClassName) throws SigLibInitializationException {
        try {

            // При формировании элемента Signature будут убраны все разрывы между элементами.
            System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");

            //Добавил инициализацию из документации jsp : jcp-build-2.0.37027

            //Перед началом использования классов из библиотеки XML Security необходимо зарегистрировать ГОСТ алгоритмы.

            //initByJCPXmlXmlInit();
            initByXmlSecurityWithConfig();

            try {
                // Реализация дополнительной трансформации.
                Transform.register(SmevTransformSpi.ALGORITHM_URN, SmevTransformSpi.class.getName());
            } catch (AlgorithmAlreadyRegisteredException e) {
                //Ignore this exception
            }

        } catch (SigLibInitializationException e) {
            throw e;
        } catch (Exception e) {
            throw new SigLibInitializationException("Возникли проблемы при инициализации XmlSec!", e);
        }
    }

    /**
     * Метод для инециализации ГОСТ алгоритмов в библиотеке XML Security по средствам вызова стандартного инициализатора org.apache.xml.security.init
     * <p>
     * Перед началом использования классов из библиотеки XML Security необходимо зарегистрировать ГОСТ алгоритмы.
     * Это можнжо сделать вызовом метода ru.CryptoPro.JCPxml.XmlInit.init()
     * (старый метод ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit.init() тоже поддерживается).
     * <p>
     * Данный метод работает с jcp-build-2.0.37027 если в jre/lib/ext/ библиотека xmlsec версии 1.4
     * <p>
     * Использовать только если библиотека xmlsec версии 1.4
     */
    private static void initByJCPXmlXmlInit() {
        System.out.println("ru.CryptoPro.JCPxml.XmlInit.isInitialized() before:" + ru.CryptoPro.JCPxml.XmlInit.isInitialized());
        if (!ru.CryptoPro.JCPxml.XmlInit.isInitialized()) {
            ru.CryptoPro.JCPxml.XmlInit.init();
        }
        System.out.println("ru.CryptoPro.JCPxml.XmlInit.isInitialized() after:" + ru.CryptoPro.JCPxml.XmlInit.isInitialized());
    }

    /**
     * Метод для инециализации ГОСТ алгоритмов в библиотеке XML Security по средствам JCPxml
     * <p>
     * Перед началом использования классов из библиотеки XML Security необходимо зарегистрировать ГОСТ алгоритмы.
     * <p>
     * Это можнжо сделать вызовом стандартного инициализатора org.apache.xml.security.Init.init(),
     * который обязателен при работе с библиотекий XML Security,
     * но с предварительно установленным свойством
     * System.setProperty("org.apache.xml.security.resource.config", "resource/jcp.xml")
     * <p>
     * Данный метод работает с jcp-build-2.0.37027 если в jre/lib/ext/ библиотека xmlsec версии 1.5
     * <p>
     * Использовать только если библиотека xmlsec версии 1.4 или 1.5
     */
    private static void initByXmlSecurityWithConfig() {
        System.setProperty("org.apache.xml.security.resource.config", "resource/jcp.xml");
        System.out.println("org.apache.xml.security.Init.isInitialized(): " + org.apache.xml.security.Init.isInitialized());
        if (!org.apache.xml.security.Init.isInitialized()) {
            org.apache.xml.security.Init.init();
        }
        System.out.println("org.apache.xml.security.Init.isInitialized(): " + org.apache.xml.security.Init.isInitialized());
    }

    public static DigitalSignatureProcessor getDigitalSignatureProcessor() throws SigLibInitializationException {
        DigitalSignatureProcessor p = processor;
        if (p == null) {
            throw new SigLibInitializationException("Перед использованием фабрику необходимо инициализировать!");
        }
        return p;
    }

    public static KeyStoreWrapper getKeyStoreWrapper() throws SigLibInitializationException {
        return getKeyStoreWrapper(null);
    }

    public static KeyStoreWrapper getKeyStoreWrapper(CacheOptions options) throws SigLibInitializationException {
        KeyStoreWrapper ks = keyStoreWrapper;
        if (ks == null) {
            throw new SigLibInitializationException("Перед использованием фабрику необходимо инициализировать!");
        }
        if (options == null) {
            return ks;
        } else {
            return new CachingKeyStoreWrapper(ks, options);
        }
    }
}
