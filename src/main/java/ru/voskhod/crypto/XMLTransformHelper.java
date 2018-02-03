package ru.voskhod.crypto;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class XMLTransformHelper {

    private static final Logger LOGGER = Logger.getLogger(XMLTransformHelper.class.getName());

    public static String elementToString(Element element) {
        return elementToString(element, false);
    }

    public static Element findElement(Element parent, String uri, String localName) {
        NodeList nl = parent.getElementsByTagNameNS(uri, localName);
        if (nl.getLength() > 0) {
            return (Element) nl.item(0);
        } else {
            return null;
        }
    }

    public static synchronized Transformer getSyncTransformer() throws TransformerConfigurationException {
        TransformerFactory tf = TransformerFactory.newInstance();
        return tf.newTransformer();
    }

    public static String elementToString(Element element, boolean omitxmldeclaration) {
        try {
            DOMSource domSource = new DOMSource(element);
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);

            Transformer transformer = getSyncTransformer();
            if (omitxmldeclaration) {
                transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            }
            transformer.transform(domSource, result);
            writer.flush();
            String xml = writer.toString();
            writer.close();
            transformer.reset();
            return xml;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, null, e);
        }
        return null;
    }

    public static String documentToString(Document arg, boolean omitxmldeclaration) {
        try {
            DOMSource domSource = new DOMSource(arg);
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);

            Transformer transformer = getSyncTransformer();
            if (omitxmldeclaration) {
                transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            }
            transformer.transform(domSource, result);
            writer.flush();
            String xml = writer.toString();
            writer.close();
            transformer.reset();
            return xml;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, null, e);
        }
        return null;
    }

    public static void documentToFile(Document arg, File dst, boolean omitxmldeclaration) {
        try {
            DOMSource domSource = new DOMSource(arg);
            OutputStream out = new FileOutputStream(dst);
            StreamResult result = new StreamResult(out);

            Transformer transformer = getSyncTransformer();
            if (omitxmldeclaration) {
                transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            }
            transformer.transform(domSource, result);
            out.flush();
            out.close();
            transformer.reset();
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, null, e);
        }
    }

    public static Document buildDocumentFromString(String xml) {
        return buildDocumentFromString(xml, true);
    }

    public static Document buildDocumentFromString(String xml, boolean namespaceaware) {
        try {
            StringReader reader = new StringReader(xml);
            InputSource is = new InputSource();
            is.setCharacterStream(reader);
            return buildDocumentFromSource(is, namespaceaware);
        } catch (Exception ex) {
            LOGGER.log(Level.SEVERE, null, ex);
            throw new RuntimeException(ex);
        }
    }

    public static Document buildDocumentFromFile(String fileName) {
        return buildDocumentFromFile(fileName, true);
    }

    public static Document buildDocumentFromFile(String fileName, boolean namespaceaware) {
        try (Reader reader = new FileReader(fileName)) {
            InputSource is = new InputSource();
            is.setCharacterStream(reader);
            return buildDocumentFromSource(is, namespaceaware);
        } catch (Exception ex) {
            LOGGER.log(Level.SEVERE, null, ex);
            throw new RuntimeException(ex);
        }
    }

    public static DocumentBuilder getSyncDocumentBuilder(boolean namespaceAware) throws ParserConfigurationException {
        return getSyncDocumentBuilder(namespaceAware, false, false);
    }

    public static synchronized DocumentBuilder getSyncDocumentBuilder(boolean namespaceAware, boolean coalescing, boolean ignoringElementContentWhitespace) throws ParserConfigurationException {
        DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
        domFactory.setNamespaceAware(namespaceAware);
        domFactory.setCoalescing(coalescing);
        domFactory.setIgnoringElementContentWhitespace(ignoringElementContentWhitespace);
        return domFactory.newDocumentBuilder();
    }

    public static Document getXMLDocument(String xml) throws Exception {
        DocumentBuilder builder = getSyncDocumentBuilder(true);

        try {
            InputSource is = new InputSource();
            StringReader reader = new StringReader(xml);
            is.setCharacterStream(reader);
            //Parse the document
            Document document = builder.parse(is);
            builder.reset();
            return document;
        } finally {
            builder.reset(); // todo: зачем???
        }
    }

    public static Document newDocument(boolean namespaceaware) throws Exception {
        DocumentBuilder builder = getSyncDocumentBuilder(namespaceaware);
        Document doc = builder.newDocument();
        builder.reset();
        return doc;
    }

    public static Document buildDocumentFromSource(InputSource is, boolean namespaceaware) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilder builder = getSyncDocumentBuilder(namespaceaware);
        //Parse the document
        Document doc = builder.parse(is);
        builder.reset();
        return doc;
    }

    public static String getXMLDocumentNamespace(Element doc) {
        return doc.getNamespaceURI();
    }
}
