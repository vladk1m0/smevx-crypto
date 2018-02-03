package ru.voskhod.crypto.impl;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.TransformSpi;
import org.apache.xml.security.transforms.TransformationException;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.*;
import javax.xml.stream.events.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.*;

/**
 * Класс, реализующий алгоритм трансформации "urn://smev-gov-ru/xmldsig/transform" для Apache Santuario.
 *
 * @author dpryakhin
 */
public class SmevTransformSpi extends TransformSpi {

    public static final String ALGORITHM_URN = "urn://smev-gov-ru/xmldsig/transform";
    private static final String ENCODING_UTF_8 = "UTF-8";

    // private static Logger logger = LoggerFactory.getLogger(SmevTransformSpi.class);
    private static final AttributeSortingComparator attributeSortingComparator = new AttributeSortingComparator();

    private static final ThreadLocal<XMLInputFactory> inputFactory =
            new ThreadLocal<XMLInputFactory>() {
                @Override
                protected XMLInputFactory initialValue() {
                    return XMLInputFactory.newInstance();
                }
            };

    private static final ThreadLocal<XMLOutputFactory> outputFactory =
            new ThreadLocal<XMLOutputFactory>() {
                @Override
                protected XMLOutputFactory initialValue() {
                    return XMLOutputFactory.newInstance();
                }
            };

    private static final ThreadLocal<XMLEventFactory> eventFactory =
            new ThreadLocal<XMLEventFactory>() {
                @Override
                protected XMLEventFactory initialValue() {
                    return XMLEventFactory.newInstance();
                }
            };

	/*static {
		logger.info("Loading SmevTransformSpi");
	}
	
	public SmevTransformSpi() {
		logger.info("Creating new instance of " + SmevTransformSpi.class.getCanonicalName());
	}*/

    private static String findPrefix(String argNamespaceURI, Stack<List<Namespace>> argMappingStack) {
        if (argNamespaceURI == null) {
            throw new IllegalArgumentException("No namespace элементы не поддерживаются.");
        }

        for (List<Namespace> elementMappingList : argMappingStack) {
            for (Namespace mapping : elementMappingList) {
                if (argNamespaceURI.equals(mapping.getNamespaceURI())) {
                    return mapping.getPrefix();
                }
            }
        }
        return null;
    }

    @Override
    protected String engineGetURI() {
        return ALGORITHM_URN;
    }

    @Override
    protected XMLSignatureInput enginePerformTransform(XMLSignatureInput argInput,
                                                       OutputStream argOutput, Transform argTransform) throws IOException,
            CanonicalizationException, InvalidCanonicalizerException,
            TransformationException, ParserConfigurationException, SAXException {

        if (argOutput == null)
            return enginePerformTransform(argInput);
        else {
            process(argInput.getOctetStream(), argOutput);
            XMLSignatureInput result = new XMLSignatureInput((byte[]) null);
            result.setOutputStream(argOutput);
            return result;
        }
    }

    @Override
    protected XMLSignatureInput enginePerformTransform(XMLSignatureInput argInput,
                                                       Transform argTransform) throws IOException, CanonicalizationException,
            InvalidCanonicalizerException, TransformationException,
            ParserConfigurationException, SAXException {

        return enginePerformTransform(argInput);
    }

    @Override
    protected XMLSignatureInput enginePerformTransform(XMLSignatureInput argInput)
            throws IOException, CanonicalizationException,
            InvalidCanonicalizerException, TransformationException,
            ParserConfigurationException, SAXException {

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        process(argInput.getOctetStream(), result);
        byte[] postTransformData = result.toByteArray();

        return new XMLSignatureInput(postTransformData);
    }

    @SuppressWarnings("unchecked")
    public void process(InputStream argSrc, OutputStream argDst) throws TransformationException {

        Stack<List<Namespace>> prefixMappingStack = new Stack<>();
        XMLEventReader src = null;
        XMLEventWriter dst = null;
        try {
            src = inputFactory.get().createXMLEventReader(argSrc, ENCODING_UTF_8);
            dst = outputFactory.get().createXMLEventWriter(argDst, ENCODING_UTF_8);
            XMLEventFactory factory = eventFactory.get();

            int prefixCnt = 1;
            while (src.hasNext()) {
                XMLEvent event = src.nextEvent();

                if (event.isCharacters()) {
                    String data = event.asCharacters().getData();
                    // Отсекаем whitespace symbols.
                    if (!data.trim().isEmpty()) {
                        dst.add(event);
                    }
                    continue;
                } else if (event.isStartElement()) {
                    List<Namespace> myPrefixMappings = new LinkedList<>();
                    prefixMappingStack.push(myPrefixMappings);

                    // Обработка элемента: NS prefix rewriting.
                    // N.B. Элементы в unqualified form не поддерживаются.
                    StartElement srcEvent = (StartElement) event;
                    String nsURI = srcEvent.getName().getNamespaceURI();
                    String prefix = findPrefix(nsURI, prefixMappingStack);

                    if (prefix == null) {
                        prefix = "ns" + String.valueOf(prefixCnt++);
                        myPrefixMappings.add(factory.createNamespace(prefix, nsURI));
                    }
                    StartElement dstEvent = factory.createStartElement(prefix, nsURI, srcEvent.getName().getLocalPart());
                    dst.add(dstEvent);

                    // == Обработка атрибутов. Два шага: отсортировать, промэпить namespace URI. ==
                    Iterator<Attribute> srcAttributeIterator = srcEvent.getAttributes();
                    // Положим атрибуты в list, чтобы их можно было отсортировать.
                    List<Attribute> srcAttributeList = new LinkedList<>();
                    while (srcAttributeIterator.hasNext()) {
                        srcAttributeList.add(srcAttributeIterator.next());
                    }
                    // Сортировка атрибутов по алфавиту.
                    Collections.sort(srcAttributeList, attributeSortingComparator);

                    // Обработка префиксов. Аналогична обработке префиксов элементов,
                    // за исключением того, что у атрибут может не иметь namespace.
                    List<Attribute> dstAttributeList = new LinkedList<>();
                    for (Attribute srcAttribute : srcAttributeList) {
                        String attributeNsURI = srcAttribute.getName().getNamespaceURI();
                        String attributeLocalName = srcAttribute.getName().getLocalPart();
                        String value = srcAttribute.getValue();
                        Attribute dstAttribute;
                        if (attributeNsURI != null && !"".equals(attributeNsURI)) {
                            String attributePrefix = findPrefix(attributeNsURI, prefixMappingStack);
                            if (attributePrefix == null) {
                                attributePrefix = "ns" + String.valueOf(prefixCnt++);
                                myPrefixMappings.add(factory.createNamespace(attributePrefix, attributeNsURI));
                            }
                            dstAttribute = factory.createAttribute(attributePrefix, attributeNsURI, attributeLocalName, value);
                        } else {
                            dstAttribute = factory.createAttribute(attributeLocalName, value);
                        }
                        dstAttributeList.add(dstAttribute);
                    }

                    // Высести namespace prefix mappings для текущего элемента.
                    // Их порядок детерминирован, т.к. перед мэппингом атрибуты были отсортированы.
                    // Поэтому дополнительной сотрировки здесь не нужно.
                    for (Namespace mapping : myPrefixMappings) {
                        dst.add(mapping);
                    }

                    // Вывести атрибуты.
                    // N.B. Мы не выводим атрибуты сразу вместе с элементом, используя метод
                    // XMLEventFactory.createStartElement(prefix, nsURI, localName, List<Namespace>, List<Attribute>),
                    // потому что при использовании этого метода порядок атрибутов в выходном документе
                    // меняется произвольным образом.
                    for (Attribute attr : dstAttributeList) {
                        dst.add(attr);
                    }

                    continue;
                } else if (event.isEndElement()) {
                    // Гарантируем, что empty tags запишутся в форме <a></a>, а не в форме <a/>.
                    dst.add(eventFactory.get().createSpace(""));

                    // NS prefix rewriting
                    EndElement srcEvent = (EndElement) event;
                    String nsURI = srcEvent.getName().getNamespaceURI();
                    String prefix = findPrefix(nsURI, prefixMappingStack);
                    if (prefix == null) {
                        throw new TransformationException("EndElement: prefix mapping is not found for namespace " + nsURI);
                    }

                    EndElement dstEvent = eventFactory.get().createEndElement(prefix, nsURI, srcEvent.getName().getLocalPart());
                    dst.add(dstEvent);

                    prefixMappingStack.pop();
                    continue;
                } else if (event.isAttribute()) {
                    // Атрибуты обрабатываются в событии startElement.
                    continue;
                }

                // Остальные события (processing instructions, start document, etc.) опускаем.
            }
        } catch (XMLStreamException e) {
            Object[] exArgs = {e.getMessage()};
            throw new TransformationException(
                    "Can not perform transformation " + ALGORITHM_URN, exArgs, e
            );
        } finally {
            if (src != null) {
                try {
                    src.close();
                } catch (XMLStreamException e) {
                    // logger.warn("Can not close XMLEventReader", e);
                }
            }
            if (dst != null) {
                try {
                    dst.close();
                } catch (XMLStreamException e) {
                    // logger.warn("Can not close XMLEventWriter", e);
                }
            }
            try {
                argSrc.close();
            } catch (IOException e) {
                // logger.warn("Can not close input stream.", e);
            }
            if (argDst != null) {
                try {
                    argDst.close();
                } catch (IOException e) {
                    // logger.warn("Can not close output stream.", e);
                }
            }
        }
    }

    private static class AttributeSortingComparator implements Comparator<Attribute> {
        private static boolean empty(String arg) {
            return arg == null || "".equals(arg);
        }

        @Override
        public int compare(Attribute x, Attribute y) {
            String xNS = x.getName().getNamespaceURI();
            String xLocal = x.getName().getLocalPart();
            String yNS = y.getName().getNamespaceURI();
            String yLocal = y.getName().getLocalPart();

            // Оба атрибута - unqualified.
            if (empty(xNS) && empty(yNS)) {
                return xLocal.compareTo(yLocal);
            }

            // Оба атрибута - qualified.
            if (!empty(xNS) && !empty(yNS)) {
                // Сначала сравниваем namespaces.
                int nsComparisonResult = xNS.compareTo(yNS);
                if (nsComparisonResult != 0) {
                    return nsComparisonResult;
                } else {
                    // Если равны - local names.
                    return xLocal.compareTo(yLocal);
                }
            }

            // Один - qualified, второй - unqualified.
            if (empty(xNS)) {
                return 1;
            } else {
                return -1;
            }
        }
    }
}
