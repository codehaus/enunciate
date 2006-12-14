package net.sf.enunciate.apt;

import com.sun.mirror.declaration.ClassDeclaration;
import com.sun.mirror.type.DeclaredType;
import com.sun.mirror.type.TypeMirror;
import junit.framework.Test;
import net.sf.enunciate.InAPTTestCase;
import net.sf.enunciate.OutsideAPTOkay;
import net.sf.enunciate.config.SchemaInfo;
import net.sf.enunciate.config.WsdlInfo;
import net.sf.enunciate.contract.jaxb.ComplexTypeDefinition;
import net.sf.enunciate.contract.jaxb.RootElementDeclaration;
import net.sf.enunciate.contract.jaxb.TypeDefinition;
import net.sf.enunciate.contract.jaxb.types.KnownXmlType;
import net.sf.enunciate.contract.jaxb.types.XmlTypeMirror;
import net.sf.enunciate.contract.jaxws.EndpointInterface;
import net.sf.jelly.apt.Context;

import javax.xml.namespace.QName;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.beanutils.DynaBean;

/**
 * @author Ryan Heaton
 */
public class TestEnunciateFreemarkerModel extends InAPTTestCase {

  /**
   * Initialization (default state) of the EnunciateFreemarkerModel.
   */
  @OutsideAPTOkay
  public void testInit() throws Exception {
    final Map<String, String> knownNamespaces = new HashMap<String, String>();
    final Map<String, XmlTypeMirror> mockKnownTypes = new HashMap<String, XmlTypeMirror>();
    EnunciateFreemarkerModel model = new EnunciateFreemarkerModel() {
      @Override
      protected Map<String, String> loadKnownNamespaces() {
        return knownNamespaces;
      }

      @Override
      protected Map<String, XmlTypeMirror> loadKnownTypes() {
        return mockKnownTypes;
      }
    };

    assertSame("The model should have been initialized with the known namespaces.", model.getNamespacesToPrefixes(), knownNamespaces);
    assertSame("The model should have been initialized with the known types.", model.knownTypes, mockKnownTypes);
    assertNotNull("The model should have a 'knownNamespaces' variable set.", model.getVariable("knownNamespaces"));
    assertNotNull("The model should have a 'ns2prefix' variable set.", model.getVariable("ns2prefix"));
    assertNotNull("The model should have a 'ns2schema' variable set.", model.getVariable("ns2schema"));
    assertNotNull("The model should have a 'ns2wsdl' variable set.", model.getVariable("ns2wsdl"));
  }

  /**
   * Tests the known types.
   */
  @OutsideAPTOkay
  public void testKnownTypes() throws Exception {

    Map<String, XmlTypeMirror> knownTypes = new EnunciateFreemarkerModel().loadKnownTypes();

    //JAXB 2.0 Spec, section 8.5.1:
    XmlTypeMirror knownType = knownTypes.get(Boolean.TYPE.getName());
    assertNotNull("The primitive boolean type should be a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("boolean", knownType.getName());
    knownType = knownTypes.get(Byte.TYPE.getName());
    assertNotNull("The primitive byte type should be a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("byte", knownType.getName());
    knownType = knownTypes.get(Short.TYPE.getName());
    assertNotNull("The primitive short type should be a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("short", knownType.getName());
    knownType = knownTypes.get(Integer.TYPE.getName());
    assertNotNull("The primitive int type should be a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("int", knownType.getName());
    knownType = knownTypes.get(Long.TYPE.getName());
    assertNotNull("The primitive long type should be a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("long", knownType.getName());
    knownType = knownTypes.get(Float.TYPE.getName());
    assertNotNull("The primitive float type should be a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("float", knownType.getName());
    knownType = knownTypes.get(Double.TYPE.getName());
    assertNotNull("The primitive double type should be a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("double", knownType.getName());
    knownType = knownTypes.get(Boolean.class.getName());
    assertNotNull("The boolean wrapper class should be a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("boolean", knownType.getName());
    knownType = knownTypes.get(Byte.class.getName());
    assertNotNull("The byte wrapper class should be a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("byte", knownType.getName());
    knownType = knownTypes.get(Short.class.getName());
    assertNotNull("The short wrapper class should be a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("short", knownType.getName());
    knownType = knownTypes.get(Integer.class.getName());
    assertNotNull("The integer wrapper class should be a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("int", knownType.getName());
    knownType = knownTypes.get(Long.class.getName());
    assertNotNull("The long wrapper class should be a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("long", knownType.getName());
    knownType = knownTypes.get(Float.class.getName());
    assertNotNull("The float wrapper class should be a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("float", knownType.getName());
    knownType = knownTypes.get(Double.class.getName());
    assertNotNull("The double wrapper class should be a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("double", knownType.getName());

    //JAXB 2.0 Spec, section 8.5.2:
    knownType = knownTypes.get(String.class.getName());
    assertNotNull("java.lang.String should have a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("string", knownType.getName());
    knownType = knownTypes.get(java.math.BigInteger.class.getName());
    assertNotNull("java.math.BigInteger should have a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("integer", knownType.getName());
    knownType = knownTypes.get(java.math.BigDecimal.class.getName());
    assertNotNull("java.math.BigDecimal should have a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("decimal", knownType.getName());
    knownType = knownTypes.get(java.util.Calendar.class.getName());
    assertNotNull("java.util.Calendar should have a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("dateTime", knownType.getName());
    knownType = knownTypes.get(java.util.Date.class.getName());
    assertNotNull("java.util.Date should have a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("dateTime", knownType.getName());
    knownType = knownTypes.get(javax.xml.namespace.QName.class.getName());
    assertNotNull("javax.xml.namespace.QName should have a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("QName", knownType.getName());
    knownType = knownTypes.get(java.net.URI.class.getName());
    assertNotNull("java.net.URI should have a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("string", knownType.getName());
    knownType = knownTypes.get(javax.xml.datatype.XMLGregorianCalendar.class.getName());
    assertNotNull("javax.xml.datatype.XMLGregorianCalendar should have a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("anySimpleType", knownType.getName());
    knownType = knownTypes.get(javax.xml.datatype.Duration.class.getName());
    assertNotNull("javax.xml.datatype.Duration should have a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("duration", knownType.getName());
    knownType = knownTypes.get(java.lang.Object.class.getName());
    assertNotNull("java.lang.Object should have a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("anyType", knownType.getName());
    knownType = knownTypes.get(java.awt.Image.class.getName());
    assertNotNull("java.awt.Image should have a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("base64Binary", knownType.getName());
    knownType = knownTypes.get(javax.xml.transform.Source.class.getName());
    assertNotNull("javax.xml.transform.Source should have a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("base64Binary", knownType.getName());
    knownType = knownTypes.get(java.util.UUID.class.getName());
    assertNotNull("java.util.UUID should have a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("string", knownType.getName());
    knownType = knownTypes.get("javax.activation.DataHandler");
    assertNotNull("javax.activation.DataHandler should have a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("base64Binary", knownType.getName());
    knownType = knownTypes.get(byte[].class.getName());
    assertNotNull("byte[] should have a known type.", knownType);
    assertEquals("http://www.w3.org/2001/XMLSchema", knownType.getNamespace());
    assertEquals("base64Binary", knownType.getName());
  }

  /**
   * Tests adding an endpoint interface.
   */
  public void testAddEndpointInterface() throws Exception {
    EnunciateFreemarkerModel model = new EnunciateFreemarkerModel();
    int originalNSSize = model.getNamespacesToPrefixes().size();
    EndpointInterface ei1 = new EndpointInterface(getDeclaration("net.sf.enunciate.samples.services.NamespacedWebService"));
    String targetNamespace = ei1.getTargetNamespace();
    model.add(ei1);
    assertNotNull(model.getNamespacesToPrefixes().get(targetNamespace));
    WsdlInfo wsdlInfo = model.getNamespacesToWSDLs().get(targetNamespace);
    assertNotNull("The model should have created a wsdl information associated with a new endpoint interface.", wsdlInfo);
    assertTrue(model.endpointInterfaces.contains(ei1));
    assertTrue(wsdlInfo.getEndpointInterfaces().contains(ei1));
    assertEquals(targetNamespace, wsdlInfo.getTargetNamespace());

    EndpointInterface ei2 = new EndpointInterface(getDeclaration("net.sf.enunciate.samples.services.NoNamespaceWebServiceImpl"));
    targetNamespace = ei2.getTargetNamespace();
    model.add(ei2);
    assertNotNull(model.getNamespacesToPrefixes().get(targetNamespace));
    wsdlInfo = model.getNamespacesToWSDLs().get(targetNamespace);
    assertNotNull("The model should have created a wsdl information associated with a new endpoint interface.", wsdlInfo);
    assertTrue(model.endpointInterfaces.contains(ei2));
    assertTrue(wsdlInfo.getEndpointInterfaces().contains(ei2));
    assertEquals(targetNamespace, wsdlInfo.getTargetNamespace());

    EndpointInterface ei3 = new EndpointInterface(getDeclaration("net.sf.enunciate.samples.services.SuperNoNamespaceWebServiceImpl"));
    targetNamespace = ei3.getTargetNamespace();
    model.add(ei3);
    assertNotNull(model.getNamespacesToPrefixes().get(targetNamespace));
    wsdlInfo = model.getNamespacesToWSDLs().get(targetNamespace);
    assertNotNull("The model should have created a wsdl information associated with a new endpoint interface.", wsdlInfo);
    assertTrue(model.endpointInterfaces.contains(ei3));
    assertTrue(wsdlInfo.getEndpointInterfaces().contains(ei3));
    assertEquals(targetNamespace, wsdlInfo.getTargetNamespace());

    assertEquals(3, model.endpointInterfaces.size());
    assertEquals(originalNSSize + 2, model.getNamespacesToPrefixes().size());
    assertEquals("There should be two endpoint interfaces in the WSDL.", 2, wsdlInfo.getEndpointInterfaces().size());
  }

  /**
   * Tests adding a type definition to the model.
   */
  public void testAddTypeDefinition() throws Exception {
    EnunciateFreemarkerModel model = new EnunciateFreemarkerModel();
    int nsCount = model.getNamespacesToPrefixes().size();
    ComplexTypeDefinition typeDef1 = new ComplexTypeDefinition((ClassDeclaration) getDeclaration("net.sf.enunciate.samples.schema.BeanOne"));
    String targetNamespace = typeDef1.getNamespace();
    assertNull(model.findTypeDefinition(typeDef1));
    model.add(typeDef1);
    SchemaInfo schemaInfo = model.getNamespacesToSchemas().get(targetNamespace);
    assertNull("The element form default should not have been set.", schemaInfo.getElementFormDefault());
    assertNull("The attribute form default should not have been set.", schemaInfo.getAttributeFormDefault());
    assertNotNull("The model should have created a schema information associated with a new type definition.", schemaInfo);
    assertTrue(model.typeDefinitions.contains(typeDef1));
    assertNotNull(model.findTypeDefinition(typeDef1));
    assertEquals(targetNamespace, schemaInfo.getNamespace());

    nsCount += 1;
    assertEquals("There should have been one and only one new namespace added", nsCount, model.getNamespacesToPrefixes().size());

    ComplexTypeDefinition typeDef2 = new ComplexTypeDefinition((ClassDeclaration) getDeclaration("net.sf.enunciate.samples.anotherschema.BeanOne"));
    targetNamespace = typeDef2.getNamespace();
    assertNull(model.findTypeDefinition(typeDef2));
    model.add(typeDef2);
    schemaInfo = model.getNamespacesToSchemas().get(targetNamespace);
    assertNotNull("The model should have created a schema information associated with a new type definition.", schemaInfo);
    assertTrue(model.typeDefinitions.contains(typeDef2));
    assertNotNull(model.findTypeDefinition(typeDef2));
    assertEquals(targetNamespace, schemaInfo.getNamespace());
    assertEquals("qualified", schemaInfo.getElementFormDefault());
    assertEquals("qualified", schemaInfo.getAttributeFormDefault());
    nsCount += 3;
    assertEquals("There should have been three new namespaces added, as specified in the package info for the schema.", nsCount, model.getNamespacesToPrefixes().size());

    ComplexTypeDefinition typeDef3 = new ComplexTypeDefinition((ClassDeclaration) getDeclaration("net.sf.enunciate.samples.anotherschema.BeanTwo"));
    targetNamespace = typeDef3.getNamespace();
    assertNull(model.findTypeDefinition(typeDef3));
    model.add(typeDef3);
    schemaInfo = model.getNamespacesToSchemas().get(targetNamespace);
    assertNotNull("The model should have created a schema information associated with a new type definition.", schemaInfo);
    assertTrue(model.typeDefinitions.contains(typeDef3));
    assertNotNull(model.findTypeDefinition(typeDef3));
    assertEquals(targetNamespace, schemaInfo.getNamespace());
    assertEquals("qualified", schemaInfo.getElementFormDefault());
    assertEquals("qualified", schemaInfo.getAttributeFormDefault());
    assertEquals("There should have been no new namespaces added.", nsCount, model.getNamespacesToPrefixes().size());

    assertEquals(3, model.typeDefinitions.size());
  }

  /**
   * Tests adding a root element declaration to the model.
   */
  public void testAddRootElementDeclaration() throws Exception {
    EnunciateFreemarkerModel model = new EnunciateFreemarkerModel();
    int nsCount = model.getNamespacesToPrefixes().size();
    ClassDeclaration declaration = (ClassDeclaration) getDeclaration("net.sf.enunciate.samples.schema.BeanThree");
    TypeDefinition typeDef1 = new ComplexTypeDefinition(declaration);
    RootElementDeclaration element1 = new RootElementDeclaration(declaration, typeDef1);
    String targetNamespace = element1.getNamespace();
    assertNull(model.findRootElementDeclaration(element1));
    model.add(element1);
    SchemaInfo schemaInfo = model.getNamespacesToSchemas().get(targetNamespace);
    assertNull("The element form default should not have been set.", schemaInfo.getElementFormDefault());
    assertNull("The attribute form default should not have been set.", schemaInfo.getAttributeFormDefault());
    assertNotNull("The model should have created a schema information associated with a new type definition.", schemaInfo);
    assertTrue(model.rootElements.contains(element1));
    assertNotNull(model.findRootElementDeclaration(element1));
    assertEquals(targetNamespace, schemaInfo.getNamespace());

    nsCount += 1;
    assertEquals("There should have been one and only one new namespace added", nsCount, model.getNamespacesToPrefixes().size());

    declaration = (ClassDeclaration) getDeclaration("net.sf.enunciate.samples.anotherschema.BeanThree");
    ComplexTypeDefinition typeDef2 = new ComplexTypeDefinition(declaration);
    RootElementDeclaration element2 = new RootElementDeclaration(declaration, typeDef2);
    targetNamespace = element2.getNamespace();
    assertNull(model.findRootElementDeclaration(element2));
    model.add(element2);
    schemaInfo = model.getNamespacesToSchemas().get(targetNamespace);
    assertNotNull("The model should have created a schema information associated with a new type definition.", schemaInfo);
    assertTrue(model.rootElements.contains(element2));
    assertNotNull(model.findRootElementDeclaration(element2));
    assertEquals(targetNamespace, schemaInfo.getNamespace());
    assertEquals("qualified", schemaInfo.getElementFormDefault());
    assertEquals("qualified", schemaInfo.getAttributeFormDefault());
    nsCount += 3;
    assertEquals("There should have been three new namespaces added, as specified in the package info for the schema.", nsCount, model.getNamespacesToPrefixes().size());

    declaration = (ClassDeclaration) getDeclaration("net.sf.enunciate.samples.anotherschema.BeanFour");
    ComplexTypeDefinition typeDef3 = new ComplexTypeDefinition(declaration);
    RootElementDeclaration element3 = new RootElementDeclaration(declaration, typeDef3);
    targetNamespace = element3.getNamespace();
    assertNull(model.findRootElementDeclaration(element3));
    model.add(element3);
    schemaInfo = model.getNamespacesToSchemas().get(targetNamespace);
    assertNotNull("The model should have created a schema information associated with a new type definition.", schemaInfo);
    assertTrue(model.rootElements.contains(element3));
    assertNotNull(model.findRootElementDeclaration(element3));
    assertEquals(targetNamespace, schemaInfo.getNamespace());
    assertEquals("There is no @XmlSchema annotation for this new namespace, so the elementFormDefault should be unset.", null, schemaInfo.getElementFormDefault());
    assertEquals("There is no @XmlSchema annotation for this new namespace, so the attributeFormDefault should be unset.", null, schemaInfo.getAttributeFormDefault());
    nsCount += 1;
    assertEquals("There should have been 1 new namespace added.", nsCount, model.getNamespacesToPrefixes().size());

    assertEquals(3, model.rootElements.size());
    assertEquals(0, model.typeDefinitions.size());
  }

  /**
   * Getting the xml type for a specified type.
   */
  public void testGetXmlType() throws Exception {
    final XmlTypeMirror mockXmlType = new MockXmlType();
    EnunciateFreemarkerModel model = new EnunciateFreemarkerModel() {
      @Override
      protected XmlTypeMirror createXmlType(TypeMirror type) {
        return mockXmlType;
      }
    };

    DeclaredType stringType = Context.getCurrentEnvironment().getTypeUtils().getDeclaredType(getDeclaration("java.lang.String"));
    XmlTypeMirror stringXmlType = model.getXmlType(stringType);
    assertSame(KnownXmlType.STRING, stringXmlType);
    assertSame(stringXmlType, model.getXmlType(String.class));

    DeclaredType beanFourType = Context.getCurrentEnvironment().getTypeUtils().getDeclaredType(getDeclaration("net.sf.enunciate.samples.anotherschema.BeanFour"));
    XmlTypeMirror beanFourXmlType = model.getXmlType(beanFourType);
    assertEquals("The xml type for bean four should have been specified at the package-level.", "specified-bean-four", beanFourXmlType.getName());
    assertEquals("The xml type for bean four should have been specified at the package-level.", "http://net.sf.enunciate/core/samples/beanfour", beanFourXmlType.getNamespace());

    DeclaredType beanThreeType = Context.getCurrentEnvironment().getTypeUtils().getDeclaredType(getDeclaration("net.sf.enunciate.samples.anotherschema.BeanThree"));
    assertSame("The xml type for bean three should have been created.", mockXmlType, model.getXmlType(beanThreeType));

    assertSame("The xml type for an actual class should have been created.", mockXmlType, model.getXmlType(DynaBean.class));
  }

  private static class MockXmlType implements XmlTypeMirror {
    public String getName() {
      return null;
    }

    public String getNamespace() {
      return null;
    }

    public QName getQname() {
      return null;
    }

    public boolean isAnonymous() {
      return false;
    }
  }

  public static Test suite() {
    return createSuite(TestEnunciateFreemarkerModel.class);
  }

}
