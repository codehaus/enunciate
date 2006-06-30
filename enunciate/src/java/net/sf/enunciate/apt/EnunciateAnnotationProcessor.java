package net.sf.enunciate.apt;

import com.sun.mirror.apt.AnnotationProcessorEnvironment;
import com.sun.mirror.declaration.*;
import net.sf.enunciate.contract.jaxb.*;
import net.sf.enunciate.contract.jaxb.types.KnownXmlType;
import net.sf.enunciate.contract.jaxb.types.XmlTypeMirror;
import net.sf.enunciate.contract.jaxws.EndpointInterface;
import net.sf.enunciate.contract.validation.*;
import net.sf.enunciate.template.freemarker.*;
import net.sf.jelly.apt.Context;
import net.sf.jelly.apt.freemarker.FreemarkerModel;
import net.sf.jelly.apt.freemarker.FreemarkerProcessor;
import net.sf.jelly.apt.freemarker.FreemarkerTransform;

import javax.jws.WebService;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.net.URL;
import java.util.Collection;

/**
 * @author Ryan Heaton
 */
public class EnunciateAnnotationProcessor extends FreemarkerProcessor {

  public EnunciateAnnotationProcessor(URL template) {
    super(template);
  }

  @Override
  protected FreemarkerModel getRootModel() {
    EnunciateFreemarkerModel model = (EnunciateFreemarkerModel) super.getRootModel();
    model.put("prefix", new PrefixMethod());
    model.put("qname", new QNameMethod());

    AnnotationProcessorEnvironment env = Context.getCurrentEnvironment();
    Collection<TypeDeclaration> typeDeclarations = env.getTypeDeclarations();
    for (TypeDeclaration declaration : typeDeclarations) {
      if (isEndpointInterface(declaration)) {
        EndpointInterface endpointInterface = new EndpointInterface(declaration);

        if (isVerbose()) {
          System.out.println(declaration.getQualifiedName() + " to be considered as an endpoint interface.");
        }

        model.add(endpointInterface);
      }
      else if (isPotentialSchemaType(declaration)) {
        TypeDefinition typeDef = createTypeDefinition((ClassDeclaration) declaration);
        if (typeDef != null) {
          if (isVerbose()) {
            System.out.println(String.format("%s to be considered as a %s (qname:{%s}%s).",
                                             declaration.getQualifiedName(),
                                             typeDef.getClass().getSimpleName(),
                                             typeDef.getTargetNamespace(),
                                             typeDef.getName()));
          }

          model.add(typeDef);

          RootElementDeclaration rootElement = createRootElementDeclaration((ClassDeclaration) declaration, typeDef);
          if (rootElement != null) {
            if (isVerbose()) {
              System.out.println(declaration.getQualifiedName() + " to be considered as a root element.");
            }

            model.add(rootElement);
          }
        }
      }
    }

    //todo: read the validator type from the config.
    Validator validator = new DefaultValidator();
    ValidationResult validationResult = validate(model, validator);

    if (validationResult.hasWarnings()) {
      for (ValidationMessage warning : validationResult.getWarnings()) {
        env.getMessager().printWarning(warning.getPosition(), warning.getText());
      }
    }

    if (validationResult.hasErrors()) {
      for (ValidationMessage error : validationResult.getErrors()) {
        env.getMessager().printError(error.getPosition(), error.getText());
      }

      throw new RuntimeException("There were validation errors.");
    }

/*
    todo: read the config file into the prefixMap and schemaMap
    todo: but don't overwrite the constant namespaces
    String configFile = env.getOptions().get(EnunciateAnnotationProcessorFactory.CONFIG_OPTION);
    if (configFile != null) {
      try {
        FileInputStream stream = new FileInputStream(configFile);
      }
      catch (IOException e) {
        throw new RuntimeException(e);
      }
    }
*/

    return model;
  }

  //Inherited.
  @Override
  protected FreemarkerModel newRootModel() {
    return new EnunciateFreemarkerModel();
  }

  /**
   * Whether the specified declaration is a potential schema type.
   *
   * @param declaration The declaration to determine whether it's a potential schema type.
   * @return Whether the specified declaration is a potential schema type.
   */
  protected boolean isPotentialSchemaType(TypeDeclaration declaration) {
    if (!(declaration instanceof ClassDeclaration)) {
      return false;
    }

    Collection<AnnotationMirror> annotationMirrors = declaration.getAnnotationMirrors();
    for (AnnotationMirror mirror : annotationMirrors) {
      AnnotationTypeDeclaration annotationDeclaration = mirror.getAnnotationType().getDeclaration();
      if (annotationDeclaration != null) {
        if ((annotationDeclaration.getQualifiedName().startsWith("javax.xml.ws") || (annotationDeclaration.getQualifiedName().startsWith("javax.jws")))) {
          return false;
        }
      }
    }

    return true;
  }

  /**
   * A quick check to see if a declaration is an endpoint interface.
   */
  public boolean isEndpointInterface(TypeDeclaration declaration) {
    WebService ws = declaration.getAnnotation(WebService.class);
    return (ws != null) && ((declaration instanceof InterfaceDeclaration)
      //if this is a class declaration, then it has an implicit endpoint interface if it doesn't reference another.
      || (ws.endpointInterface() == null) || ("".equals(ws.endpointInterface())));
  }

  /**
   * Find the type definition for a class given the class's declaration, or null if the class is xml transient.
   *
   * @param declaration The declaration.
   * @return The type definition.
   */
  public TypeDefinition createTypeDefinition(ClassDeclaration declaration) {
    if (isEnumType(declaration)) {
      return new EnumTypeDefinition((EnumDeclaration) declaration);
    }
    else if (isSimpleType(declaration)) {
      return new SimpleTypeDefinition(declaration);
    }
    else {
      //assume its a complex type.
      return new ComplexTypeDefinition(declaration);
    }
  }

  /**
   * Find or create the root element declaration for the specified type definition.
   *
   * @param declaration    The class declaration
   * @param typeDefinition The specified type definition.
   * @return The root element declaration.
   */
  public RootElementDeclaration createRootElementDeclaration(ClassDeclaration declaration, TypeDefinition typeDefinition) {
    if (!isRootSchemaElement(declaration)) {
      return null;
    }
    else {
      return new RootElementDeclaration(declaration, typeDefinition);
    }
  }

  /**
   * A quick check to see if a declaration defines a complex schema type.
   */
  protected boolean isComplexType(TypeDeclaration declaration) {
    return !(declaration instanceof InterfaceDeclaration) && !isEnumType(declaration) && !isSimpleType(declaration);
  }

  /**
   * A quick check to see if a declaration defines a enum schema type.
   */
  protected boolean isEnumType(TypeDeclaration declaration) {
    return (declaration instanceof EnumDeclaration);
  }

  /**
   * A quick check to see if a declaration defines a simple schema type.
   */
  protected boolean isSimpleType(TypeDeclaration declaration) {
    if (declaration instanceof InterfaceDeclaration) {
      if (declaration.getAnnotation(XmlType.class) != null) {
        throw new ValidationException(declaration.getPosition(), "An interface must not be annotated with @XmlType.");
      }

      return false;
    }

    if (isEnumType(declaration)) {
      return false;
    }

    GenericTypeDefinition typeDef = new GenericTypeDefinition((ClassDeclaration) declaration);
    return ((typeDef.getValue() != null) && (typeDef.getAttributes().isEmpty()) && (typeDef.getElements().isEmpty()));
  }

  /**
   * A quick check to see if a declaration defines a root schema element.
   */
  protected boolean isRootSchemaElement(TypeDeclaration declaration) {
    return declaration.getAnnotation(XmlRootElement.class) != null;
  }

  //Inherited.
  @Override
  protected Collection<FreemarkerTransform> getTransforms() {
    String namespace = Context.getCurrentEnvironment().getOptions().get(EnunciateAnnotationProcessorFactory.FM_LIBRARY_NS_OPTION);
    Collection<FreemarkerTransform> transforms = super.getTransforms();

    //jaxws transforms.
    transforms.add(new ForEachBindingTypeTransform(namespace));
    transforms.add(new ForEachEndpointInterfaceTransform(namespace));
    transforms.add(new ForEachThrownWebFaultTransform(namespace));
    transforms.add(new ForEachWebFaultTransform(namespace));
    transforms.add(new ForEachWebMessageTransform(namespace));
    transforms.add(new ForEachWebMethodTransform(namespace));
    transforms.add(new ForEachWsdlTransform(namespace));

    //jaxb transforms.
    transforms.add(new ForEachSchemaTransform(namespace));
    return transforms;
  }

  /**
   * Whether verbose output is requested.
   *
   * @return Whether verbose output is requested.
   */
  protected boolean isVerbose() {
    return Context.getCurrentEnvironment().getOptions().containsKey(EnunciateAnnotationProcessorFactory.VERBOSE_OPTION);
  }

  /**
   * Validates the model given a validator.
   *
   * @param model     The model to validate.
   * @param validator The validator.
   * @return The results of the validation.
   */
  protected ValidationResult validate(EnunciateFreemarkerModel model, Validator validator) {
    ValidationResult validationResult = new ValidationResult();

    for (EndpointInterface ei : model.endpointInterfaces) {
      validationResult.aggregate(validator.validateEndpointInterface(ei));
    }

    for (TypeDefinition typeDefinition : model.typeDefinitions) {
      validationResult.aggregate(typeDefinition.accept(validator));
    }

    for (RootElementDeclaration rootElement : model.rootElements) {
      validationResult.aggregate(validator.validateRootElement(rootElement));
    }

    return validationResult;
  }

  /**
   * Internal class used to inherit some functionality for determining whether a declaration is a simple type
   * or a complex type.
   */
  protected static class GenericTypeDefinition extends TypeDefinition {

    protected GenericTypeDefinition(ClassDeclaration delegate) {
      super(delegate);
    }

    public ValidationResult accept(Validator validator) {
      return new ValidationResult();
    }

    public XmlTypeMirror getBaseType() {
      return KnownXmlType.ANY_TYPE;
    }
  }

}
