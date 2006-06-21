package net.sf.enunciate.contract.jaxb;

import com.sun.mirror.declaration.ClassDeclaration;
import net.sf.enunciate.contract.jaxb.types.XmlTypeMirror;
import net.sf.enunciate.contract.validation.ValidationResult;
import net.sf.enunciate.contract.validation.Validator;

/**
 * A simple type definition.
 *
 * @author Ryan Heaton
 */
public class SimpleTypeDefinition extends TypeDefinition {

  public SimpleTypeDefinition(ClassDeclaration delegate) {
    super(delegate);
  }

  /**
   * The base type for this simple type, or null if none exists.
   *
   * @return The base type for this simple type.
   */
  public XmlTypeMirror getBaseType() {
    Value value = getValue();

    if (value != null) {
      return value.getBaseType();
    }

    return null;
  }

  public ValidationResult accept(Validator validator) {
    return validator.validateSimpleType(this);
  }

}
