/*
 * Copyright 2006 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.codehaus.enunciate.contract.jaxb;

import com.sun.mirror.declaration.MemberDeclaration;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlNsForm;
import javax.xml.namespace.QName;

/**
 * An accessor that is marshalled in xml to an xml attribute.
 *
 * @author Ryan Heaton
 */
public class Attribute extends Accessor {

  private final XmlAttribute xmlAttribute;

  public Attribute(MemberDeclaration delegate, TypeDefinition typedef) {
    super(delegate, typedef);

    xmlAttribute = getAnnotation(XmlAttribute.class);
  }

  // Inherited.
  public String getName() {
    String name = getSimpleName();

    if ((xmlAttribute != null) && (!"##default".equals(xmlAttribute.name()))) {
      name = xmlAttribute.name();
    }

    return name;
  }

  // Inherited.
  public String getNamespace() {
    String namespace = null;

    if (getTypeDefinition().getSchema().getAttributeFormDefault() == XmlNsForm.QUALIFIED) {
      namespace = getTypeDefinition().getNamespace();
    }

    if ((xmlAttribute != null) && (!"##default".equals(xmlAttribute.namespace()))) {
      namespace = xmlAttribute.namespace();
    }

    return namespace;
  }


  /**
   * An attribute is a ref if its namespace differs from that of its type definition (JAXB spec 8.9.7.2).
   *
   * @return The ref or null.
   */
  @Override
  public QName getRef() {
    String namespace = getNamespace();
    namespace = namespace == null ? "" : namespace;
    String typeNamespace = getTypeDefinition().getNamespace();
    typeNamespace = (typeNamespace == null || (getTypeDefinition().getSchema().getAttributeFormDefault() != XmlNsForm.QUALIFIED)) ? "" : typeNamespace;

    if (!namespace.equals(typeNamespace)) {
      return new QName(namespace, getName());
    }

    return null;
  }

  /**
   * Whether the attribute is required.
   *
   * @return Whether the attribute is required.
   */
  public boolean isRequired() {
    boolean required = false;

    if (xmlAttribute != null) {
      required = xmlAttribute.required();
    }

    return required;
  }
}
