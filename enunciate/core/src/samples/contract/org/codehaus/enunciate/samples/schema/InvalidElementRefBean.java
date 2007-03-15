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

package org.codehaus.enunciate.samples.schema;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementRef;

/**
 * @author Ryan Heaton
 */
public class InvalidElementRefBean
{
  private ElementBeanOne property1;

  @XmlElementRef
  @XmlElement
  public ElementBeanOne getProperty1() {
    return property1;
  }

  public void setProperty1(ElementBeanOne property1) {
    this.property1 = property1;
  }

}
