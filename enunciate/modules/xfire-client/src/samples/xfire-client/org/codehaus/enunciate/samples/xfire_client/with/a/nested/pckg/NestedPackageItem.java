/*
 * Copyright 2006-2008 Web Cohesion
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

package org.codehaus.enunciate.samples.xfire_client.with.a.nested.pckg;

/**
 * @author Ryan Heaton
 */
public class NestedPackageItem {

  private boolean property1;
  private int[] property2;

  public boolean isProperty1() {
    return property1;
  }

  public void setProperty1(boolean property1) {
    this.property1 = property1;
  }

  public int[] getProperty2() {
    return property2;
  }

  public void setProperty2(int[] property2) {
    this.property2 = property2;
  }
}
