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

package org.codehaus.enunciate.modules.docs;

import freemarker.template.TemplateModel;
import freemarker.template.TemplateModelException;
import net.sf.jelly.apt.freemarker.APTJellyObjectWrapper;
import org.codehaus.enunciate.main.Artifact;

/**
 * @author Ryan Heaton
 */
public class DocumentationObjectWrapper extends APTJellyObjectWrapper {

  @Override
  public TemplateModel wrap(Object obj) throws TemplateModelException {
    if (obj instanceof Artifact) {
      return new ArtifactWrapper((Artifact) obj, this);
    }
    else {
      return super.wrap(obj);
    }
  }
}
