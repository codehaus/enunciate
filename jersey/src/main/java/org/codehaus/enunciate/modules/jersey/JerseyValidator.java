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

package org.codehaus.enunciate.modules.jersey;

import org.codehaus.enunciate.contract.jaxrs.ResourceMethod;
import org.codehaus.enunciate.contract.jaxrs.RootResource;
import org.codehaus.enunciate.contract.validation.BaseValidator;
import org.codehaus.enunciate.contract.validation.ValidationResult;

import javax.ws.rs.core.MediaType;
import java.util.List;

import net.sf.jelly.apt.decorations.type.DecoratedTypeMirror;

/**
 * @author Ryan Heaton
 */
public class JerseyValidator extends BaseValidator {

  private final boolean allowWildcardServlet;

  public JerseyValidator(boolean allowWildcardServlet) {
    this.allowWildcardServlet = allowWildcardServlet;
  }

  @Override
  public ValidationResult validateRootResources(List<RootResource> rootResources) {
    ValidationResult result = new ValidationResult();

    for (RootResource rootResource : rootResources) {
      for (ResourceMethod resourceMethod : rootResource.getResourceMethods(true)) {
        if ("/*".equals(resourceMethod.getServletPattern())) {
          if (!allowWildcardServlet) {
            result.addError(resourceMethod, "This JAX-RS resource method is designed to catch all requests (including requests to " +
              "Enunciate-generated documentation and other static files). If this is what you want, then please set 'disableWildcardServletError' to 'true'" +
              "in the Enunciate config for the Jersey module.  Otherwise, enable the rest subcontext or adjust the @Path annotation to be more specific.");
          }
          else {
            result.addWarning(resourceMethod, "JAX-RS resource method is designed to catch all requests.");
          }
        }

        for (String producesMime : resourceMethod.getProducesMime()) {
          try {
            MediaType.valueOf(producesMime);
          }
          catch (Exception e) {
            result.addError(resourceMethod, "Invalid produces MIME type: " + producesMime + "(" + e.getMessage() + ").");
          }
        }

        if (resourceMethod.getHttpMethods().size() > 1) {
          result.addError(resourceMethod, "You must not apply multiple HTTP operations to the same method: " + resourceMethod.getHttpMethods());
        }

        for (String method : resourceMethod.getHttpMethods()) {
          if ("GET".equalsIgnoreCase(method) && ((DecoratedTypeMirror)resourceMethod.getReturnType()).isVoid()) {
            result.addError(resourceMethod, "A resource method that is mapped to HTTP GET must not return void.");
          }

          if ("GET".equalsIgnoreCase(method) && resourceMethod.getEntityParameter() != null) {
            result.addError(resourceMethod, "A resource method that is mapped to HTTP GET must not specify an entity parameter.");
          }
        }
      }
    }

    return result;
  }
}