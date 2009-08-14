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

package org.codehaus.enunciate.test.integration;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.support.DelegatingIntroductionInterceptor;

/**
 * Advice for a source service.
 *
 * @author Ryan Heaton
 */
@org.codehaus.enunciate.XmlTransient
public class SourceServiceAdvice extends DelegatingIntroductionInterceptor implements MethodInterceptor {

  public Object invoke(MethodInvocation methodInvocation) throws Throwable {
    if (("addInfoSet".equals(methodInvocation.getMethod().getName())) && ("SPECIAL".equals(methodInvocation.getArguments()[0]))) {
      return "intercepted";
    }

    return methodInvocation.proceed();
  }

}
