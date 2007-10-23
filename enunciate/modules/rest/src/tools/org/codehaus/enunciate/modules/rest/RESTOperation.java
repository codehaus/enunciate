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

package org.codehaus.enunciate.modules.rest;

import org.codehaus.enunciate.rest.annotations.*;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.annotation.XmlRootElement;
import java.lang.annotation.Annotation;
import java.lang.reflect.*;
import java.util.*;

/**
 * A REST operation.
 *
 * @author Ryan Heaton
 */
public class RESTOperation {

  private final VerbType verb;
  private final Object endpoint;
  final Method method;
  private final int properNounIndex;
  private final Class properNounType;
  private final Boolean properNounOptional;
  private final Map<String, Integer> adjectiveIndices;
  private final Map<String, Class> adjectiveTypes;
  private final Map<String, Boolean> adjectivesOptional;
  private final int nounValueIndex;
  private final Class nounValueType;
  private final Boolean nounValueOptional;
  private final JAXBContext context;
  private final Class resultType;
  private final String contentType;
  private final String charset;
  private final String JSONPParameter;

  /**
   * Construct a REST operation.
   *
   * @param verb     The verb for the operation.
   * @param endpoint The REST endpoint.
   * @param method   The method.
   */
  protected RESTOperation(VerbType verb, Object endpoint, Method method) {
    this.verb = verb;
    this.endpoint = endpoint;
    this.method = method;

    int properNounIndex = -1;
    Class properNoun = null;
    Boolean properNounOptional = null;
    int nounValueIndex = -1;
    Class nounValue = null;
    Boolean nounValueOptional = null;
    adjectiveTypes = new HashMap<String, Class>();
    adjectiveIndices = new HashMap<String, Integer>();
    adjectivesOptional = new HashMap<String, Boolean>();
    Class[] parameterTypes = method.getParameterTypes();
    HashSet<Class> contextClasses = new HashSet<Class>();
    for (int i = 0; i < parameterTypes.length; i++) {
      Class parameterType = Collection.class.isAssignableFrom(parameterTypes[i]) ? getCollectionTypeAsArrayType(method, i) : parameterTypes[i];

      boolean isAdjective = true;
      String adjectiveName = "arg" + i;
      boolean adjectiveOptional = !parameterType.isPrimitive();
      Annotation[] parameterAnnotations = method.getParameterAnnotations()[i];
      for (Annotation annotation : parameterAnnotations) {
        if (annotation instanceof ProperNoun) {
          if (parameterType.isArray()) {
            throw new IllegalStateException("Proper nouns must be simple types, found an array or collection for parameter " + i + " of method " +
              method.getDeclaringClass().getName() + "." + method.getName() + ".");
          }
          else if (properNoun == null) {
            if (((ProperNoun) annotation).optional()) {
              if (parameterType.isPrimitive()) {
                throw new IllegalStateException("An optional proper noun cannot be a primitive type for method " +
                  method.getDeclaringClass().getName() + "." + method.getName() + ".");
              }

              properNounOptional = true;
            }

            properNoun = parameterType;
            properNounIndex = i;
            isAdjective = false;
            break;
          }
          else {
            throw new IllegalStateException("There are two proper nouns for method " + method.getDeclaringClass().getName() + "." + method.getName() + ".");
          }
        }
        else if (annotation instanceof NounValue) {
          if (!parameterType.isAnnotationPresent(XmlRootElement.class)) {
            throw new IllegalStateException("Noun values must be XML root elements.  Invalid noun value for parameter " + i + " of method " +
              method.getDeclaringClass().getName() + "." + method.getName() + ".");
          }
          else if (nounValue == null) {
            if (((NounValue) annotation).optional()) {
              if (parameterType.isPrimitive()) {
                throw new IllegalStateException("An optional noun value cannot be a primitive type for method " +
                  method.getDeclaringClass().getName() + "." + method.getName() + ".");
              }

              nounValueOptional = true;
            }

            nounValue = parameterType;
            nounValueIndex = i;
            isAdjective = false;
            break;
          }
          else {
            throw new IllegalStateException("There are two proper nouns for method " + method.getDeclaringClass().getName() + "." + method.getName() + ".");
          }
        }
        else if (annotation instanceof Adjective) {
          adjectiveOptional = ((Adjective) annotation).optional();
          if (adjectiveOptional && parameterType.isPrimitive()) {
            throw new IllegalStateException("An optional adjective cannot be a primitive type for method " +
              method.getDeclaringClass().getName() + "." + method.getName() + ".");
          }
          adjectiveName = ((Adjective) annotation).name();
          break;
        }
      }

      if (isAdjective) {
        this.adjectiveTypes.put(adjectiveName, parameterType);
        this.adjectiveIndices.put(adjectiveName, i);
        this.adjectivesOptional.put(adjectiveName, adjectiveOptional);
      }

      if (parameterType.isArray()) {
        contextClasses.add(parameterType.getComponentType());
      }
      else {
        contextClasses.add(parameterType);
      }
    }

    Class returnType = method.getReturnType();
    if (!Void.TYPE.equals(returnType)) {
      if (!returnType.isAnnotationPresent(XmlRootElement.class)) {
        throw new IllegalStateException("REST operation results must be xml root elements.  Invalid return type for method " +
          method.getDeclaringClass() + "." + method.getName() + ".");
      }
      contextClasses.add(returnType);
    }
    else {
      returnType = null;
    }

    String jsonpParameter = null;
    JSONP jsonpInfo = method.getAnnotation(JSONP.class);
    if (jsonpInfo == null) {
      jsonpInfo = method.getDeclaringClass().getAnnotation(JSONP.class);
      if (jsonpInfo == null) {
        jsonpInfo = method.getDeclaringClass().getPackage().getAnnotation(JSONP.class);
      }
    }
    if (jsonpInfo != null) {
      jsonpParameter = jsonpInfo.paramName();
    }


    this.properNounType = properNoun;
    this.properNounIndex = properNounIndex;
    this.properNounOptional = properNounOptional;
    this.nounValueType = nounValue;
    this.nounValueIndex = nounValueIndex;
    this.nounValueOptional = nounValueOptional;
    this.resultType = returnType;
    this.contentType = this.method.isAnnotationPresent(ContentType.class) ? this.method.getAnnotation(ContentType.class).value() : "text/xml";
    this.charset = this.method.isAnnotationPresent(ContentType.class) ? this.method.getAnnotation(ContentType.class).charset() : "utf-8";
    this.JSONPParameter = jsonpParameter;
    try {
      this.context = JAXBContext.newInstance(contextClasses.toArray(new Class[contextClasses.size()]));
    }
    catch (JAXBException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Gets the collection type for the specified parameter as an array type.
   *
   * @param method The method.
   * @param i      The parameter index.
   * @return The conversion.
   */
  protected Class getCollectionTypeAsArrayType(Method method, int i) {
    Class parameterType;
    Type collectionType = method.getGenericParameterTypes()[i];
    if (collectionType instanceof ParameterizedType) {
      Type[] typeArgs = ((ParameterizedType) collectionType).getActualTypeArguments();
      if (typeArgs.length < 1) {
        throw new IllegalStateException("A type parameter must be supplied to the collection for parameter " + i + " of method " +
          method.getDeclaringClass().getName() + "." + method.getName() + ".");
      }

      Class componentType = (Class) typeArgs[0];
      parameterType = Array.newInstance(componentType, 0).getClass();
    }
    else {
      throw new IllegalStateException("Non-parameterized collection found at parameter" + i + " on method " + method.getDeclaringClass().getName() +
        "." + method.getName() + ". Only parameterized collections are supported.");
    }
    return parameterType;
  }

  /**
   * Invokes the operation with the specified proper noun, adjectives, and noun value.
   *
   * @param properNoun The value for the proper noun.
   * @param adjectives The value for the adjectives.
   * @param nounValue  The value for the noun.
   * @return The result of the invocation.  If the invocation has no return type (void), returns null.
   * @throws Exception if any problems occur.
   */
  public Object invoke(Object properNoun, Map<String, Object> adjectives, Object nounValue) throws Exception {
    Class[] parameterTypes = this.method.getParameterTypes();
    Object[] parameters = new Object[parameterTypes.length];
    if (properNounIndex > -1) {
      parameters[properNounIndex] = properNoun;
    }

    if (nounValueIndex > -1) {
      parameters[nounValueIndex] = nounValue;
    }

    for (String adjective : adjectiveIndices.keySet()) {
      Object adjectiveValue = adjectives.get(adjective);
      Integer index = adjectiveIndices.get(adjective);
      if ((adjectiveValue != null) && (Collection.class.isAssignableFrom(parameterTypes[index]))) {
        //convert the array back into a collection...
        Object[] values;
        try {
          values = (Object[]) adjectiveValue;
        }
        catch (ClassCastException e) {
          throw new IllegalArgumentException("Adjective '" + adjective + "' should be an array...");
        }

        Collection collection = newCollectionInstance(parameterTypes[index]);
        collection.addAll(Arrays.asList(values));
        adjectiveValue = collection;
      }

      parameters[index] = adjectiveValue;
    }

    try {
      return this.method.invoke(this.endpoint, parameters);
    }
    catch (InvocationTargetException e) {
      Throwable target = e.getTargetException();
      if (target instanceof Error) {
        throw (Error) target;
      }

      throw (Exception) target;
    }
  }

  /**
   * Create a new instance of something of the specified collection type.
   *
   * @param collectionType The collection type.
   * @return the new instance.
   */
  public static Collection newCollectionInstance(Class collectionType) {
    if (Collection.class.isAssignableFrom(collectionType)) {
      Collection collection;
      if ((collectionType.isInterface()) || (Modifier.isAbstract(collectionType.getModifiers()))) {
        if (Set.class.isAssignableFrom(collectionType)) {
          if (SortedSet.class.isAssignableFrom(collectionType)) {
            collection = new TreeSet();
          }
          else {
            collection = new HashSet();
          }
        }
        else {
          collection = new ArrayList();
        }
      }
      else {
        try {
          collection = (Collection) collectionType.newInstance();
        }
        catch (Exception e) {
          throw new IllegalArgumentException("Unable to create an instance of " + collectionType.getName() + ".", e);
        }
      }
      return collection;
    }
    else {
      throw new IllegalArgumentException("Invalid list type: " + collectionType.getName());
    }
  }

  @Override
  public String toString() {
    return this.method.toString();
  }

  /**
   * The verb for the operation.
   *
   * @return The verb for the operation.
   */
  public VerbType getVerb() {
    return verb;
  }

  /**
   * If this operation accepts a proper noun, return the type of the proper noun.  Otherwise, return null.
   *
   * @return The proper noun type, or null.
   */
  public Class getProperNounType() {
    return properNounType;
  }

  /**
   * Whether the proper noun is optional.
   *
   * @return Whether the proper noun is optional, or null if no proper noun.
   */
  public Boolean isProperNounOptional() {
    return properNounOptional;
  }

  /**
   * If this operation accepts a noun value, return the type of the noun value.  Otherwise, return null.
   *
   * @return The noun value type, or null.
   */
  public Class getNounValueType() {
    return nounValueType;
  }

  /**
   * Whether the noun value is optional.
   *
   * @return Whether the noun value is optional, or null if no noun value.
   */
  public Boolean isNounValueOptional() {
    return nounValueOptional;
  }

  /**
   * The adjective types for this operation.
   *
   * @return The adjective types for this operation.
   */
  public Map<String, Class> getAdjectiveTypes() {
    return adjectiveTypes;
  }

  /**
   * The map of whether the adjectives are optional.
   *
   * @return The map of whether the adjectives are optional.
   */
  public Map<String, Boolean> getAdjectivesOptional() {
    return adjectivesOptional;
  }

  /**
   * Gets the serialization context for this operation.
   *
   * @return The serialization context.
   */
  public JAXBContext getSerializationContext() {
    return context;
  }

  /**
   * The endpoint handling this REST operation.
   *
   * @return The endpoint handling this REST operation.
   */
  public Object getEndpoint() {
    return endpoint;
  }

  /**
   * The result type for the operation.
   *
   * @return The result type for the operation.
   */
  public Class getResultType() {
    return resultType;
  }

  /**
   * The content type of this REST operation.
   *
   * @return The content type of this REST operation.
   */
  public String getContentType() {
    return contentType;
  }

  /**
   * The character set of this REST operation.
   *
   * @return The character set of this REST operation.
   */
  public String getCharset() {
    return charset;
  }

  /**
   * The JSONP parameter name for this operation.
   *
   * @return The JSONP parameter name for this operation, or null if none.
   */
  public String getJSONPParameter() {
    return JSONPParameter;
  }
}
