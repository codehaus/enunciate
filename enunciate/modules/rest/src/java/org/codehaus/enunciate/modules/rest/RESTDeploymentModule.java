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

import org.codehaus.enunciate.modules.BasicDeploymentModule;
import org.codehaus.enunciate.contract.validation.Validator;
import org.codehaus.enunciate.EnunciateException;

import java.io.IOException;

/**
 * <h1>REST Module</h1>
 *
 * <p>All metadata for REST endpoints can be discovered at runtime, therefore, the REST deployment module
 * exists only as a set of tools used to deploy the REST API.  In other words, no compile-time
 * generation or validation is needed.</p>
 *
 * <p>The order of the REST deployment module is 0, as it doesn't depend on any artifacts exported
 * by any other module.</p>
 *
 * <ul>
 *   <li><a href="#model">REST Model</a></li>
 *   <li><a href="#constraints">Constraints</a></li>
 *   <li><a href="#java2rest">Mapping Java to a REST API</a></li>
 *   <li><a href="#json">JSON API</a></li>
 *   <li><a href="#steps">steps</a></li>
 *   <li><a href="#config">configuration</a></li>
 *   <li><a href="#artifacts">artifacts</a></li>
 * </ul>
 *
 * <h1><a name="model">REST Model</a></h1>
 *
 * <p>We start by defining a model for the REST API.  A REST API is comprised of a set of <i>resources</i>
 * on which a constrained set of <i>operations</i> can act.  Borrowing terms from english grammar, Enunciate
 * refers to the REST resources as <i>nouns</i> and the REST operations as <i>verbs</i>.  Because the REST
 * API is to be deployed using HTTP, Enunciate constrains the set of verbs to the set {<i>create</i>, <i>read</i>,
 * <i>update</i>, <i>delete</i>}, mapping to the HTTP verbs {<i>PUT</i>, <i>GET</i>, <i>POST</i>, <i>DELETE</i>},
 * respectively.</p>
 *
 * <p>While a REST endpoint <i>must</i> have a noun and a verb, it can optionally use other constructs to
 * more clearly define itself.</p>
 *
 * <h3>Adjectives</h3>
 *
 * <p>REST adjectives are used to qualify a REST noun or a REST verb.  For a REST invocation, an adjective
 * has a name and one or more values.  In terms of HTTP, adjectives are passed as HTTP parameters.</p>
 *
 * <p>For example, if we were to invoke the verb "read" on a noun "circle", but we wanted to describe the
 * color of the circle as "red", then "color" would be the adjective and "red" would be the adjective value.
 * And mapped to HTTP, the HTTP request would look something like this:</p>
 *
 * <code>
 * GET /rest/circle?color=red
 * </code>
 *
 * <h3>Proper Noun</h3>
 *
 * <p>A proper noun is used to identify a specific <i>noun</i>.  In practical terms, a proper noun usually takes
 * the form of an id, and the only difference between a proper noun and an adjective is that the proper noun is
 * supplied directly on the URL, as opposed to being supplied as a query parameter.</p>
 *
 * <p>For example, if we wanted to invoke the verb "read" on a noun "purchase-order", but identify the specific
 * purchase order by the id "12345", the "12345" could be a proper noun.  (Note that it could also be an adjective,
 * the only difference is that a proper noun doesn't need a name, only a value.)</p>
 *
 * <p>And an HTTP request might like like this:</p>
 *
 * <code>
 * GET /rest/purchase-order/12345
 * </code>
 *
 * <h3>Noun Value</h3>
 *
 * <p>In REST, a noun value often needs to be supplied, such as during a "create" or an "update".  For example,
 * If we were to invoke the verb "update" on the noun "shape" to be "red circle", "red circle" would be the
 * noun value.  In terms of HTTP, the noun value is the payload of the request, and the request would look
 * something like this:</p>
 *
 * <code>
 * POST /rest/shape
 *
 * &lt;circle color="red"/&gt;
 * </code>
 *
 * <h3>Noun Context</h3>
 *
 * <p>A noun can be qualified by a noun context.  The noun context can be though of as a "grouping" of nouns.
 * Perhaps, as an admittedly contrived example, we were to have two separate resources for the noun "rectangle",
 * say "wide" and "tall". The "rectangle" those two contexts could be applied to qualifies the different "rectangle"
 * nouns.</p>
 *
 * <h3>Noun Context Parameters</h3>
 *
 * <p>A noun context parameter (or just "context parameter") is a parameter that is defined by the noun context. For example, if we wanted to identify
 * a specific user of a specific group, we could identify the "group id" as a context parameter, the user as the noun, and the user id as the proper
 * noun.</p>
 *
 * <h3>REST Payloads and Responses of Other Content Types</h3>
 *
 * <p>It is often necessary to provide REST resources of custom content types along with the XML responses. We define these resources as REST payloads.
 * A REST payload consists of the resource, it's content type (MIME type), and an optional set of metadata (i.e. HTTP headers) that are associated with
 * the resource.</p>
 *
 * <h1><a name="constraints">Constraints</a></h1>
 *
 * <p>Enunciate uses J2EE and JAXB 2.0 to map a REST model onto HTTP.  In order to do that definitively, Enunciate
 * imposes the following constraints:</p>
 *
 * <ul>
 *   <li>All verbs that act on the same noun must be unique.  (E.g. there can't be two "read" methods for the same noun.)</li>
 *   <li>Proper nouns must not be of a complex XML type.  Only simple types are allowed (e.g. integer, string, enum, etc.).</li>
 *   <li>There can only be one proper noun for a REST operation</li>
 *   <li>Adjectives must be simple types, but there can be more than one value for a single adjective.</li>
 *   <li>The verbs "read" and "delete" cannot support a noun value.</li>
 *   <li>A noun value must be an xml root element (not just a complex type)</li>
 *   <li>A return type must be either a root element or a REST payload.</li>
 *   <li>Noun context parameters must be simple types</li>
 * </ul>
 *
 * <h1><a name="java2rest">Mapping Java to a REST API</a></h1>
 *
 * <h3>Java Types</h3>
 *
 * <p>The <i>org.codehaus.enunciate.rest.annotations.RESTEndpoint</i> annotation is used on a Java type (i.e. class or interface)
 * to indicate that it contains methods that will service REST endpoints.  This is used simply to indicate to
 * the engine that the methods on the annotated class or interface should be searched for their nouns and verbs.
 * Only if a method is annotated with <i>org.codehaus.enunciate.rest.annotations.Verb</i> will it service a REST endpoint
 * (see below).</p>
 *
 * <p>The @RESTEndpoint annotation on an interface means that the annotated interface defines the REST methods
 * for any methods on an annotated class that <i>directly implement</i> it.  In practical terms, classes annotated
 * with @RESTEndpoint will use the metadata on any @RESTEnpoint interface instead of the metadata in their own
 * methods.  Allowing interfaces to define the REST API allows developers to leverage the advantages of coding to
 * interfaces (e.g. introduction of aspects, multiple implementations, etc.).</p>
 *
 * <h3>Java Methods</h3>
 *
 * <p>Each Java method that is to serve as a REST endpoint must be assigned a verb and a noun.  A public method can be assigned a
 * verb with the <i>org.codehaus.enunciate.rest.annotations.Verb</i> annotation.  A method that is not assigned a verb will
 * not be considered to service a REST endpoint.</p>
 *
 * <p>A method that is assigned a verb must be assigned a noun as well.  The noun is specified with the
 * <i>org.codehaus.enunciate.rest.annotations.Noun</i> annotation, which can supply both the name and the context of the noun.  As a convenience,
 * The <i>org.codehaus.enunciate.rest.annotations.NounContext</i> annotation can be supplied along with the @RESTEndpoint
 * annotation at the level of the interface (or class) to specify the default context for all nouns that are defined by the methods
 * of the interface (or class).</p>
 *
 * <p>To identify a context parameter, specify the name of the context parameter in braces ("{" and "}") in the noun context.  When context
 * parameters are defined, Enunciate will look for a method parameter that is defined to be a context parameter with the same name.  If there is
 * no context parameter defined by that name, the context parameter will be silently ignored. See below for how to define a method parameter
 * as a context parameter.</p>
 *
 * <h3>Java Return Types</h3>
 *
 * <p>The return type of the Java method determines the content type (MIME type) of a REST resource.  By default, Enunciate will attempt serialize the return
 * value of a method using JAXB.  Thus the default requirement that return types must be XML root elements, since otherwise JAXB wouldn't know the name of the outer
 * root XML element. The default content type of a JAXB response is "text/xml" for XML requests and "application/json" for JSON requests.  You can use the
 * org.codehaus.enunciate.rest.annotations.ContentType annotation to specify a different content type for the XML requests (e.g. "application/atom+xml").</p>
 *
 * <p>However, Enunciate also supports REST payloads and resources of different content types. One way you can do this is by defining the Java method to return
 * javax.activation.DataHandler, which defines its own payload and content type.  The other way of doing this is by defining a custom "REST payload" object that
 * has its own methods for returning the payload, content type, and metadata (HTTP headers). The class of a REST payload object is annotated with the
 * org.codehaus.enunciate.rest.annotations.RESTPayload annotation.  Such a class <i>must</i> define a single no-argument method that returns either byte[],
 * javax.activation.DataHandler, or java.io.InputStream and is annotated with org.codehaus.enunciate.rest.annotations.RESTPayloadBody. This method will
 * return the payload body.</p>
 *
 * <p>The default content type of REST payloads is "applicaiton/octet-stream".  This can be customized by defining a single no-argument method on the payload
 * object that returns a String and is annotated with org.codehaus.enunciate.rest.annotations.RESTPayloadContentType. If the Java return type is
 * javax.activation.DataHandler instead of a REST payload object, then the content type defined by the data handler is used.</p>
 *
 * <p>You may also define a no-argument method on the REST payload object that returns an instance of java.util.Map and is annotated with
 * org.codehaus.enunciate.rest.annotations.RESTPayloadHeaders that will define a set of HTTP headers that will be set in the HTTP response.</p>
 *
 * <h3>Java Method Parameters</h3>
 *
 * <p>A parameter to a method can be a proper noun, an adjective, a context parameter, or a noun value.  By default, a parameter is mapped
 * as an adjective.  The name of the adjective by default is arg<i>i</i>, where <i>i</i> is the parameter index.  Parameters
 * can be customized with the <i>org.codehaus.enunciate.rest.annotations.Adjective</i>, <i>org.codehaus.enunciate.rest.annotations.NounValue</i>,
 * <i>org.codehaus.enunciate.rest.annotations.ContextParameter</i>, and <i>org.codehaus.enunciate.rest.annotations.ProperNoun</i> annotations.</p>
 *
 * <h3>Exceptions</h3>
 *
 * <p>By default, an exception that gets thrown during a REST invocation will return an HTTP 500 error.  This
 * can be customized with the <i>org.codehaus.enunciate.rest.annotations.RESTError</i> annotation on the exception
 * that gets thrown.</p>
 *
 * <h1><a name="json">JSON API</a></h1>
 *
 * <p>Each READ verb (and only the read verb) is also published as a JSON endpoint.  The mapping of XML to JSON is done by default using the
 * "mapped convention".  The badgerfish convention is also available by passing in the http request parameter named "badgerfish."  To learn
 * more about the difference between the two convensions, see the <a href="http://jettison.codehaus.org/User%27s+Guide">Jettison user's guide</a>.</p>
 *
 * <h3>JSONP</h3>
 *
 * <p>You can tell Enunciate to enable a <a href="http://bob.pythonmac.org/archives/2005/12/05/remote-json-jsonp/">JSONP parameter</a> in a JSON request with
 * the use of the <i>org.codehaus.enunciate.rest.annotations.JSONP</i> annotation. When this annotation is applied at the method, class, or package level, any
 * JSON requests can supply a JSONP parameter.  The parameter name can be customized with the annotation.  The default value is "callback".</p>
 *
 * <h1><a name="steps">Steps</a></h1>
 *
 * <p>There are no significant steps in the REST module.  </p>
 *
 * <h1><a name="config">Configuration</a></h1>
 *
 * <p>There are no configuration options for the REST deployment module.</p>
 *
 * <h1><a name="artifacts">Artifacts</a></h1>
 *
 * <p>The REST deployment module exports no artifacts.</p>
 *
 * @author Ryan Heaton
 */
public class RESTDeploymentModule extends BasicDeploymentModule {

  /**
   * @return "rest"
   */
  @Override
  public String getName() {
    return "rest";
  }

  /**
   * @return A new {@link org.codehaus.enunciate.modules.rest.RESTValidator}.
   */
  @Override
  public Validator getValidator() {
    return new RESTValidator();
  }

  @Override
  protected void doGenerate() throws EnunciateException, IOException {
    //todo: export the parameter names.  But if you do this, you have to come up with a way to support overloaded methods...
    //todo: export the namespace prefixes for Jettison export.
    super.doGenerate();
  }
}
