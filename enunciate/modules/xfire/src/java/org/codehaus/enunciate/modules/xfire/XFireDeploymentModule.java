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

package org.codehaus.enunciate.modules.xfire;

import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import freemarker.template.TemplateException;
import org.codehaus.enunciate.EnunciateException;
import org.codehaus.enunciate.apt.EnunciateFreemarkerModel;
import org.codehaus.enunciate.config.WsdlInfo;
import org.codehaus.enunciate.contract.jaxws.*;
import org.codehaus.enunciate.contract.validation.Validator;
import org.codehaus.enunciate.main.Artifact;
import org.codehaus.enunciate.main.Enunciate;
import org.codehaus.enunciate.main.FileArtifact;
import org.codehaus.enunciate.modules.DeploymentModule;
import org.codehaus.enunciate.modules.FreemarkerDeploymentModule;
import org.codehaus.enunciate.modules.xfire.config.*;
import org.apache.commons.digester.RuleSet;
import org.springframework.util.AntPathMatcher;
import sun.misc.Service;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.File;
import java.io.IOException;
import java.io.FileReader;
import java.io.FileInputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * <h1>XFire Module</h1>
 *
 * <p>The XFire deployment module generates the web app for hosting the API endpoints and documentation.</p>
 *
 * <p>The order of the XFire deployment module is 200, putting it after any of the other modules, including
 * the documentation deployment module.  The XFire deployment module has a hard dependency on the JAXWS module,
 * expecting to find the generated JAX-WS source files exported.  The XFire deployment module has a soft
 * dependency on the documentation deployment module.  This means that if there is no documentation artifact
 * found, a warning will be issued, but an artifact will still be built.</p> 
 *
 * <ul>
 *   <li><a href="#steps">steps</a></li>
 *   <li><a href="#config">configuration</a></li>
 *   <li><a href="#artifacts">artifacts</a></li>
 * </ul>
 *
 * <h1><a name="steps">Steps</a></h1>
 *
 * <h3>generate</h3>
 * 
 * <p>The "generate" step generates the deployment descriptors, <a href="http://www.springframework.org/">Spring</a> configuration file, and 
 * classes needed to support the deployed endpoints using <a href="http://xfire.codehaus.org">XFire</a>.  Refer to the
 * <a href="#config">configuration of the xfire deployment module</a> to learn how to customize the deployment descriptors and spring config file.</p>
 *
 * <h3>compile</h3>
 *
 * <p>The "compile" step compiles all API source files.</p> 
 *
 * <p>The "compile" step also compiles the JAX-WS support classes generated by the JAXWS deployment module.  This step will fail
 * if no JAXWS source directory artifact was found.  There are also some support classes generated during the "generate" step
 * that are compiled during this step.</p>
 *
 * <h3>build</h3>
 *
 * <p>The "build" step assembles all the generated artifacts, compiled classes, and deployment descriptors into an (expanded)
 * war directory.</p>
 *
 * <p>All classes compiled in the compile step are copied to the WEB-INF/classes directory.</p>
 *
 * <p>A set of libraries are copied to the WEB-INF/lib directory.  This set of libraries can be specified in the
 * <a href="#config">configuration file</a>.  If no libraries are specified in the configuration file, the
 * libraries copied will be filtered from the classpath passed to Enunciate.  The filtered libraries are those
 * libraries that are determined to be specific to running the enunciate engine.  All other libraries on the classpath
 * are assumed to be dependencies for the API and are therefore copied to WEB-INF/lib.  (If a directory is found on the classpath,
 * it's contents are copied to WEB-INF/classes.)</p>
 *
 * <p>The web.xml file is copied to the WEB-INF directory.  A tranformation can be applied to the web.xml file before the copy,
 * if specified on the config, allowing you to apply your own servlet filters, etc.  <i>Take care to preserve the existing elements
 * when applying a transformation to the web.xml file, as losing data will result in missing or malfunctioning endpoints.</i></p>
 *
 * <p>The spring-servlet.xml file is generated and copied to the WEB-INF directory.  You can specify other spring config files that
 * will be copied (and imported by the spring-servlet.xml file) in the configuration.  This option allows you to specify spring AOP
 * interceptors and XFire in/out handlers to wrap your endpoints, if desired.</p>
 *
 * <p>Finally, the documentation (if found) is copied to the base of the web app directory.</p>
 *
 * <h3>package</h3>
 *
 * <p>The "package" step packages the expanded war and exports it.</p>
 *
 * <h1><a name="config">Configuration</a></h1>
 *
 * <p>The configuration for the XFire deployment module is specified by the "xfire" child element under the "modules" element
 * of the enunciate configuration file.</p>
 *
 * <h3>attributes</h3>
 *
 * <ul>
 *   <li>The "<b>compileDebugInfo</b>" attribute specifies that the compiled classes should be compiled with debug info.  The default is "true."</li>
 * </ul>
 *
 * <h3>The "war" element</h3>
 *
 * <p>The "war" element is used to specify configuration for the assembly of the war.  It supports the following attributes:</p>
 *
 * <ul>
 *   <li>The "<b>name</b>" attribute specifies the name of the war.  The default is the enunciate configuration label.</li>
 *   <li>The "<b>webXMLTransform</b>" attribute specifies the XSLT tranform file that the web.xml file will pass through before being copied to the WEB-INF
 *       directory.  No tranformation will be applied if none is specified.</li>
 *   <li>The "<b>webXMLTransformURL</b>" attribute specifies the URL to an XSLT tranform that the web.xml file will pass through before being copied to the WEB-INF
 *       directory.  No tranformation will be applied if none is specified.</li>
 *   <li>The "<b>preBase</b>" attribute specifies a directory (could be gzipped) that supplies a "base" for the war.  The directory contents will be copied to
 *       the building war directory <i>before</i> it is provided with any Enunciate-specific files and directories.</li>
 *   <li>The "<b>postBase</b>" attribute specifies a directory (could be gzipped) that supplies a "base" for the war.  The directory contents will be copied to
 *       the building war directory <i>after</i> it is provided with any Enunciate-specific files and directories.</li>
 * </ul>
 *
 * <p>By default, the war is constructed by copying jars that are on the classpath to its "lib" directory (the contents of directories on the classpath
 * will be copied to the "classes" directory).  There is a set of known jars that will not be copied to the "lib" directory.  These include the jars that
 * ship by default with the JDK and the jars that are known to be build-time-only jars for Enunciate.  You can specify additional jars that are to be
 * excluded with an arbitrary number of "excludeJar" child elements under the "war" element in the configuration file.  The "excludeJar" element supports a
 * single attribute, "pattern", that is an ant-style pattern matcher against the absolute path of the file (or directory) on the classpath that should not
 * be copied to the destination war.</p>
 *
 * <p>More strict control over what gets copied to the "lib" directory in the war can be obtained by using an arbitrary number of "lib" child elements under the
 * "war" element of the configuration file. The "lib" element supports a single attribute, "path", that specifies the path to the library that is to be copied.
 * <i>NOTE: if ANY "lib" child elements are specified, then only those files will be copied, and no others.</i></p>
 *
 * <h3>The "springImport" element</h3>
 *
 * <p>The "springImport" element is used to specify a spring configuration file that will be imported by the main
 * spring servlet config. It supports the following attributes:</p>
 *
 * <ul>
 *   <li>The "file" attribute specifies the spring import file on the filesystem.  It will be copied to the WEB-INF directory.</li>
 *   <li>The "uri" attribute specifies the URI to the spring import file.  The URI will not be resolved at compile-time, nor will anything be copied to the
 *       WEB-INF directory. The value of this attribute will be used to reference the spring import file in the main config file.  This attribute is useful
 *       to specify an import file on the classpath, e.g. "classpath:com/myco/spring/config.xml".</li>
 * </ul>
 *
 * <p>One use of specifying spring a import file is to wrap your endpoints with a spring interceptors and/or XFire in/out/fault handlers.  This can be done
 * by simply declaring a bean that is an instance of your endpoint class.  This bean can be advised however is needed, and if it implements
 * org.codehaus.xfire.handler.HandlerSupport (perhaps <a href="http://static.springframework.org/spring/docs/1.2.x/reference/aop.html#d0e4128">through the use
 * of a mixin</a>?), the in/out/fault handlers will be used for the XFire invocation of that endpoint.</p>
 *
 * <p>It's important to note that the type on which the bean context will be searched is the type of the endpoint <i>interface</i>, and then only if it exists.
 * If there are more than one beans that are assignable to the endpoint interface, the bean that is named the name of the service will be used.  Otherwise,
 * the deployment of your endpoint will fail.</p>
 *
 * <p>The same procedure can be used to specify the beans to use as REST endpoints, although the XFire in/out/fault handlers will be ignored.  In this case,
 * the bean context will be searched for each <i>REST interface</i> that the endpoint implements.  If there is a bean that implements that interface, it will
 * used instead of the default implementation.  If there is more than one, the bean that is named the same as the REST endpoint will be used.</p>
 *
 * <p>There also exists a mechanism to add certain AOP interceptors to all service endpoint beans.  Such interceptors are referred to as "global service
 * interceptors." This can be done by using the "globalServiceInterceptor" element (see below), or by simply creating an interceptor that implements
 * org.codehaus.enunciate.modules.xfire.EnunciateServiceAdvice or org.codehaus.enunciate.modules.xfire.EnunciateServiceAdvisor and declaring it in your
 * imported spring beans file.</p>
 *
 * <p>Each global interceptor has an order.  The default order is 0 (zero).  If a global service interceptor implements org.springframework.core.Ordered, the
 * order will be respected. As a global service interceptors are added, it will be assigned a position in the chain according to it's order.  Interceptors
 * of the same order will be ordered together according to their position in the config file, with priority to those declared by the "globalServiceInterceptor"
 * element, then to instances of org.codehaus.enunciate.modules.xfire.EnunciateServiceAdvice, then to instances of
 * org.codehaus.enunciate.modules.xfire.EnunciateServiceAdvisor.</p>
 *
 * <p>For more information on spring bean configuration and interceptor advice, see
 * <a href="http://static.springframework.org/spring/docs/1.2.x/reference/index.html">the spring reference documentation</a>.</p>
 *
 * <h3>The "globalServiceInterceptor" element</h3>
 *
 * <p>The "globalServiceInterceptor" element is used to specify a Spring interceptor (instance of org.aopalliance.aop.Advice or
 * org.springframework.aop.Advisor) that is to be injected on all service endpoint beans.</p>
 *
 * <ul>
 *   <li>The "interceptorClass" attribute specified the class of the interceptor.</p>
 *   <li>The "beanName" attribute specifies the bean name of the interceptor.</p>
 * </ul>
 *
 * <h3>The "handlerInterceptor" element</h3>
 *
 * <p>The "handlerInterceptor" element is used to specify a Spring interceptor (instance of org.springframework.web.servlet.HandlerInterceptor)
 * that is to be injected on the handler mapping.</p>
 *
 * <ul>
 *   <li>The "interceptorClass" attribute specifies the class of the interceptor.</p>
 *   <li>The "beanName" attribute specifies the bean name of the interceptor.</p>
 * </ul>
 *
 * <p>For more information on spring bean configuration and interceptor advice, see
 * <a href="http://static.springframework.org/spring/docs/1.2.x/reference/index.html">the spring reference documentation</a>.</p>
 *
 * <h3>The "copyResources" element</h3>
 *
 * <p>The "copyResources" element is used to specify a pattern of resources to copy to the compile directory.  It supports the following attributes:</p>
 *
 * <ul>
 *   <li>The "<b>dir</b>" attribute specifies the base directory of the resources to copy.</li>
 *   <li>The "<b>pattern</b>" attribute specifies an <a href="http://ant.apache.org/">Ant</a>-style
 *       pattern used to find the resources to copy.  For more information, see the documentation for the
 *       <a href="http://static.springframework.org/spring/docs/1.2.x/api/org/springframework/util/AntPathMatcher.html">ant path matcher</a> in the Spring
 *       JavaDocs.</li>
 * </ul>
 *
 * <h1><a name="artifacts">Artifacts</a></h1>
 *
 * <p>The XFire deployment module exports the following artifacts:</p>
 *
 * <ul>
 *   <li>The "xfire.webapp" artifact is the (expanded) web app directory, exported during the build step.</li>
 *   <li>The "xfire.war" artifact is the packaged war, exported during the package step.</li>
 * </ul>
 *
 * @author Ryan Heaton
 */
public class XFireDeploymentModule extends FreemarkerDeploymentModule {

  private WarConfig warConfig;
  private final List<SpringImport> springImports = new ArrayList<SpringImport>();
  private final List<CopyResources> copyResources = new ArrayList<CopyResources>();
  private final List<GlobalServiceInterceptor> globalServiceInterceptors = new ArrayList<GlobalServiceInterceptor>();
  private final List<HandlerInterceptor> handlerInterceptors = new ArrayList<HandlerInterceptor>();
  private boolean compileDebugInfo = true;
  private File preBase = null;
  private File postBase = null;

  /**
   * @return "xfire"
   */
  @Override
  public String getName() {
    return "xfire";
  }

  /**
   * @return The URL to "xfire-servlet.fmt"
   */
  protected URL getSpringServletTemplateURL() {
    return XFireDeploymentModule.class.getResource("spring-servlet.fmt");
  }

  /**
   * @return The URL to "xfire-servlet.fmt"
   */
  protected URL getWebXmlTemplateURL() {
    return XFireDeploymentModule.class.getResource("web.xml.fmt");
  }

  /**
   * @return The URL to "rpc-request-bean.fmt"
   */
  protected URL getRPCRequestBeanTemplateURL() {
    return XFireDeploymentModule.class.getResource("rpc-request-bean.fmt");
  }

  /**
   * @return The URL to "rpc-response-bean.fmt"
   */
  protected URL getRPCResponseBeanTemplateURL() {
    return XFireDeploymentModule.class.getResource("rpc-response-bean.fmt");
  }

  @Override
  public void doFreemarkerGenerate() throws IOException, TemplateException {
    EnunciateFreemarkerModel model = getModel();

    //generate the xfire-servlet.xml
    model.setFileOutputDirectory(getXMLGenerateDir());
    model.put("springImports", getSpringImportURIs());
    if (!globalServiceInterceptors.isEmpty()) {
      for (GlobalServiceInterceptor interceptor : this.globalServiceInterceptors) {
        if ((interceptor.getBeanName() == null) && (interceptor.getInterceptorClass() == null)) {
          throw new IllegalStateException("A global interceptor must have either a bean name or a class set.");
        }
      }
      model.put("globalServiceInterceptors", this.globalServiceInterceptors);
    }
    if (!handlerInterceptors.isEmpty()) {
      for (HandlerInterceptor interceptor : this.handlerInterceptors) {
        if ((interceptor.getBeanName() == null) && (interceptor.getInterceptorClass() == null)) {
          throw new IllegalStateException("A handler interceptor must have either a bean name or a class set.");
        }
      }
      model.put("handlerInterceptors", this.handlerInterceptors);
    }
    processTemplate(getSpringServletTemplateURL(), model);
    processTemplate(getWebXmlTemplateURL(), model);

    //generate the rpc request/response beans.
    model.setFileOutputDirectory(getJAXWSGenerateDir());
    for (WsdlInfo wsdlInfo : model.getNamespacesToWSDLs().values()) {
      for (EndpointInterface ei : wsdlInfo.getEndpointInterfaces()) {
        for (WebMethod webMethod : ei.getWebMethods()) {
          for (WebMessage webMessage : webMethod.getMessages()) {
            if (webMessage instanceof RPCInputMessage) {
              model.put("message", webMessage);
              processTemplate(getRPCRequestBeanTemplateURL(), model);
            }
            else if (webMessage instanceof RPCOutputMessage) {
              model.put("message", webMessage);
              processTemplate(getRPCResponseBeanTemplateURL(), model);
            }
          }
        }
      }
    }
  }

  @Override
  protected void doCompile() throws EnunciateException, IOException {
    ArrayList<String> javacAdditionalArgs = new ArrayList<String>();
    if (compileDebugInfo) {
      javacAdditionalArgs.add("-g");
    }

    Enunciate enunciate = getEnunciate();
    File compileDir = getCompileDir();
    enunciate.invokeJavac(enunciate.getDefaultClasspath(), compileDir, javacAdditionalArgs, enunciate.getSourceFiles());

    File jaxwsSources = (File) enunciate.getProperty("jaxws.src.dir");
    if (jaxwsSources == null) {
      throw new EnunciateException("Required dependency on the JAXWS module was not found.  The generated request/response/fault beans are required.");
    }

    Collection<String> jaxwsSourceFiles = new ArrayList<String>(enunciate.getJavaFiles(jaxwsSources));
    //make sure we include all the wrappers generated for the rpc methods, too...
    jaxwsSourceFiles.addAll(enunciate.getJavaFiles(getJAXWSGenerateDir()));
    StringBuilder jaxwsClasspath = new StringBuilder(enunciate.getDefaultClasspath());
    jaxwsClasspath.append(File.pathSeparator).append(compileDir.getAbsolutePath());
    enunciate.invokeJavac(jaxwsClasspath.toString(), compileDir, javacAdditionalArgs, jaxwsSourceFiles.toArray(new String[jaxwsSourceFiles.size()]));

    if (!this.copyResources.isEmpty()) {
      AntPathMatcher matcher = new AntPathMatcher();
      for (CopyResources copyResource : this.copyResources) {
        String pattern = copyResource.getPattern();
        if (pattern == null) {
          throw new EnunciateException("A pattern must be specified for copying resources.");
        }

        if (!matcher.isPattern(pattern)) {
          warn("'%s' is not a valid pattern.  Resources NOT copied!", pattern);
          continue;
        }

        File basedir;
        if (copyResource.getDir() == null) {
          File configFile = enunciate.getConfigFile();
          if (configFile != null) {
            basedir = configFile.getAbsoluteFile().getParentFile();
          }
          else {
            basedir = new File(System.getProperty("user.dir"));
          }
        }
        else {
          basedir = enunciate.resolvePath(copyResource.getDir());
        }

        for (String file : enunciate.getFiles(basedir, new PatternFileFilter(basedir, pattern, matcher))) {
          enunciate.copyFile(new File(file), basedir, compileDir);
        }
      }
    }
  }

  @Override
  protected void doBuild() throws IOException, EnunciateException {
    Enunciate enunciate = getEnunciate();
    File buildDir = getBuildDir();
    if ((this.warConfig != null) && (this.warConfig.getPreBase() != null)) {
      File preBase = enunciate.resolvePath(this.warConfig.getPreBase());
      if (preBase.isDirectory()) {
        info("Copying preBase directory %s to %s...", preBase, buildDir);
        enunciate.copyDir(preBase, buildDir);
      }
      else {
        info("Extracting preBase zip file %s to %s...", preBase, buildDir);
        enunciate.extractBase(new FileInputStream(preBase), buildDir);
      }
    }

    info("Building the expanded WAR in %s", buildDir);
    File webinf = new File(buildDir, "WEB-INF");
    File webinfClasses = new File(webinf, "classes");
    File webinfLib = new File(webinf, "lib");

    //copy the compiled classes to WEB-INF/classes.
    enunciate.copyDir(getCompileDir(), webinfClasses);

    List<String> warLibs = getWarLibs();
    if ((warLibs == null) || (warLibs.isEmpty())) {
      String classpath = enunciate.getClasspath();
      if (classpath == null) {
        classpath = System.getProperty("java.class.path");
      }
      warLibs = Arrays.asList(classpath.split(File.pathSeparator));
    }

    AntPathMatcher excludeJarsMatcher = new AntPathMatcher();
    PATH_ENTRIES : for (String pathEntry : warLibs) {
      File file = new File(pathEntry);
      if (file.exists()) {
        if ((this.warConfig != null) && (!this.warConfig.getExcludeJars().isEmpty())) {
          for (ExcludeJars excludeJar : this.warConfig.getExcludeJars()) {
            String pattern = excludeJar.getPattern();
            if ((pattern != null) && (excludeJarsMatcher.isPattern(pattern)) && (excludeJarsMatcher.match(pattern, file.getAbsolutePath()))) {
              continue PATH_ENTRIES;
            }
          }
        }

        if (file.isDirectory()) {
          info("Adding the contents of %s to WEB-INF/classes.", file);
          enunciate.copyDir(file, webinfClasses);
        }
        else if (!excludeLibrary(file)) {
          info("Including %s in WEB-INF/lib.", file);
          enunciate.copyFile(file, file.getParentFile(), webinfLib);
        }
      }
    }

    //todo: assert that the necessary jars (spring, xfire, commons-whatever, etc.) are there?

    //put the web.xml in WEB-INF.  Pass it through a stylesheet, if specified.
    File xfireConfigDir = getXMLGenerateDir();
    File webXML = new File(xfireConfigDir, "web.xml");
    File destWebXML = new File(webinf, "web.xml");
    if ((this.warConfig != null) && (this.warConfig.getWebXMLTransformURL() != null)) {
      URL transformURL = this.warConfig.getWebXMLTransformURL();
      info("web.xml transform has been specified as %s.", transformURL);
      try {
        StreamSource source = new StreamSource(transformURL.openStream());
        Transformer transformer = new TransformerFactoryImpl().newTransformer(source);
        info("Transforming %s to %s.", webXML, destWebXML);
        transformer.transform(new StreamSource(new FileReader(webXML)), new StreamResult(destWebXML));
      }
      catch (TransformerException e) {
        throw new EnunciateException("Error during transformation of the web.xml (stylesheet " + transformURL + ", file " + webXML + ")", e);
      }
    }
    else {
      enunciate.copyFile(webXML, destWebXML);
    }

    //copy the spring servlet config from the build dir to the WEB-INF directory.
    enunciate.copyFile(new File(xfireConfigDir, "spring-servlet.xml"), new File(webinf, "spring-servlet.xml"));
    for (SpringImport springImport : springImports) {
      //copy the extra spring import files to the WEB-INF directory to be imported.
      if (springImport.getFile() != null) {
        File importFile = enunciate.resolvePath(springImport.getFile());
        enunciate.copyFile(importFile, new File(webinf, importFile.getName()));
      }
    }

    //now try to find the documentation and export it to the build directory...
    Artifact artifact = enunciate.findArtifact("docs");
    if (artifact != null) {
      artifact.exportTo(buildDir, enunciate);
    }
    else {
      warn("WARNING: No documentation artifact found!");
    }

    //extract a post base if specified.
    if ((this.warConfig != null) && (this.warConfig.getPostBase() != null)) {
      File postBase = enunciate.resolvePath(this.warConfig.getPostBase());
      if (postBase.isDirectory()) {
        info("Copying preBase directory %s to %s...", postBase, buildDir);
        enunciate.copyDir(postBase, buildDir);
      }
      else {
        info("Extracting preBase zip file %s to %s...", postBase, buildDir);
        enunciate.extractBase(new FileInputStream(postBase), buildDir);
      }
    }

    //export the unexpanded application directory.
    enunciate.addArtifact(new FileArtifact(getName(), "xfire.webapp", buildDir));
  }

  @Override
  protected void doPackage() throws EnunciateException, IOException {
    File buildDir = getBuildDir();
    File warFile = getWarFile();

    if (!warFile.getParentFile().exists()) {
      warFile.getParentFile().mkdirs();
    }

    Enunciate enunciate = getEnunciate();
    info("Creating " + warFile.getAbsolutePath());

    enunciate.zip(buildDir, warFile);
    enunciate.addArtifact(new FileArtifact(getName(), "xfire.war", warFile));
  }

  /**
   * Get the list of libraries to include in the war.
   *
   * @return the list of libraries to include in the war.
   */
  public List<String> getWarLibs() {
    if (this.warConfig != null) {
      return this.warConfig.getWarLibs();
    }

    return null;
  }

  /**
   * The war file to create.
   *
   * @return The war file to create.
   */
  public File getWarFile() {
    String filename = "enunciate.war";
    if (getEnunciate().getConfig().getLabel() != null) {
      filename = getEnunciate().getConfig().getLabel() + ".war";
    }
    
    if ((this.warConfig != null) && (this.warConfig.getName() != null)) {
      filename = this.warConfig.getName();
    }

    return new File(getPackageDir(), filename);
  }

  /**
   * Set the configuration for the war.
   *
   * @param warConfig The configuration for the war.
   */
  public void setWarConfig(WarConfig warConfig) {
    this.warConfig = warConfig;
  }

  /**
   * Get the string form of the spring imports that have been configured.
   *
   * @return The string form of the spring imports that have been configured.
   */
  protected ArrayList<String> getSpringImportURIs() {
    ArrayList<String> springImportURIs = new ArrayList<String>(this.springImports.size());
    for (SpringImport springImport : springImports) {
      if (springImport.getFile() != null) {
        if (springImport.getUri() != null) {
          throw new IllegalStateException("A spring import configuration must specify a file or a URI, but not both.");
        }

        springImportURIs.add(new File(springImport.getFile()).getName());
      }
      else if (springImport.getUri() != null) {
        springImportURIs.add(springImport.getUri());
      }
      else {
        throw new IllegalStateException("A spring import configuration must specify either a file or a URI.");
      }
    }
    return springImportURIs;
  }

  /**
   * Add a spring import.
   *
   * @param springImports The spring import to add.
   */
  public void addSpringImport(SpringImport springImports) {
    this.springImports.add(springImports);
  }

  /**
   * Add a copy resources.
   *
   * @param copyResources The copy resources to add.
   */
  public void addCopyResources(CopyResources copyResources) {
    this.copyResources.add(copyResources);
  }

  /**
   * Add a global service interceptor to the spring configuration.
   *
   * @param interceptorConfig The interceptor configuration.
   */
  public void addGlobalServiceInterceptor(GlobalServiceInterceptor interceptorConfig) {
    this.globalServiceInterceptors.add(interceptorConfig);
  }

  /**
   * Add a handler interceptor to the spring configuration.
   *
   * @param interceptorConfig The interceptor configuration.
   */
  public void addHandlerInterceptor(HandlerInterceptor interceptorConfig) {
    this.handlerInterceptors.add(interceptorConfig);
  }

  /**
   * Whether to exclude a file from copying to the WEB-INF/lib directory.
   *
   * @param file The file to exclude.
   * @return Whether to exclude a file from copying to the lib directory.
   */
  protected boolean excludeLibrary(File file) throws IOException {
    List<String> warLibs = getWarLibs();
    if ((warLibs != null) && (!warLibs.isEmpty())) {
      //if the war libraries were explicitly declared, don't exclude anything.
      return false;
    }

    //instantiate a loader with this library only in its path...
    URLClassLoader loader = new URLClassLoader(new URL[]{file.toURL()}, null);
    if (loader.findResource("META-INF/enunciate/preserve-in-war") != null) {
      debug("%s will be included in the war because it contains the entry META-INF/enunciate/preserve-in-war.", file);
      //if a jar happens to have the enunciate "preserve-in-war" file, it is NOT excluded.
      return false;
    }
    else if (loader.findResource(com.sun.tools.apt.Main.class.getName().replace('.', '/').concat(".class")) != null) {
      debug("%s will be excluded from the war because it appears to be tools.jar.", file);
      //exclude tools.jar.
      return true;
    }
    else if (loader.findResource(net.sf.jelly.apt.Context.class.getName().replace('.', '/').concat(".class")) != null) {
      debug("%s will be excluded from the war because it appears to be apt-jelly.", file);
      //exclude apt-jelly-core.jar
      return true;
    }
    else if (loader.findResource(net.sf.jelly.apt.freemarker.FreemarkerModel.class.getName().replace('.', '/').concat(".class")) != null) {
      debug("%s will be excluded from the war because it appears to be the apt-jelly-freemarker libs.", file);
      //exclude apt-jelly-freemarker.jar
      return true;
    }
    else if (loader.findResource(freemarker.template.Configuration.class.getName().replace('.', '/').concat(".class")) != null) {
      debug("%s will be excluded from the war because it appears to be the freemarker libs.", file);
      //exclude freemarker.jar
      return true;
    }
    else if (loader.findResource(Enunciate.class.getName().replace('.', '/').concat(".class")) != null) {
      debug("%s will be excluded from the war because it appears to be the enunciate core jar.", file);
      //exclude enunciate-core.jar
      return true;
    }
    else if (loader.findResource("javax/servlet/ServletContext.class") != null) {
      debug("%s will be excluded from the war because it appears to be the servlet api.", file);
      //exclude the servlet api.
      return true;
    }
    else if (loader.findResource("org/codehaus/enunciate/modules/xfire_client/EnunciatedClientSoapSerializerHandler.class") != null) {
      debug("%s will be excluded from the war because it appears to be the enunciated xfire client tools jar.", file);
      //exclude xfire-client-tools
      return true;
    }
    else if (loader.findResource("javax/swing/SwingBeanInfoBase.class") != null) {
      debug("%s will be excluded from the war because it appears to be dt.jar.", file);
      //exclude dt.jar
      return true;
    }
    else if (loader.findResource("HTMLConverter.class") != null) {
      debug("%s will be excluded from the war because it appears to be htmlconverter.jar.", file);
      return true;
    }
    else if (loader.findResource("sun/tools/jconsole/JConsole.class") != null) {
      debug("%s will be excluded from the war because it appears to be jconsole.jar.", file);
      return true;
    }
    else if (loader.findResource("sun/jvm/hotspot/debugger/Debugger.class") != null) {
      debug("%s will be excluded from the war because it appears to be sa-jdi.jar.", file);
      return true;
    }
    else if (loader.findResource("sun/io/ByteToCharDoubleByte.class") != null) {
      debug("%s will be excluded from the war because it appears to be charsets.jar.", file);
      return true;
    }
    else if (loader.findResource("com/sun/deploy/ClientContainer.class") != null) {
      debug("%s will be excluded from the war because it appears to be deploy.jar.", file);
      return true;
    }
    else if (loader.findResource("com/sun/javaws/Globals.class") != null) {
      debug("%s will be excluded from the war because it appears to be javaws.jar.", file);
      return true;
    }
    else if (loader.findResource("javax/crypto/SecretKey.class") != null) {
      debug("%s will be excluded from the war because it appears to be jce.jar.", file);
      return true;
    }
    else if (loader.findResource("sun/net/www/protocol/https/HttpsClient.class") != null) {
      debug("%s will be excluded from the war because it appears to be jsse.jar.", file);
      return true;
    }
    else if (loader.findResource("sun/plugin/JavaRunTime.class") != null) {
      debug("%s will be excluded from the war because it appears to be plugin.jar.", file);
      return true;
    }
    else if (loader.findResource("com/sun/corba/se/impl/activation/ServerMain.class") != null) {
      debug("%s will be excluded from the war because it appears to be rt.jar.", file);
      return true;
    }
    else if (Service.providers(DeploymentModule.class, loader).hasNext()) {
      debug("%s will be excluded from the war because it appears to be an enunciate module.", file);
      //exclude by default any deployment module libraries.
      return true;
    }

    return false;
  }

  /**
   * Configure whether to compile with debug info (default: true).
   *
   * @param compileDebugInfo Whether to compile with debug info (default: true).
   */
  public void setCompileDebugInfo(boolean compileDebugInfo) {
    this.compileDebugInfo = compileDebugInfo;
  }

  /**
   * @return 200
   */
  @Override
  public int getOrder() {
    return 200;
  }

  @Override
  public RuleSet getConfigurationRules() {
    return new XFireRuleSet();
  }

  @Override
  public Validator getValidator() {
    return new XFireValidator();
  }

  /**
   * The directory where the RPC request/response beans are generated.
   *
   * @return The directory where the RPC request/response beans are generated.
   */
  protected File getJAXWSGenerateDir() {
    return new File(getGenerateDir(), "jaxws");
  }

  /**
   * The directory where the servlet config file is generated.
   *
   * @return The directory where the servlet config file is generated.
   */
  protected File getXMLGenerateDir() {
    return new File(getGenerateDir(), "xml");
  }

}
