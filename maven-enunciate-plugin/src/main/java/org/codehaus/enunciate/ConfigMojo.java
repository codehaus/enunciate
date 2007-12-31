package org.codehaus.enunciate;

/*
 * Copyright 2001-2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.codehaus.enunciate.config.EnunciateConfiguration;
import org.codehaus.enunciate.main.Enunciate;
import org.codehaus.enunciate.modules.DeploymentModule;
import org.codehaus.enunciate.modules.amf.AMFDeploymentModule;
import org.codehaus.enunciate.modules.amf.config.FlexApp;
import org.codehaus.enunciate.modules.gwt.GWTDeploymentModule;
import org.codehaus.enunciate.modules.gwt.config.GWTApp;
import org.codehaus.enunciate.modules.spring_app.SpringAppDeploymentModule;
import org.codehaus.enunciate.modules.spring_app.config.IncludeExcludeLibs;
import org.codehaus.enunciate.modules.spring_app.config.WarConfig;

import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * Goal which initializes an Enunciate build process.
 *
 * @goal config
 * @phase validate
 * @requiresDependencyResolution runtime
 */
public class ConfigMojo extends AbstractMojo {

  public static final String ENUNCIATE_STEPPER_PROPERTY = "urn:" + ConfigMojo.class.getName() + "#stepper";

  /**
   * @parameter expression="${plugin.artifacts}"
   * @required
   * @readonly
   */
  private Collection<org.apache.maven.artifact.Artifact> pluginDepdendencies;

  /**
   * Project dependencies.
   *
   * @parameter expression="${project.artifacts}"
   * @required
   * @readonly
   */
  private Collection<org.apache.maven.artifact.Artifact> projectDependencies;

  /**
   * Project artifacts.
   *
   * @parameter
   */
  private Artifact[] artifacts;

  /**
   * The enunciate configuration file to use.
   *
   * @parameter
   */
  private File configFile = null;

  /**
   * The output directory for the "generate" step.
   *
   * @parameter expression="${project.build.directory}/enunciate-generate"
   */
  private File generateDir = null;

  /**
   * The output directory for the "compile" step.
   *
   * @parameter
   */
  private File compileDir = null;

  /**
   * The output directory for the "build" step.
   *
   * @parameter
   */
  private File buildDir = null;

  /**
   * The output directory for the "package" step.
   *
   * @parameter
   */
  private File packageDir = null;

  /**
   * The directory for the generated WAR.
   *
   * @parameter expression="${project.build.directory}"
   * @required
   */
  private File outputDir = null;

  /**
   * Whether to add the GWT sources to the project compile sources.
   *
   * @parameter
   */
  private boolean addGWTSources = true;

  /**
   * Whether to add the actionscript sources to the project compile sources.
   *
   * @parameter
   */
  private boolean addActionscriptSources = true;

  /**
   * The GWT home.
   *
   * @parameter
   */
  private String gwtHome = null;

  /**
   * The Flex home.
   *
   * @parameter
   */
  private String flexHome = null;

  /**
   * The exports.
   *
   * @parameter
   */
  private Map<String, String> exports = new HashMap<String, String>();

  /**
   * The id of the Enunciate artifact that is to be the primary artifact for the maven project.
   *
   * @parameter default-value="spring.war.file"
   */
  private String warArtifactId = "spring.war.file";

  /**
   * The name of the generated WAR.
   *
   * @parameter expression="${project.build.finalName}"
   * @required
   */
  private String warArtifactName;

  /**
   * Classifier to add to the artifact generated. If given, the artifact will be an attachment instead.
   *
   * @parameter
   */
  private String warArtifactClassifier = null;

  /**
   * The Maven project reference.
   *
   * @parameter expression="${project}"
   * @required
   * @readonly
   */
  protected MavenProject project;

  /**
   * Maven ProjectHelper
   *
   * @component
   * @readonly
   */
  private MavenProjectHelper projectHelper;

  public void execute() throws MojoExecutionException {
    Set<File> sourceFiles = new HashSet<File>();
    Collection<String> sourcePaths = (Collection<String>) project.getCompileSourceRoots();
    for (String sourcePath : sourcePaths) {
      sourceFiles.add(new File(sourcePath));
    }

    Enunciate enunciate = loadMavenSpecificEnunciate(sourceFiles);
    EnunciateConfiguration config = new EnunciateConfiguration();
    if (this.configFile != null) {
      try {
        config.load(this.configFile);
      }
      catch (Exception e) {
        throw new MojoExecutionException("Problem with enunciate config file " + this.configFile, e);
      }
      enunciate.setConfigFile(this.configFile);
    }
    enunciate.setConfig(config);
    WarConfig warConfig = null;
    for (DeploymentModule module : config.getAllModules()) {
      if (!module.isDisabled()) {
        if (module instanceof SpringAppDeploymentModule) {
          warConfig = ((SpringAppDeploymentModule) module).getWarConfig();
        }
      }
    }

    Set<org.apache.maven.artifact.Artifact> classpathEntries = new HashSet<org.apache.maven.artifact.Artifact>();
    classpathEntries.addAll(this.projectDependencies);
    // todo: figure out whether we need these artifacts included in the classpath.
    // If not, we wouldn't have to declare the dependency on Enunciate in our project.
    // If so, we get maven jars included in the generated war.... 
    //classpathEntries.addAll(this.pluginArtifacts);
    Iterator<org.apache.maven.artifact.Artifact> it = classpathEntries.iterator();
    while (it.hasNext()) {
      org.apache.maven.artifact.Artifact artifact = it.next();
      String artifactScope = artifact.getScope();
      if (org.apache.maven.artifact.Artifact.SCOPE_TEST.equals(artifactScope)) {
        //remove just the test-scope artifacts from the classpath.
        it.remove();
      }
      else if ((warConfig != null) && ((org.apache.maven.artifact.Artifact.SCOPE_PROVIDED.equals(artifactScope)) || (org.apache.maven.artifact.Artifact.SCOPE_SYSTEM.equals(artifactScope)))) {
        IncludeExcludeLibs excludeLibs = new IncludeExcludeLibs();
        excludeLibs.setFile(artifact.getFile());
        warConfig.addExcludeLibs(excludeLibs);
      }
    }

    StringBuffer classpath = new StringBuffer();
    Iterator<org.apache.maven.artifact.Artifact> classpathIt = classpathEntries.iterator();
    while (classpathIt.hasNext()) {
      classpath.append(classpathIt.next().getFile().getAbsolutePath());
      if (classpathIt.hasNext()) {
        classpath.append(File.pathSeparatorChar);
      }
    }
    enunciate.setClasspath(classpath.toString());

    if (this.generateDir != null) {
      enunciate.setGenerateDir(this.generateDir);
    }

    if (this.compileDir != null) {
      enunciate.setCompileDir(this.compileDir);
    }

    if (this.buildDir != null) {
      enunciate.setBuildDir(this.buildDir);
    }

    if (this.packageDir != null) {
      enunciate.setPackageDir(this.packageDir);
    }

    if (this.exports != null) {
      for (String exportId : this.exports.keySet()) {
        String filename = this.exports.get(exportId);
        File exportFile = new File(filename);
        if (!exportFile.isAbsolute()) {
          exportFile = new File(this.outputDir, filename);
        }

        enunciate.addExport(exportId, exportFile);
      }
    }

    try {
      Enunciate.Stepper stepper = enunciate.getStepper();
      Properties properties = this.project.getProperties();
      properties.put(ENUNCIATE_STEPPER_PROPERTY, stepper);
    }
    catch (Exception e) {
      throw new MojoExecutionException("Error initializing Enunciate mechanism.", e);
    }
  }

  /**
   * Loads a correct instance of the Maven-specific Enunciate mechanism.
   *
   * @param sourceFiles The source files.
   * @return The maven-specific Enunciate mechanism.
   */
  protected MavenSpecificEnunciate loadMavenSpecificEnunciate(Set<File> sourceFiles) {
    return new MavenSpecificEnunciate(sourceFiles);
  }

  /**
   * Enunciate mechanism that logs via the Maven logging mechanism.
   */
  protected class MavenSpecificEnunciate extends Enunciate {

    public MavenSpecificEnunciate(Collection<File> rootDirs) {
      super();
      ArrayList<String> sources = new ArrayList<String>();
      for (File rootDir : rootDirs) {
        sources.addAll(getJavaFiles(rootDir));
      }

      setSourceFiles(sources.toArray(new String[sources.size()]));
    }


    @Override
    protected List<DeploymentModule> doInit() throws EnunciateException, IOException {
      List<DeploymentModule> modules = super.doInit();

      AMFDeploymentModule amfModule = null;
      GWTDeploymentModule gwtModule = null;
      SpringAppDeploymentModule springAppModule = null;
      for (DeploymentModule module : modules) {
        if (module instanceof SpringAppDeploymentModule) {
          springAppModule = (SpringAppDeploymentModule) module;
        }
        else if (module instanceof GWTDeploymentModule) {
          gwtModule = (GWTDeploymentModule) module;
        }
        else if (module instanceof AMFDeploymentModule) {
          amfModule = (AMFDeploymentModule) module;
        }
      }

      if ((springAppModule != null) && (!springAppModule.isDisabled())) {
        configureSpringAppDeploymentModule(springAppModule);
      }

      if ((gwtModule != null) && (!gwtModule.isDisabled())) {
        configureGWTDeploymentModule(gwtModule);
      }

      if ((amfModule != null) && (!amfModule.isDisabled())) {
        configureAMFModule(amfModule);
      }

      return modules;
    }

    protected void configureAMFModule(AMFDeploymentModule amfModule) {
      if (flexHome != null) {
        amfModule.setFlexSDKHome(flexHome);
      }

      if (addActionscriptSources) {
        String clientSidePath = amfModule.getClientSideGenerateDir().getPath();
        getLog().info("Adding '" + clientSidePath + "' to the compile source roots.");
        project.addCompileSourceRoot(clientSidePath);
        String serverSidePath = amfModule.getServerSideGenerateDir().getPath();
        getLog().info("Adding '" + serverSidePath + "' to the compile source roots.");
        project.addCompileSourceRoot(serverSidePath);
        for (FlexApp flexApp : amfModule.getFlexApps()) {
          File srcDir = resolvePath(flexApp.getSrcDir());
          String path = srcDir.getPath();
          getLog().info("Adding '" + path + "' to the compile source roots.");
          project.addCompileSourceRoot(path);
        }
      }

      if (amfModule.getCompilerConfig().getContextRoot() == null) {
        amfModule.getCompilerConfig().setContextRoot("/" + project.getArtifactId());
      }
    }

    protected void configureGWTDeploymentModule(GWTDeploymentModule gwtModule) {
      if (gwtHome != null) {
        gwtModule.setGwtHome(gwtHome);
      }

      if (addGWTSources) {
        String clientSidePath = gwtModule.getClientSideGenerateDir().getPath();
        getLog().info("Adding '" + clientSidePath + "' to the compile source roots.");
        project.addCompileSourceRoot(clientSidePath);
        String serverSidePath = gwtModule.getServerSideGenerateDir().getPath();
        getLog().info("Adding '" + serverSidePath + "' to the compile source roots.");
        project.addCompileSourceRoot(serverSidePath);
        for (GWTApp gwtApp : gwtModule.getGwtApps()) {
          File srcDir = resolvePath(gwtApp.getSrcDir());
          String path = srcDir.getPath();
          getLog().info("Adding '" + path + "' to the compile source roots.");
          project.addCompileSourceRoot(path);
        }
      }
    }

    protected void configureSpringAppDeploymentModule(SpringAppDeploymentModule springAppModule) throws IOException {
      if (compileDir == null) {
        //set an explicit compile dir if one doesn't exist because we're going to need to reference it to set the output directory for Maven.
        setCompileDir(createTempDir());
      }

      String outputDir = springAppModule.getCompileDir().getAbsolutePath();
      getLog().info("Setting 'build.outputDirectory' to " + outputDir);
      project.getBuild().setOutputDirectory(outputDir);
    }

    @Override
    public void info(String message, Object... formatArgs) {
      getLog().info(String.format(message, formatArgs));
    }

    @Override
    public void debug(String message, Object... formatArgs) {
      getLog().debug(String.format(message, formatArgs));
    }

    @Override
    public void warn(String message, Object... formatArgs) {
      getLog().warn(String.format(message, formatArgs));
    }

    @Override
    public boolean isDebug() {
      return getLog().isDebugEnabled();
    }


    @Override
    public boolean isVerbose() {
      return getLog().isInfoEnabled();
    }

    @Override
    protected void doClose(List<DeploymentModule> list) throws EnunciateException, IOException {
      super.doClose(list);

      if (warArtifactId != null) {
        org.codehaus.enunciate.main.Artifact warArtifact = null;
        for (org.codehaus.enunciate.main.Artifact artifact : getArtifacts()) {
          if (warArtifactId.equals(artifact.getId())) {
            warArtifact = artifact;
            break;
          }
        }

        if (warArtifact != null) {
          String classifier = warArtifactClassifier;
          if (classifier == null) {
            classifier = "";
          }
          else if (classifier.trim().length() > 0 && !classifier.startsWith("-")) {
            classifier = "-" + classifier;
          }

          File warArtifactFile = new File(outputDir, warArtifactName + classifier + ".war");
          warArtifact.exportTo(warArtifactFile, this);
          project.getArtifact().setFile(warArtifactFile);
        }
        else {
          getLog().warn("War artifact '" + warArtifactId + "' not found in the project...");
        }
      }

      if (artifacts != null) {
        for (Artifact projectArtifact : artifacts) {
          if (projectArtifact.getEnunciateArtifactId() == null) {
            getLog().warn("No enunciate export id specified.  Skipping project artifact...");
            continue;
          }

          org.codehaus.enunciate.main.Artifact artifact = null;
          for (org.codehaus.enunciate.main.Artifact enunciateArtifact : getArtifacts()) {
            if (projectArtifact.getEnunciateArtifactId().equals(enunciateArtifact.getId())) {
              artifact = enunciateArtifact;
              break;
            }
          }

          if (artifact != null) {
            File tempExportFile = File.createTempFile(project.getArtifactId() + "-" + projectArtifact.getClassifier(), projectArtifact.getArtifactType());
            artifact.exportTo(tempExportFile, this);
            projectHelper.attachArtifact(project, projectArtifact.getArtifactType(), projectArtifact.getClassifier(), tempExportFile);
          }
          else {
            getLog().warn("Enunciate artifact '" + projectArtifact.getEnunciateArtifactId() + "' not found in the project...");
          }
        }
      }
    }

  }
}
