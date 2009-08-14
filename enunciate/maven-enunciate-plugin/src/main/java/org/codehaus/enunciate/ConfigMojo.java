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

import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Resource;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.apache.maven.shared.filtering.MavenFileFilter;
import org.apache.maven.shared.filtering.MavenFilteringException;
import org.codehaus.enunciate.config.EnunciateConfiguration;
import org.codehaus.enunciate.main.Enunciate;
import org.codehaus.enunciate.modules.*;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * Goal which initializes an Enunciate build process.
 *
 * @goal config
 * @phase validate
 * @requiresDependencyResolution compile
 */
public class ConfigMojo extends AbstractMojo {

  public static final String ENUNCIATE_PROPERTY = "urn:" + ConfigMojo.class.getName() + "#enunciate";
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
   * @parameter expression="${project.build.directory}/enunciate/generate"
   */
  private File generateDir = null;

  /**
   * The output directory for the "compile" step.
   *
   * @parameter expression="${project.build.directory}/enunciate/compile"
   */
  private File compileDir = null;

  /**
   * The output directory for the "build" step.
   *
   * @parameter expression="${project.build.directory}/enunciate/build"
   */
  private File buildDir = null;

  /**
   * The output directory for the "package" step.
   *
   * @parameter expression="${project.build.directory}/enunciate/package"
   */
  private File packageDir = null;

  /**
   * The directory where Enunciate puts scratch files.
   *
   * @parameter expression="${project.build.directory}/enunciate-scratch"
   */
  private File scratchDir = null;

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
   * Whether to add the XFire client sources to the project test sources.
   *
   * @parameter
   */
  private boolean addXFireClientSourcesToTestClasspath = false;

  /**
   * Whether to add the JAXWS client sources to the project test sources.
   *
   * @parameter
   */
  private boolean addJAXWSClientSourcesToTestClasspath = false;

  /**
   * List of modules that are to be excluded as extensions to this project.
   *
   * @parameter
   */
  private String[] excludeProjectExtensions;

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
   * Whether to compile with debug information.
   *
   * @parameter
   */
  private boolean compileDebug = true;

  /**
   * The exports.
   *
   * @parameter
   */
  private Map<String, String> exports = new HashMap<String, String>();

  /**
   * The include patterns.
   */
  private String[] includes;

  /**
   * The exclude patterns.
   */
  private String[] excludes;

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

  /**
   * @parameter expression="${session}"
   * @readonly
   */
  private MavenSession session;

  /**
   * Maven file filter.
   *
   * @component role="org.apache.maven.shared.filtering.MavenFileFilter" role-hint="default"
   * @readonly
   */
  private MavenFileFilter configFilter;

  /**
   * List of source directories that are enunciate-added.
   */
  private static final TreeSet<String> ENUNCIATE_ADDED = new TreeSet<String>();

  public void execute() throws MojoExecutionException {
    Set<File> sourceDirs = new HashSet<File>();
    Collection<String> sourcePaths = (Collection<String>) project.getCompileSourceRoots();
    for (String sourcePath : sourcePaths) {
      File sourceDir = new File(sourcePath);
      if (!isEnunciateAdded(sourceDir)) {
        sourceDirs.add(sourceDir);
      }
      else {
        getLog().info(sourceDir + " appears to be added to the source roots by Enunciate.  Excluding from original source roots....");
      }
    }

    MavenSpecificEnunciate enunciate = loadMavenSpecificEnunciate(sourceDirs);
    EnunciateConfiguration config = createEnunciateConfiguration();
    config.setLabel(project.getArtifactId());
    if (this.configFile != null) {
      try {
        loadConfig(config, this.configFile);
      }
      catch (Exception e) {
        throw new MojoExecutionException("Problem with enunciate config file " + this.configFile, e);
      }
      enunciate.setConfigFile(this.configFile);
    }
    else {
      File defaultConfig = new File(project.getBasedir(), "enunciate.xml");
      if (defaultConfig.exists()) {
        getLog().info(defaultConfig.getAbsolutePath() + " exists, so it will be used.");
        try {
          loadConfig(config, defaultConfig);
        }
        catch (Exception e) {
          throw new MojoExecutionException("Problem with enunciate config file " + defaultConfig, e);
        }
        enunciate.setConfigFile(defaultConfig);
      }
    }

    if (this.includes != null) {
      for (String include : this.includes) {
        config.addApiIncludePattern(include);
      }
    }

    if (this.excludes != null) {
      for (String exclude : this.excludes) {
        config.addApiExcludePattern(exclude);
      }
    }

    enunciate.setConfig(config);
    Set<org.apache.maven.artifact.Artifact> classpathEntries = new HashSet<org.apache.maven.artifact.Artifact>();
    classpathEntries.addAll(this.projectDependencies);
    Iterator<org.apache.maven.artifact.Artifact> it = classpathEntries.iterator();
    while (it.hasNext()) {
      org.apache.maven.artifact.Artifact artifact = it.next();
      String artifactScope = artifact.getScope();
      if (org.apache.maven.artifact.Artifact.SCOPE_TEST.equals(artifactScope)) {
        //remove just the test-scope artifacts from the classpath.
        it.remove();
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
    enunciate.setRuntimeClasspath(classpath.toString());

    classpathEntries.clear();
    classpathEntries.addAll(this.pluginDepdendencies);
    classpath = new StringBuffer();
    classpathIt = classpathEntries.iterator();
    while (classpathIt.hasNext()) {
      classpath.append(classpathIt.next().getFile().getAbsolutePath());
      if (classpathIt.hasNext()) {
        classpath.append(File.pathSeparatorChar);
      }
    }
    enunciate.setBuildClasspath(classpath.toString());


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

    if (this.scratchDir != null) {
      enunciate.setScratchDir(this.scratchDir);
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

    enunciate.setCompileDebugInfo(this.compileDebug);

    try {
      enunciate.loadMavenConfiguration();
      Enunciate.Stepper stepper = enunciate.getStepper();
      getPluginContext().put(ENUNCIATE_STEPPER_PROPERTY, stepper);
      getPluginContext().put(ENUNCIATE_PROPERTY, enunciate);
    }
    catch (Exception e) {
      throw new MojoExecutionException("Error initializing Enunciate mechanism.", e);
    }
  }

  /**
   * Load the config, do filtering as needed.
   *
   * @param config     The config to load into.
   * @param configFile The config file.
   */
  protected void loadConfig(EnunciateConfiguration config, File configFile) throws IOException, SAXException, MavenFilteringException {
    if (this.configFilter == null) {
      getLog().info("No maven file filter was provided, so no filtering of the config file will be done.");
      config.load(configFile);
    }
    else {
      this.scratchDir.mkdirs();
      File filteredConfig = File.createTempFile("enunciateConfig", ".xml", this.scratchDir);
      getLog().info("Filtering " + configFile + " to " + filteredConfig + "...");
      this.configFilter.copyFile(configFile, filteredConfig, true, this.project, null, true, "utf-8", this.session);
      config.load(filteredConfig);
    }
  }

  /**
   * Whether the given source directory is Enunciate-generated.
   *
   * @param sourceDir The source directory.
   * @return Whether the given source directory is Enunciate-generated.Whether the given source directory is Enunciate-generated.
   */
  protected boolean isEnunciateAdded(File sourceDir) {
    return ENUNCIATE_ADDED.contains(sourceDir.getAbsolutePath());
  }

  /**
   * Adds the specified source directory to the Maven project.
   *
   * @param dir The directory to add to the project.
   */
  protected void addSourceDirToProject(File dir) {
    String sourceDir = dir.getAbsolutePath();
    ENUNCIATE_ADDED.add(sourceDir);
    if (!project.getCompileSourceRoots().contains(sourceDir)) {
      getLog().info("Adding '" + sourceDir + "' to the compile source roots.");
      project.addCompileSourceRoot(sourceDir);
    }
  }

  /**
   * Create an Enunciate configuration.
   *
   * @return The enunciate configuration.
   */
  protected EnunciateConfiguration createEnunciateConfiguration() {
    return new EnunciateConfiguration();
  }

  /**
   * Loads a correct instance of the Maven-specific Enunciate mechanism.
   *
   * @param sourceDirs The directories where the source files exist.
   * @return The maven-specific Enunciate mechanism.
   */
  protected MavenSpecificEnunciate loadMavenSpecificEnunciate(Set<File> sourceDirs) {
    return new MavenSpecificEnunciate(sourceDirs);
  }

  protected Set<String> getExcludedProjectExtensions() {
    TreeSet<String> excluded = new TreeSet<String>();
    if (excludeProjectExtensions != null) {
      excluded.addAll(Arrays.asList(excludeProjectExtensions));
    }

    if (!addActionscriptSources) {
      excluded.add("amf");
    }

    if (!addGWTSources) {
      excluded.add("gwt");
    }

    if (!addJAXWSClientSourcesToTestClasspath) {
      excluded.add("jaxws-client");
    }

    if (!addXFireClientSourcesToTestClasspath) {
      excluded.add("xfire-client");
    }

    return excluded;
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

    public void loadMavenConfiguration() throws IOException {
      for (DeploymentModule module : getConfig().getAllModules()) {
        if (!module.isDisabled()) {
          if (gwtHome != null && (module instanceof GWTHomeAwareModule)) {
            ((GWTHomeAwareModule) module).setGwtHome(gwtHome);
          }
          else if (flexHome != null && (module instanceof FlexHomeAwareModule)) {
            ((FlexHomeAwareModule) module).setFlexHome(flexHome);
          }
        }
      }
    }

    @Override
    protected void initModules(Collection<DeploymentModule> modules) throws EnunciateException, IOException {
      super.initModules(modules);

      if (compileDir == null) {
        //set an explicit compile dir if one doesn't exist because we're going to need to reference it to set the output directory for Maven.
        setCompileDir(createTempDir());
      }

      for (DeploymentModule module : modules) {
        if (!module.isDisabled()) {
          if (module instanceof OutputDirectoryAware) {
            String outputDir = project.getBuild().getOutputDirectory();
            debug("Setting the output directory for module %s to %s...", module.getName(), outputDir);
            ((OutputDirectoryAware) module).setOutputDirectory(new File(outputDir));
          }

          if (project.getName() != null && !"".equals(project.getName().trim()) && module instanceof ProjectTitleAware) {
            ((ProjectTitleAware)module).setTitleConditionally(project.getName());
          }
        }
      }
    }

    @Override
    protected void doGenerate() throws IOException, EnunciateException {
      super.doGenerate();

      for (DeploymentModule module : getConfig().getAllModules()) {
        if (!module.isDisabled() && (module instanceof ProjectExtensionModule) && !getExcludedProjectExtensions().contains(module.getName())) {
          ProjectExtensionModule extensions = (ProjectExtensionModule) module;
          for (File projectSource : extensions.getProjectSources()) {
            addSourceDirToProject(projectSource);
          }

          for (File testSource : extensions.getProjectTestSources()) {
            project.addTestCompileSourceRoot(testSource.getAbsolutePath());
          }

          for (File resourceDir : extensions.getProjectResourceDirectories()) {
            Resource restResource = new Resource();
            restResource.setDirectory(resourceDir.getAbsolutePath());
            project.addResource(restResource);
          }

          for (File resourceDir : extensions.getProjectTestResourceDirectories()) {
            Resource resource = new Resource();
            resource.setDirectory(resourceDir.getAbsolutePath());
            project.addTestResource(resource);
          }
        }
      }
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
    protected void doClose() throws EnunciateException, IOException {
      super.doClose();

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
            File tempExportFile = createTempFile(project.getArtifactId() + "-" + projectArtifact.getClassifier(), projectArtifact.getArtifactType());
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
