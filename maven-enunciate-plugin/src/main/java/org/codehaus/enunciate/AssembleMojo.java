package org.codehaus.enunciate;

import org.apache.maven.plugin.MojoExecutionException;
import org.codehaus.enunciate.modules.spring_app.SpringAppDeploymentModule;
import org.codehaus.enunciate.main.Enunciate;

import java.io.File;
import java.io.IOException;
import java.util.Set;
import java.util.Collection;
import java.util.Properties;

/**
 * Assembles the whole Enunciate app without compilation or packaging of the war.
 * For use with the "war" packaging.
 *
 * @goal assemble
 * @phase generate-sources
 * @requiresDependencyResolution compile

 * @author Ryan Heaton
 */
public class AssembleMojo extends ConfigMojo {

  /**
   * The directory where the webapp is built.  If using this goal along with "war" packaging, this must be configured to be the
   * same value as the "webappDirectory" parameter to the war plugin.
   *
   * @parameter expression="target/${project.build.finalName}"
   * @required
   */
  private String webappDirectory;

  /**
   * Whether to force the "packaging" of the project to be "war" packaging.
   *
   * @parameter
   */
  private boolean forceWarPackaging = true;

  private AssembleOnlyMavenSpecificEnunciate enunciate = null;

  @Override
  public void execute() throws MojoExecutionException {
    if (forceWarPackaging && !"war".equalsIgnoreCase(this.project.getPackaging())) {
      throw new MojoExecutionException("The 'assemble' goal requires 'war' packaging.");
    }

    super.execute();

    Enunciate.Stepper stepper = (Enunciate.Stepper) getPluginContext().get(ConfigMojo.ENUNCIATE_STEPPER_PROPERTY);
    if (stepper == null) {
      throw new MojoExecutionException("No stepper found in the project!");
    }

    try {
      stepper.stepTo(Enunciate.Target.PACKAGE);
      stepper.close();
    }
    catch (Exception e) {
      throw new MojoExecutionException("Problem assembling the enunciate app.", e);
    }

    //now we have to include the server-side sources into the compile source roots.
    File jaxwsSources = (File) this.enunciate.getProperty("jaxws.src.dir");
    if (jaxwsSources != null) {
      project.addCompileSourceRoot(jaxwsSources.getAbsolutePath());
    }

    File xfireServerSources = (File) this.enunciate.getProperty("xfire-server.src.dir");
    if (xfireServerSources != null) {
      project.addCompileSourceRoot(xfireServerSources.getAbsolutePath());
    }

    File gwtServerSources = (File) this.enunciate.getProperty("gwt.server.src.dir");
    if (gwtServerSources != null) {
      project.addCompileSourceRoot(gwtServerSources.getAbsolutePath());
    }

    File gwtClientSources = (File) this.enunciate.getProperty("gwt.client.src.dir");
    if (gwtClientSources != null) {
      project.addCompileSourceRoot(gwtClientSources.getAbsolutePath());
    }

    File amfServerSources = (File) this.enunciate.getProperty("amf.server.src.dir");
    if (amfServerSources != null) {
      project.addCompileSourceRoot(amfServerSources.getAbsolutePath());
    }
  }

  @Override
  protected MavenSpecificEnunciate loadMavenSpecificEnunciate(Set<File> sourceFiles) {
    enunciate = new AssembleOnlyMavenSpecificEnunciate(sourceFiles);
    return enunciate;
  }

  /**
   * A maven-specific enunciate mechanism that performs assembly-only (skips compilation/packaging of the war).
   */
  protected class AssembleOnlyMavenSpecificEnunciate extends MavenSpecificEnunciate {

    public AssembleOnlyMavenSpecificEnunciate(Collection<File> rootDirs) {
      super(rootDirs);
    }

    @Override
    protected void onInitSpringAppDeploymentModule(SpringAppDeploymentModule springAppModule) throws IOException {
      super.onInitSpringAppDeploymentModule(springAppModule);

      springAppModule.setDoCompile(false);
      springAppModule.setDoLibCopy(false);
      springAppModule.setDoPackage(false);
      springAppModule.setBuildDir(new File(project.getBasedir(), webappDirectory));
    }
  }
}
