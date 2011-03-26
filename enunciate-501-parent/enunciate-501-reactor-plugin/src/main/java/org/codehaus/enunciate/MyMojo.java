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

import org.apache.maven.model.Model;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;

import java.util.List;

/**
 * Goal which touches a timestamp file.
 *
 * @goal go
 * @phase install
 */
public class MyMojo extends AbstractMojo {
  /**
   * @parameter expression="${reactorProjects}"
   * @required
   * @readonly
   */
  protected List reactorProjects;

  public void execute() throws MojoExecutionException {
    Model model = new Model();
    model.setGroupId("org.codehaus.enunciate.samples");
    model.setArtifactId("enunciate-501-webapp-client");
    model.setVersion("1.0-SNAPSHOT");
    reactorProjects.add(new MavenProject(model));
  }
}
