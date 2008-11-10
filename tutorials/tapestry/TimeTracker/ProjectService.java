package org.apache.tapestry.timetracker.ws;

import org.apache.tapestry.timetracker.model.Project;
import org.apache.tapestry.timetracker.dao.ProjectDao;
import org.apache.hivemind.Registry;
import org.apache.hivemind.servlet.HiveMindFilter;
import org.codehaus.enunciate.modules.spring_app.HTTPRequestContext;

import javax.jws.WebService;
import javax.ws.rs.Path;
import javax.ws.rs.GET;
import javax.ws.rs.PathParam;
import java.util.List;

/**
 * Service for retrieving and updating projects.
 *
 * @author Ryan Heaton
 */
@WebService
@Path ("/projects")
public class ProjectService {

  /**
   * Get a project by id.
   *
   * @param id The id of the project.
   * @return The project id.
   */
  @Path("/project/{id}")
  @GET
  public Project getProject(@PathParam ("id") long id) {
    for (Project project : listProjects()) {
      if (project.getId() == id) {
        return project;
      }
    }

    return null;
  }

  /**
   * The list of projects.
   *
   * @return The list of projects.
   */
  public List<Project> listProjects() {
    ProjectDao dao = (ProjectDao) getRegistry().getService(ProjectDao.class);
    return dao.list();
  }

  private Registry getRegistry() {
    return HiveMindFilter.getRegistry(HTTPRequestContext.get().getRequest());
  }
}