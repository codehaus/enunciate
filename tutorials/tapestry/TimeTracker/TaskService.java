package org.apache.tapestry.timetracker.ws;

import org.apache.tapestry.timetracker.model.Task;
import org.apache.tapestry.timetracker.dao.TaskDao;
import org.apache.hivemind.Registry;
import org.apache.hivemind.servlet.HiveMindFilter;
import org.codehaus.enunciate.modules.spring_app.HTTPRequestContext;

import javax.jws.WebService;
import javax.ws.rs.Path;
import javax.ws.rs.GET;
import javax.ws.rs.PathParam;
import java.util.List;

/**
 * Service for retrieving and updating tasks.
 *
 * @author Ryan Heaton
 */
@WebService
@Path ("/tasks")
public class TaskService {

  /**
   * Get a task by id.
   *
   * @param id The id of the task.
   * @return The task id.
   */
  @Path("/task/{id}")
  @GET
  public Task getTask(@PathParam ("id") long id) {
    for (Task task : listTasks()) {
      if (task.getId() == id) {
        return task;
      }
    }

    return null;
  }

  /**
   * The list of tasks.
   *
   * @return The list of tasks.
   */
  public List<Task> listTasks() {
    TaskDao dao = (TaskDao) getRegistry().getService(TaskDao.class);
    return dao.list();
  }

  private Registry getRegistry() {
    return HiveMindFilter.getRegistry(HTTPRequestContext.get().getRequest());
  }
}
