package org.apache.struts2.showcase.dao;

import org.apache.struts2.showcase.model.Employee;
import org.apache.struts2.showcase.exception.CreateException;
import org.springframework.beans.factory.annotation.Autowired;

import javax.jws.WebService;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.GET;

/**
 * Service for employees.
 *
 * @author Ryan Heaton
 */
@WebService
@Path ("/employees")
public class EmployeeService {

  @Autowired
  private EmployeeDao dao;

  /**
   * Get the employee.
   *
   * @param id The id of the employee.
   * @return The employee.
   */
  @GET
  @Path("/employee/{id}")
  public Employee getEmployee(@PathParam("id") long id) {
    return (Employee) this.dao.get(id);
  }

  /**
   * Create an employee.
   *
   * @param employee The employee to create.
   */
  public void createEmployee(Employee employee) {
    try {
      this.dao.create(employee);
    }
    catch (CreateException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Delete an employee.
   *
   * @param id Id of the employee to delete.
   */
  public void deleteEmployee(long id) {
    try {
      this.dao.delete(id);
    }
    catch (CreateException e) {
      throw new RuntimeException(e);
    }
  }
}
