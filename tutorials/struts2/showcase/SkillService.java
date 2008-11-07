package org.apache.struts2.showcase.dao;

import org.apache.struts2.showcase.model.Skill;
import org.apache.struts2.showcase.exception.CreateException;
import org.springframework.beans.factory.annotation.Autowired;

import javax.jws.WebService;
import javax.ws.rs.Path;
import javax.ws.rs.GET;
import javax.ws.rs.PathParam;

/**
 * Service for skills.
 *
 * @author Ryan Heaton
 */
@WebService
@Path("/skills")
public class SkillService {

  @Autowired
  private SkillDao dao;

  /**
   * Get the skill.
   *
   * @param name The name of the skill.
   * @return The skill.
   */
  @GET
  @Path("/skill/{name}")
  public Skill getSkill(@PathParam("name") String name) {
    return (Skill) this.dao.get(name);
  }

  /**
   * Create an skill.
   *
   * @param skill The skill to create.
   */
  public void createSkill(Skill skill) {
    try {
      this.dao.create(skill);
    }
    catch (CreateException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Delete an skill.
   *
   * @param name Name of the skill to delete.
   */
  public void deleteSkill(String name) {
    try {
      this.dao.delete(name);
    }
    catch (CreateException e) {
      throw new RuntimeException(e);
    }
  }
}