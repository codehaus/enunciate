package net.sf.enunciate.template.strategies.jaxb;

import net.sf.enunciate.config.SchemaInfo;
import net.sf.enunciate.template.strategies.EnunciateTemplateLoopStrategy;
import net.sf.jelly.apt.TemplateException;
import net.sf.jelly.apt.TemplateModel;

import java.util.Iterator;

/**
 * Strategy that loops through each schema.
 *
 * @author Ryan Heaton
 */
public class SchemaLoopStrategy extends EnunciateTemplateLoopStrategy<SchemaInfo> {

  private String var = "schema";
  private SchemaInfo currentSchema;

  /**
   * Get the loop through the schemas.
   *
   * @param model The model to work with.
   * @return The loop through the schemas.
   */
  protected Iterator<SchemaInfo> getLoop(TemplateModel model) throws TemplateException {
    return getNamespacesToSchemas().values().iterator();
  }

  // Inherited.
  @Override
  protected void setupModelForLoop(TemplateModel model, SchemaInfo schemaInfo, int index) throws TemplateException {
    super.setupModelForLoop(model, schemaInfo, index);

    if (var != null) {
      getModel().setVariable(var, schemaInfo);
    }

    if (isVerbose()) {
      System.out.println("Current schema target namespace: " + schemaInfo.getNamespace());
    }

    this.currentSchema = schemaInfo;
  }

  /**
   * The variable to which to assign the current schema in the loop.
   *
   * @return The variable to which to assign the current schema in the loop.
   */
  public String getVar() {
    return var;
  }

  /**
   * The variable to which to assign the current schema in the loop.
   *
   * @param var The variable to which to assign the current schema in the loop.
   */
  public void setVar(String var) {
    this.var = var;
  }

  /**
   * The current schema in the loop.
   *
   * @return The current schema in the loop.
   */
  public SchemaInfo getCurrentSchema() {
    return currentSchema;
  }
}
