package net.sf.enunciate.config;

import net.sf.enunciate.decorations.jaxws.WebService;
import net.sf.enunciate.apt.EnunciateFreemarkerModel;
import net.sf.jelly.apt.freemarker.FreemarkerModel;

import java.util.*;

/**
 * Configuration information about a WSDL.
 *
 * @author Ryan Heaton
 */
public class WsdlInfo {

  private String targetNamespace;
  private SchemaInfo schemaInfo;
  private Collection<WebService> endpointInterfaces;
  private boolean generate;
  private String file;

  /**
   * The target namespace.
   *
   * @return The target namespace.
   */
  public String getTargetNamespace() {
    return targetNamespace;
  }

  /**
   * The target namespace.
   *
   * @param targetNamespace The target namespace.
   */
  public void setTargetNamespace(String targetNamespace) {
    this.targetNamespace = targetNamespace;
  }

  /**
   * The endpoint interfaces making up this WSDL.
   *
   * @return The endpoint interfaces making up this WSDL.
   */
  public Collection<WebService> getEndpointInterfaces() {
    return endpointInterfaces;
  }

  /**
   * The endpoint interfaces making up this WSDL.
   *
   * @param endpointInterfaces The endpoint interfaces making up this WSDL.
   */
  public void setEndpointInterfaces(Collection<WebService> endpointInterfaces) {
    this.endpointInterfaces = endpointInterfaces;
  }

  /**
   * The configuration information about the schema section of this WSDL.
   *
   * @return The configuration information about the schema section of this WSDL.
   */
  public SchemaInfo getSchemaInfo() {
    return schemaInfo;
  }

  /**
   * The configuration information about the inline schema of this WSDL.
   *
   * @param schemaInfo The configuration information about the inline schema of this WSDL.
   */
  public void setSchemaInfo(SchemaInfo schemaInfo) {
    this.schemaInfo = schemaInfo;
  }

  /**
   * Whether or not to generate this wsdl.
   *
   * @return Whether or not to generate this wsdl.
   */
  public boolean isGenerate() {
    return generate;
  }

  /**
   * Whether or not to generate this wsdl.
   *
   * @param generate Whether or not to generate this wsdl.
   */
  public void setGenerate(boolean generate) {
    this.generate = generate;
  }

  /**
   * The file to which to write this wsdl.
   *
   * @return The file to which to write this wsdl.
   */
  public String getFile() {
    return file;
  }

  /**
   * The file to which to write this wsdl.
   *
   * @param file The file to which to write this wsdl.
   */
  public void setFile(String file) {
    this.file = file;
  }

  /**
   * Get the imported namespaces used by this WSDL.
   *
   * @return The imported namespaces used by this WSDL.
   */
  public Set<String> getImportedNamespaces() {
    Collection<WebService> endpointInterfaces = getEndpointInterfaces();
    if ((endpointInterfaces == null) || (endpointInterfaces.size() == 0)) {
      throw new IllegalStateException("WSDL for " + getTargetNamespace() + " has no endpoint interfaces!");
    }

    TreeSet<String> importedNamespaces = new TreeSet<String>();
    for (WebService webService : endpointInterfaces) {
      importedNamespaces.addAll(webService.getReferencedNamespaces());
    }
    
    return importedNamespaces;
  }

  /**
   * The list of imported schemas.
   *
   * @return The list of imported schemas.
   */
  public List<SchemaInfo> getImportedSchemas() {
    Set<String> importedNamespaces = getImportedNamespaces();
    List<SchemaInfo> schemas = new ArrayList<SchemaInfo>();
    for (String ns : importedNamespaces) {
      schemas.add(lookupSchema(ns));
    }
    return schemas;
  }

  /**
   * Convenience method to lookup a namespace schema given a namespace.
   *
   * @param namespace The namespace for which to lookup the schema.
   * @return The schema info.
   */
  protected SchemaInfo lookupSchema(String namespace) {
    return getNamespacesToSchemas().get(namespace);
  }

  /**
   * The namespace to schema map.
   *
   * @return The namespace to schema map.
   */
  protected Map<String, SchemaInfo> getNamespacesToSchemas() {
    return getModel().getNamespacesToSchemas();
  }

  /**
   * Get the current root model.
   *
   * @return The current root model.
   */
  protected EnunciateFreemarkerModel getModel() {
    return ((EnunciateFreemarkerModel) FreemarkerModel.get());
  }

}
