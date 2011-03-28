package org.codehaus.enunciate.samples.ws;

import org.codehaus.enunciate.jaxrs.TypeHint;
import org.codehaus.enunciate.samples.domain.Bogie;

import javax.jws.WebMethod;
import javax.jws.WebService;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

/**
 * @author Ryan Heaton
 */
@WebService
@Path ("/hello")
public class BogusService {

  public String doSomethingBogus(String param1) {
    return null;
  }

  @WebMethod (exclude = true)
  @GET
  @TypeHint (Bogie.class)
  public Response get() {
    return null;
  }
}
