package org.jboss.seam.example.messages;

import org.jboss.seam.Component;
import org.jboss.seam.ScopeType;

import javax.jws.WebService;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import java.util.List;

/**
 * Message service for retrieving messages.
 *
 * @author Ryan Heaton
 */
@WebService
@Path("/messages")
public class MessageService {

  /**
   * Get the list of messages.
   *
   * @return The list of messages.
   */
  public List<Message> getMessages() {
    MessageManager bean = getMessageManager();
    return bean.findMessages();
  }

  /**
   * Get the message of the specified id.
   *
   * @param id The message id.
   * @return The message, if any.
   */
  @GET
  @Path("/message/{id}")
  public Message getMessage(@PathParam("id") long id) {
    for (Message message : getMessages()) {
      if (message.getId() != null && message.getId().equals(id)) {
        return message;
      }
    }

    return null;
  }

  private MessageManager getMessageManager() {
    return (MessageManager) Component.getInstance(MessageManagerBean.class, ScopeType.SESSION, true);
  }
}
