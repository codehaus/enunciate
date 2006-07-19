package net.sf.enunciate.samples.petclinic.services.impl;

import net.sf.enunciate.samples.petclinic.Owner;
import net.sf.enunciate.samples.petclinic.services.OwnerService;
import net.sf.enunciate.samples.petclinic.services.ServiceException;

import javax.jws.WebService;
import java.util.*;

/**
 * @author Ryan Heaton
 */
@WebService (
  endpointInterface = "net.sf.enunciate.samples.petclinic.services.OwnerService"
)
public class OwnerServiceImpl implements OwnerService {

  private static Map<Integer, Owner> OWNERS = Collections.synchronizedMap(new HashMap<Integer, Owner>());

  static {
    for (int i = 1; i <= 9; i++) {
      Owner owner = new Owner();
      owner.setId(i);
      owner.setAddress(String.format("address %s", i));
      owner.setCity(String.format("city %s", i));
      owner.setFirstName("Owner");
      owner.setLastName(String.format("%tA", new GregorianCalendar(2000, 1, i)));
      owner.setTelephone(String.format("%1$s%1$s%1$s-%1$s%1$s%1$s-%1$s%1$s%1$s%1$s", i));
      OWNERS.put(i, owner);
    }
  }

  public Collection<Owner> findOwners(String lastName) throws ServiceException {
    ArrayList<Owner> found = new ArrayList<Owner>();
    for (Owner owner : OWNERS.values()) {
      if ((owner.getLastName() != null) && (owner.getLastName().equals(lastName))) {
        found.add(owner);
      }
    }
    return found;
  }

  public Owner readOwner(int id) throws ServiceException {
    return OWNERS.get(id);
  }

  public void storeOwner(Owner owner) throws ServiceException {
    OWNERS.put(owner.getId(), owner);
  }
}
