package org.codehaus.enunciate.json;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * <p>
 * Denotes that a type represents a JSON type.
 * </p>
 *
 * @author Steven Cummings
 */
@Target ( ElementType.TYPE )
@Retention ( RetentionPolicy.RUNTIME )
public @interface JsonType {
}
