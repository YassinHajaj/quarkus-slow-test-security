import io.quarkus.test.security.SecurityAttribute;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface CustomTestSecurity {

    /**
     * If this is false then all security constraints are disabled.
     */
    boolean authorizationEnabled() default true;

    /**
     * If this is non-zero then the test will be run with a SecurityIdentity with the specified username.
     */
    String user() default "";

    /**
     * Used in combination with {@link #user()} to specify the users roles.
     */
    String[] roles() default {};

    SecurityAttribute[] attributes() default {};
}
