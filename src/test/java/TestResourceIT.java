import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import io.quarkus.test.security.oidc.Claim;
import io.quarkus.test.security.oidc.OidcSecurity;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.stream.Stream;

@QuarkusTest
@TestMethodOrder(OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class TestResourceIT {

    public static Stream<Arguments> generate() {
        return Stream.iterate(0, i -> i + 1)
                .map(Arguments::of)
                .limit(1000);
    }

    @Test
    @Order(1)
    public void _warmUp() {

    }

    @Order(2)
    @Test
    public void printTimeStamp() {
        System.out.println("Before testWithoutSecurity " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS")));
    }

    @Order(3)
    @ParameterizedTest
    @MethodSource("generate")
    public void testWithoutSecurity(int sequenceNumber) {

    }

    @Order(4)
    @Test
    public void printTimeStamp2() {
        System.out.println("After testWithoutSecurity " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS")));
        System.out.println("Before testWithSecurity " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS")));
    }

    @Order(5)
    @ParameterizedTest
    @MethodSource("generate")
    @OidcSecurity(claims = @Claim(key = "sub", value = "Neo"))
    @TestSecurity(user = "johnDoe", authorizationEnabled = false)
    public void testWithSecurity(int sequenceNumber) {

    }

    @Order(6)
    @Test
    public void printTimeStamp3() {
        System.out.println("After testWithSecurity " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS")));
    }

    @Order(7)
    @Test
    public void printTimeStamp4() {
        System.out.println("Before testWithCustomSecurity " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS")));
    }

    @Order(8)
    @ParameterizedTest
    @MethodSource("generate")
    @OidcSecurity(claims = @Claim(key = "sub", value = "Neo"))
    @CustomTestSecurity(user = "johnDoe", authorizationEnabled = false)
    public void testWithCustomSecurity(int sequenceNumber) {

    }

    @Order(9)
    @Test
    public void printTimeStamp5() {
        System.out.println("After testWithCustomSecurity " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS")));
    }

}
