import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.oidc.IdTokenCredential;
import io.quarkus.oidc.OidcConfigurationMetadata;
import io.quarkus.oidc.common.runtime.OidcConstants;
import io.quarkus.oidc.runtime.OidcJwtCallerPrincipal;
import io.quarkus.oidc.runtime.OidcUtils;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.junit.callback.QuarkusTestMethodContext;
import io.quarkus.test.security.TestAuthController;
import io.quarkus.test.security.TestIdentityAssociation;
import io.quarkus.test.security.oidc.Claim;
import io.quarkus.test.security.oidc.ClaimType;
import io.quarkus.test.security.oidc.ConfigMetadata;
import io.quarkus.test.security.oidc.OidcSecurity;
import io.quarkus.test.security.oidc.TokenIntrospection;
import io.quarkus.test.security.oidc.UserInfo;
import io.quarkus.test.util.annotations.AnnotationContainer;
import io.quarkus.test.util.annotations.AnnotationUtils;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.util.KeyUtils;
import io.vertx.core.json.JsonObject;
import jakarta.enterprise.inject.spi.CDI;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonReader;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jose4j.jwt.JwtClaims;

import java.io.StringReader;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

public class TestSecuritySetup {

    private static final PrivateKey privateKey;

    static {
        try {
            privateKey = KeyUtils.generateKeyPair(2048).getPrivate();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void setUpSecurity(QuarkusTestMethodContext context) {
        try {
            Optional<AnnotationContainer<CustomTestSecurity>> annotationContainerOptional = getAnnotationContainer(context);
            if (annotationContainerOptional.isEmpty()) {
                return;
            }
            var annotationContainer = annotationContainerOptional.get();
            Annotation[] allAnnotations = annotationContainer.getElement().getAnnotations();
            CustomTestSecurity testSecurity = annotationContainer.getAnnotation();
            CDI.current().select(TestAuthController.class).get().setEnabled(testSecurity.authorizationEnabled());
            if (testSecurity.user().isEmpty()) {
                if (testSecurity.roles().length != 0) {
                    throw new RuntimeException("Cannot specify roles without a username in @CustomTestSecurity");
                }
            } else {
                QuarkusSecurityIdentity.Builder user = QuarkusSecurityIdentity.builder()
                        .setPrincipal(new QuarkusPrincipal(testSecurity.user()))
                        .addRoles(new HashSet<>(Arrays.asList(testSecurity.roles())));

                if (testSecurity.attributes() != null) {
                    user.addAttributes(Arrays.stream(testSecurity.attributes())
                            .collect(Collectors.toMap(s -> s.key(), s -> s.value())));
                }

                SecurityIdentity userIdentity = augment(user.build(), allAnnotations);

                CDI.current().select(TestIdentityAssociation.class).get().setTestIdentity(userIdentity);
            }
        } catch (Exception e) {
            throw new RuntimeException("Unable to setup @CustomTestSecurity", e);
        }
    }

    private static Optional<AnnotationContainer<CustomTestSecurity>> getAnnotationContainer(QuarkusTestMethodContext context)
            throws Exception {
        //the usual ClassLoader hacks to get our copy of the CustomTestSecurity annotation
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        Class<?> original = cl.loadClass(context.getTestMethod().getDeclaringClass().getName());
        Method method = original.getDeclaredMethod(context.getTestMethod().getName(),
                Arrays.stream(context.getTestMethod().getParameterTypes()).map(s -> {
                    if (s.isPrimitive()) {
                        return s;
                    }
                    try {
                        return Class.forName(s.getName(), false, cl);
                    } catch (ClassNotFoundException e) {
                        throw new RuntimeException(e);
                    }
                }).toArray(Class<?>[]::new));
        Optional<AnnotationContainer<CustomTestSecurity>> annotationContainerOptional = AnnotationUtils.findAnnotation(method,
                CustomTestSecurity.class);
        if (annotationContainerOptional.isEmpty()) {
            annotationContainerOptional = AnnotationUtils.findAnnotation(original, CustomTestSecurity.class);
        }
        return annotationContainerOptional;
    }


    private static SecurityIdentity augment(SecurityIdentity identity, Annotation[] annotations) {
        return augmentSecurityIdentity(identity, annotations);
    }

    public static SecurityIdentity augmentSecurityIdentity(final SecurityIdentity identity, final Annotation[] annotations) {
        QuarkusSecurityIdentity.Builder builder = QuarkusSecurityIdentity.builder(identity);

        final OidcSecurity oidcSecurity = findOidcSecurity(annotations);

        if (oidcSecurity == null) {
            return builder.build();
        }

        final boolean introspectionRequired = oidcSecurity != null && oidcSecurity.introspectionRequired();

        if (!introspectionRequired) {
            // JsonWebToken
            JsonObjectBuilder claims = Json.createObjectBuilder();
            claims.add(Claims.preferred_username.name(), identity.getPrincipal().getName());
            claims.add(Claims.groups.name(),
                    Json.createArrayBuilder(new ArrayList<>(identity.getRoles())).build());
            if (oidcSecurity.claims() != null) {
                for (Claim claim : oidcSecurity.claims()) {
                    Object claimValue = convertClaimValue(claim);
                    if (claimValue instanceof String) {
                        claims.add(claim.key(), (String) claimValue);
                    } else if (claimValue instanceof Long) {
                        claims.add(claim.key(), (Long) claimValue);
                    } else if (claimValue instanceof Integer) {
                        claims.add(claim.key(), (Integer) claimValue);
                    } else if (claimValue instanceof Boolean) {
                        claims.add(claim.key(), (Boolean) claimValue);
                    } else if (claimValue instanceof JsonArray) {
                        claims.add(claim.key(), (JsonArray) claimValue);
                    } else if (claimValue instanceof jakarta.json.JsonObject) {
                        claims.add(claim.key(), (jakarta.json.JsonObject) claimValue);
                    }
                }
            }

            jakarta.json.JsonObject claimsJson = claims.build();
            String jwt = generateToken(claimsJson);
            IdTokenCredential idToken = new IdTokenCredential(jwt);
            AccessTokenCredential accessToken = new AccessTokenCredential(jwt);

            try {
                JsonWebToken principal = new OidcJwtCallerPrincipal(JwtClaims.parse(claimsJson.toString()), idToken);
                builder.setPrincipal(principal);
            } catch (Exception ex) {
                throw new RuntimeException();
            }
            builder.addCredential(idToken);
            builder.addCredential(accessToken);
        } else {
            JsonObjectBuilder introspectionBuilder = Json.createObjectBuilder();
            introspectionBuilder.add(OidcConstants.INTROSPECTION_TOKEN_ACTIVE, true);
            introspectionBuilder.add(OidcConstants.INTROSPECTION_TOKEN_USERNAME, identity.getPrincipal().getName());
            introspectionBuilder.add(OidcConstants.TOKEN_SCOPE,
                    String.join(" ", identity.getRoles()));

            if (oidcSecurity.introspection() != null) {
                for (TokenIntrospection introspection : oidcSecurity.introspection()) {
                    introspectionBuilder.add(introspection.key(), introspection.value());
                }
            }

            builder.addAttribute(OidcUtils.INTROSPECTION_ATTRIBUTE,
                    new io.quarkus.oidc.TokenIntrospection(introspectionBuilder.build()));
            builder.addCredential(new AccessTokenCredential(UUID.randomUUID().toString(), null));
        }

        // UserInfo
        if (oidcSecurity.userinfo() != null) {
            JsonObjectBuilder userInfoBuilder = Json.createObjectBuilder();
            for (UserInfo userinfo : oidcSecurity.userinfo()) {
                userInfoBuilder.add(userinfo.key(), userinfo.value());
            }
            builder.addAttribute(OidcUtils.USER_INFO_ATTRIBUTE, new io.quarkus.oidc.UserInfo(userInfoBuilder.build()));
        }

        // OidcConfigurationMetadata
        JsonObject configMetadataBuilder = new JsonObject();
//        if (issuer.isPresent()) {
//            configMetadataBuilder.put("issuer", issuer.get());
//        }
        if (oidcSecurity != null && oidcSecurity.config() != null) {
            for (ConfigMetadata config : oidcSecurity.config()) {
                configMetadataBuilder.put(config.key(), config.value());
            }
        }
        builder.addAttribute(OidcUtils.CONFIG_METADATA_ATTRIBUTE, new OidcConfigurationMetadata(configMetadataBuilder));

        return builder.build();
    }

    private static String generateToken(jakarta.json.JsonObject claims) {
        try {
            return Jwt.claims(claims).sign(privateKey);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private static OidcSecurity findOidcSecurity(Annotation[] annotations) {
        for (Annotation ann : annotations) {
            if (ann instanceof OidcSecurity) {
                return (OidcSecurity) ann;
            }
        }
        return null;
    }

    private static Map<String, ClaimType> standardClaimTypes = Map.of(
            Claims.exp.name(), ClaimType.LONG,
            Claims.iat.name(), ClaimType.LONG,
            Claims.nbf.name(), ClaimType.LONG,
            Claims.auth_time.name(), ClaimType.LONG,
            Claims.email_verified.name(), ClaimType.BOOLEAN);

    private static Object convertClaimValue(Claim claim) {
        ClaimType type = claim.type();
        if (type == ClaimType.DEFAULT && standardClaimTypes.containsKey(claim.key())) {
            type = standardClaimTypes.get(claim.key());
        }
        return CustomClaimType.valueOf(type.name()).convert(claim.value());
    }

    public enum CustomClaimType {
        LONG {
            public Long convert(String value) {
                return Long.parseLong(value);
            }
        },
        INTEGER {
            public Integer convert(String value) {
                return Integer.parseInt(value);
            }
        },
        BOOLEAN {
            public Boolean convert(String value) {
                return Boolean.parseBoolean(value);
            }
        },
        STRING {
            public String convert(String value) {
                return value;
            }
        },
        JSON_ARRAY {
            public JsonArray convert(String value) {
                JsonReader jsonReader = Json.createReader(new StringReader(value));

                JsonArray var3;
                try {
                    var3 = jsonReader.readArray();
                } catch (Throwable var6) {
                    if (jsonReader != null) {
                        try {
                            jsonReader.close();
                        } catch (Throwable var5) {
                            var6.addSuppressed(var5);
                        }
                    }

                    throw var6;
                }

                if (jsonReader != null) {
                    jsonReader.close();
                }

                return var3;
            }
        },
        JSON_OBJECT {
            public jakarta.json.JsonObject convert(String value) {
                JsonReader jsonReader = Json.createReader(new StringReader(value));

                jakarta.json.JsonObject var3;
                try {
                    var3 = jsonReader.readObject();
                } catch (Throwable var6) {
                    if (jsonReader != null) {
                        try {
                            jsonReader.close();
                        } catch (Throwable var5) {
                            var6.addSuppressed(var5);
                        }
                    }

                    throw var6;
                }

                if (jsonReader != null) {
                    jsonReader.close();
                }

                return var3;
            }
        },
        DEFAULT {
            public String convert(String value) {
                return value;
            }
        };

        private CustomClaimType() {
        }

        abstract Object convert(String value);
    }
}
