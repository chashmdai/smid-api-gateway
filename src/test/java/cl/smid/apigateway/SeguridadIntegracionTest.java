package cl.smid.apigateway;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

/**
 * Pruebas de integración del Gateway sobre un servidor real (puerto aleatorio).
 * Verifican el comportamiento OBSERVABLE de extremo a extremo, que es lo que
 * consume el frontend: el sobre unificado 2.5 en las negativas, el mapeo de un
 * destino caído a {@code 503 GTW-001}, el preflight CORS y el actuator público.
 *
 * <p>Para hacer el caso 503 determinista en CI, {@code PERSONAS_SERVICE_URL}
 * apunta a un puerto cerrado ({@code 59999}): un token válido pasa la seguridad
 * y, al intentar enrutar, recibe «conexión rechazada», que el
 * {@code ManejadorGlobalExcepciones} traduce a {@code GTW-001}.</p>
 *
 * <p>El secreto del test es un literal (las anotaciones exigen constantes de
 * compilación) y coincide con el {@code kid} {@code smid-2026-06} mapeado en
 * {@code application.yml}, de modo que los tokens forjados aquí validan de
 * verdad contra el decoder del Gateway.</p>
 */
@SpringBootTest(webEnvironment = RANDOM_PORT, properties = {
		"JWT_SECRET=" + SeguridadIntegracionTest.SECRETO,
		"PERSONAS_SERVICE_URL=http://localhost:59999",
		"CORS_ALLOWED_ORIGINS=http://localhost:3000",
		"GATEWAY_RESPONSE_TIMEOUT=3s"
})
class SeguridadIntegracionTest {

	/** Debe coincidir byte a byte con el kid smid-2026-06 de application.yml. */
	static final String SECRETO =
			"clave-de-integracion-con-mas-de-256-bits-abcdefghijklmnop";
	private static final String KID = "smid-2026-06";
	private static final String EMISOR = "smid-auth";
	private static final String AUDIENCIA = "smid-servicios";

	@LocalServerPort
	private int puerto;

	private WebTestClient cliente;

	private WebTestClient cliente() {
		if (cliente == null) {
			cliente = WebTestClient.bindToServer()
					.baseUrl("http://localhost:" + puerto)
					.build();
		}
		return cliente;
	}

	// -------------------------------------------------------------------------
	// 401 — sobre unificado en toda negativa de autenticación
	// -------------------------------------------------------------------------

	@Test
	@DisplayName("Ruta protegida SIN token -> 401 con sobre AUTZ-003 completo")
	void sinTokenDevuelve401ConSobre() {
		cliente().get().uri("/api/personas/abc")
				.exchange()
				.expectStatus().isUnauthorized()
				.expectBody()
				.jsonPath("$.status").isEqualTo(401)
				.jsonPath("$.error").isEqualTo("Unauthorized")
				.jsonPath("$.codigo").isEqualTo("AUTZ-003")
				.jsonPath("$.mensaje").exists()
				.jsonPath("$.ruta").isEqualTo("/api/personas/abc")
				.jsonPath("$.timestamp").exists();
	}

	@Test
	@DisplayName("Ruta protegida con Bearer basura -> 401 AUTZ-003 (token inválido también usa el sobre)")
	void tokenBasuraDevuelve401() {
		cliente().get().uri("/api/personas/abc")
				.header(HttpHeaders.AUTHORIZATION, "Bearer esto-no-es-un-jwt")
				.exchange()
				.expectStatus().isUnauthorized()
				.expectBody()
				.jsonPath("$.codigo").isEqualTo("AUTZ-003");
	}

	@Test
	@DisplayName("Token bien firmado pero con audiencia ajena -> 401 AUTZ-003")
	void tokenConAudienciaAjenaDevuelve401() {
		String token = firmar(KID, SECRETO, EMISOR, "otra-audiencia",
				Instant.now().plusSeconds(3600));

		cliente().get().uri("/api/personas/abc")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.exchange()
				.expectStatus().isUnauthorized()
				.expectBody()
				.jsonPath("$.codigo").isEqualTo("AUTZ-003");
	}

	// -------------------------------------------------------------------------
	// 503 — destino caído, con el id de correlación de auditoría
	// -------------------------------------------------------------------------

	@Test
	@DisplayName("Token VÁLIDO hacia un destino caído -> 503 GTW-001 y cabecera X-Request-Id")
	void tokenValidoConDestinoCaidoDevuelve503() {
		String token = firmar(KID, SECRETO, EMISOR, AUDIENCIA,
				Instant.now().plusSeconds(3600));

		cliente().get().uri("/api/personas/abc")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.exchange()
				.expectStatus().isEqualTo(503)
				.expectHeader().exists("X-Request-Id")
				.expectBody()
				.jsonPath("$.status").isEqualTo(503)
				.jsonPath("$.codigo").isEqualTo("GTW-001")
				.jsonPath("$.ruta").isEqualTo("/api/personas/abc");
	}

	// -------------------------------------------------------------------------
	// CORS y actuator
	// -------------------------------------------------------------------------

	@Test
	@DisplayName("Preflight OPTIONS desde un origen permitido -> 200 con Access-Control-Allow-Origin")
	void preflightCorsPermitido() {
		cliente().options().uri("/api/personas/abc")
				.header(HttpHeaders.ORIGIN, "http://localhost:3000")
				.header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
				.exchange()
				.expectStatus().isOk()
				.expectHeader().valueEquals("Access-Control-Allow-Origin", "http://localhost:3000");
	}

	@Test
	@DisplayName("El actuator /actuator/health es público y responde 200")
	void actuatorHealthEsPublico() {
		cliente().get().uri("/actuator/health")
				.exchange()
				.expectStatus().isOk()
				.expectBody()
				.jsonPath("$.status").isEqualTo("UP");
	}

	// -------------------------------------------------------------------------
	// Utilidad de firma
	// -------------------------------------------------------------------------

	private String firmar(String kid, String secreto, String emisor, String audiencia,
			Instant expira) {
		try {
			JWSHeader cabecera = new JWSHeader.Builder(JWSAlgorithm.HS256)
					.keyID(kid)
					.type(JOSEObjectType.JWT)
					.build();
			JWTClaimsSet claims = new JWTClaimsSet.Builder()
					.subject("8f3b2c1d-0000-4a5b-8c7d-1e2f3a4b5c6d")
					.issuer(emisor)
					.audience(List.of(audiencia))
					.jwtID("11112222-3333-4444-5555-666677778888")
					.claim("roles", List.of("ADMIN_NACIONAL"))
					.claim("idSede", "uuid-sede")
					.claim("idUnidad", "uuid-unidad")
					.claim("alcance", "NACIONAL")
					.claim("nombre", "Admin SMID")
					.issueTime(Date.from(Instant.now().minusSeconds(30)))
					.expirationTime(Date.from(expira))
					.build();
			SignedJWT jwt = new SignedJWT(cabecera, claims);
			jwt.sign(new MACSigner(secreto.getBytes(StandardCharsets.UTF_8)));
			return jwt.serialize();
		}
		catch (Exception ex) {
			throw new IllegalStateException("No se pudo firmar el token de prueba", ex);
		}
	}
}
