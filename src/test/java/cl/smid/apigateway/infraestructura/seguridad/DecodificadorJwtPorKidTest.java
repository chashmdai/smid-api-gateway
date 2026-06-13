package cl.smid.apigateway.infraestructura.seguridad;

import cl.smid.apigateway.config.PropiedadesJwt;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pruebas unitarias del {@link DecodificadorJwtPorKid}, columna vertebral de la
 * seguridad del Gateway. Se construyen tokens reales con Nimbus (la misma
 * librería que usa {@code smid-auth} para firmar) y se verifica el decoder de
 * forma <strong>aislada</strong>, sin levantar contexto de Spring — exactamente
 * la ventaja de haber dejado la fábrica como clase de utilidad pura.
 *
 * <p>Cubre la matriz E2E §11 de la auditoría en su porción de validación de
 * token: firma correcta, rotación por kid, kid ausente/desconocido,
 * iss/aud ajenos, y la frontera del skew de reloj de 30 s.</p>
 */
class DecodificadorJwtPorKidTest {

	// --- Datos de prueba (secretos >= 256 bits, exigidos por HS256) ----------
	private static final String KID_VIGENTE = "smid-2026-06";
	private static final String KID_ANTERIOR = "smid-2026-01";

	private static final String SECRETO_VIGENTE =
			"clave-de-prueba-vigente-con-mas-de-256-bits-0123456789";
	private static final String SECRETO_ANTERIOR =
			"clave-de-prueba-anterior-con-mas-de-256-bits-9876543210";
	private static final String SECRETO_INTRUSO =
			"clave-intrusa-que-no-pertenece-al-gateway-000000000000";

	private static final String EMISOR = "smid-auth";
	private static final String AUDIENCIA = "smid-servicios";
	private static final String SUB_UUID = "8f3b2c1d-0000-4a5b-8c7d-1e2f3a4b5c6d";

	/** Decoder con UNA sola clave (operación normal, fuera de rotación). */
	private ReactiveJwtDecoder decoderUnaClave() {
		return DecodificadorJwtPorKid.crear(new PropiedadesJwt(
				EMISOR, AUDIENCIA, Map.of(KID_VIGENTE, SECRETO_VIGENTE)));
	}

	/** Decoder con DOS claves (ventana de rotación: vigente + anterior). */
	private ReactiveJwtDecoder decoderDosClaves() {
		return DecodificadorJwtPorKid.crear(new PropiedadesJwt(
				EMISOR, AUDIENCIA,
				Map.of(KID_VIGENTE, SECRETO_VIGENTE, KID_ANTERIOR, SECRETO_ANTERIOR)));
	}

	// -------------------------------------------------------------------------
	// Camino feliz
	// -------------------------------------------------------------------------

	@Test
	@DisplayName("Token válido (kid vigente, iss/aud correctos, no vencido) decodifica y expone los claims 2.4")
	void tokenValidoDecodifica() {
		String token = firmar(KID_VIGENTE, SECRETO_VIGENTE, EMISOR, AUDIENCIA,
				Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));

		StepVerifier.create(decoderUnaClave().decode(token))
				.assertNext(jwt -> {
					assertThat(jwt.getSubject()).isEqualTo(SUB_UUID);
					assertThat(jwt.getClaimAsString("iss")).isEqualTo(EMISOR);
					assertThat(jwt.getAudience()).contains(AUDIENCIA);
					// Claims territoriales del contrato 2.4.
					assertThat(jwt.getClaimAsString("idSede")).isEqualTo("uuid-sede");
					assertThat(jwt.getClaimAsString("idUnidad")).isEqualTo("uuid-unidad");
					assertThat(jwt.getClaimAsString("alcance")).isEqualTo("NACIONAL");
				})
				.verifyComplete();
	}

	@Test
	@DisplayName("Rotación sin caída: un token firmado con la clave ANTERIOR valida por su kid")
	void tokenDeClaveAnteriorValidaDuranteRotacion() {
		String token = firmar(KID_ANTERIOR, SECRETO_ANTERIOR, EMISOR, AUDIENCIA,
				Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));

		StepVerifier.create(decoderDosClaves().decode(token))
				.assertNext(jwt -> assertThat(jwt.getSubject()).isEqualTo(SUB_UUID))
				.verifyComplete();
	}

	// -------------------------------------------------------------------------
	// Rechazos por política de kid (decisión D3, corte duro)
	// -------------------------------------------------------------------------

	@Test
	@DisplayName("Token SIN kid en la cabecera se rechaza (política de rotación D3)")
	void tokenSinKidSeRechaza() {
		String token = firmarSinKid(SECRETO_VIGENTE, EMISOR, AUDIENCIA,
				Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));

		StepVerifier.create(decoderUnaClave().decode(token))
				.expectError(JwtException.class)
				.verify();
	}

	@Test
	@DisplayName("Token con kid DESCONOCIDO para el Gateway se rechaza")
	void tokenConKidDesconocidoSeRechaza() {
		String token = firmar("kid-fantasma", SECRETO_VIGENTE, EMISOR, AUDIENCIA,
				Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));

		StepVerifier.create(decoderUnaClave().decode(token))
				.expectError(JwtException.class)
				.verify();
	}

	// -------------------------------------------------------------------------
	// Rechazos por firma y por contrato de claims 2.4
	// -------------------------------------------------------------------------

	@Test
	@DisplayName("Firma forjada: kid conocido pero secreto distinto -> rechazo (cierre de algorithm/key confusion)")
	void firmaConSecretoIntrusoSeRechaza() {
		// El atacante conoce el kid vigente pero no el secreto: firma con otro.
		String token = firmar(KID_VIGENTE, SECRETO_INTRUSO, EMISOR, AUDIENCIA,
				Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));

		StepVerifier.create(decoderUnaClave().decode(token))
				.expectError(JwtException.class)
				.verify();
	}

	@Test
	@DisplayName("Emisor (iss) incorrecto se rechaza")
	void emisorIncorrectoSeRechaza() {
		String token = firmar(KID_VIGENTE, SECRETO_VIGENTE, "emisor-falso", AUDIENCIA,
				Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));

		StepVerifier.create(decoderUnaClave().decode(token))
				.expectError(JwtException.class)
				.verify();
	}

	@Test
	@DisplayName("Audiencia (aud) ajena se rechaza")
	void audienciaIncorrectaSeRechaza() {
		String token = firmar(KID_VIGENTE, SECRETO_VIGENTE, EMISOR, "otra-audiencia",
				Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));

		StepVerifier.create(decoderUnaClave().decode(token))
				.expectError(JwtException.class)
				.verify();
	}

	// -------------------------------------------------------------------------
	// Frontera del skew de reloj (30 s)
	// -------------------------------------------------------------------------

	@Test
	@DisplayName("Token vencido MÁS ALLÁ del skew (exp hace 120 s) se rechaza")
	void tokenVencidoFueraDeSkewSeRechaza() {
		String token = firmar(KID_VIGENTE, SECRETO_VIGENTE, EMISOR, AUDIENCIA,
				Instant.now().minusSeconds(3600), Instant.now().minusSeconds(120));

		StepVerifier.create(decoderUnaClave().decode(token))
				.expectError(JwtException.class)
				.verify();
	}

	@Test
	@DisplayName("Token vencido DENTRO del skew (exp hace 15 s) se acepta por tolerancia de 30 s")
	void tokenVencidoDentroDeSkewSeAcepta() {
		String token = firmar(KID_VIGENTE, SECRETO_VIGENTE, EMISOR, AUDIENCIA,
				Instant.now().minusSeconds(3600), Instant.now().minusSeconds(15));

		StepVerifier.create(decoderUnaClave().decode(token))
				.assertNext(jwt -> assertThat(jwt.getSubject()).isEqualTo(SUB_UUID))
				.verifyComplete();
	}

	// -------------------------------------------------------------------------
	// Validación de arranque (fallo rápido)
	// -------------------------------------------------------------------------

	@Test
	@DisplayName("Clave por debajo de 256 bits aborta la construcción (fallo rápido y visible)")
	void claveDebilAbortaConstruccion() {
		PropiedadesJwt propiedadesDebiles = new PropiedadesJwt(
				EMISOR, AUDIENCIA, Map.of(KID_VIGENTE, "corta"));

		try {
			DecodificadorJwtPorKid.crear(propiedadesDebiles);
			throw new AssertionError("Se esperaba IllegalStateException por clave débil");
		}
		catch (IllegalStateException esperada) {
			assertThat(esperada.getMessage()).contains("256 bits");
		}
	}

	// -------------------------------------------------------------------------
	// Utilidades de firma de tokens de prueba
	// -------------------------------------------------------------------------

	/** Firma un JWT HS256 con kid en la cabecera y los claims del contrato 2.4. */
	private String firmar(String kid, String secreto, String emisor, String audiencia,
			Instant emitido, Instant expira) {
		try {
			JWSHeader cabecera = new JWSHeader.Builder(JWSAlgorithm.HS256)
					.keyID(kid)
					.type(com.nimbusds.jose.JOSEObjectType.JWT)
					.build();
			SignedJWT jwt = new SignedJWT(cabecera, claims(emisor, audiencia, emitido, expira));
			jwt.sign(new MACSigner(secreto.getBytes(StandardCharsets.UTF_8)));
			return jwt.serialize();
		}
		catch (Exception ex) {
			throw new IllegalStateException("No se pudo firmar el token de prueba", ex);
		}
	}

	/** Firma un JWT HS256 SIN kid en la cabecera (para el caso de rechazo D3). */
	private String firmarSinKid(String secreto, String emisor, String audiencia,
			Instant emitido, Instant expira) {
		try {
			JWSHeader cabecera = new JWSHeader.Builder(JWSAlgorithm.HS256)
					.type(com.nimbusds.jose.JOSEObjectType.JWT)
					.build();
			SignedJWT jwt = new SignedJWT(cabecera, claims(emisor, audiencia, emitido, expira));
			jwt.sign(new MACSigner(secreto.getBytes(StandardCharsets.UTF_8)));
			return jwt.serialize();
		}
		catch (Exception ex) {
			throw new IllegalStateException("No se pudo firmar el token de prueba", ex);
		}
	}

	/** Claims del contrato territorial 2.4 usados por todos los tokens de prueba. */
	private JWTClaimsSet claims(String emisor, String audiencia, Instant emitido, Instant expira) {
		return new JWTClaimsSet.Builder()
				.subject(SUB_UUID)
				.issuer(emisor)
				.audience(List.of(audiencia))
				.jwtID("11112222-3333-4444-5555-666677778888")
				.claim("roles", List.of("ADMIN_NACIONAL"))
				.claim("idSede", "uuid-sede")
				.claim("idUnidad", "uuid-unidad")
				.claim("alcance", "NACIONAL")
				.claim("nombre", "Admin SMID")
				.issueTime(Date.from(emitido.truncatedTo(ChronoUnit.SECONDS)))
				.expirationTime(Date.from(expira.truncatedTo(ChronoUnit.SECONDS)))
				.build();
	}
}
