package cl.smid.apigateway.infraestructura.seguridad;

import cl.smid.apigateway.config.PropiedadesJwt;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Adaptador de infraestructura que construye el {@link ReactiveJwtDecoder} del
 * Gateway con <strong>selección de clave por {@code kid}</strong> (cierra las
 * brechas B1 y B2 de la auditoría; implementación literal de la receta técnica
 * de su §8, Fase 1 / DT-3).
 *
 * <p><strong>Propiedades que esta construcción garantiza:</strong></p>
 * <ul>
 *   <li><strong>HS256 forzado</strong> en el {@link JWSVerificationKeySelector}:
 *       se preserva el cierre de <em>algorithm confusion</em> del diseño
 *       original (un token con {@code alg} distinto no encuentra clave).</li>
 *   <li><strong>Rotación sin caída:</strong> con dos claves cargadas (vigente +
 *       anterior) los tokens viejos validan por su {@code kid} hasta expirar.
 *       La rotación deja de ser un corte coordinado de tres actores.</li>
 *   <li><strong>Rechazo de {@code kid} ausente o desconocido</strong> (decisión
 *       D3, corte duro): tras el rewrite y la rotación del secreto, los tokens
 *       del legado —que no portan {@code kid}— son inválidos de todos modos;
 *       no se les concede tolerancia. El guardia explícito vuelve el rechazo
 *       determinista en vez de depender del comportamiento del selector.</li>
 *   <li><strong>Contrato 2.4 completo:</strong> {@code iss == emisor},
 *       {@code aud} contiene la audiencia, y {@code exp}/{@code nbf} con skew
 *       de reloj de 30 segundos.</li>
 *   <li><strong>Evolución P2 sin reescritura:</strong> migrar a RS256/JWKS
 *       remoto solo exige sustituir {@link ImmutableJWKSet} por un
 *       {@code JWKSource} remoto y el algoritmo del selector; el resto de la
 *       cadena (procesador, validadores, contrato de claims) no cambia.</li>
 * </ul>
 *
 * <p>Clase de utilidad pura (sin anotaciones de Spring): el cableado como bean
 * ocurre en el composition root ({@code SeguridadConfig}), siguiendo el patrón
 * de {@code DominioConfig} en {@code smid-auth}. Esto permite probarla de forma
 * aislada sin levantar contexto.</p>
 */
public final class DecodificadorJwtPorKid {

	/** Mínimo de bytes exigido por HS256 para la clave (256 bits). */
	private static final int BYTES_MINIMOS_CLAVE = 32;

	/** Skew de reloj tolerado al validar exp/nbf (Núcleo 2.4). */
	private static final Duration SKEW_RELOJ = Duration.ofSeconds(30);

	private DecodificadorJwtPorKid() {
		// Clase de utilidad: no instanciable.
	}

	/**
	 * Construye el decoder reactivo a partir de las propiedades
	 * {@code smid.jwt.*}. Falla rápido en el arranque (excepción de
	 * configuración) si el mapa de claves está vacío, si alguna clave no
	 * alcanza los 256 bits o si emisor/audiencia vienen en blanco.
	 *
	 * @param propiedades contrato JWT externalizado (emisor, audiencia, claves)
	 * @return decoder listo para inyectar en el resource server reactivo
	 */
	public static ReactiveJwtDecoder crear(PropiedadesJwt propiedades) {
		validar(propiedades);

		// ------------------------------------------------------------------
		// 1) Mapa kid -> secreto materializado como JWKSet en memoria: cada
		//    clave simétrica (OctetSequenceKey) lleva su keyID y declara HS256.
		// ------------------------------------------------------------------
		List<JWK> jwks = propiedades.claves().entrySet().stream()
				.map(entrada -> (JWK) new OctetSequenceKey.Builder(
						entrada.getValue().getBytes(StandardCharsets.UTF_8))
						.keyID(entrada.getKey())
						.algorithm(JWSAlgorithm.HS256)
						.build())
				.toList();

		JWKSource<SecurityContext> fuenteDeClaves = new ImmutableJWKSet<>(new JWKSet(jwks));

		// ------------------------------------------------------------------
		// 2) Procesador Nimbus: el selector resuelve la clave por el kid de la
		//    cabecera y FUERZA HS256 (cierre de algorithm confusion).
		//    El verificador temporal interno de Nimbus se anula con un no-op
		//    —exactamente como hace el builder de NimbusJwtDecoder de Spring—
		//    para que exp/nbf se validen en UN solo lugar: el JwtTimestampValidator
		//    con el skew del contrato (30 s), y no con el skew por defecto de
		//    Nimbus (60 s).
		// ------------------------------------------------------------------
		DefaultJWTProcessor<SecurityContext> procesador = new DefaultJWTProcessor<>();
		procesador.setJWSKeySelector(
				new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, fuenteDeClaves));
		procesador.setJWTClaimsSetVerifier((claims, contexto) -> {
			// no-op: la validación de claims es responsabilidad exclusiva de
			// los OAuth2TokenValidator configurados más abajo.
		});

		// Copia inmutable de los kids conocidos para el guardia del paso 3.
		Set<String> kidsConocidos = Set.copyOf(propiedades.claves().keySet());

		// ------------------------------------------------------------------
		// 3) Decoder reactivo sobre el procesador, con guardia explícito de
		//    kid: ausente o desconocido -> BadJWTException, que el decoder de
		//    Spring envuelve en JwtException -> 401 AUTZ-003 aguas arriba.
		//    La verificación HMAC (bloqueante para Reactor) se delega al
		//    scheduler boundedElastic, según la receta de la auditoría.
		// ------------------------------------------------------------------
		NimbusReactiveJwtDecoder decoder = new NimbusReactiveJwtDecoder(jwtFirmado -> {
			Object kidCabecera = jwtFirmado.getHeader().toJSONObject().get("kid");
			String kid = kidCabecera instanceof String valor ? valor : null;
			if (kid == null || kid.isBlank()) {
				return Mono.error(new BadJWTException(
						"Token sin cabecera kid: rechazado por política de rotación (D3)"));
			}
			if (!kidsConocidos.contains(kid)) {
				return Mono.error(new BadJWTException(
						"Token con kid desconocido para este Gateway: " + kid));
			}
			return Mono.fromCallable(() -> procesador.process(jwtFirmado, null))
					.subscribeOn(Schedulers.boundedElastic());
		});

		// ------------------------------------------------------------------
		// 4) Validadores del contrato 2.4: exp/nbf con skew de 30 s, emisor
		//    exacto y audiencia contenida. Cualquier fallo -> 401.
		// ------------------------------------------------------------------
		decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
				new JwtTimestampValidator(SKEW_RELOJ),
				new JwtIssuerValidator(propiedades.emisor()),
				new JwtClaimValidator<Collection<String>>(JwtClaimNames.AUD,
						aud -> aud != null && aud.contains(propiedades.audiencia()))));

		return decoder;
	}

	/**
	 * Validación de arranque (fallo rápido y visible, filosofía DT-2): el
	 * Gateway prefiere no levantar antes que levantar con un contrato JWT
	 * incompleto o con claves criptográficamente débiles.
	 */
	private static void validar(PropiedadesJwt propiedades) {
		if (propiedades == null) {
			throw new IllegalStateException(
					"Propiedades smid.jwt ausentes: revise application.yml y las variables de entorno");
		}
		if (propiedades.emisor() == null || propiedades.emisor().isBlank()) {
			throw new IllegalStateException(
					"smid.jwt.emisor vacío: defina JWT_ISSUER (contrato 2.4)");
		}
		if (propiedades.audiencia() == null || propiedades.audiencia().isBlank()) {
			throw new IllegalStateException(
					"smid.jwt.audiencia vacía: defina JWT_AUDIENCE (contrato 2.4)");
		}
		Map<String, String> claves = propiedades.claves();
		if (claves == null || claves.isEmpty()) {
			throw new IllegalStateException(
					"smid.jwt.claves vacío: defina al menos un par kid -> secreto (JWT_SECRET)");
		}
		claves.forEach((kid, secreto) -> {
			if (secreto == null
					|| secreto.getBytes(StandardCharsets.UTF_8).length < BYTES_MINIMOS_CLAVE) {
				throw new IllegalStateException(
						"La clave del kid '" + kid + "' no alcanza los 256 bits mínimos de HS256 "
						+ "(genere una con: openssl rand -base64 48)");
			}
		});
	}
}
