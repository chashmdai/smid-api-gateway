package cl.smid.apigateway.config;

import cl.smid.apigateway.api.error.EscritorRespuestaError;
import cl.smid.apigateway.dominio.error.CodigoError;
import cl.smid.apigateway.infraestructura.auditoria.FiltroAuditoria;
import cl.smid.apigateway.infraestructura.seguridad.DecodificadorJwtPorKid;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.lang.NonNull;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;

/**
 * <strong>Composition root</strong> de seguridad del Gateway: aquí, y solo
 * aquí, se cablean los componentes del hexágono en una {@link SecurityWebFilterChain}.
 * Siguiendo el patrón de {@code SeguridadConfig} en {@code smid-auth}, el
 * framework vive en el borde: el {@code DecodificadorJwtPorKid} y el
 * {@code EscritorRespuestaError} son piezas neutrales que esta clase ensambla.
 *
 * <p><strong>Decisiones de seguridad materializadas:</strong></p>
 * <ul>
 *   <li><strong>Resource server JWT</strong> con el decoder de selección por
 *       {@code kid} (brechas B1/B2). El pass-through del header
 *       {@code Authorization} se conserva intacto: el Gateway valida pero NO
 *       reescribe la credencial ni inyecta cabeceras sintéticas de identidad
 *       (defensa en profundidad aguas abajo).</li>
 *   <li><strong>Sobre unificado en TODA negativa</strong> (brechas B4/B8):
 *       el {@code authenticationEntryPoint} (401 {@code AUTZ-003}) y el
 *       {@code accessDeniedHandler} (403 {@code AUTZ-004}) se registran en el
 *       bloque {@code exceptionHandling} <em>y</em> dentro de
 *       {@code oauth2ResourceServer}. Esto corrige un defecto real del legado:
 *       allí el entry point solo estaba en {@code exceptionHandling}, de modo
 *       que un token presente pero inválido podía escapar al sobre unificado.
 *       Con ambos puntos cubiertos, "sin token" y "token inválido" responden
 *       el mismo contrato 2.5.</li>
 *   <li><strong>Rutas públicas mínimas:</strong> preflight {@code OPTIONS},
 *       {@code /api/auth/**} (el servicio valida credenciales en su cuerpo) y
 *       los actuator <em>propios</em> {@code /actuator/health} e
 *       {@code /actuator/info} (brecha B7). Todo lo demás exige autenticación.</li>
 *   <li><strong>CORS en un solo bean</strong> (mecanismo conservado, brecha
 *       B5): un único {@link CorsConfigurationSource} alimentado por entorno;
 *       no se declara CORS en el YAML de rutas, evitando cabeceras duplicadas.</li>
 * </ul>
 */
@Configuration
@EnableWebFluxSecurity
public class SeguridadConfig {

	/** Antigüedad máxima de la respuesta preflight cacheada por el navegador. */
	private static final long MAX_EDAD_PREFLIGHT_SEGUNDOS = 3600L;

	private final EscritorRespuestaError escritorError;
	private final boolean documentacionLocalHabilitada;

	public SeguridadConfig(EscritorRespuestaError escritorError, Environment environment) {
		this.escritorError = escritorError;
		this.documentacionLocalHabilitada = Arrays.stream(environment.getActiveProfiles())
				.anyMatch(perfil -> "local".equals(perfil) || "dev".equals(perfil));
	}

	/**
	 * Cadena de filtros reactiva del Gateway.
	 *
	 * @param http       builder de seguridad WebFlux
	 * @param jwtDecoder decoder de selección por kid (bean de más abajo)
	 * @return la cadena de filtros que protege todas las rutas del Gateway
	 */
	@Bean
	public SecurityWebFilterChain cadenaDeFiltros(ServerHttpSecurity http,
			ReactiveJwtDecoder jwtDecoder) {
		return http
				// Sin estado (sin sesión, sin cookie): no aplica CSRF.
				.csrf(ServerHttpSecurity.CsrfSpec::disable)
				// CORS gobernado por el único bean corsConfigurationSource.
				.cors(Customizer.withDefaults())
				.authorizeExchange(intercambios -> {
						// Preflight CORS: nunca lleva credencial, siempre pasa.
						intercambios.pathMatchers(HttpMethod.OPTIONS, "/**").permitAll();
						if (documentacionLocalHabilitada) {
							intercambios.pathMatchers("/swagger-ui/**", "/swagger-ui.html",
									"/webjars/swagger-ui/**", "/v3/api-docs/**",
									"/openapi/**").permitAll();
						}
						// Autenticación: valida credenciales en su propio cuerpo.
						intercambios.pathMatchers("/api/auth/**").permitAll()
						// Actuator PROPIO del Gateway, endurecido (B7).
						.pathMatchers("/actuator/health", "/actuator/health/**",
								"/actuator/info").permitAll()
						// Resto del tráfico: token válido obligatorio.
						.anyExchange().authenticated();
				})
				// 401 / 403 con el sobre unificado en el nivel de excepción.
				.exceptionHandling(excepciones -> excepciones
						.authenticationEntryPoint(this::responder401)
						.accessDeniedHandler(this::responder403))
				// Resource server JWT con el decoder por kid. Se REPITEN aquí
				// los handlers: un token inválido se rechaza dentro de este
				// bloque, antes de llegar al exceptionHandling genérico.
				.oauth2ResourceServer(oauth2 -> oauth2
						.authenticationEntryPoint(this::responder401)
						.accessDeniedHandler(this::responder403)
						.jwt(jwt -> jwt.jwtDecoder(jwtDecoder)))
				.build();
	}

	/**
	 * Bean del decoder reactivo. Delegar en la fábrica estática mantiene la
	 * lógica criptográfica en infraestructura (probable sin contexto Spring) y
	 * deja a la config solo la responsabilidad de cableado.
	 *
	 * @param propiedades contrato JWT externalizado ({@code smid.jwt.*})
	 * @return decoder con selección por kid, HS256 forzado y validadores 2.4
	 */
	@Bean
	public ReactiveJwtDecoder reactiveJwtDecoder(PropiedadesJwt propiedades) {
		return DecodificadorJwtPorKid.crear(propiedades);
	}

	/**
	 * Fuente CORS única del ecosistema, alimentada por {@link PropiedadesCors}.
	 * Expone {@code X-Request-Id} para que el frontend lea el identificador de
	 * correlación que estampa el {@link FiltroAuditoria} (trazabilidad de punta
	 * a punta).
	 *
	 * @param propiedades orígenes permitidos resueltos por entorno
	 * @return configuración CORS registrada para todas las rutas
	 */
	@Bean
	public CorsConfigurationSource corsConfigurationSource(PropiedadesCors propiedades) {
		CorsConfiguration configuracion = new CorsConfiguration();
		configuracion.setAllowedOrigins(propiedades.origenesPermitidos());
		configuracion.setAllowedMethods(
				List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
		configuracion.setAllowedHeaders(
				List.of("Authorization", "Content-Type", "Accept"));
		// El navegador solo entrega al JS los headers explícitamente expuestos.
		configuracion.setExposedHeaders(List.of(FiltroAuditoria.CABECERA_REQUEST_ID));
		configuracion.setAllowCredentials(true);
		configuracion.setMaxAge(MAX_EDAD_PREFLIGHT_SEGUNDOS);

		UrlBasedCorsConfigurationSource fuente = new UrlBasedCorsConfigurationSource();
		fuente.registerCorsConfiguration("/**", configuracion);
		return fuente;
	}

	// -------------------------------------------------------------------------
	// Adaptadores de los handlers de seguridad al EscritorRespuestaError. Se
	// ignora la excepción/denegación recibida: el contrato del sobre no expone
	// el detalle interno (evita filtrar información de la causa al cliente).
	// -------------------------------------------------------------------------

	/** 401: token ausente, inválido, vencido, con kid/iss/aud no aceptados. */
	@NonNull
	private Mono<Void> responder401(@NonNull ServerWebExchange exchange,
			@NonNull AuthenticationException ex) {
		return escritorError.escribir(exchange, CodigoError.AUTZ_003);
	}

	/** 403: autenticado pero sin permisos suficientes (reservado a futura RBAC). */
	@NonNull
	private Mono<Void> responder403(@NonNull ServerWebExchange exchange,
			@NonNull AccessDeniedException ex) {
		return escritorError.escribir(exchange, CodigoError.AUTZ_004);
	}
}
