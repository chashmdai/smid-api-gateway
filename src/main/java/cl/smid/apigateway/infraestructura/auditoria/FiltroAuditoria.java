package cl.smid.apigateway.infraestructura.auditoria;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.util.UUID;

/**
 * Filtro global de auditoría de tráfico del Gateway.
 *
 * <p>La auditoría §3 califica este diseño como correcto y ordena conservarlo;
 * el rewrite lo preserva íntegro y agrega dos refuerzos de trazabilidad:</p>
 *
 * <ul>
 *   <li><strong>Conservado:</strong> generación/reutilización del
 *       {@code X-Request-Id} y su propagación al microservicio destino;
 *       resolución de la IP real del cliente desde {@code X-Forwarded-For}
 *       (primer salto de la lista tras Nginx) con fallback al socket; y log de
 *       salida garantizado con {@code doFinally} en <em>complete</em>,
 *       <em>error</em> y <em>cancel</em>.</li>
 *   <li><strong>Nuevo:</strong> el {@code X-Request-Id} también se devuelve en
 *       la cabecera de la RESPUESTA (el frontend puede reportarlo en
 *       incidencias) y se publica como atributo del exchange para que el
 *       manejador global de errores correlacione sus bitácoras.</li>
 * </ul>
 *
 * <p>Nota de alcance: al ser un {@link GlobalFilter} de Spring Cloud Gateway,
 * este filtro corre DESPUÉS de la cadena de Spring Security; las peticiones
 * rechazadas con 401/403 no llegan aquí y se trazan en los logs del manejador
 * de seguridad. Es el comportamiento del diseño original, conservado a
 * propósito.</p>
 */
@Component
public class FiltroAuditoria implements GlobalFilter, Ordered {

	private static final Logger log = LoggerFactory.getLogger(FiltroAuditoria.class);

	/** Cabecera estándar de correlación, compartida con los downstream. */
	public static final String CABECERA_REQUEST_ID = "X-Request-Id";

	/** Atributo del exchange con el id de correlación, para otros componentes. */
	public static final String ATRIBUTO_REQUEST_ID =
			FiltroAuditoria.class.getName() + ".REQUEST_ID";

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		long inicio = System.currentTimeMillis();

		ServerHttpRequest peticion = exchange.getRequest();
		String ruta = peticion.getURI().getPath();
		String metodo = peticion.getMethod().name();
		String ipCliente = resolverIpCliente(exchange);
		String requestId = resolverRequestId(exchange);

		// Publicar el id de correlación para el resto del pipeline:
		//  - atributo del exchange (lo lee el manejador global de errores),
		//  - cabecera de respuesta (visible para el cliente/SPA).
		exchange.getAttributes().put(ATRIBUTO_REQUEST_ID, requestId);
		exchange.getResponse().getHeaders().set(CABECERA_REQUEST_ID, requestId);

		// Propagar el id de correlación al microservicio de destino para
		// trazabilidad cruzada (matriz E2E #10 de la auditoría).
		ServerWebExchange exchangeMutado = exchange.mutate()
				.request(builder -> builder.header(CABECERA_REQUEST_ID, requestId))
				.build();

		log.info("▶ [AUDITORÍA INICIO] [{}] Request: {} {} | IP Cliente: {}",
				requestId, metodo, ruta, ipCliente);

		// doFinally garantiza el log de salida en complete, error Y cancel
		// (un .then(...) solo se ejecutaría en el complete exitoso).
		return chain.filter(exchangeMutado).doFinally(senal -> {
			long duracion = System.currentTimeMillis() - inicio;

			// Una sola lectura del status en variable local: evita la doble
			// llamada y el warning de posible null (respuesta aún sin estado
			// en señales de cancelación).
			HttpStatusCode estadoResuelto = exchangeMutado.getResponse().getStatusCode();
			int estado = estadoResuelto != null ? estadoResuelto.value() : 500;

			log.info("◀ [AUDITORÍA FIN] [{}] Request: {} {} | Status: {} | Tiempo: {}ms | Señal: {}",
					requestId, metodo, ruta, estado, duracion, senal);
		});
	}

	/**
	 * Rescata la IP real del cliente. {@code X-Forwarded-For} puede llegar como
	 * lista {@code "clienteReal, proxy1, proxy2"} tras pasar por Nginx, por lo
	 * que se toma el primer salto; fallback a la IP del socket remoto.
	 */
	private String resolverIpCliente(ServerWebExchange exchange) {
		String reenviada = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
		if (reenviada != null && !reenviada.isBlank()) {
			return reenviada.split(",")[0].trim();
		}
		InetSocketAddress remoto = exchange.getRequest().getRemoteAddress();
		if (remoto != null && remoto.getAddress() != null) {
			return remoto.getAddress().getHostAddress();
		}
		return "Desconocida";
	}

	/**
	 * Reutiliza el {@code X-Request-Id} entrante si existe (cadena de proxies)
	 * o genera un UUID nuevo para esta petición.
	 */
	private String resolverRequestId(ServerWebExchange exchange) {
		String existente = exchange.getRequest().getHeaders().getFirst(CABECERA_REQUEST_ID);
		return (existente != null && !existente.isBlank())
				? existente
				: UUID.randomUUID().toString();
	}

	@Override
	public int getOrder() {
		// Orden -1: de los primeros GlobalFilter en ejecutarse al entrar y de
		// los últimos al salir (envuelve la latencia real del enrutamiento).
		return -1;
	}
}
