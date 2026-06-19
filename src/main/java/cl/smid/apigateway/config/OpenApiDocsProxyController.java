package cl.smid.apigateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
@RequestMapping("/openapi")
@Profile({"local", "dev"})
public class OpenApiDocsProxyController {

	private final WebClient webClient;
	private final Map<String, String> servicios;

	public OpenApiDocsProxyController(
			WebClient.Builder webClientBuilder,
			@Value("${AUTH_SERVICE_URL:http://localhost:8081}") String authUrl,
			@Value("${PERSONAS_SERVICE_URL:http://localhost:8088}") String personasUrl,
			@Value("${REQUERIMIENTOS_SERVICE_URL:http://localhost:8089}") String requerimientosUrl,
			@Value("${CATALOGO_SERVICE_URL:http://localhost:8087}") String catalogoUrl,
			@Value("${CASOS_SERVICE_URL:http://localhost:8090}") String casosUrl,
			@Value("${VULNERACIONES_SERVICE_URL:http://localhost:8091}") String vulneracionesUrl,
			@Value("${PRODUCTOS_SERVICE_URL:http://localhost:8092}") String productosUrl) {
		this.webClient = webClientBuilder.build();
		this.servicios = Map.of(
				"auth", authUrl,
				"personas", personasUrl,
				"requerimientos", requerimientosUrl,
				"catalogo", catalogoUrl,
				"casos", casosUrl,
				"vulneraciones", vulneracionesUrl,
				"productos", productosUrl);
	}

	@GetMapping(value = "/{servicio}/v3/api-docs", produces = MediaType.APPLICATION_JSON_VALUE)
	public Mono<ResponseEntity<String>> apiDocs(@PathVariable String servicio) {
		String baseUrl = servicios.get(servicio);
		if (baseUrl == null) {
			return Mono.just(ResponseEntity.notFound().build());
		}

		return webClient.get()
				.uri(baseUrl + "/v3/api-docs")
				.accept(MediaType.APPLICATION_JSON)
				.retrieve()
				.toEntity(String.class);
	}
}
