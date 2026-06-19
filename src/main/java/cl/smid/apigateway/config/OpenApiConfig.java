package cl.smid.apigateway.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile({"local", "dev"})
public class OpenApiConfig {

	private static final String DESCRIPCION = """
			Frontera unica de entrada y agregador de documentacion OpenAPI del ecosistema SMID. \
			Los contratos funcionales reales viven en cada microservicio; el Gateway solo lista \
			sus especificaciones remotas para consulta en entornos local/dev.
			""";

	@Bean
	public OpenAPI smidGatewayOpenApi() {
		return new OpenAPI()
				.info(new Info()
						.title("SMID - API Gateway")
						.description(DESCRIPCION));
	}
}
