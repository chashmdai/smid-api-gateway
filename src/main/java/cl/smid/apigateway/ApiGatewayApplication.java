package cl.smid.apigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Punto de entrada del API Gateway SMID (puerto 8080).
 *
 * <p>El Gateway es la frontera de seguridad del ecosistema: valida el contrato
 * de claims 2.4 (firma por {@code kid}, {@code iss}, {@code aud}, {@code exp}
 * con skew de 30 s), audita el tráfico con {@code X-Request-Id}, normaliza
 * todo error al sobre unificado 2.5 y enruta hacia el núcleo fundacional
 * (8081/8087/8088/8089) y los servicios legados del patrón strangler.</p>
 *
 * <p>{@link ConfigurationPropertiesScan} habilita el binding por constructor
 * de los records de configuración ({@code PropiedadesJwt},
 * {@code PropiedadesCors}) sin necesidad de declararlos bean a bean.</p>
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class ApiGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(ApiGatewayApplication.class, args);
	}

}
