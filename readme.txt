=== DDoS Shield Pro ===
Contributors: nubasec
Tags: security, rate limit, login protection, firewall, monitoring
Requires at least: 6.0
Tested up to: 6.6
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Protección básica contra abuso de solicitudes, intentos de fuerza bruta, bloqueo de IPs, alertas y monitoreo administrativo.

== Description ==

DDoS Shield Pro permite monitorear y mitigar eventos básicos de abuso web desde WordPress.

Funcionalidades principales:

* Rate limit por IP.
* Protección contra intentos repetidos de login fallido.
* Bloqueo temporal de IPs.
* Dashboard administrativo con métricas, tendencia y logs.
* Exportación CSV con protección contra CSV injection.
* Alertas HTML por correo con rate limit.
* Whitelist de IPs y rangos CIDR IPv4.
* Opción controlada para confiar en X-Forwarded-For solo desde proxies permitidos.
* Geolocalización externa desactivada por defecto.
* Marca Nubasec configurable desde el panel.

Nota importante: este plugin proporciona controles básicos de monitoreo y bloqueo. No reemplaza un WAF perimetral, Cloudflare, ModSecurity, reglas OWASP CRS, controles del hosting ni mecanismos especializados contra ataques distribuidos.

== Privacy ==

Por defecto, el plugin no realiza consultas externas para geolocalizar IPs.

Si el administrador activa la opción de geolocalización, el plugin puede consultar ipapi.co para obtener el país de origen de IPs bloqueadas. Esta función debe activarse explícitamente desde la configuración.

== Installation ==

1. Sube el ZIP del plugin desde Plugins > Añadir nuevo > Subir plugin.
2. Activa DDoS Shield Pro.
3. Ve al menú DDoS Shield Pro.
4. Ajusta límites, whitelist, correo de alertas y retención de logs.
5. Valida cuidadosamente los límites antes de usarlo en producción.

== Frequently Asked Questions ==

= ¿Este plugin es un WAF completo? =

No. Es un sistema de protección básica, rate limit, bloqueo temporal, alertas y monitoreo. Debe complementarse con controles perimetrales.

= ¿El plugin consulta servicios externos? =

No por defecto. La geolocalización externa viene desactivada. Si se activa, puede consultar ipapi.co.

= ¿Puedo usar X-Forwarded-For? =

Sí, pero solo si activas la opción y declaras proxies confiables. No se confía en ese header por defecto.

= ¿El plugin elimina datos al desinstalar? =

Solo si activas la opción "Eliminar datos al desinstalar".

== Screenshots ==

1. Dashboard Nubasec Shield con métricas y logs.
2. Panel de configuración de protección, marca y privacidad.

== Changelog ==

= 1.0.0 =
* Primera versión endurecida bajo marca Nubasec.
* Rate limit por IP.
* Protección contra fuerza bruta de login.
* Dashboard administrativo moderno.
* Exportación CSV segura.
* Geolocalización externa opcional y desactivada por defecto.
* Whitelist con soporte para IPs y CIDR IPv4.
