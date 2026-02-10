# 🛡️ DDoS Shield Pro - Enterprise WAF for WordPress

![Version](https://img.shields.io/badge/version-12.0-blue.svg)
![WordPress](https://img.shields.io/badge/WordPress-%3E%3D5.8-blue.svg)
![PHP](https://img.shields.io/badge/PHP-%3E%3D7.4-777bb4.svg)
![License](https://img.shields.io/badge/license-GPLv2-green.svg)

**DDoS Shield Pro** es una solución de seguridad integral (WAF) para WordPress diseñada para mitigar ataques de Capa 7 (HTTP Floods) y prevenir intentos de intrusión por Fuerza Bruta en el login. 

Incluye un **Centro de Comando Visual** con mapas de calor geográficos, reportes forenses exportables y capacidades de **Marca Blanca (White Label)** para agencias y equipos de seguridad corporativos.

---

## 🚀 Características Principales

### 1. Protección de Tráfico (Anti-DDoS)
* **Rate Limiting Dinámico:** Monitorea solicitudes por minuto (RPM) por dirección IP.
* **Bloqueo Automático:** Detiene IPs que exceden el umbral configurado antes de que cargue WordPress.
* **Optimización de Recursos:** Utiliza tablas SQL personalizadas y Transients para minimizar el impacto en la CPU.

### 2. Escudo de Login (Anti-Brute Force)
* **Protección de `wp-login.php`:** Detecta intentos fallidos de contraseña repetitivos.
* **Bloqueo Inteligente:** Diferencia entre un usuario olvidadizo y un bot de ataque.
* **Configuración Flexible:** Permite definir intentos máximos y tiempo de castigo (horas).

### 3. Dashboard "Security Command Center"
* **🌍 Mapa Mundi Interactivo:** Visualización de ataques por país en tiempo real (Google GeoCharts).
* **📈 Tendencias de Ataque:** Gráficas de línea y dona (Chart.js) para analizar picos de tráfico.
* **🎨 Marca Blanca (White Label):** Personaliza el dashboard con el **Logo** y **Colores Corporativos** de tu empresa.

### 4. Reportes y Alertas
* **📧 Alertas HTML Premium:** Notificaciones por correo electrónico con diseño responsivo, detalles del ataque y marca personalizada.
* **📥 Análisis Forense (CSV):** Exportación de logs filtrados por fecha (Rango) y tipo de amenaza (DDoS vs Login).
* **Detección de Huella Digital:** Registra IP, País, Sistema Operativo, Navegador y User Agent completo.

### 5. Mantenimiento Automático
* **Auto-Purge:** Sistema Cron interno que elimina registros de más de 30 días para mantener la base de datos optimizada.

---

## 🛠️ Instalación

1.  Clona este repositorio en tu carpeta de plugins:
    ```bash
    cd wp-content/plugins
    git clone [https://github.com/nubasec/ddos-shield-pro.git](https://github.com/nubasec/ddos-shield-pro.git)
    ```
2.  Accede al panel de administración de WordPress.
3.  Ve a **Plugins** > **Plugins Instalados**.
4.  Activa **DDoS Shield Pro**.

---

## ⚙️ Configuración

Una vez activado, navega a **Ajustes** > **Security Monitor**.

### Panel de Control
* **Límite DDoS (Req/Min):** Recomendado `60` para sitios normales, `120` para alto tráfico.
* **Protección Login:** Recomendado `5` intentos máximos.
* **Whitelist:** Agrega las IPs de tus administradores (una por línea) para evitar bloqueos accidentales.

### Personalización (Marca Blanca)
1.  Sube tu logo a la biblioteca de medios.
2.  Copia la URL del logo y pégala en el campo **URL del Logo**.
3.  Selecciona tu **Color Primario** y **Secundario** usando los selectores de color.
4.  Guarda los cambios para transformar la interfaz del plugin.

---

## 📂 Estructura del Proyecto

```text
ddos-shield-pro/
├── ddos-shield-pro.php    # Núcleo lógico (Firewall, Admin, DB)
├── README.md              # Documentación
└── index.php              # Acceso

---

## 🌐 Conecta con Nubasec

Llevamos la seguridad web al siguiente nivel. Síguenos para actualizaciones y nuevas herramientas.

---

## 🌐 Conecta con Nubasec

Mantente actualizado con las últimas herramientas de seguridad y lanzamientos.

