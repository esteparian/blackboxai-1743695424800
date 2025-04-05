flowchart TD
    A[Inicio] -->|Login| B[Login]
    A -->|Registro| C[Registro]
    A -->|Recuperar Contraseña| D[Recuperar Contraseña]
    
    B -->|Éxito| E[Dashboard]
    B -->|Redes Sociales| F[Login Social]
    C -->|Éxito| G[Configuración de Perfil]
    
    E --> H[Perfil]
    E --> I[Denuncias]
    E --> J[Mapa]
    E --> K[Configuración]
    
    F -->|Google/Facebook| E
    G --> E
    
    H --> L[Editar Perfil]
    I --> M[Nueva Denuncia]
    I --> N[Historial]
    
    K --> O[Seguridad]
    K --> P[Notificaciones]
    
    classDef primary fill:#3b82f6,color:white
    classDef secondary fill:#10b981,color:white
    classDef tertiary fill:#6366f1,color:white
    
    class A,B,C,D primary
    class E,F,G secondary
    class H,I,J,K tertiary
```

### Páginas Principales:
1. **Inicio (index.html)** - Página de bienvenida
2. **Login (user_login.html)** - Inicio de sesión
3. **Registro (register.html)** - Creación de cuenta
4. **Dashboard (dashboard.html)** - Panel principal
5. **Perfil (profile.html)** - Información de usuario
6. **Denuncias (denuncias.html)** - Reportes de incidentes
7. **Configuración** - Ajustes de cuenta

### Flujos Principales:
- Registro → Configuración de Perfil → Dashboard
- Login → Dashboard
- Recuperación de Contraseña → Login