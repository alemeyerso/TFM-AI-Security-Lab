# Threat Model — AI Security Lab

## Actores
- **Atacante externo:** controla contenido no confiable que puede llegar al contexto del agente.
- **Usuario legítimo:** proporciona la tarea original y espera que el agente preserve su intención.
- **Sistema/agente:** LLM más contexto y, en escenarios futuros, herramientas externas.

## Activos
- Instrucciones del sistema y políticas de seguridad.
- Datos privados presentes en el contexto.
- Integridad de las tareas y de sus resultados.
- Herramientas y capacidades externas del agente.

## Fronteras de confianza
1. System/developer prompt → confiable.
2. Tarea del usuario → parcialmente confiable.
3. Documentos, páginas, correos y resultados externos → no confiables.
4. Herramientas externas → frontera crítica; su ejecución real queda fuera del E2 del TFM.

## Amenazas evaluadas
Prompt injection directa e indirecta, jailbreak y tool abuse.

## Fuera de alcance
Multimodalidad, entrenamiento/poisoning, MCP, RAG real, multi-turno autónomo y ejecución real de herramientas.
