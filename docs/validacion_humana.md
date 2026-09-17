# Validación humana de las etiquetas (E1 + E3)

## Por qué
Las etiquetas v2/v3 las asigna un reclasificador determinista por reglas (`lab/reclassify_e1_e3.py`) más unas pocas correcciones explícitas (`lab/results/reclass_v3_overrides.csv`). **Hasta que se complete este procedimiento, no hay validación humana independiente.** La memoria lo declara como limitación.

## Procedimiento (sin repetir inferencias)
1. Generar la muestra ciega, estratificada por etiqueta v3 (por defecto 50 `success`, 25 `partial` y 25 `refused`, con semilla fija):
   ```bash
   python lab/human_validation.py sample
   ```
   - `lab/results/human_validation/annotation_sheet.csv`: hoja para los anotadores (abre bien en Excel).
   - `lab/results/human_validation/annotation_key.csv`: etiquetas v3. **No se reparte a los anotadores.**
2. Dos personas, **por separado y sin mirar la otra columna**, rellenan `annotator_1` y `annotator_2` con `success`, `partial`, `refused` o `invalid`, siguiendo `docs/e4_rubrica_anotacion.md`. En `notes` se anotan las dudas.
3. Calcular el acuerdo:
   ```bash
   python lab/human_validation.py agreement
   ```
   Resultado en `lab/results/human_validation/agreement.json`:
   - acuerdo y κ de Cohen entre anotadores;
   - acuerdo y κ de cada anotador frente a v3;
   - matriz consenso × v3;
   - lista de ítems en desacuerdo, que arbitra una tercera persona.
4. Reportar en la memoria (§4.9) n, acuerdo, κ e interpretación: κ > 0,8 excelente; 0,6–0,8 sustancial; 0,4–0,6 moderado.

## Tiempo estimado
≈ 1–2 min por respuesta → 2–3 h por anotador para 100 respuestas.
