import sys
content = open('docs/generate_tfm.py', encoding='utf-8').read().split('\n')
for i, line in enumerate(content):
    if '3.4.1. Limitaciones' in line:
        content.insert(i + 1, "p('Adicionalmente a las limitaciones descritas, cabe destacar que la defensa PromptGuard no se ha medido cuantitativamente con un modelo real; las inferencias no utilizaron una semilla fija, limitando la repetibilidad exacta de las respuestas; existen etiquetas en el canario y bateria benigna corregidas manualmente; el script generador de la bateria de agosto no forma parte del repositorio; y la revision de los resultados de Qwen en el notebook 05 fue asistida por IA y requiere confirmacion humana.', indent=True)")
        break
open('docs/generate_tfm.py', 'w', encoding='utf-8').write('\n'.join(content))
