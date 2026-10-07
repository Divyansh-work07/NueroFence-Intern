import json
from pathlib import Path

def write_json(result, destination):
    Path(destination).write_text(json.dumps(result, indent=2), encoding='utf-8')

def write_pdf(result, destination):
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(str(destination), pagesize=letter); w, h = letter; y = h-48
    def line(text, size=10):
        nonlocal y
        if y < 55: c.showPage(); y = h-48
        c.setFont('Helvetica', size); c.drawString(48, y, str(text)[:110]); y -= 16
    c.setFont('Helvetica-Bold', 18); c.drawString(48, y, 'NeuroFence Security Scan'); y -= 28
    for key, val in [('File',result['file']['filename']),('Format',result['file']['format']),('SHA-256',result['file']['sha256']),('Risk',f"{result['risk']['level']} ({result['risk']['score']}/100)"),('Tensor count',result['model']['tensor_count']),('Parameters inspected',result['model']['parameter_count'])]: line(f'{key}: {val}')
    y -= 8; line('Findings',14)
    for item in result['findings']:
        line(f"[{item['severity']}] {item['title']} - {item['detail']}"); line('Recommendation: '+item['recommendation'])
    y -= 8; line('Limitations',14)
    for item in result['scope']['limitations']: line('- '+item)
    c.save()
