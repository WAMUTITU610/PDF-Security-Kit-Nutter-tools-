import pikepdf
from pikepdf import Pdf, Dictionary, Name, String, Stream

JS = 'eval(unescape("%61%70%70%2e%61%6c%65%72%74%28%31%29")); app.launchURL("http://example.test/x");'

def build(js_as_stream: bool):
    pdf = Pdf.new()
    pdf.add_blank_page()
    if js_as_stream:
        js = Stream(pdf, JS.encode())
    else:
        js = String(JS)
    action = pdf.make_indirect(Dictionary(S=Name.JavaScript, JS=js))
    pdf.Root.OpenAction = action
    return pdf

# control: plain, uncompressed objects
p = build(False); p.save("t1_plain.pdf", object_stream_mode=pikepdf.ObjectStreamMode.disable, compress_streams=False)
# same content, objects packed into compressed ObjStm
p = build(False); p.save("t2_objstm.pdf", object_stream_mode=pikepdf.ObjectStreamMode.generate, compress_streams=True)
# JS held in a Flate-compressed stream, objects packed
p = build(True);  p.save("t3_stream_objstm.pdf", object_stream_mode=pikepdf.ObjectStreamMode.generate, compress_streams=True)
# benign blank
p = Pdf.new(); p.add_blank_page(); p.save("t0_benign.pdf")
