#!/usr/bin/env python3
"""Render the atlas offline with actual Mermaid, using Chromium through Playwright.
Usage: python tools/render_diagrams.py [--only A00 I01] [--resume]
No remote navigation, production changes, credentials, or network requests.
"""
from pathlib import Path
import json, re, math, hashlib, argparse, time, traceback, shutil, importlib.metadata
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
p=argparse.ArgumentParser();p.add_argument('--only',nargs='*');p.add_argument('--resume',action='store_true');p.add_argument('--chromium',default=shutil.which('chromium') or shutil.which('google-chrome'));a=p.parse_args()
if not a.chromium:raise SystemExit('Chromium is required. Pass --chromium /path/to/chromium.')
index=json.loads((ROOT/'Diagram_Index.json').read_text());out=ROOT/'evidence/package/render-results.json'
old=json.loads(out.read_text()) if out.exists() else {'results':[]}
results={r['id']:r for r in old.get('results',[])}
style='''*{box-sizing:border-box}html,body{margin:0;background:#eef2f6;font-family:DejaVu Sans,Arial,sans-serif;color:#0f172a}#card{background:#fff;padding:0;border:1px solid #dbe3ef;overflow:hidden}header{background:#10233f;color:white;padding:32px 38px 27px;border-top:7px solid #14b8a6}#eyebrow{font-size:13px;letter-spacing:2.5px;text-transform:uppercase;color:#9ddde8;margin-bottom:12px}h1{font-size:30px;line-height:1.25;margin:0 0 12px;font-weight:700}#desc{font-size:15px;line-height:1.5;color:#d5dfec;max-width:1600px}#chart{padding:26px 30px 22px;display:flex;justify-content:center;align-items:flex-start;overflow:visible;background:#fff}#chart svg{display:block;max-width:none!important}footer{border-top:1px solid #e2e8f0;padding:20px 38px;background:#f8fafc;line-height:1.6;font-size:13px;color:#475569}.legend{display:flex;gap:22px;flex-wrap:wrap;margin-bottom:7px}.key{display:inline-flex;align-items:center;gap:7px}.dot{width:11px;height:11px;display:inline-block;border-radius:3px}.gate{background:#fbbf24}.done{background:#14b8a6}.control{background:#a78bfa}.hold{background:#fb7185}.nodeLabel p{margin:0}'''
html='''<!doctype html><html><head><meta charset="utf-8"><style>'''+style+'''</style></head><body><article id="card"><header><div id="eyebrow"></div><h1 id="title"></h1><div id="desc"></div></header><div id="chart"></div><footer><div class="legend"><span class="key"><i class="dot gate"></i>Approval / decision</span><span class="key"><i class="dot control"></i>Shared control</span><span class="key"><i class="dot done"></i>Confirmed output</span><span class="key"><i class="dot hold"></i>Hold / reconcile</span></div>MARKETING · V7 / AGENT DELIVERY · DESIGN & CONTROL LOGIC — NOT A LIVE DEPLOYMENT<br>Editable Mermaid and zoomable SVG included. Solid lines: process or handoff. Dotted lines: controls or contextual dependencies.</footer></article></body></html>'''
with sync_playwright() as pw:
 browser=pw.chromium.launch(executable_path=a.chromium,headless=True,args=['--no-sandbox','--disable-dev-shm-usage'])
 page=browser.new_page(viewport={'width':2400,'height':1800},device_scale_factor=1.6)
 page.route('**/*',lambda route:route.abort())
 page.set_content(html);page.add_script_tag(path=str(ROOT/'third_party/mermaid-runtime.js'))
 page.evaluate('''() => mermaid.initialize({startOnLoad:false,securityLevel:'strict',theme:'base',maxTextSize:500000,maxEdges:5000,fontFamily:'DejaVu Sans, Arial, sans-serif',themeVariables:{fontFamily:'DejaVu Sans, Arial, sans-serif',fontSize:'17px',primaryColor:'#f8fafc',primaryTextColor:'#172554',primaryBorderColor:'#94a3b8',lineColor:'#64748b',secondaryColor:'#ecfeff',tertiaryColor:'#f1f5f9',clusterBkg:'#f8fafc',clusterBorder:'#cbd5e1',edgeLabelBackground:'#ffffff'},flowchart:{htmlLabels:true,curve:'basis',useMaxWidth:false,nodeSpacing:34,rankSpacing:52,padding:18}})''')
 for n,d in enumerate(index):
  if a.only and d['id'] not in a.only:continue
  src=ROOT/d['mmd'];h=sha(src)
  if a.resume and results.get(d['id'],{}).get('status')=='PASS' and results[d['id']].get('source_sha256')==h and (ROOT/d['png']).exists():continue
  t=time.time()
  try:
   text=src.read_text()
   r=page.evaluate('''async ({text,id,title,kind,description})=>{
   document.getElementById('chart').innerHTML='';
   const result=await mermaid.render('render_'+id,text);
   const chart=document.getElementById('chart');chart.innerHTML=result.svg;
   const svg=chart.querySelector('svg');const v=svg.viewBox.baseVal;
   let w=v.width,h=v.height;
   // Keep raster resources bounded. Large topology remains fully zoomable in SVG.
   const limitW=id==='A03'?5600:2600, limitH=id==='A03'?8500:6500;
   let scale=Math.min(1,limitW/w,limitH/h,Math.sqrt(18000000/(w*h)));
   const sw=Math.ceil(w*scale),sh=Math.ceil(h*scale);
   svg.style.width=sw+'px';svg.style.height=sh+'px';svg.style.maxWidth='none';
   svg.setAttribute('width',String(sw));svg.setAttribute('height',String(sh));
   const cw=Math.max(900,sw+64);document.getElementById('card').style.width=cw+'px';
   document.getElementById('eyebrow').textContent=id+'  /  '+(kind==='workflow'?'WORKFLOW SPECIFICATION':'CONNECTED ARCHITECTURE');
   document.getElementById('title').textContent=title;
   document.getElementById('desc').textContent=description||'Controlled execution · accountable owner · explicit handoffs · recoverable state';
   return {svg:result.svg,natural_width:w,natural_height:h,scale,card_width:cw,render_width:sw,render_height:sh};
   }''',{'text':text,'id':d['id'],'title':d['title'],'kind':d['kind'],'description':d.get('description',d.get('subfamily',''))})
   (ROOT/d['svg']).write_text(r.pop('svg'))
   page.locator('#card').screenshot(path=str(ROOT/d['png']),timeout=120000)
   from PIL import Image
   with Image.open(ROOT/d['png']) as im:size=im.size
   results[d['id']]={'id':d['id'],'status':'PASS','source_sha256':h,'png_sha256':sha(ROOT/d['png']),'svg_sha256':sha(ROOT/d['svg']),'png_width':size[0],'png_height':size[1],'seconds':round(time.time()-t,2),**r}
   print(f'{d["id"]}: PASS {size} {time.time()-t:.1f}s',flush=True)
  except Exception as e:
   results[d['id']]={'id':d['id'],'status':'FAIL','source_sha256':h,'error':str(e)}
   print(f'{d["id"]}: FAIL {e}',flush=True)
  report={'renderer':'Actual Mermaid bundled flowchart parser + Dagre layout + Chromium/Playwright','runtime_sha256':sha(ROOT/'third_party/mermaid-runtime.js'),'playwright_version':importlib.metadata.version('playwright'),'chromium_version':browser.version,'diagram_count':len(index),'runtime_service_tests':'NOT_RUN','results':list(results.values())}
  out.write_text(json.dumps(report,indent=2))
 browser.close()
failed=[r for r in results.values() if r['status']!='PASS'];print(f'COMPLETE {len(results)} records; {len(failed)} failed',flush=True)
if failed:raise SystemExit(1)
